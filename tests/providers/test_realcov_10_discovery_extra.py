# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-logic coverage for DiscoveryCache TTL and ModelDiscovery query helpers.

These tests exercise the genuine cache-expiry, lookup, and aggregation logic
of :class:`~intellicrack.providers.discovery.DiscoveryCache` and
:class:`~intellicrack.providers.discovery.ModelDiscovery` without any network
access. The cache and query helpers are pure in-memory logic units with no
external dependency, so they are driven directly with real ``ModelInfo`` data
and the computed result is asserted, not merely that a call occurred.
"""

from __future__ import annotations

import time

import pytest

from intellicrack.core.types import ModelInfo, ProviderName
from intellicrack.providers.discovery import DiscoveryCache, ModelDiscovery
from intellicrack.providers.registry import ProviderRegistry


def _model(
    provider: ProviderName,
    mid: str,
    *,
    context_window: int = 128000,
    supports_tools: bool = True,
    supports_streaming: bool = True,
) -> ModelInfo:
    """Build a real ModelInfo for cache-population tests.

    Args:
        provider: Provider that owns the model.
        mid: Model identifier and display name.
        context_window: Context window size in tokens.
        supports_tools: Whether the model advertises tool support.
        supports_streaming: Whether the model advertises streaming.

    Returns:
        ModelInfo: The constructed model record.
    """
    return ModelInfo(
        id=mid,
        name=mid,
        provider=provider,
        context_window=context_window,
        supports_tools=supports_tools,
        supports_vision=False,
        supports_streaming=supports_streaming,
        input_cost_per_1m_tokens=1.0,
        output_cost_per_1m_tokens=2.0,
    )


class TestDiscoveryCacheTtlExpiry:
    """The cache honours its TTL and reports expiry accurately."""

    @staticmethod
    def test_entry_expires_after_ttl_elapses() -> None:
        """An entry set with a zero TTL is treated as immediately expired."""
        cache = DiscoveryCache(ttl_seconds=0)
        cache.set(ProviderName.OPENAI, [_model(ProviderName.OPENAI, "gpt-x")])
        time.sleep(0.01)
        assert cache.get(ProviderName.OPENAI) is None
        assert cache.is_expired(ProviderName.OPENAI) is True

    @staticmethod
    def test_fresh_entry_within_ttl_is_returned() -> None:
        """A fresh entry inside its TTL window is returned and not expired."""
        cache = DiscoveryCache(ttl_seconds=3600)
        models = [_model(ProviderName.ANTHROPIC, "claude-x")]
        cache.set(ProviderName.ANTHROPIC, models)
        result = cache.get(ProviderName.ANTHROPIC)
        assert result is not None
        assert [m.id for m in result] == ["claude-x"]
        assert cache.is_expired(ProviderName.ANTHROPIC) is False

    @staticmethod
    def test_missing_provider_reports_expired() -> None:
        """A provider that was never cached is reported as expired."""
        cache = DiscoveryCache(ttl_seconds=3600)
        assert cache.is_expired(ProviderName.GOOGLE) is True
        assert cache.get(ProviderName.GOOGLE) is None

    @staticmethod
    def test_get_all_cached_excludes_expired_entries() -> None:
        """Expired entries are filtered out of the aggregate snapshot."""
        cache = DiscoveryCache(ttl_seconds=0)
        cache.set(ProviderName.OPENAI, [_model(ProviderName.OPENAI, "a")])
        time.sleep(0.01)
        assert cache.get_all_cached() == {}

    @staticmethod
    def test_invalidate_specific_provider_keeps_others() -> None:
        """Invalidating one provider leaves other cached providers intact."""
        cache = DiscoveryCache(ttl_seconds=3600)
        cache.set(ProviderName.OPENAI, [_model(ProviderName.OPENAI, "a")])
        cache.set(ProviderName.GOOGLE, [_model(ProviderName.GOOGLE, "b")])
        cache.invalidate(ProviderName.OPENAI)
        assert cache.get(ProviderName.OPENAI) is None
        google = cache.get(ProviderName.GOOGLE)
        assert google is not None
        assert google[0].id == "b"


class TestModelDiscoveryQueryHelpers:
    """Search, lookup, and aggregation read genuine cached model data."""

    @staticmethod
    def _populate() -> ModelDiscovery:
        """Build a ModelDiscovery whose cache holds real multi-provider data.

        Returns:
            ModelDiscovery: Orchestrator with a pre-populated cache.
        """
        discovery = ModelDiscovery(ProviderRegistry(), cache_ttl=3600)
        discovery.cache.set(
            ProviderName.OPENAI,
            [
                _model(ProviderName.OPENAI, "gpt-4o", context_window=128000),
                _model(ProviderName.OPENAI, "gpt-4o-mini", context_window=128000),
            ],
        )
        discovery.cache.set(
            ProviderName.ANTHROPIC,
            [_model(ProviderName.ANTHROPIC, "claude-sonnet", context_window=200000)],
        )
        return discovery

    def test_search_matches_substring_case_insensitively(self) -> None:
        """search() returns every model whose id/name contains the query."""
        discovery = self._populate()
        results = discovery.search("GPT-4O")
        ids = sorted(m.id for m in results)
        assert ids == ["gpt-4o", "gpt-4o-mini"]

    def test_get_by_id_returns_exact_model(self) -> None:
        """get_by_id() resolves a model from the right provider's cache."""
        discovery = self._populate()
        model = discovery.get_by_id(ProviderName.ANTHROPIC, "claude-sonnet")
        assert model is not None
        assert model.context_window == 200000

    def test_get_by_id_unknown_returns_none(self) -> None:
        """get_by_id() returns None for an id not present in the cache."""
        discovery = self._populate()
        assert discovery.get_by_id(ProviderName.OPENAI, "no-such-model") is None

    def test_provider_model_count_reflects_cache(self) -> None:
        """get_provider_model_count() reports per-provider cached counts."""
        discovery = self._populate()
        counts = discovery.get_provider_model_count()
        assert counts[ProviderName.OPENAI] == 2
        assert counts[ProviderName.ANTHROPIC] == 1


class TestGetRecommendedModelSelection:
    """Recommendation logic picks real models matching the task profile."""

    @staticmethod
    def _discovery_with_models() -> ModelDiscovery:
        """Build a ModelDiscovery with models of varied capabilities.

        Returns:
            ModelDiscovery: Orchestrator with a populated cache.
        """
        discovery = ModelDiscovery(ProviderRegistry(), cache_ttl=3600)
        discovery.cache.set(
            ProviderName.OPENAI,
            [
                _model(
                    ProviderName.OPENAI,
                    "small-tools",
                    context_window=8000,
                    supports_tools=True,
                ),
                _model(
                    ProviderName.OPENAI,
                    "large-tools",
                    context_window=1000000,
                    supports_tools=True,
                ),
            ],
        )
        return discovery

    @pytest.mark.asyncio
    async def test_analysis_prefers_largest_context_tool_model(self) -> None:
        """Analysis recommendation selects the largest-context tool model."""
        discovery = self._discovery_with_models()
        recommendation = await discovery.get_recommended_model("analysis")
        assert recommendation is not None
        assert recommendation.id == "large-tools"
