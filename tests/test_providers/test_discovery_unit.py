# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Unit tests for providers.discovery (audit2 F-0006..F-0024 coverage)."""

from __future__ import annotations

import asyncio
import json
from itertools import starmap
from typing import TYPE_CHECKING, override

import pytest

from intellicrack.core.types import (
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
    ToolCall,
)
from intellicrack.providers.base import LLMProviderBase
from intellicrack.providers.discovery import (
    DiscoveryCache,
    DiscoveryFilter,
    ModelDiscovery,
)
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from intellicrack.core.types import ThinkingConfig, ToolChoice, ToolDefinition


class _DiscoveryProvider(LLMProviderBase):
    """Provider with a configurable list_models() result."""

    def __init__(
        self,
        provider_name: ProviderName,
        models: list[ModelInfo] | None = None,
        error: BaseException | None = None,
    ) -> None:
        """Initialize the provider with the configured behaviour.

        Args:
            provider_name: The provider name to use.
            models: Models that ``list_models()`` should return.
            error: Optional error to raise instead of returning models.
        """
        super().__init__()
        self._name = provider_name
        self.models = models or []
        self._error = error
        self.connected = True

    @property
    @override
    def name(self) -> ProviderName:
        """Return the provider's enum name.

        Returns:
            ProviderName: The configured provider name.
        """
        return self._name

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Mark the provider connected.

        Args:
            credentials: Provided credentials (recorded but unused).
        """
        self._credentials = credentials
        self.connected = True

    @override
    async def list_models(self) -> list[ModelInfo]:
        """Return the configured models or raise the configured error.

        Returns:
            list[ModelInfo]: The configured model list.
        """
        if self._error is not None:
            _reraise(self._error)
        return list(self.models)

    @override
    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Return an empty assistant response.

        Args:
            messages: Conversation history.
            model: Model ID.
            tools: Available tools.
            temperature: Sampling temperature.
            max_tokens: Max response tokens.
            tool_choice: Tool selection directive.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable provider-side prompt caching.

        Returns:
            tuple[Message, list[ToolCall] | None]: (assistant message, no tool calls).
        """
        _ = (messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache)
        return Message(role="assistant", content=""), None

    @override
    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> AsyncIterator[str]:
        """Yield a single empty chunk.

        Args:
            messages: Conversation history.
            model: Model ID.
            tools: Available tools.
            temperature: Sampling temperature.
            max_tokens: Max response tokens.
            tool_choice: Tool selection directive.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable provider-side prompt caching.

        Yields:
            str: An empty string.
        """
        _ = (messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache)
        yield ""

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Return an empty tool list.

        Args:
            tools: Tools to convert.

        Returns:
            list[dict[str, object]]: Empty list.
        """
        _ = tools
        return []

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Return an empty message list.

        Args:
            messages: Messages to convert.

        Returns:
            list[dict[str, object]]: Empty list.
        """
        _ = messages
        return []


def _reraise(err: BaseException) -> None:
    """Re-raise a previously captured exception.

    The exception passed in is propagated unchanged so that callers can
    plug arbitrary configured errors into the test providers.

    Args:
        err: The exception instance to re-raise.

    Raises:
        err: The exception instance supplied as the ``err`` argument.
    """
    raise err


def _model(
    provider: ProviderName,
    mid: str,
    *,
    name: str | None = None,
    context_window: int = 128000,
    supports_tools: bool = True,
    supports_vision: bool = False,
    supports_streaming: bool = True,
    input_cost_per_1m_tokens: float | None = 1.0,
    output_cost_per_1m_tokens: float | None = 2.0,
) -> ModelInfo:
    """Build a ModelInfo with sensible defaults.

    Args:
        provider: Provider that owns the model.
        mid: Model identifier (also used for the display name when ``name`` is None).
        name: Optional display name override; defaults to ``mid``.
        context_window: Context window size in tokens.
        supports_tools: Whether the model supports function calling.
        supports_vision: Whether the model supports image input.
        supports_streaming: Whether the model supports streaming.
        input_cost_per_1m_tokens: Cost per 1M input tokens; None to omit.
        output_cost_per_1m_tokens: Cost per 1M output tokens; None to omit.

    Returns:
        ModelInfo: The constructed model.
    """
    return ModelInfo(
        id=mid,
        name=name if name is not None else mid,
        provider=provider,
        context_window=context_window,
        supports_tools=supports_tools,
        supports_vision=supports_vision,
        supports_streaming=supports_streaming,
        input_cost_per_1m_tokens=input_cost_per_1m_tokens,
        output_cost_per_1m_tokens=output_cost_per_1m_tokens,
    )


class TestF0006F0007AsyncCacheLockHonoured:
    """F-0006/F-0007: aget/aset/ainvalidate serialize through the lock."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_async_set_then_async_get_round_trip() -> None:
        """A value written via aset() must be visible via aget()."""
        cache = DiscoveryCache(ttl_seconds=60)
        models = [_model(ProviderName.OPENAI, "gpt-x")]
        await cache.aset(ProviderName.OPENAI, models)
        result = await cache.aget(ProviderName.OPENAI)
        assert result is not None
        assert [m.id for m in result] == ["gpt-x"]

    @pytest.mark.asyncio
    @staticmethod
    async def test_concurrent_async_writes_do_not_lose_entries() -> None:
        """Concurrent aset() calls under the lock leave a consistent cache."""
        cache = DiscoveryCache(ttl_seconds=60)
        targets = [
            (ProviderName.OPENAI, "openai-1"),
            (ProviderName.ANTHROPIC, "claude-1"),
            (ProviderName.GOOGLE, "gemini-1"),
        ]

        async def writer(provider: ProviderName, model_id: str) -> None:
            await cache.aset(provider, [_model(provider, model_id)])

        await asyncio.gather(*starmap(writer, targets))
        for provider, model_id in targets:
            entry = await cache.aget(provider)
            assert entry is not None
            assert entry[0].id == model_id


class TestF0008GetRecommendedAwaitsDiscovery:
    """F-0008: get_recommended_model awaits discovery on a cold cache."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_cold_cache_triggers_discover_all() -> None:
        """Cold cache triggers discover_all and returns a candidate."""
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "gpt-x")],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        recommendation = await discovery.get_recommended_model("analysis")
        assert recommendation is not None
        assert recommendation.id == "gpt-x"


class TestF0009UnknownTaskTypeRaises:
    """F-0009: get_recommended_model rejects unknown task types."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_unknown_task_type_raises_value_error() -> None:
        """An unknown task_type must raise ValueError."""
        reg = ProviderRegistry()
        discovery = ModelDiscovery(reg)
        with pytest.raises(ValueError, match="unknown task_type"):
            await discovery.get_recommended_model("not_real")


class TestF0010F0024RegexFilter:
    """F-0010: filter uses re.search; F-0024: invalid regex raises."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_regex_substring_match() -> None:
        """A substring regex must match models even if not anchored to the start."""
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "openai/gpt-4o")],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()
        results = discovery.filter(DiscoveryFilter(model_id_pattern="gpt-4"))
        assert any(m.id == "openai/gpt-4o" for m in results)

    @staticmethod
    def test_invalid_regex_raises_value_error() -> None:
        """An invalid regex must raise ValueError instead of degrading silently."""
        reg = ProviderRegistry()
        discovery = ModelDiscovery(reg)
        with pytest.raises(ValueError, match="invalid regex"):
            discovery.filter(DiscoveryFilter(model_id_pattern="["))


class TestF0011EmptyModelsNotCached:
    """F-0011: empty discovery results are never cached as success."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_empty_list_not_cached_via_discover_all() -> None:
        """An empty list returned by list_models must not populate the cache."""
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(ProviderName.OPENAI, models=[])
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()
        assert discovery.cache.get(ProviderName.OPENAI) is None

    @pytest.mark.asyncio
    @staticmethod
    async def test_empty_aset_clears_existing_entry() -> None:
        """Calling aset() with an empty list invalidates any existing entry."""
        cache = DiscoveryCache(ttl_seconds=60)
        await cache.aset(ProviderName.OPENAI, [_model(ProviderName.OPENAI, "x")])
        assert cache.get(ProviderName.OPENAI) is not None
        await cache.aset(ProviderName.OPENAI, [])
        assert cache.get(ProviderName.OPENAI) is None


class TestF0012NoCacheUseFalse:
    """F-0012: discover_all(use_cache=False) does not write the shared cache."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_use_cache_false_leaves_cache_unchanged() -> None:
        """Existing cache must be untouched when use_cache=False."""
        reg = ProviderRegistry()
        models = [_model(ProviderName.OPENAI, "preexisting")]
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "fresh")],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.cache.aset(ProviderName.OPENAI, models)
        results = await discovery.discover_all(use_cache=False)
        assert results[ProviderName.OPENAI][0].id == "fresh"
        cached = discovery.cache.get(ProviderName.OPENAI)
        assert cached is not None
        assert cached[0].id == "preexisting"


class TestF0017DiscoverProviderInvalidatesStaleCache:
    """F-0017: discover_provider invalidates cache when provider unconnected."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_unconnected_provider_invalidates_stale_cache() -> None:
        """Stale cache entries are dropped when the provider is unconnected."""
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "stale")],
        )
        provider.connected = False
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.cache.aset(
            ProviderName.OPENAI,
            [_model(ProviderName.OPENAI, "stale")],
        )
        result = await discovery.discover_provider(
            ProviderName.OPENAI,
            use_cache=False,
        )
        assert result == []
        assert discovery.cache.get(ProviderName.OPENAI) is None


class TestF0018DRYDiffHelper:
    """F-0018: model-diff logic is consolidated in a single helper."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_discover_provider_diff_against_cache() -> None:
        """discover_provider records new/removed model IDs vs prior cache."""
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "b"),
                _model(ProviderName.OPENAI, "c"),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.cache.aset(
            ProviderName.OPENAI,
            [_model(ProviderName.OPENAI, "a"), _model(ProviderName.OPENAI, "b")],
        )
        await discovery.discover_provider(ProviderName.OPENAI, use_cache=False)
        last = discovery.get_last_event(ProviderName.OPENAI)
        assert last is not None
        assert sorted(last.new_models) == ["c"]
        assert sorted(last.removed_models) == ["a"]


class TestF0019SaveSnapshotsTime:
    """F-0019: save_to_disk samples time once and persists entries."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_save_persists_unexpired_entries(tmp_path: Path) -> None:
        """Saving the cache must not skip valid entries due to TOCTOU drift."""
        cache = DiscoveryCache(ttl_seconds=60)
        await cache.aset(ProviderName.OPENAI, [_model(ProviderName.OPENAI, "a")])
        out = tmp_path / "cache.json"
        await cache.save_to_disk(out)
        data = json.loads(out.read_text("utf-8"))
        entries = data["entries"]
        assert ProviderName.OPENAI.value in entries


class TestF0020AtomicLoadFromDisk:
    """F-0020: load_from_disk leaves the in-memory cache intact on errors."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_corrupt_json_preserves_existing_cache(tmp_path: Path) -> None:
        """A malformed JSON file must not clobber the existing cache."""
        cache = DiscoveryCache(ttl_seconds=60)
        await cache.aset(ProviderName.OPENAI, [_model(ProviderName.OPENAI, "live")])
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        await cache.load_from_disk(bad)
        result = cache.get(ProviderName.OPENAI)
        assert result is not None
        assert result[0].id == "live"

    @pytest.mark.asyncio
    @staticmethod
    async def test_partially_invalid_payload_preserves_existing_cache(
        tmp_path: Path,
    ) -> None:
        """A partially invalid payload must not partially overwrite the cache."""
        cache = DiscoveryCache(ttl_seconds=60)
        await cache.aset(ProviderName.OPENAI, [_model(ProviderName.OPENAI, "live")])

        bad_payload = {
            "version": 1,
            "ttl_seconds": 60,
            "saved_at": 0,
            "entries": {
                ProviderName.GOOGLE.value: {
                    "models": "not-a-list",
                    "expires_at": 9999999999,
                    "timestamp": 0,
                },
            },
        }
        bad = tmp_path / "partial.json"
        bad.write_text(json.dumps(bad_payload), encoding="utf-8")
        await cache.load_from_disk(bad)
        live = cache.get(ProviderName.OPENAI)
        assert live is not None
        assert live[0].id == "live"
        assert cache.get(ProviderName.GOOGLE) is None


class TestF0021DiscoverAllInvalidatesOnError:
    """F-0021: per-provider discovery errors invalidate stale cache entries."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_error_invalidates_stale_entry() -> None:
        """A failing list_models() call must invalidate the prior cache entry."""
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            error=ConnectionError("network unreachable"),
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.cache.aset(
            ProviderName.OPENAI,
            [_model(ProviderName.OPENAI, "stale")],
        )
        await discovery.discover_all(force_refresh=True)
        assert discovery.cache.get(ProviderName.OPENAI) is None


class TestRealProviderConnectionContract:
    """Discovery against a real production provider, with no network.

    The other tests in this module deliberately feed the real
    :class:`ModelDiscovery` logic through a configurable provider source
    (``_DiscoveryProvider``); the provider there is an input, not the thing
    under test. These tests close the gap flagged in the audit by driving the
    pipeline through the genuine production :class:`OpenAIProvider` in its real,
    unconnected state. They exercise the real base-class connection-state
    contract (``is_connected`` derived from ``connected``) and the real
    provider's ``list_models`` guard, neither of which a stub that hardcodes
    ``connected = True`` can verify. No credentials and no sockets are used: a
    freshly constructed provider is unconnected by contract.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_real_unconnected_provider_gates_discovery() -> None:
        """A real unconnected OpenAIProvider yields no models and clears stale cache.

        ``discover_provider`` must consult the provider's real ``is_connected``
        property. A fresh provider is unconnected, so discovery returns an empty
        list and any stale cache entry is invalidated. A regression making
        ``is_connected`` always-true (or dropping the guard) would let stale
        models leak through and fail this test.
        """
        provider = OpenAIProvider()
        assert provider.is_connected is False

        reg = ProviderRegistry()
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.cache.aset(
            ProviderName.OPENAI,
            [_model(ProviderName.OPENAI, "gpt-stale")],
        )

        result = await discovery.discover_provider(ProviderName.OPENAI, use_cache=False)

        assert result == []
        assert discovery.cache.get(ProviderName.OPENAI) is None

    @pytest.mark.asyncio
    @staticmethod
    async def test_real_provider_list_models_raises_when_unconnected() -> None:
        """A real unconnected OpenAIProvider.list_models raises ProviderError.

        This is the production guard the discovery layer relies on. If the guard
        were removed the call would attempt to use a ``None`` client; the test
        pins the exact contract (``ProviderError`` with the not-connected
        message).
        """
        provider = OpenAIProvider()
        with pytest.raises(ProviderError, match="Not connected to OpenAI API"):
            await provider.list_models()

    @pytest.mark.asyncio
    @staticmethod
    async def test_real_provider_connect_then_disconnect_round_trips_state() -> None:
        """The real base-class connection flag flips through connect/disconnect.

        ``discover_provider`` gates on ``is_connected``; that property must
        reflect the real ``connected`` flag. Driving the genuine provider
        through ``disconnect`` proves the flag is honoured rather than pinned.
        """
        provider = OpenAIProvider()
        provider.connected = True
        assert provider.is_connected is True

        await provider.disconnect()

        assert provider.connected is False
        assert provider.is_connected is False


class TestRoundTripPersistence:
    """Sanity check: save_to_disk -> load_from_disk preserves entries."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_save_then_load_round_trip(tmp_path: Path) -> None:
        """Round-trip persistence keeps a non-expired entry intact."""
        cache_a = DiscoveryCache(ttl_seconds=600)
        await cache_a.aset(
            ProviderName.OPENAI,
            [_model(ProviderName.OPENAI, "round-trip")],
        )
        path = tmp_path / "cache.json"
        await cache_a.save_to_disk(path)

        cache_b = DiscoveryCache(ttl_seconds=600)
        await cache_b.load_from_disk(path)
        loaded = cache_b.get(ProviderName.OPENAI)
        assert loaded is not None
        assert loaded[0].id == "round-trip"
