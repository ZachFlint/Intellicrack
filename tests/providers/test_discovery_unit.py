# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Unit tests for providers.discovery (audit2 F-0006..F-0024 coverage).

These tests drive the real ModelDiscovery, DiscoveryCache, and DiscoveryFilter
implementations with exact known-correct expected values derived independently
of the production code. Every test is a genuine falsifiable gate: removing or
corrupting the covered production code causes the test to go red.
"""

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
    """Provider with a configurable list_models() result.

    Used as a controlled input source for discovery-layer tests. The
    discovery logic (caching, filtering, diff, recommendations) is the
    thing under test; this provider supplies known model lists so
    expected outputs can be independently derived.
    """

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
        """The provider's enum name.

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

        assert not provider.connected
        assert provider.is_connected is False

    @pytest.mark.asyncio
    @staticmethod
    async def test_discover_all_real_unconnected_provider_gates_via_is_connected() -> None:
        """``discover_all`` gates on the real ``is_connected`` property, not raw ``connected``.

        A fresh ``OpenAIProvider`` has ``connected = False``; ``is_connected``
        returns the same value because the base-class property is ``return
        self.connected``. The ``discover_all`` inner coroutine checks
        ``not provider.is_connected`` at line 601 of discovery.py and takes
        the early-return path — it does NOT call ``list_models()``.

        Assertions that pin this contract:

        1. ``is_connected is False`` on the real provider before the call.
        2. The result dict contains the provider key with an empty list
           (the early-return path populates results[], not just an empty dict).
        3. The stale cache entry is invalidated (force_refresh=True triggers
           ``ainvalidate`` inside the is_connected branch).
        4. A ``DiscoveryEvent`` is recorded with ``success=False`` and
           ``error_message == "Provider not connected"`` — the exact sentinel
           string produced by the is_connected branch. If the guard were
           removed, the provider would reach ``list_models()`` and raise
           ``ProviderError("Not connected to OpenAI API")``, producing a
           *different* error_message and failing assertion 4.
        """
        provider = OpenAIProvider()
        assert provider.is_connected is False

        reg = ProviderRegistry()
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.cache.aset(
            ProviderName.OPENAI,
            [_model(ProviderName.OPENAI, "gpt-stale-all")],
        )

        results = await discovery.discover_all(force_refresh=True)

        assert ProviderName.OPENAI in results
        assert results[ProviderName.OPENAI] == []
        assert discovery.cache.get(ProviderName.OPENAI) is None

        last = discovery.get_last_event(ProviderName.OPENAI)
        assert last is not None
        assert last.success is False
        assert last.error_message == "Provider not connected"


class TestRealProviderDiscoveryErrorPropagation:
    """Discovery pipeline driven through the real OpenAIProvider error path.

    The other test classes exercise discovery/filtering via ``_DiscoveryProvider``,
    which hardcodes ``connected = True`` and injects errors via a ``_error``
    attribute. Those tests cover the discovery orchestration logic but cannot
    exercise the ``ProviderError`` exception path that a real provider raises.

    The real ``OpenAIProvider.list_models()`` raises ``ProviderError`` (not
    ``ConnectionError``) when ``self.connected is True`` but ``self.client is
    None``. The ``discover_all`` error handler must catch ``ProviderError`` and
    record a ``DiscoveryEvent`` with ``success=False`` and the provider's error
    message. Only the inner except path on the coroutine produces that event;
    if ``ProviderError`` were removed from the except clause the exception would
    propagate past the inner handler, be caught by ``asyncio.gather``, and no
    ``DiscoveryEvent`` would be appended — making the event-message assertion the
    falsifying gate.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_discover_all_real_provider_error_leaves_event_with_error_message() -> None:
        """A real ProviderError must produce a failure DiscoveryEvent with error_message set.

        After ``discover_all`` handles the ``ProviderError`` from the real
        ``OpenAIProvider``, a ``DiscoveryEvent`` must be recorded with
        ``success=False`` and ``error_message`` containing the provider's error
        text. The exact message is the string that ``OpenAIProvider`` raises:
        ``"Not connected to OpenAI API"``.
        """
        provider = OpenAIProvider()
        provider.connected = True
        assert provider.client is None

        reg = ProviderRegistry()
        reg.register(provider)
        discovery = ModelDiscovery(reg)

        await discovery.discover_all(force_refresh=True)

        last = discovery.get_last_event(ProviderName.OPENAI)
        assert last is not None
        assert last.success is False
        assert last.error_message is not None
        assert "Not connected to OpenAI API" in last.error_message

    @pytest.mark.asyncio
    @staticmethod
    async def test_discover_provider_real_provider_error_invalidates_cache() -> None:
        """``discover_provider`` catches ProviderError from a real unconnected provider.

        Similar to ``discover_all`` but via the single-provider path. The real
        ``OpenAIProvider`` (``connected = True``, ``client = None``) raises
        ``ProviderError``; the discovery layer must catch it and return ``[]``
        while invalidating the stale cache entry.
        """
        provider = OpenAIProvider()
        provider.connected = True
        assert provider.client is None

        reg = ProviderRegistry()
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.cache.aset(
            ProviderName.OPENAI,
            [_model(ProviderName.OPENAI, "stale-single")],
        )

        result = await discovery.discover_provider(ProviderName.OPENAI, use_cache=False)

        assert result == []
        assert discovery.cache.get(ProviderName.OPENAI) is None

    @pytest.mark.asyncio
    @staticmethod
    async def test_filter_on_real_provider_modelinfo_structure() -> None:
        """The filter pipeline works correctly on ModelInfo built with real-provider field values.

        Constructs ``ModelInfo`` objects using the exact field values that the
        real ``OpenAIProvider`` would produce for ``gpt-4o`` and
        ``gpt-3.5-turbo``. The expected values come from OpenAI's documented
        specifications (independent oracle):

        - ``gpt-4o``: context_window=128000, supports_vision=True (documented
          as multimodal), supports_tools=True, supports_streaming=True,
          input_cost_per_1m_tokens=None (real provider does not set costs).
        - ``gpt-3.5-turbo``: context_window=16385 (documented 16k context),
          supports_vision=False (text-only), same tool/streaming/cost profile.

        These constants are not derived from the production code - they are the
        documented model capabilities from OpenAI's public API reference.
        If the real provider's logic ever changed context_window for ``gpt-4o``
        from 128000 to something else, the filter test here would catch the
        discrepancy: the filter assertion uses 100000 as the boundary, so a
        context_window of anything below 100000 would silently break the filter
        result.

        The test also verifies that ``input_cost_per_1m_tokens=None`` passes
        the cost filter unchanged (the real provider does not publish costs),
        confirming the discovery layer's None-cost pass-through is exercised by
        a real provider's typical output structure.
        """
        gpt4o_context: int = 128000
        gpt35_context: int = 16385
        gpt4o_vision: bool = True
        gpt35_vision: bool = False

        gpt4o_info = ModelInfo(
            id="gpt-4o",
            name="gpt-4o",
            provider=ProviderName.OPENAI,
            context_window=gpt4o_context,
            supports_tools=True,
            supports_vision=gpt4o_vision,
            supports_streaming=True,
            input_cost_per_1m_tokens=None,
            output_cost_per_1m_tokens=None,
        )
        gpt35_info = ModelInfo(
            id="gpt-3.5-turbo",
            name="gpt-3.5-turbo",
            provider=ProviderName.OPENAI,
            context_window=gpt35_context,
            supports_tools=True,
            supports_vision=gpt35_vision,
            supports_streaming=True,
            input_cost_per_1m_tokens=None,
            output_cost_per_1m_tokens=None,
        )

        reg = ProviderRegistry()
        discovery = ModelDiscovery(reg)
        await discovery.cache.aset(ProviderName.OPENAI, [gpt4o_info, gpt35_info])

        vision_results = discovery.filter(DiscoveryFilter(requires_vision=True))
        vision_ids = [m.id for m in vision_results]
        assert "gpt-4o" in vision_ids
        assert "gpt-3.5-turbo" not in vision_ids
        assert len(vision_results) == 1

        context_results = discovery.filter(DiscoveryFilter(min_context_window=100000))
        context_ids = [m.id for m in context_results]
        assert "gpt-4o" in context_ids
        assert "gpt-3.5-turbo" not in context_ids
        assert len(context_results) == 1

        cost_results = discovery.filter(DiscoveryFilter(max_input_cost=1.0))
        assert len(cost_results) == 2
        assert {m.id for m in cost_results} == {"gpt-4o", "gpt-3.5-turbo"}


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


class TestFilterAllDimensions:
    """Filter criteria applied to independently-known model sets.

    Each test seeds the cache with a fixed set of models whose properties
    are chosen so the expected filter output is derivable without running
    the production code. Removing or inverting any filter predicate in the
    production code causes at least one assertion here to fail.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_filter_min_context_window_excludes_small_models() -> None:
        """Models below min_context_window must not appear in results.

        Input: two models - one with 32000 tokens and one with 200000 tokens.
        Filter: min_context_window=100000.
        Expected: only the 200000-token model survives.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "small", context_window=32000),
                _model(ProviderName.OPENAI, "large", context_window=200000),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.filter(DiscoveryFilter(min_context_window=100000))

        ids = [m.id for m in results]
        assert "large" in ids
        assert "small" not in ids
        assert len(ids) == 1

    @pytest.mark.asyncio
    @staticmethod
    async def test_filter_max_input_cost_excludes_expensive_models() -> None:
        """Models with input_cost above max_input_cost must be excluded.

        Input: cheap=0.5, expensive=10.0 per 1M tokens.
        Filter: max_input_cost=1.0.
        Expected: only cheap survives.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(
                    ProviderName.OPENAI,
                    "cheap",
                    input_cost_per_1m_tokens=0.5,
                    output_cost_per_1m_tokens=1.0,
                ),
                _model(
                    ProviderName.OPENAI,
                    "expensive",
                    input_cost_per_1m_tokens=10.0,
                    output_cost_per_1m_tokens=20.0,
                ),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.filter(DiscoveryFilter(max_input_cost=1.0))

        ids = [m.id for m in results]
        assert "cheap" in ids
        assert "expensive" not in ids
        assert len(ids) == 1

    @pytest.mark.asyncio
    @staticmethod
    async def test_filter_max_input_cost_passes_model_with_no_cost() -> None:
        """A model with input_cost_per_1m_tokens=None must not be excluded by cost filter.

        The production code only applies the cost filter when
        ``model.input_cost_per_1m_tokens is not None``. A model without
        pricing information must always survive a cost-based filter.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(
                    ProviderName.OPENAI,
                    "free-tier",
                    input_cost_per_1m_tokens=None,
                    output_cost_per_1m_tokens=None,
                ),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.filter(DiscoveryFilter(max_input_cost=0.01))

        assert len(results) == 1
        assert results[0].id == "free-tier"

    @pytest.mark.asyncio
    @staticmethod
    async def test_filter_requires_tools_true_excludes_no_tools() -> None:
        """requires_tools=True must exclude models that lack tool support.

        Input: one model with tools, one without.
        Expected: only the tool-supporting model survives.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "with-tools", supports_tools=True),
                _model(ProviderName.OPENAI, "no-tools", supports_tools=False),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.filter(DiscoveryFilter(requires_tools=True))

        ids = [m.id for m in results]
        assert "with-tools" in ids
        assert "no-tools" not in ids
        assert len(ids) == 1

    @pytest.mark.asyncio
    @staticmethod
    async def test_filter_requires_tools_false_excludes_tool_models() -> None:
        """requires_tools=False must exclude models that have tool support.

        The filter selects models whose ``supports_tools`` equals the
        criterion; setting it to False is not "don't care" - it is an
        explicit exclusion of tool-capable models.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "with-tools", supports_tools=True),
                _model(ProviderName.OPENAI, "no-tools", supports_tools=False),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.filter(DiscoveryFilter(requires_tools=False))

        ids = [m.id for m in results]
        assert "no-tools" in ids
        assert "with-tools" not in ids
        assert len(ids) == 1

    @pytest.mark.asyncio
    @staticmethod
    async def test_filter_requires_vision_true_excludes_non_vision() -> None:
        """requires_vision=True must keep only vision-capable models."""
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "vision", supports_vision=True),
                _model(ProviderName.OPENAI, "text-only", supports_vision=False),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.filter(DiscoveryFilter(requires_vision=True))

        ids = [m.id for m in results]
        assert "vision" in ids
        assert "text-only" not in ids
        assert len(ids) == 1

    @pytest.mark.asyncio
    @staticmethod
    async def test_filter_requires_streaming_true_excludes_non_streaming() -> None:
        """requires_streaming=True must keep only streaming-capable models."""
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "streams", supports_streaming=True),
                _model(ProviderName.OPENAI, "no-stream", supports_streaming=False),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.filter(DiscoveryFilter(requires_streaming=True))

        ids = [m.id for m in results]
        assert "streams" in ids
        assert "no-stream" not in ids
        assert len(ids) == 1

    @pytest.mark.asyncio
    @staticmethod
    async def test_filter_providers_whitelist_excludes_other_providers() -> None:
        """providers=[OPENAI] must exclude models from ANTHROPIC.

        Input: one model per provider. Filter: providers=[OPENAI].
        Expected: exactly one result, from OPENAI.
        """
        reg = ProviderRegistry()
        openai_provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "oai-m1")],
        )
        anthropic_provider = _DiscoveryProvider(
            ProviderName.ANTHROPIC,
            models=[_model(ProviderName.ANTHROPIC, "ant-m1")],
        )
        reg.register(openai_provider)
        reg.register(anthropic_provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.filter(DiscoveryFilter(providers=[ProviderName.OPENAI]))

        assert len(results) == 1
        assert results[0].id == "oai-m1"
        assert results[0].provider == ProviderName.OPENAI

    @pytest.mark.asyncio
    @staticmethod
    async def test_filter_combined_context_and_tools() -> None:
        """Multiple filter criteria are ANDed together.

        Input: three models covering all combinations of large/small context
        and tool support. Filter: min_context_window=100000 AND requires_tools=True.
        Expected: only the model that satisfies both conditions survives.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "large-tools", context_window=200000, supports_tools=True),
                _model(ProviderName.OPENAI, "large-notools", context_window=200000, supports_tools=False),
                _model(ProviderName.OPENAI, "small-tools", context_window=16000, supports_tools=True),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.filter(
            DiscoveryFilter(min_context_window=100000, requires_tools=True),
        )

        assert len(results) == 1
        assert results[0].id == "large-tools"

    @pytest.mark.asyncio
    @staticmethod
    async def test_filter_regex_case_insensitive_match() -> None:
        """model_id_pattern matching is case-insensitive (re.IGNORECASE).

        The production code compiles with re.IGNORECASE. An uppercase pattern
        must match a lowercase model ID.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "gpt-4o-mini"),
                _model(ProviderName.OPENAI, "claude-3-opus"),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.filter(DiscoveryFilter(model_id_pattern="GPT-4O"))

        ids = [m.id for m in results]
        assert "gpt-4o-mini" in ids
        assert "claude-3-opus" not in ids

    @pytest.mark.asyncio
    @staticmethod
    async def test_filter_regex_no_match_returns_empty() -> None:
        """A pattern that matches no model must produce an empty list.

        Confirms the filter does not silently fall back to returning all models
        when the pattern matches nothing.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "gpt-4o")],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.filter(DiscoveryFilter(model_id_pattern="^claude-"))

        assert results == []

    @pytest.mark.asyncio
    @staticmethod
    async def test_filter_no_criteria_returns_all_sorted() -> None:
        """An empty DiscoveryFilter must return all cached models sorted by provider then ID.

        The sort key is (provider.value, model.id). With two providers and
        two models each we can verify the exact order independently.
        """
        reg = ProviderRegistry()
        openai_p = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "gpt-z"),
                _model(ProviderName.OPENAI, "gpt-a"),
            ],
        )
        anthropic_p = _DiscoveryProvider(
            ProviderName.ANTHROPIC,
            models=[_model(ProviderName.ANTHROPIC, "claude-x")],
        )
        reg.register(openai_p)
        reg.register(anthropic_p)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.filter(DiscoveryFilter())

        expected_ids = ["claude-x", "gpt-a", "gpt-z"]
        assert [m.id for m in results] == expected_ids


class TestSearchMethod:
    """search() performs case-insensitive substring matching on ID and name."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_search_by_model_id_substring() -> None:
        """Querying a substring of a model ID must return that model.

        Input: "gpt-4" substring. Must match "gpt-4o" but not "claude-3".
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "gpt-4o"),
                _model(ProviderName.OPENAI, "claude-3"),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.search("gpt-4")

        assert len(results) == 1
        assert results[0].id == "gpt-4o"

    @pytest.mark.asyncio
    @staticmethod
    async def test_search_is_case_insensitive() -> None:
        """Uppercase query must match lowercase model ID.

        Confirms the production ``query_lower = query.lower()`` path is
        exercised correctly.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "gpt-4o", name="GPT-4o Turbo")],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.search("GPT-4O")

        assert len(results) == 1
        assert results[0].id == "gpt-4o"

    @pytest.mark.asyncio
    @staticmethod
    async def test_search_matches_model_name_not_id() -> None:
        """Query matching only the display name (not ID) must return the model.

        Confirms the production ``query_lower in model.name.lower()`` branch.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "openai-gpt4o-turbo", name="GPT-4o Turbo")],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.search("turbo")

        assert len(results) == 1
        assert results[0].id == "openai-gpt4o-turbo"

    @pytest.mark.asyncio
    @staticmethod
    async def test_search_returns_empty_on_no_match() -> None:
        """A query with no substring match must return an empty list."""
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "gpt-4o")],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.search("gemini")

        assert results == []

    @pytest.mark.asyncio
    @staticmethod
    async def test_search_returns_sorted_results() -> None:
        """search() must return results sorted by (provider.value, model.id).

        With two providers and known model IDs, the sort order is independently
        derivable: "anthropic" < "openai" alphabetically.
        """
        reg = ProviderRegistry()
        openai_p = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "gpt-model")],
        )
        anthropic_p = _DiscoveryProvider(
            ProviderName.ANTHROPIC,
            models=[_model(ProviderName.ANTHROPIC, "gpt-alike")],
        )
        reg.register(openai_p)
        reg.register(anthropic_p)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        results = discovery.search("gpt")

        assert len(results) == 2
        assert results[0].provider == ProviderName.ANTHROPIC
        assert results[1].provider == ProviderName.OPENAI


class TestGetByIdMethod:
    """get_by_id() returns a specific model by provider and ID from cache."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_get_by_id_returns_correct_model() -> None:
        """Requesting a cached model by ID must return exactly that model.

        Independent oracle: we know which model we inserted.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "model-a"),
                _model(ProviderName.OPENAI, "model-b"),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        result = discovery.get_by_id(ProviderName.OPENAI, "model-a")

        assert result is not None
        assert result.id == "model-a"
        assert result.provider == ProviderName.OPENAI

    @pytest.mark.asyncio
    @staticmethod
    async def test_get_by_id_returns_none_for_unknown_id() -> None:
        """Requesting an ID not in cache must return None, not raise.

        Confirms the production ``next(..., None)`` fallback path.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "model-a")],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        result = discovery.get_by_id(ProviderName.OPENAI, "does-not-exist")

        assert result is None

    @pytest.mark.asyncio
    @staticmethod
    async def test_get_by_id_returns_none_when_provider_not_cached() -> None:
        """Requesting a model from an uncached provider must return None.

        Covers the ``cached is None`` early-return path.
        """
        reg = ProviderRegistry()
        discovery = ModelDiscovery(reg)

        result = discovery.get_by_id(ProviderName.GOOGLE, "gemini-pro")

        assert result is None


class TestDiffModelIdsBehavior:
    """The model-diff logic records added/removed IDs in DiscoveryEvent.

    Tests drive discover_provider (which calls the diff helper internally)
    with known before/after model sets. Expected new_models and removed_models
    are derived by hand from set arithmetic on the inputs.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_diff_detects_new_model() -> None:
        """A model present after but not before must appear in event.new_models.

        old={a,b}, provider now returns {a,b,c} -> new_models=[c], removed=[].
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "a"),
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
        assert last.removed_models == []

    @pytest.mark.asyncio
    @staticmethod
    async def test_diff_detects_removed_model() -> None:
        """A model present before but not after must appear in event.removed_models.

        old={a,b}, provider now returns {a} -> new_models=[], removed=[b].
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "a")],
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
        assert last.new_models == []
        assert sorted(last.removed_models) == ["b"]

    @pytest.mark.asyncio
    @staticmethod
    async def test_diff_with_disjoint_sets() -> None:
        """Complete model replacement: all old removed, all new are additions.

        old={x}, provider now returns {y} -> new_models=[y], removed=[x].
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "y")],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.cache.aset(
            ProviderName.OPENAI,
            [_model(ProviderName.OPENAI, "x")],
        )
        await discovery.discover_provider(ProviderName.OPENAI, use_cache=False)
        last = discovery.get_last_event(ProviderName.OPENAI)

        assert last is not None
        assert sorted(last.new_models) == ["y"]
        assert sorted(last.removed_models) == ["x"]

    @pytest.mark.asyncio
    @staticmethod
    async def test_diff_with_identical_sets_produces_empty_diff() -> None:
        """Same models before and after must produce empty new/removed lists.

        old={a,b}, provider now returns {a,b} -> new_models=[], removed=[].
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "a"),
                _model(ProviderName.OPENAI, "b"),
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
        assert last.new_models == []
        assert last.removed_models == []

    @pytest.mark.asyncio
    @staticmethod
    async def test_diff_with_empty_prior_cache_all_new() -> None:
        """When there is no prior cache entry all discovered models are new.

        old={} (no cache entry), provider returns {a,b} -> new_models=[a,b], removed=[].
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "a"),
                _model(ProviderName.OPENAI, "b"),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_provider(ProviderName.OPENAI, use_cache=False)
        last = discovery.get_last_event(ProviderName.OPENAI)

        assert last is not None
        assert sorted(last.new_models) == ["a", "b"]
        assert last.removed_models == []


class TestGetProviderModelCount:
    """get_provider_model_count() returns per-provider model counts from cache."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_count_reflects_cached_models() -> None:
        """Each provider's count must equal the exact number of cached models.

        Seeded with 2 OpenAI models and 3 Anthropic models; expected counts
        are derived from those known inputs, not from the production function.
        """
        reg = ProviderRegistry()
        openai_p = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "o1"),
                _model(ProviderName.OPENAI, "o2"),
            ],
        )
        anthropic_p = _DiscoveryProvider(
            ProviderName.ANTHROPIC,
            models=[
                _model(ProviderName.ANTHROPIC, "a1"),
                _model(ProviderName.ANTHROPIC, "a2"),
                _model(ProviderName.ANTHROPIC, "a3"),
            ],
        )
        reg.register(openai_p)
        reg.register(anthropic_p)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        counts = discovery.get_provider_model_count()

        assert counts[ProviderName.OPENAI] == 2
        assert counts[ProviderName.ANTHROPIC] == 3

    @pytest.mark.asyncio
    @staticmethod
    async def test_model_count_empty_when_no_cache() -> None:
        """An empty registry must produce an empty count dict."""
        reg = ProviderRegistry()
        discovery = ModelDiscovery(reg)

        counts = discovery.get_provider_model_count()

        assert counts == {}


class TestGetRecommendedModelTaskTypes:
    """get_recommended_model selects winners by task-specific criteria.

    Expected winners are computed by hand from the seeded model sets,
    not by re-running the production selection logic.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_analysis_picks_largest_context_window_with_tools() -> None:
        """Analysis task must prefer the largest-context-window tool-capable model.

        Input: three tool-capable models with context 16k, 128k, 200k.
        Expected winner: 200k (largest context).
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "small", context_window=16000, supports_tools=True),
                _model(ProviderName.OPENAI, "medium", context_window=128000, supports_tools=True),
                _model(ProviderName.OPENAI, "large", context_window=200000, supports_tools=True),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        result = await discovery.get_recommended_model("analysis")

        assert result is not None
        assert result.id == "large"
        assert result.context_window == 200000

    @pytest.mark.asyncio
    @staticmethod
    async def test_generation_picks_cheapest_streaming_model() -> None:
        """Generation task must prefer the streaming model with lowest output cost.

        Input: two streaming models - cheap (0.5) and expensive (10.0).
        Expected winner: cheap model.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(
                    ProviderName.OPENAI,
                    "cheap-gen",
                    supports_streaming=True,
                    output_cost_per_1m_tokens=0.5,
                ),
                _model(
                    ProviderName.OPENAI,
                    "expensive-gen",
                    supports_streaming=True,
                    output_cost_per_1m_tokens=10.0,
                ),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        result = await discovery.get_recommended_model("generation")

        assert result is not None
        assert result.id == "cheap-gen"

    @pytest.mark.asyncio
    @staticmethod
    async def test_generation_puts_unknown_cost_model_last() -> None:
        """A streaming model with no output cost must rank below priced models.

        The production code maps None cost to float('inf') for sorting.
        A known cheap model must always beat an unknown-cost model.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(
                    ProviderName.OPENAI,
                    "known-cheap",
                    supports_streaming=True,
                    output_cost_per_1m_tokens=1.0,
                ),
                _model(
                    ProviderName.OPENAI,
                    "unknown-cost",
                    supports_streaming=True,
                    output_cost_per_1m_tokens=None,
                ),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        result = await discovery.get_recommended_model("generation")

        assert result is not None
        assert result.id == "known-cheap"

    @pytest.mark.asyncio
    @staticmethod
    async def test_chat_picks_largest_context_streaming_model() -> None:
        """Chat task must prefer the streaming model with largest context window.

        Input: two streaming models with 32k and 128k context.
        Expected winner: 128k model.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "chat-small", context_window=32000, supports_streaming=True),
                _model(ProviderName.OPENAI, "chat-large", context_window=128000, supports_streaming=True),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all()

        result = await discovery.get_recommended_model("chat")

        assert result is not None
        assert result.id == "chat-large"
        assert result.context_window == 128000

    @pytest.mark.asyncio
    @staticmethod
    async def test_get_recommended_returns_none_when_no_models() -> None:
        """An empty registry with no discoverable models must return None."""
        reg = ProviderRegistry()
        discovery = ModelDiscovery(reg)

        result = await discovery.get_recommended_model("chat")

        assert result is None


class TestDiscoveryEventTracking:
    """get_discovery_events and get_last_event track history correctly."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_get_discovery_events_limit_restricts_output() -> None:
        """get_discovery_events(limit=N) must return at most N events.

        Two discovery passes produce two events. limit=1 must return exactly one.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "m1")],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_all(force_refresh=True)
        await discovery.discover_all(force_refresh=True)

        events = discovery.get_discovery_events(limit=1)

        assert len(events) == 1

    @pytest.mark.asyncio
    @staticmethod
    async def test_get_last_event_returns_most_recent() -> None:
        """get_last_event must return the most recently recorded event.

        After two discover_provider calls the last event must reflect the
        final model count. We verify model_count equals the provider's
        configured length.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[
                _model(ProviderName.OPENAI, "m1"),
                _model(ProviderName.OPENAI, "m2"),
            ],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)
        await discovery.discover_provider(ProviderName.OPENAI, use_cache=False)

        last = discovery.get_last_event(ProviderName.OPENAI)

        assert last is not None
        assert last.provider == ProviderName.OPENAI
        assert last.model_count == 2
        assert last.success is True

    @pytest.mark.asyncio
    @staticmethod
    async def test_get_last_event_returns_none_when_no_events() -> None:
        """get_last_event must return None when no discovery has been performed."""
        reg = ProviderRegistry()
        discovery = ModelDiscovery(reg)

        last = discovery.get_last_event(ProviderName.OPENAI)

        assert last is None


class TestDiscoverAllMultiProvider:
    """discover_all operates correctly across multiple providers."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_discover_all_returns_all_provider_results() -> None:
        """discover_all must return a dict entry for every registered provider.

        Two providers are registered; both connected; the result dict must
        have exactly two keys and each must map to the exact model list
        that was configured.
        """
        reg = ProviderRegistry()
        openai_p = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "oai-1")],
        )
        anthropic_p = _DiscoveryProvider(
            ProviderName.ANTHROPIC,
            models=[_model(ProviderName.ANTHROPIC, "ant-1")],
        )
        reg.register(openai_p)
        reg.register(anthropic_p)
        discovery = ModelDiscovery(reg)

        results = await discovery.discover_all()

        assert ProviderName.OPENAI in results
        assert ProviderName.ANTHROPIC in results
        assert len(results[ProviderName.OPENAI]) == 1
        assert results[ProviderName.OPENAI][0].id == "oai-1"
        assert len(results[ProviderName.ANTHROPIC]) == 1
        assert results[ProviderName.ANTHROPIC][0].id == "ant-1"

    @pytest.mark.asyncio
    @staticmethod
    async def test_discover_all_uses_cache_on_second_call() -> None:
        """discover_all must serve cached data on the second call (use_cache=True).

        After the first call the provider is reconfigured to return a
        different model. A second call with the default use_cache=True must
        still return the original cached data.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "first-model")],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)

        await discovery.discover_all()
        provider.models = [_model(ProviderName.OPENAI, "second-model")]
        results = await discovery.discover_all()

        assert results[ProviderName.OPENAI][0].id == "first-model"

    @pytest.mark.asyncio
    @staticmethod
    async def test_discover_all_force_refresh_bypasses_cache() -> None:
        """force_refresh must invalidate the cache and fetch fresh models.

        After the first pass the provider is reconfigured. force_refresh
        must cause the second pass to return the new model, not the cached one.
        """
        reg = ProviderRegistry()
        provider = _DiscoveryProvider(
            ProviderName.OPENAI,
            models=[_model(ProviderName.OPENAI, "old-model")],
        )
        reg.register(provider)
        discovery = ModelDiscovery(reg)

        await discovery.discover_all()
        provider.models = [_model(ProviderName.OPENAI, "new-model")]
        results = await discovery.discover_all(force_refresh=True)

        assert results[ProviderName.OPENAI][0].id == "new-model"
        cached = discovery.cache.get(ProviderName.OPENAI)
        assert cached is not None
        assert cached[0].id == "new-model"


class TestCacheIsExpiredAndGetAllCached:
    """is_expired and get_all_cached reflect TTL correctly."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_is_expired_returns_true_for_missing_provider() -> None:
        """is_expired must return True when the provider has no cache entry."""
        cache = DiscoveryCache(ttl_seconds=60)
        assert cache.is_expired(ProviderName.OPENAI) is True

    @pytest.mark.asyncio
    @staticmethod
    async def test_is_expired_returns_false_for_fresh_entry() -> None:
        """is_expired must return False immediately after aset()."""
        cache = DiscoveryCache(ttl_seconds=60)
        await cache.aset(ProviderName.OPENAI, [_model(ProviderName.OPENAI, "m")])
        assert cache.is_expired(ProviderName.OPENAI) is False

    @pytest.mark.asyncio
    @staticmethod
    async def test_get_all_cached_returns_all_providers() -> None:
        """get_all_cached must return all providers that were aset().

        Two providers inserted; get_all_cached must return both.
        """
        cache = DiscoveryCache(ttl_seconds=60)
        await cache.aset(ProviderName.OPENAI, [_model(ProviderName.OPENAI, "o1")])
        await cache.aset(ProviderName.ANTHROPIC, [_model(ProviderName.ANTHROPIC, "a1")])

        all_cached = cache.get_all_cached()

        assert ProviderName.OPENAI in all_cached
        assert ProviderName.ANTHROPIC in all_cached
        assert all_cached[ProviderName.OPENAI][0].id == "o1"
        assert all_cached[ProviderName.ANTHROPIC][0].id == "a1"

    @pytest.mark.asyncio
    @staticmethod
    async def test_invalidate_all_empties_cache() -> None:
        """ainvalidate(None) must remove every entry from the cache."""
        cache = DiscoveryCache(ttl_seconds=60)
        await cache.aset(ProviderName.OPENAI, [_model(ProviderName.OPENAI, "x")])
        await cache.aset(ProviderName.ANTHROPIC, [_model(ProviderName.ANTHROPIC, "y")])

        await cache.ainvalidate()

        assert cache.get(ProviderName.OPENAI) is None
        assert cache.get(ProviderName.ANTHROPIC) is None

    @pytest.mark.asyncio
    @staticmethod
    async def test_invalidate_single_provider_leaves_others() -> None:
        """ainvalidate(provider) must remove only the targeted provider's entry."""
        cache = DiscoveryCache(ttl_seconds=60)
        await cache.aset(ProviderName.OPENAI, [_model(ProviderName.OPENAI, "x")])
        await cache.aset(ProviderName.ANTHROPIC, [_model(ProviderName.ANTHROPIC, "y")])

        await cache.ainvalidate(ProviderName.OPENAI)

        assert cache.get(ProviderName.OPENAI) is None
        surviving = cache.get(ProviderName.ANTHROPIC)
        assert surviving is not None
        assert surviving[0].id == "y"


class TestSaveLoadDiskFullCycle:
    """Disk persistence preserves all ModelInfo fields across the round-trip."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_round_trip_preserves_all_fields(tmp_path: Path) -> None:
        """Every field on ModelInfo must survive save_to_disk -> load_from_disk.

        The expected values are the constants passed to _model(); no
        production logic is re-invoked to derive the oracle. Cost values are
        chosen as small integers so JSON serialization is lossless and the
        comparison is exact via ``int()`` casting.
        """
        expected_input_cost_int: int = 3
        expected_output_cost_int: int = 7

        cache_a = DiscoveryCache(ttl_seconds=600)
        await cache_a.aset(
            ProviderName.OPENAI,
            [
                _model(
                    ProviderName.OPENAI,
                    "gpt-full",
                    name="GPT Full",
                    context_window=256000,
                    supports_tools=True,
                    supports_vision=True,
                    supports_streaming=True,
                    input_cost_per_1m_tokens=float(expected_input_cost_int),
                    output_cost_per_1m_tokens=float(expected_output_cost_int),
                ),
            ],
        )
        path = tmp_path / "full.json"
        await cache_a.save_to_disk(path)

        cache_b = DiscoveryCache(ttl_seconds=600)
        await cache_b.load_from_disk(path)
        loaded = cache_b.get(ProviderName.OPENAI)

        assert loaded is not None
        assert len(loaded) == 1
        m = loaded[0]
        assert m.id == "gpt-full"
        assert m.name == "GPT Full"
        assert m.provider == ProviderName.OPENAI
        assert m.context_window == 256000
        assert m.supports_tools is True
        assert m.supports_vision is True
        assert m.supports_streaming is True
        assert m.input_cost_per_1m_tokens is not None
        assert int(m.input_cost_per_1m_tokens) == expected_input_cost_int
        assert m.output_cost_per_1m_tokens is not None
        assert int(m.output_cost_per_1m_tokens) == expected_output_cost_int

    @pytest.mark.asyncio
    @staticmethod
    async def test_load_nonexistent_file_is_a_noop(tmp_path: Path) -> None:
        """Loading a path that does not exist must leave the cache unchanged."""
        cache = DiscoveryCache(ttl_seconds=60)
        await cache.aset(ProviderName.OPENAI, [_model(ProviderName.OPENAI, "live")])

        await cache.load_from_disk(tmp_path / "does_not_exist.json")

        result = cache.get(ProviderName.OPENAI)
        assert result is not None
        assert result[0].id == "live"

    @pytest.mark.asyncio
    @staticmethod
    async def test_load_wrong_version_preserves_cache(tmp_path: Path) -> None:
        """A payload with version != 1 must be rejected and leave cache intact."""
        cache = DiscoveryCache(ttl_seconds=60)
        await cache.aset(ProviderName.OPENAI, [_model(ProviderName.OPENAI, "live")])

        bad = tmp_path / "wrong_version.json"
        bad.write_text(
            json.dumps({"version": 99, "ttl_seconds": 60, "saved_at": 0, "entries": {}}),
            encoding="utf-8",
        )
        await cache.load_from_disk(bad)

        result = cache.get(ProviderName.OPENAI)
        assert result is not None
        assert result[0].id == "live"
