# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Audit7 U2 regression tests for discovery cache invalidation on exceptions.

Each test corresponds to F-0021 in audit7.md under "Findings:
providers-meta". The fix in
:mod:`intellicrack.providers.discovery` ensures that when a per-provider
``discover_one`` task escapes with an exception type not caught
internally, ``discover_all`` invalidates the corresponding cache entry
so future reads cannot return stale data.

The tests use real ``ModelDiscovery``, ``DiscoveryCache``, and
``ProviderRegistry`` instances; only the provider's ``list_models``
method is configured to raise so an uncaught exception reaches
``asyncio.gather(..., return_exceptions=True)``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, override

import pytest
from structlog.testing import capture_logs

from intellicrack.core.types import (
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderName,
    ToolCall,
)
from intellicrack.providers.base import LLMProviderBase
from intellicrack.providers.discovery import ModelDiscovery
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping, Sequence

    from intellicrack.core.types import ThinkingConfig, ToolChoice, ToolDefinition


class _RaisingProvider(LLMProviderBase):
    """Provider whose ``list_models`` always raises a configured exception.

    The configured exception is chosen so it is NOT a member of the set
    explicitly caught inside ``ModelDiscovery.discover_one`` (which catches
    ``ConnectionError``, ``OSError``, ``RuntimeError`` and ``ValueError``).
    The raised exception therefore propagates up through
    ``asyncio.gather(return_exceptions=True)`` and exercises the
    BaseException branch of the per-result loop in ``discover_all``.
    """

    def __init__(self, provider_name: ProviderName, error: BaseException) -> None:
        """Initialize the provider with an enum name and a failure to raise.

        Args:
            provider_name: Provider enum identity exposed via :attr:`name`.
            error: Exception instance to raise from :meth:`list_models`.
        """
        super().__init__()
        self._name = provider_name
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
        """Mark the provider connected and record credentials.

        Args:
            credentials: Credentials object recorded on the instance.
        """
        self._credentials = credentials
        self.connected = True

    @override
    async def list_models(self) -> list[ModelInfo]:
        """Raise the configured exception unconditionally.

        Returns:
            list[ModelInfo]: Never returns; raises before producing a list.

        Raises:
            self._error: The exception instance supplied at construction.
        """
        raise self._error

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
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in the response.
            tool_choice: Tool selection directive.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable provider-side prompt caching.

        Returns:
            tuple[Message, list[ToolCall] | None]: (empty assistant message,
            None tool calls).
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
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in the response.
            tool_choice: Tool selection directive.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable provider-side prompt caching.

        Yields:
            str: A single empty string.
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


class _SuccessfulProvider(LLMProviderBase):
    """Provider whose ``list_models`` returns a configured static list."""

    def __init__(
        self,
        provider_name: ProviderName,
        models: list[ModelInfo],
    ) -> None:
        """Initialize the provider with a name and model list.

        Args:
            provider_name: Provider enum identity exposed via :attr:`name`.
            models: Models to return from :meth:`list_models`.
        """
        super().__init__()
        self._name = provider_name
        self._models = list(models)
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
        """Record credentials and mark the provider connected.

        Args:
            credentials: Credentials object recorded on the instance.
        """
        self._credentials = credentials
        self.connected = True

    @override
    async def list_models(self) -> list[ModelInfo]:
        """Return a fresh copy of the configured model list.

        Returns:
            list[ModelInfo]: Copy of the configured models.
        """
        return list(self._models)

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
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in the response.
            tool_choice: Tool selection directive.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable provider-side prompt caching.

        Returns:
            tuple[Message, list[ToolCall] | None]: (empty assistant message,
            None tool calls).
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
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in the response.
            tool_choice: Tool selection directive.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable provider-side prompt caching.

        Yields:
            str: A single empty string.
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


def _make_model(provider: ProviderName, model_id: str) -> ModelInfo:
    """Build a minimal :class:`ModelInfo` with deterministic capabilities.

    Args:
        provider: Provider that owns the model.
        model_id: Model identifier and human-readable name.

    Returns:
        ModelInfo: A populated model entry suitable for cache seeding.
    """
    return ModelInfo(
        id=model_id,
        name=model_id,
        provider=provider,
        context_window=128000,
        supports_tools=True,
        supports_vision=False,
        supports_streaming=True,
        input_cost_per_1m_tokens=1.0,
        output_cost_per_1m_tokens=2.0,
    )


def _event_names(records: Sequence[Mapping[str, Any]]) -> list[str]:
    """Return the ordered list of structlog event names from a record list.

    Args:
        records: Sequence of structlog event mappings captured via
            :func:`structlog.testing.capture_logs`.

    Returns:
        list[str]: ``event`` field of each captured record, in capture order.
    """
    return [str(rec.get("event", "")) for rec in records]


# --- F-0021: discover_all invalidates cache on unexpected exceptions ---


class TestF0021DiscoverAllInvalidatesCacheOnException:
    """F-0021: ``discover_all`` invalidates the cache on unexpected exceptions.

    The pre-fix code logged the error and continued without touching the
    cache. The post-fix code calls ``await self._cache.ainvalidate(provider)``
    before logging, so any stale or pre-seeded entry is dropped.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_attribute_error_invalidates_seeded_cache_entry() -> None:
        """An ``AttributeError`` escaping ``discover_one`` drops the cache entry.

        ``AttributeError`` is not in the explicit ``except`` clause inside
        ``discover_one`` (``ConnectionError | OSError | RuntimeError |
        ValueError``), so it propagates through ``asyncio.gather`` and reaches
        the result loop. Pre-fix, the loop logged but left the cache untouched.
        Post-fix, the cache entry for that provider is removed.
        """
        registry = ProviderRegistry()
        provider = _RaisingProvider(
            ProviderName.OPENAI,
            error=AttributeError("simulated unexpected attribute access"),
        )
        registry.register(provider)

        discovery = ModelDiscovery(registry, cache_ttl=3600)

        seeded_models = [_make_model(ProviderName.OPENAI, "gpt-stale")]
        await discovery.cache.aset(ProviderName.OPENAI, seeded_models)
        assert await discovery.cache.aget(ProviderName.OPENAI) is not None

        results = await discovery.discover_all(use_cache=False)

        assert results == {}
        assert await discovery.cache.aget(ProviderName.OPENAI) is None

    @pytest.mark.asyncio
    @staticmethod
    async def test_type_error_invalidates_seeded_cache_entry() -> None:
        """A ``TypeError`` escaping ``discover_one`` drops the cache entry.

        ``TypeError`` is not in the explicit ``except`` clause inside
        ``discover_one``; it bypasses the inner handler and propagates
        through ``asyncio.gather(return_exceptions=True)`` as a returned
        exception value, exercising the outer cache-invalidation path.
        """
        registry = ProviderRegistry()
        provider = _RaisingProvider(
            ProviderName.OPENAI,
            error=TypeError("simulated type mismatch"),
        )
        registry.register(provider)

        discovery = ModelDiscovery(registry, cache_ttl=3600)

        seeded_models = [_make_model(ProviderName.OPENAI, "gpt-pre-existing")]
        await discovery.cache.aset(ProviderName.OPENAI, seeded_models)
        assert await discovery.cache.aget(ProviderName.OPENAI) is not None

        results = await discovery.discover_all(use_cache=False)

        assert results == {}
        assert await discovery.cache.aget(ProviderName.OPENAI) is None

    @pytest.mark.asyncio
    @staticmethod
    async def test_discovery_task_exception_log_event_emitted_with_provider() -> None:
        """The structured log event still names the affected provider.

        The fix adds a ``provider`` key to the existing
        ``discovery_task_exception`` event while preserving the event name.
        """
        registry = ProviderRegistry()
        provider = _RaisingProvider(
            ProviderName.ANTHROPIC,
            error=AttributeError("simulated"),
        )
        registry.register(provider)

        discovery = ModelDiscovery(registry, cache_ttl=3600)
        await discovery.cache.aset(
            ProviderName.ANTHROPIC,
            [_make_model(ProviderName.ANTHROPIC, "claude-stale")],
        )

        with capture_logs() as records:
            results = await discovery.discover_all(use_cache=False)

        assert results == {}

        events = _event_names(records)
        assert "discovery_task_exception" in events

        matching = [rec for rec in records if rec.get("event") == "discovery_task_exception"]
        assert matching, "discovery_task_exception event must be emitted"
        record = matching[0]
        assert record.get("provider") == ProviderName.ANTHROPIC.value
        assert "simulated" in str(record.get("error", ""))

    @pytest.mark.asyncio
    @staticmethod
    async def test_other_providers_still_complete_when_one_raises() -> None:
        """A successful provider remains in the result when another raises.

        This guards against a regression where pairing results via
        ``zip(registered, completed)`` accidentally drops successful results
        or misattributes them to the wrong provider.
        """
        registry = ProviderRegistry()
        good_provider = _SuccessfulProvider(
            ProviderName.OPENAI,
            models=[_make_model(ProviderName.OPENAI, "gpt-good")],
        )
        bad_provider = _RaisingProvider(
            ProviderName.ANTHROPIC,
            error=AttributeError("boom"),
        )
        registry.register(good_provider)
        registry.register(bad_provider)

        discovery = ModelDiscovery(registry, cache_ttl=3600)
        await discovery.cache.aset(
            ProviderName.ANTHROPIC,
            [_make_model(ProviderName.ANTHROPIC, "claude-stale")],
        )

        results = await discovery.discover_all(use_cache=False)

        assert set(results.keys()) == {ProviderName.OPENAI}
        assert [m.id for m in results[ProviderName.OPENAI]] == ["gpt-good"]
        assert await discovery.cache.aget(ProviderName.ANTHROPIC) is None
