# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Dynamic model discovery and caching for LLM providers.

This module provides centralized model discovery orchestration with TTL-based caching, filtering, and fault tolerance across all registered
providers.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from intellicrack.core.logging import get_logger
from intellicrack.core.types import ModelInfo, ProviderName


if TYPE_CHECKING:
    from pathlib import Path

    from intellicrack.providers.registry import ProviderRegistry


@dataclass
class DiscoveryEvent:
    """Metadata about a discovery operation.

    Attributes:
        provider: Provider that was discovered.
        timestamp: When the discovery was performed.
        model_count: Number of models found.
        success: Whether the discovery completed successfully.
        error_message: Error message if discovery failed.
        new_models: Model IDs added since last discovery.
        removed_models: Model IDs no longer available.
        duration_ms: Time taken for discovery in milliseconds.
    """

    provider: ProviderName
    timestamp: datetime
    model_count: int
    success: bool
    error_message: str | None = None
    new_models: list[str] = field(default_factory=list)
    removed_models: list[str] = field(default_factory=list)
    duration_ms: float = 0.0


@dataclass
class DiscoveryFilter:
    """Filter criteria for model discovery.

    Attributes:
        min_context_window: Minimum context window size in tokens.
        max_input_cost: Maximum input cost per 1M tokens.
        requires_tools: Filter for tool support capability.
        requires_vision: Filter for vision support capability.
        requires_streaming: Filter for streaming support capability.
        providers: List of providers to include (None = all).
        model_id_pattern: Regex pattern matched against model IDs using
            :func:`re.search` (substring semantics, not anchored).
    """

    min_context_window: int | None = None
    max_input_cost: float | None = None
    requires_tools: bool | None = None
    requires_vision: bool | None = None
    requires_streaming: bool | None = None
    providers: list[ProviderName] | None = None
    model_id_pattern: str | None = None


@dataclass
class _CacheEntry:
    """Internal cache entry with expiration tracking."""

    models: list[ModelInfo]
    timestamp: float
    expires_at: float


_logger = get_logger(__name__)
_cache_logger = _logger.bind(component="discovery_cache")


class DiscoveryCache:
    """TTL-based cache for discovered models.

    Provides per-provider caching of model lists with configurable TTL and optional disk persistence. Disk and asynchronous helpers
    serialize access through an internal :class:`asyncio.Lock`; the synchronous helpers (:meth:`get`, :meth:`set`, :meth:`invalidate`,
    :meth:`is_expired`, :meth:`get_all_cached`) are intended to be called from a single asyncio task at a time and are not protected by the
    lock.
    """

    def __init__(self, ttl_seconds: int = 3600) -> None:
        """Initialize the DiscoveryCache with the given TTL.

        Args:
            ttl_seconds: Cache entry time-to-live in seconds.
        """
        self._ttl_seconds = ttl_seconds
        self._cache: dict[ProviderName, _CacheEntry] = {}
        self._cache_lock = asyncio.Lock()
        _logger.info("discovery_cache_initialized", component="discovery_cache", ttl_seconds=ttl_seconds)

    async def aget(self, provider: ProviderName) -> list[ModelInfo] | None:
        """Asynchronously get cached models for a provider.

        Args:
            provider: The provider to get cached models for.

        Returns:
            list[ModelInfo] | None: Cached models, or None if missing/expired.
        """
        _cache_logger.debug("discovery_cache_aget", provider=provider)
        async with self._cache_lock:
            return self._get_locked(provider)

    def get(self, provider: ProviderName) -> list[ModelInfo] | None:
        """Get cached models for a provider.

        Args:
            provider: The provider to get cached models for.

        Returns:
            list[ModelInfo] | None: List of cached models, or None if not cached or expired.
        """
        return self._get_locked(provider)

    def _get_locked(self, provider: ProviderName) -> list[ModelInfo] | None:
        """Return cached models or None when missing/expired.

        Args:
            provider: The provider to look up.

        Returns:
            list[ModelInfo] | None: Cached entries or None if missing/expired.
        """
        entry = self._cache.get(provider)
        if entry is None:
            return None

        if time.time() > entry.expires_at:
            _cache_logger.debug("cache_expired", provider=provider.value)
            return None

        return entry.models

    async def aset(self, provider: ProviderName, models: list[ModelInfo]) -> None:
        """Asynchronously cache a non-empty model list.

        Empty lists are rejected (the call is logged and any existing entry
        is invalidated) because an empty discovery result is indistinguishable
        from a discovery failure for cache purposes.

        Args:
            provider: The provider to cache models for.
            models: Models to cache.
        """
        _cache_logger.debug("discovery_cache_aset", provider=provider, model_count=len(models))
        async with self._cache_lock:
            self._set_locked(provider, models)

    def set(self, provider: ProviderName, models: list[ModelInfo]) -> None:
        """Cache models for a provider.

        Empty model lists are not cached: callers should treat an empty
        discovery as a failure so that a stale entry from a previous run is
        not returned. If a stale entry exists for the provider it is removed.

        Args:
            provider: The provider to cache models for.
            models: List of models to cache. Must be non-empty.
        """
        self._set_locked(provider, models)

    def _set_locked(self, provider: ProviderName, models: list[ModelInfo]) -> None:
        """Insert/update a cache entry, dropping empty lists.

        Args:
            provider: The provider to cache models for.
            models: Models to cache.
        """
        if not models:
            _cache_logger.debug("cache_set_skipped_empty", provider=provider.value)
            if provider in self._cache:
                del self._cache[provider]
            return
        now = time.time()
        entry = _CacheEntry(
            models=models,
            timestamp=now,
            expires_at=now + self._ttl_seconds,
        )
        self._cache[provider] = entry
        _cache_logger.debug(
            "cache_set",
            model_count=len(models),
            provider=provider.value,
            ttl_seconds=self._ttl_seconds,
        )

    async def ainvalidate(self, provider: ProviderName | None = None) -> None:
        """Asynchronously invalidate cache entries.

        Args:
            provider: Specific provider to invalidate, or None for all.
        """
        _cache_logger.debug("discovery_cache_ainvalidate", provider=provider)
        async with self._cache_lock:
            self._invalidate_locked(provider)

    def invalidate(self, provider: ProviderName | None = None) -> None:
        """Invalidate cache entries.

        Args:
            provider: Specific provider to invalidate, or None for all.
        """
        self._invalidate_locked(provider)

    def _invalidate_locked(self, provider: ProviderName | None) -> None:
        """Drop a cache entry or all of them.

        Args:
            provider: Specific provider to invalidate, or None for all.
        """
        if provider is None:
            self._cache.clear()
            _cache_logger.debug("cache_invalidated_all", cache_size=len(self._cache))
        elif provider in self._cache:
            del self._cache[provider]
            _cache_logger.debug("cache_invalidated", provider=provider.value)

    def is_expired(self, provider: ProviderName) -> bool:
        """Check if cache entry is expired.

        Args:
            provider: The provider to check.

        Returns:
            bool: True if cache entry doesn't exist or is expired.
        """
        entry = self._cache.get(provider)
        return True if entry is None else time.time() > entry.expires_at

    def get_all_cached(self) -> dict[ProviderName, list[ModelInfo]]:
        """Get all non-expired cached models.

        Returns:
            dict[ProviderName, list[ModelInfo]]: Dictionary mapping providers to their cached models.
        """
        now = time.time()
        result: dict[ProviderName, list[ModelInfo]] = {
            provider: entry.models for provider, entry in self._cache.items() if now <= entry.expires_at
        }
        return result

    async def save_to_disk(self, path: Path) -> None:
        """Persist cache to disk as JSON.

        ``time.time()`` is sampled once at the start of the operation and
        reused as both the saved-at marker and the per-entry expiration
        check, avoiding TOCTOU drift between the two reads.

        Args:
            path: File path to save cache to.
        """
        _cache_logger.info("cache_save_starting", cache_path=str(path))
        async with self._cache_lock:
            snapshot_now = time.time()
            entries_dict: dict[str, object] = {}
            for provider, entry in self._cache.items():
                if snapshot_now <= entry.expires_at:
                    model_dicts = [
                        {
                            "id": m.id,
                            "name": m.name,
                            "provider": m.provider.value,
                            "context_window": m.context_window,
                            "supports_tools": m.supports_tools,
                            "supports_vision": m.supports_vision,
                            "supports_streaming": m.supports_streaming,
                            "input_cost_per_1m_tokens": m.input_cost_per_1m_tokens,
                            "output_cost_per_1m_tokens": m.output_cost_per_1m_tokens,
                        }
                        for m in entry.models
                    ]
                    entries_dict[provider.value] = {
                        "models": model_dicts,
                        "timestamp": entry.timestamp,
                        "expires_at": entry.expires_at,
                    }

            data: dict[str, object] = {
                "version": 1,
                "ttl_seconds": self._ttl_seconds,
                "saved_at": snapshot_now,
                "entries": entries_dict,
            }

            try:
                await asyncio.to_thread(path.parent.mkdir, parents=True, exist_ok=True)
                json_text = json.dumps(data, indent=2)
                await asyncio.to_thread(path.write_text, json_text, "utf-8")
                _cache_logger.info("cache_saved", path=str(path))
            except (OSError, ValueError, TypeError):
                _cache_logger.exception("cache_save_failed", cache_path=str(path))

    @staticmethod
    def _parse_cache_entries(
        entries: dict[str, Any],
        now: float,
    ) -> dict[ProviderName, _CacheEntry]:
        """Validate and parse a deserialized entries mapping.

        Args:
            entries: Mapping of provider-name strings to entry payloads.
            now: Current time used to drop expired entries.

        Returns:
            dict[ProviderName, _CacheEntry]: Fully validated cache entries.

        Raises:
            TypeError: If any entry payload or model list is not the expected
                container type. The implementation also propagates ValueError
                (raised by ``ProviderName(...)`` for unknown enum values) and
                KeyError (raised when a model entry is missing required keys);
                the caller catches all three so that any malformed input
                aborts the load atomically.
        """
        staged: dict[ProviderName, _CacheEntry] = {}
        for provider_str, entry_data in entries.items():
            if not isinstance(entry_data, dict):
                msg = f"entry for {provider_str} is not a mapping"
                raise TypeError(msg)
            entry_dict: dict[str, Any] = cast("dict[str, Any]", entry_data)
            provider = ProviderName(provider_str)
            expires_at_raw = entry_dict.get("expires_at", 0)
            expires_at = float(expires_at_raw) if expires_at_raw is not None else 0.0

            if now > expires_at:
                continue

            raw_models = entry_dict.get("models", [])
            if not isinstance(raw_models, list):
                msg = f"models for {provider_str} is not a list"
                raise TypeError(msg)
            raw_models_list: list[Any] = cast("list[Any]", raw_models)

            models: list[ModelInfo] = []
            for m_raw in raw_models_list:
                if not isinstance(m_raw, dict):
                    msg = f"model entry for {provider_str} is not a mapping"
                    raise TypeError(msg)
                m: dict[str, Any] = cast("dict[str, Any]", m_raw)
                models.append(
                    ModelInfo(
                        id=str(m["id"]),
                        name=str(m["name"]),
                        provider=ProviderName(str(m["provider"])),
                        context_window=int(m["context_window"]),
                        supports_tools=bool(m["supports_tools"]),
                        supports_vision=bool(m["supports_vision"]),
                        supports_streaming=bool(m["supports_streaming"]),
                        input_cost_per_1m_tokens=m.get("input_cost_per_1m_tokens"),
                        output_cost_per_1m_tokens=m.get("output_cost_per_1m_tokens"),
                    ),
                )

            timestamp_raw = entry_dict.get("timestamp", now)
            staged[provider] = _CacheEntry(
                models=models,
                timestamp=float(timestamp_raw) if timestamp_raw is not None else now,
                expires_at=expires_at,
            )
        return staged

    async def load_from_disk(self, path: Path) -> None:
        """Load cache from disk atomically.

        The on-disk file is parsed and validated into a temporary dictionary.
        The in-memory cache is only replaced when the entire structure has
        been consumed without errors. Any failure (missing/invalid JSON,
        unknown version, malformed entry) leaves ``self._cache`` untouched.

        Args:
            path: File path to load cache from.
        """
        _cache_logger.info("cache_load_starting", cache_path=str(path))
        async with self._cache_lock:
            exists = await asyncio.to_thread(path.exists)
            if not exists:
                _cache_logger.debug("cache_file_not_found", path=str(path))
                return

            try:
                content = await asyncio.to_thread(path.read_text, "utf-8")
                raw_data = json.loads(content)
            except json.JSONDecodeError:
                _cache_logger.exception("cache_parse_failed", cache_path=str(path))
                return
            except (OSError, ValueError, TypeError):
                _cache_logger.exception("cache_load_failed", cache_path=str(path))
                return

            if not isinstance(raw_data, dict):
                _cache_logger.warning("cache_payload_not_mapping", cache_path=str(path))
                return
            data: dict[str, Any] = cast("dict[str, Any]", raw_data)

            if data.get("version") != 1:
                _cache_logger.warning("unknown_cache_version", version=data.get("version"))
                return

            entries = data.get("entries", {})
            if not isinstance(entries, dict):
                _cache_logger.warning("cache_entries_not_mapping", cache_path=str(path))
                return

            entries_dict: dict[str, Any] = cast("dict[str, Any]", entries)

            now = time.time()
            try:
                staged = self._parse_cache_entries(entries_dict, now)
            except (ValueError, KeyError, TypeError):
                _cache_logger.exception(
                    "cache_load_aborted_existing_preserved",
                    cache_path=str(path),
                )
                return

            self._cache = staged
            _cache_logger.info("cache_loaded", provider_count=len(self._cache), path=str(path))


class ModelDiscovery:
    """Orchestrates model discovery from all providers.

    Provides unified model discovery with caching, filtering, and intelligent recommendations.
    """

    def __init__(
        self,
        registry: ProviderRegistry,
        cache_ttl: int = 3600,
        timeout_per_provider: float = 30.0,
    ) -> None:
        """Initialize the ModelDiscovery orchestrator.

        Args:
            registry: Provider registry containing registered providers.
            cache_ttl: Cache time-to-live in seconds.
            timeout_per_provider: Timeout in seconds for each provider's discovery request.
        """
        self._registry = registry
        self._cache = DiscoveryCache(ttl_seconds=cache_ttl)
        self._timeout = timeout_per_provider
        self._events: list[DiscoveryEvent] = []
        _logger.info(
            "model_discovery_initialized",
            cache_ttl_seconds=cache_ttl,
            timeout_per_provider=timeout_per_provider,
        )

    @property
    def cache(self) -> DiscoveryCache:
        """Get the discovery cache.

        Returns:
            DiscoveryCache: The DiscoveryCache instance.
        """
        return self._cache

    @staticmethod
    def _diff_model_ids(
        old_models: list[ModelInfo],
        new_models: list[ModelInfo],
    ) -> tuple[list[str], list[str]]:
        """Compute new and removed model IDs between two model lists.

        Args:
            old_models: Previously known models for the provider.
            new_models: Freshly discovered models for the provider.

        Returns:
            tuple[list[str], list[str]]: ``(new_ids, removed_ids)`` - IDs
            that appeared in ``new_models`` but not ``old_models``, and vice
            versa.
        """
        old_ids = {m.id for m in old_models}
        new_ids = {m.id for m in new_models}
        return list(new_ids - old_ids), list(old_ids - new_ids)

    async def _record_discovery(
        self,
        provider: ProviderName,
        models: list[ModelInfo],
        duration_ms: float,
        *,
        write_cache: bool,
    ) -> DiscoveryEvent:
        """Build a discovery event and optionally update the shared cache.

        Args:
            provider: Provider that produced the models.
            models: Newly discovered models.
            duration_ms: Discovery duration in milliseconds.
            write_cache: Whether to persist the result in the shared cache.

        Returns:
            DiscoveryEvent: Event capturing model count, diff, and timing.
        """
        old_models = await self._cache.aget(provider) or []
        new_ids, removed_ids = self._diff_model_ids(old_models, models)

        if write_cache:
            await self._cache.aset(provider, models)

        return DiscoveryEvent(
            provider=provider,
            timestamp=datetime.now(tz=UTC),
            model_count=len(models),
            success=True,
            new_models=new_ids,
            removed_models=removed_ids,
            duration_ms=duration_ms,
        )

    async def discover_all(
        self,
        *,
        use_cache: bool = True,
        force_refresh: bool = False,
    ) -> dict[ProviderName, list[ModelInfo]]:
        """Discover models from all registered providers.

        When ``use_cache`` is False the shared cache is neither read nor
        written for this call; per-provider results are returned directly to
        the caller and the existing cache is left untouched. ``force_refresh``
        is the explicit opt-in for invalidating and rewriting the cache.

        Args:
            use_cache: Whether to use cached results when available.
            force_refresh: Force refresh even if cache is valid.

        Returns:
            dict[ProviderName, list[ModelInfo]]: Dictionary mapping provider names to their available models.
        """
        _logger.info("discovery_starting", force_refresh=force_refresh)
        results: dict[ProviderName, list[ModelInfo]] = {}
        registered = self._registry.list_registered()

        if not registered:
            _logger.warning("no_providers_registered", registry_size=len(registered))
            return results

        if force_refresh:
            await self._cache.ainvalidate()

        write_cache = use_cache or force_refresh

        async def discover_one(
            provider_name: ProviderName,
        ) -> tuple[ProviderName, list[ModelInfo], DiscoveryEvent]:
            """Discover models for a single provider with caching.

            Args:
                provider_name: The provider whose models should be listed.

            Returns:
                tuple[ProviderName, list[ModelInfo], DiscoveryEvent]: The
                provider name, the discovered models, and a discovery event
                capturing timing and success metadata.
            """
            start_time = time.time()

            if use_cache and not force_refresh:
                cached = await self._cache.aget(provider_name)
                if cached is not None:
                    return (
                        provider_name,
                        cached,
                        DiscoveryEvent(
                            provider=provider_name,
                            timestamp=datetime.now(tz=UTC),
                            model_count=len(cached),
                            success=True,
                            error_message=None,
                            duration_ms=0.0,
                        ),
                    )

            provider = self._registry.get(provider_name)
            if provider is None or not provider.is_connected:
                if write_cache:
                    await self._cache.ainvalidate(provider_name)
                return (
                    provider_name,
                    [],
                    DiscoveryEvent(
                        provider=provider_name,
                        timestamp=datetime.now(tz=UTC),
                        model_count=0,
                        success=False,
                        error_message="Provider not connected",
                        duration_ms=(time.time() - start_time) * 1000,
                    ),
                )

            try:
                models = await asyncio.wait_for(
                    provider.list_models(),
                    timeout=self._timeout,
                )
            except TimeoutError:
                _logger.warning(
                    "discovery_timeout",
                    provider=provider_name.value,
                    timeout=self._timeout,
                )
                duration_ms = (time.time() - start_time) * 1000
                if write_cache:
                    await self._cache.ainvalidate(provider_name)
                return (
                    provider_name,
                    [],
                    DiscoveryEvent(
                        provider=provider_name,
                        timestamp=datetime.now(tz=UTC),
                        model_count=0,
                        success=False,
                        error_message=f"Timeout after {self._timeout}s",
                        duration_ms=duration_ms,
                    ),
                )
            except (ConnectionError, OSError, RuntimeError, ValueError) as exc:
                duration_ms = (time.time() - start_time) * 1000
                _logger.exception(
                    "discovery_failed",
                    provider=provider_name.value,
                )
                if write_cache:
                    await self._cache.ainvalidate(provider_name)
                return (
                    provider_name,
                    [],
                    DiscoveryEvent(
                        provider=provider_name,
                        timestamp=datetime.now(tz=UTC),
                        model_count=0,
                        success=False,
                        error_message=str(exc),
                        duration_ms=duration_ms,
                    ),
                )

            duration_ms = (time.time() - start_time) * 1000

            if not models:
                if write_cache:
                    await self._cache.ainvalidate(provider_name)
                return (
                    provider_name,
                    [],
                    DiscoveryEvent(
                        provider=provider_name,
                        timestamp=datetime.now(tz=UTC),
                        model_count=0,
                        success=False,
                        error_message="Provider returned no models",
                        duration_ms=duration_ms,
                    ),
                )

            event = await self._record_discovery(
                provider_name,
                models,
                duration_ms,
                write_cache=write_cache,
            )
            return provider_name, models, event

        tasks = [discover_one(name) for name in registered]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for provider_name, result in zip(registered, completed, strict=True):
            if isinstance(result, BaseException):
                await self._cache.ainvalidate(provider_name)
                _logger.error(
                    "discovery_task_exception",
                    provider=provider_name.value,
                    error=str(result),
                )
                continue
            result_provider, models, event = result
            results[result_provider] = models
            self._events.append(event)

        _logger.info(
            "discovery_complete",
            provider_count=len(results),
            total_models=sum(len(m) for m in results.values()),
        )

        return results

    async def discover_provider(
        self,
        provider: ProviderName,
        *,
        use_cache: bool = True,
    ) -> list[ModelInfo]:
        """Discover models from a specific provider.

        Args:
            provider: The provider to discover models from.
            use_cache: Whether to use cached results when available.

        Returns:
            list[ModelInfo]: List of available models from the provider.
        """
        if use_cache:
            cached = await self._cache.aget(provider)
            if cached is not None:
                return cached

        provider_instance = self._registry.get(provider)
        if provider_instance is None:
            _logger.warning("provider_not_registered", provider=provider.value)
            await self._cache.ainvalidate(provider)
            return []

        if not provider_instance.is_connected:
            _logger.warning("provider_not_connected", provider=provider.value)
            await self._cache.ainvalidate(provider)
            return []

        start_time = time.time()

        try:
            models = await asyncio.wait_for(
                provider_instance.list_models(),
                timeout=self._timeout,
            )
        except TimeoutError:
            _logger.warning(
                "discovery_timeout",
                provider=provider.value,
                timeout_seconds=self._timeout,
            )
            await self._cache.ainvalidate(provider)
            return []
        except (ConnectionError, OSError, RuntimeError, ValueError):
            _logger.exception("discovery_failed", provider=provider.value)
            await self._cache.ainvalidate(provider)
            return []

        duration_ms = (time.time() - start_time) * 1000

        if not models:
            _logger.warning("discovery_empty", provider=provider.value)
            await self._cache.ainvalidate(provider)
            return []

        event = await self._record_discovery(
            provider,
            models,
            duration_ms,
            write_cache=use_cache,
        )
        self._events.append(event)
        return models

    def search(
        self,
        query: str,
    ) -> list[ModelInfo]:
        """Search for models by name or ID.

        Performs case-insensitive substring matching on model ID and name.

        Args:
            query: Search query string.

        Returns:
            list[ModelInfo]: List of matching models.
        """
        query_lower = query.lower()
        results: list[ModelInfo] = []

        all_models = self._cache.get_all_cached()

        for models in all_models.values():
            results.extend(model for model in models if query_lower in model.id.lower() or query_lower in model.name.lower())

        results.sort(key=lambda m: (m.provider.value, m.id))
        return results

    def filter(
        self,
        criteria: DiscoveryFilter,
    ) -> list[ModelInfo]:
        """Filter models by criteria.

        Args:
            criteria: Filter criteria to apply.

        Returns:
            list[ModelInfo]: List of models matching all criteria.

        Raises:
            ValueError: If ``criteria.model_id_pattern`` is not a valid regex.
        """
        all_models = self._cache.get_all_cached()
        results: list[ModelInfo] = []

        pattern: re.Pattern[str] | None = None
        if criteria.model_id_pattern:
            try:
                pattern = re.compile(criteria.model_id_pattern, re.IGNORECASE)
            except re.error as exc:
                _logger.warning(
                    "invalid_regex_pattern",
                    pattern=criteria.model_id_pattern,
                    error=str(exc),
                )
                msg = f"invalid regex in DiscoveryFilter: {criteria.model_id_pattern!r}: {exc}"
                raise ValueError(msg) from exc

        for provider, models in all_models.items():
            if criteria.providers is not None and provider not in criteria.providers:
                continue

            for model in models:
                if criteria.min_context_window is not None and model.context_window < criteria.min_context_window:
                    continue

                if (
                    criteria.max_input_cost is not None
                    and model.input_cost_per_1m_tokens is not None
                    and model.input_cost_per_1m_tokens > criteria.max_input_cost
                ):
                    continue

                if criteria.requires_tools is not None and model.supports_tools != criteria.requires_tools:
                    continue

                if criteria.requires_vision is not None and model.supports_vision != criteria.requires_vision:
                    continue

                if criteria.requires_streaming is not None and model.supports_streaming != criteria.requires_streaming:
                    continue

                if pattern is not None and not pattern.search(model.id):
                    continue

                results.append(model)

        results.sort(key=lambda m: (m.provider.value, m.id))
        return results

    def get_by_id(
        self,
        provider: ProviderName,
        model_id: str,
    ) -> ModelInfo | None:
        """Get a specific model by provider and ID.

        Args:
            provider: The provider the model belongs to.
            model_id: The model identifier.

        Returns:
            ModelInfo | None: ModelInfo if found, None otherwise.
        """
        cached = self._cache.get(provider)
        if cached is None:
            return None

        return next((model for model in cached if model.id == model_id), None)

    def get_discovery_events(
        self,
        limit: int | None = None,
    ) -> list[DiscoveryEvent]:
        """Get history of discovery events.

        Args:
            limit: Maximum number of events to return (newest first).

        Returns:
            list[DiscoveryEvent]: List of discovery events.
        """
        events = sorted(self._events, key=lambda e: e.timestamp, reverse=True)
        if limit is not None:
            events = events[:limit]
        return events

    def get_last_event(
        self,
        provider: ProviderName,
    ) -> DiscoveryEvent | None:
        """Get the most recent discovery event for a provider.

        Args:
            provider: The provider to get the event for.

        Returns:
            DiscoveryEvent | None: Most recent DiscoveryEvent or None if none exists.
        """
        return next(
            (event for event in reversed(self._events) if event.provider == provider),
            None,
        )

    async def get_recommended_model(
        self,
        task_type: str,
    ) -> ModelInfo | None:
        """Get a recommended model for a specific task type.

        Recommends models based on task requirements:
        - "analysis": Prefers large context, tool support
        - "generation": Prefers fast, streaming models
        - "chat": Balanced recommendation

        If no provider has any cached models, this awaits a fresh discovery
        pass via :meth:`discover_all` so that recommendations are not made
        from a stale empty cache.

        Args:
            task_type: Type of task ("analysis", "generation", "chat").

        Returns:
            ModelInfo | None: Recommended ModelInfo or None if no suitable model found.

        Raises:
            ValueError: If ``task_type`` is not one of the supported values.
        """
        valid_task_types = {"analysis", "generation", "chat"}
        if task_type not in valid_task_types:
            msg = f"unknown task_type {task_type!r}; expected one of {sorted(valid_task_types)}"
            _logger.warning("get_recommended_model_raise_pending", error_type="ValueError")
            raise ValueError(msg)

        all_models = self._cache.get_all_cached()
        if not all_models:
            await self.discover_all()
            all_models = self._cache.get_all_cached()

        candidates: list[ModelInfo] = []
        for models in all_models.values():
            candidates.extend(models)

        if not candidates:
            return None

        if task_type == "analysis":
            analysis_candidates = [m for m in candidates if m.supports_tools]
            if analysis_candidates:
                analysis_candidates.sort(key=lambda m: m.context_window, reverse=True)
                return analysis_candidates[0]

        elif task_type == "generation":
            gen_candidates = [m for m in candidates if m.supports_streaming]
            if gen_candidates:

                def cost_key(m: ModelInfo) -> float:
                    """Return the per-million-token output cost for sorting.

                    Args:
                        m: Model whose cost should be used as the sort key.

                    Returns:
                        float: The output cost, or ``inf`` when unknown so
                        models without pricing sort last.
                    """
                    if m.output_cost_per_1m_tokens is not None:
                        return m.output_cost_per_1m_tokens
                    return float("inf")

                gen_candidates.sort(key=cost_key)
                return gen_candidates[0]

        elif task_type == "chat":
            chat_candidates = [m for m in candidates if m.supports_streaming]
            if chat_candidates:
                chat_candidates.sort(key=lambda m: m.context_window, reverse=True)
                return chat_candidates[0]

        return candidates[0] if candidates else None

    def get_provider_model_count(self) -> dict[ProviderName, int]:
        """Get model count per provider from cache.

        Returns:
            dict[ProviderName, int]: Dictionary mapping providers to their cached model count.
        """
        result: dict[ProviderName, int] = {}
        cached = self._cache.get_all_cached()

        for provider, models in cached.items():
            result[provider] = len(models)

        return result

    async def save_cache(self, path: Path) -> None:
        """Save the discovery cache to disk.

        Args:
            path: File path to save cache to.
        """
        await self._cache.save_to_disk(path)

    async def load_cache(self, path: Path) -> None:
        """Load the discovery cache from disk.

        Args:
            path: File path to load cache from.
        """
        await self._cache.load_from_disk(path)
