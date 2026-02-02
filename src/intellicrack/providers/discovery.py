"""Dynamic model discovery and caching for LLM providers.

This module provides centralized model discovery orchestration with TTL-based
caching, filtering, and fault tolerance across all registered providers.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from ..core.logging import get_logger
from ..core.types import ModelInfo, ProviderName


if TYPE_CHECKING:
    from pathlib import Path

    from .registry import ProviderRegistry


@dataclass
class DiscoveryEvent:
    """Metadata about a discovery operation.

    Attributes:
        provider: The provider that was queried.
        timestamp: When the discovery occurred.
        model_count: Number of models discovered.
        success: Whether the discovery succeeded.
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
        model_id_pattern: Regex pattern for model ID matching.
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
    """Internal cache entry with expiration tracking.

    Attributes:
        models: Cached list of models.
        timestamp: When the cache entry was created.
        expires_at: When the cache entry expires.
    """

    models: list[ModelInfo]
    timestamp: float
    expires_at: float


class DiscoveryCache:
    """TTL-based cache for discovered models.

    Provides thread-safe caching of model lists per provider with
    configurable TTL and optional disk persistence.

    Attributes:
        _ttl_seconds: Cache entry time-to-live in seconds.
        _cache: Dictionary mapping providers to cache entries.
        _lock: Asyncio lock for thread-safe operations.
    """

    def __init__(self, ttl_seconds: int = 3600) -> None:
        """Initialize the discovery cache.

        Args:
            ttl_seconds: Cache entry time-to-live in seconds. Default 1 hour.
        """
        self._ttl_seconds = ttl_seconds
        self._cache: dict[ProviderName, _CacheEntry] = {}
        self._lock = asyncio.Lock()
        self._logger = get_logger("providers.discovery.cache")

    def get(self, provider: ProviderName) -> list[ModelInfo] | None:
        """Get cached models for a provider.

        Args:
            provider: The provider to get cached models for.

        Returns:
            List of cached models, or None if not cached or expired.
        """
        entry = self._cache.get(provider)
        if entry is None:
            return None

        if time.time() > entry.expires_at:
            self._logger.debug("cache_expired", extra={"provider": provider.value})
            return None

        return entry.models

    def set(self, provider: ProviderName, models: list[ModelInfo]) -> None:
        """Cache models for a provider.

        Args:
            provider: The provider to cache models for.
            models: List of models to cache.
        """
        now = time.time()
        entry = _CacheEntry(
            models=models,
            timestamp=now,
            expires_at=now + self._ttl_seconds,
        )
        self._cache[provider] = entry
        self._logger.debug(
            "cache_set",
            extra={
                "model_count": len(models),
                "provider": provider.value,
                "ttl_seconds": self._ttl_seconds,
            },
        )

    def invalidate(self, provider: ProviderName | None = None) -> None:
        """Invalidate cache entries.

        Args:
            provider: Specific provider to invalidate, or None for all.
        """
        if provider is None:
            self._cache.clear()
            self._logger.debug("cache_invalidated_all")
        elif provider in self._cache:
            del self._cache[provider]
            self._logger.debug("cache_invalidated", extra={"provider": provider.value})

    def is_expired(self, provider: ProviderName) -> bool:
        """Check if cache entry is expired.

        Args:
            provider: The provider to check.

        Returns:
            True if cache entry doesn't exist or is expired.
        """
        entry = self._cache.get(provider)
        return True if entry is None else time.time() > entry.expires_at

    def get_all_cached(self) -> dict[ProviderName, list[ModelInfo]]:
        """Get all non-expired cached models.

        Returns:
            Dictionary mapping providers to their cached models.
        """
        now = time.time()
        result: dict[ProviderName, list[ModelInfo]] = {
            provider: entry.models
            for provider, entry in self._cache.items()
            if now <= entry.expires_at
        }
        return result

    async def save_to_disk(self, path: Path) -> None:
        """Persist cache to disk as JSON.

        Args:
            path: File path to save cache to.
        """
        async with self._lock:
            try:
                data: dict[str, object] = {
                    "version": 1,
                    "ttl_seconds": self._ttl_seconds,
                    "saved_at": time.time(),
                    "entries": {},
                }

                entries_dict: dict[str, object] = {}
                for provider, entry in self._cache.items():
                    if time.time() <= entry.expires_at:
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

                data["entries"] = entries_dict
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(data, indent=2), encoding="utf-8")
                self._logger.info("cache_saved", extra={"path": str(path)})

            except Exception:
                self._logger.exception("cache_save_failed")

    async def load_from_disk(self, path: Path) -> None:
        """Load cache from disk.

        Args:
            path: File path to load cache from.
        """
        async with self._lock:
            if not path.exists():
                self._logger.debug("cache_file_not_found", extra={"path": str(path)})
                return

            try:
                content = path.read_text(encoding="utf-8")
                data = json.loads(content)

                if data.get("version") != 1:
                    self._logger.warning("unknown_cache_version")
                    return

                entries = data.get("entries", {})
                now = time.time()

                for provider_str, entry_data in entries.items():
                    try:
                        provider = ProviderName(provider_str)
                        expires_at = entry_data.get("expires_at", 0)

                        if now > expires_at:
                            continue

                        models = [
                            ModelInfo(
                                id=m["id"],
                                name=m["name"],
                                provider=ProviderName(m["provider"]),
                                context_window=m["context_window"],
                                supports_tools=m["supports_tools"],
                                supports_vision=m["supports_vision"],
                                supports_streaming=m["supports_streaming"],
                                input_cost_per_1m_tokens=m.get("input_cost_per_1m_tokens"),
                                output_cost_per_1m_tokens=m.get("output_cost_per_1m_tokens"),
                            )
                            for m in entry_data.get("models", [])
                        ]

                        self._cache[provider] = _CacheEntry(
                            models=models,
                            timestamp=entry_data.get("timestamp", now),
                            expires_at=expires_at,
                        )

                    except (ValueError, KeyError) as e:
                        self._logger.warning("cache_entry_load_failed", extra={"provider": provider_str, "error": str(e)})

                self._logger.info("cache_loaded", extra={"provider_count": len(self._cache), "path": str(path)})

            except json.JSONDecodeError:
                self._logger.exception("cache_parse_failed")
            except Exception:
                self._logger.exception("cache_load_failed")


class ModelDiscovery:
    """Orchestrates model discovery from all providers.

    Provides unified model discovery with caching, filtering, and
    intelligent recommendations.

    Attributes:
        _registry: Provider registry for accessing provider instances.
        _cache: Discovery cache for caching results.
        _timeout: Per-provider timeout for discovery operations.
        _events: History of discovery events.
    """

    def __init__(
        self,
        registry: ProviderRegistry,
        cache_ttl: int = 3600,
        timeout_per_provider: float = 30.0,
    ) -> None:
        """Initialize the model discovery orchestrator.

        Args:
            registry: Provider registry containing registered providers.
            cache_ttl: Cache time-to-live in seconds.
            timeout_per_provider: Timeout for each provider's discovery.
        """
        self._registry = registry
        self._cache = DiscoveryCache(ttl_seconds=cache_ttl)
        self._timeout = timeout_per_provider
        self._events: list[DiscoveryEvent] = []
        self._lock = asyncio.Lock()
        self._logger = get_logger("providers.discovery")

    @property
    def cache(self) -> DiscoveryCache:
        """Get the discovery cache.

        Returns:
            The DiscoveryCache instance.
        """
        return self._cache

    async def discover_all(
        self,
        use_cache: bool = True,
        force_refresh: bool = False,
    ) -> dict[ProviderName, list[ModelInfo]]:
        """Discover models from all registered providers.

        Args:
            use_cache: Whether to use cached results when available.
            force_refresh: Force refresh even if cache is valid.

        Returns:
            Dictionary mapping provider names to their available models.
        """
        results: dict[ProviderName, list[ModelInfo]] = {}
        registered = self._registry.list_registered()

        if not registered:
            self._logger.warning("no_providers_registered")
            return results

        if force_refresh:
            self._cache.invalidate()

        async def discover_one(
            provider_name: ProviderName,
        ) -> tuple[ProviderName, list[ModelInfo], DiscoveryEvent]:
            start_time = time.time()

            if use_cache and not force_refresh:
                cached = self._cache.get(provider_name)
                if cached is not None:
                    return (
                        provider_name,
                        cached,
                        DiscoveryEvent(
                            provider=provider_name,
                            timestamp=datetime.now(),
                            model_count=len(cached),
                            success=True,
                            error_message=None,
                            duration_ms=0.0,
                        ),
                    )

            provider = self._registry.get(provider_name)
            if provider is None or not provider.is_connected:
                return (
                    provider_name,
                    [],
                    DiscoveryEvent(
                        provider=provider_name,
                        timestamp=datetime.now(),
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
                duration_ms = (time.time() - start_time) * 1000

                old_models = self._cache.get(provider_name) or []
                old_ids = {m.id for m in old_models}
                new_ids = {m.id for m in models}

                new_model_ids = list(new_ids - old_ids)
                removed_model_ids = list(old_ids - new_ids)

                self._cache.set(provider_name, models)

                return (
                    provider_name,
                    models,
                    DiscoveryEvent(
                        provider=provider_name,
                        timestamp=datetime.now(),
                        model_count=len(models),
                        success=True,
                        new_models=new_model_ids,
                        removed_models=removed_model_ids,
                        duration_ms=duration_ms,
                    ),
                )

            except TimeoutError:
                duration_ms = (time.time() - start_time) * 1000
                return (
                    provider_name,
                    [],
                    DiscoveryEvent(
                        provider=provider_name,
                        timestamp=datetime.now(),
                        model_count=0,
                        success=False,
                        error_message=f"Timeout after {self._timeout}s",
                        duration_ms=duration_ms,
                    ),
                )

            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                self._logger.warning("discovery_failed", extra={"provider": provider_name.value, "error": str(e)})
                return (
                    provider_name,
                    [],
                    DiscoveryEvent(
                        provider=provider_name,
                        timestamp=datetime.now(),
                        model_count=0,
                        success=False,
                        error_message=str(e),
                        duration_ms=duration_ms,
                    ),
                )

        tasks = [discover_one(name) for name in registered]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for result in completed:
            if isinstance(result, BaseException):
                self._logger.error("discovery_task_exception", extra={"error": str(result)})
                continue
            provider_name, models, event = result
            results[provider_name] = models
            self._events.append(event)

        self._logger.info(
            "discovery_complete",
            extra={
                "provider_count": len(results),
                "total_models": sum(len(m) for m in results.values()),
            },
        )

        return results

    async def discover_provider(
        self,
        provider: ProviderName,
        use_cache: bool = True,
    ) -> list[ModelInfo]:
        """Discover models from a specific provider.

        Args:
            provider: The provider to discover models from.
            use_cache: Whether to use cached results when available.

        Returns:
            List of available models from the provider.
        """
        if use_cache:
            cached = self._cache.get(provider)
            if cached is not None:
                return cached

        provider_instance = self._registry.get(provider)
        if provider_instance is None:
            self._logger.warning("provider_not_registered", extra={"provider": provider.value})
            return []

        if not provider_instance.is_connected:
            self._logger.warning("provider_not_connected", extra={"provider": provider.value})
            return []

        start_time = time.time()

        try:
            models = await asyncio.wait_for(
                provider_instance.list_models(),
                timeout=self._timeout,
            )
        except TimeoutError:
            self._logger.warning(
                "discovery_timeout",
                extra={"provider": provider.value, "timeout_seconds": self._timeout},
            )
            return []
        except Exception:
            self._logger.exception("discovery_failed", extra={"provider": provider.value})
            return []
        else:
            duration_ms = (time.time() - start_time) * 1000

            old_models = self._cache.get(provider) or []
            old_ids = {m.id for m in old_models}
            new_ids = {m.id for m in models}

            self._cache.set(provider, models)

            event = DiscoveryEvent(
                provider=provider,
                timestamp=datetime.now(),
                model_count=len(models),
                success=True,
                new_models=list(new_ids - old_ids),
                removed_models=list(old_ids - new_ids),
                duration_ms=duration_ms,
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
            List of matching models.
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
            List of models matching all criteria.
        """
        all_models = self._cache.get_all_cached()
        results: list[ModelInfo] = []

        pattern: re.Pattern[str] | None = None
        if criteria.model_id_pattern:
            try:
                pattern = re.compile(criteria.model_id_pattern, re.IGNORECASE)
            except re.error as e:
                self._logger.warning("invalid_regex_pattern", extra={"error": str(e)})

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

                if pattern is not None and not pattern.match(model.id):
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
            ModelInfo if found, None otherwise.
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
            List of discovery events.
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
            Most recent DiscoveryEvent or None if none exists.
        """
        return next(
            (
                event
                for event in reversed(self._events)
                if event.provider == provider
            ),
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

        Args:
            task_type: Type of task ("analysis", "generation", "chat").

        Returns:
            Recommended ModelInfo or None if no suitable model found.
        """
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

        if candidates:
            return candidates[0]

        return None

    def get_provider_model_count(self) -> dict[ProviderName, int]:
        """Get model count per provider from cache.

        Returns:
            Dictionary mapping providers to their cached model count.
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
