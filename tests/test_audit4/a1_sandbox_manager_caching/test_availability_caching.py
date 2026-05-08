# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for F-0024 and F-0032: availability caching in SandboxManager.

Each test is designed to FAIL against the original (uncached) implementation
and PASS with the caching fix in place.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.manager import (
    FAILURE_CACHE_TTL_SECONDS,
    AvailabilityCacheEntry,
    SandboxManager,
    SandboxType,
)


if TYPE_CHECKING:
    from collections.abc import Coroutine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_manager() -> SandboxManager:
    """Return a fresh SandboxManager with a minimal config.

    Returns:
        SandboxManager: A new manager instance with default SandboxConfig.
    """
    return SandboxManager(default_config=SandboxConfig())


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run a coroutine on a fresh event loop, ensuring test isolation.

    Args:
        coro: The coroutine to execute.

    Returns:
        T: The return value of the coroutine.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _inject_cache(manager: SandboxManager, sandbox_type: SandboxType, entry: AvailabilityCacheEntry) -> None:
    """Inject a cache entry directly for clock-injection tests.

    Args:
        manager: The SandboxManager to inject into.
        sandbox_type: The sandbox type key.
        entry: The cache entry to inject.
    """
    manager.availability_cache[sandbox_type] = entry


# ---------------------------------------------------------------------------
# F-0024: get_available_types caches probes
# ---------------------------------------------------------------------------


class TestGetAvailableTypesSubprocessCalledOnce:
    """F-0024: Repeated calls to get_available_types must not re-run subprocesses."""

    def test_probe_called_once_per_type_across_five_calls(self) -> None:
        """Five calls to get_available_types trigger exactly one probe per type.

        Without the cache each call re-instantiates the sandbox and calls
        is_available() which spawns subprocesses. With the cache the probe
        runs exactly once and subsequent calls read from the dict.
        """
        manager = _make_manager()
        probe_counter: dict[SandboxType, int] = {"windows": 0, "qemu": 0}

        def fake_probe(sandbox_type: SandboxType) -> bool:
            probe_counter[sandbox_type] += 1
            return True

        async def run_test() -> None:
            with patch.object(manager, "_probe_type", side_effect=fake_probe):
                for _ in range(5):
                    await manager.get_available_types()

        _run(run_test())

        assert probe_counter["windows"] == 1, (
            f"Expected 1 probe for 'windows', got {probe_counter['windows']}. The cache is not working — probe ran more than once."
        )
        assert probe_counter["qemu"] == 1, (
            f"Expected 1 probe for 'qemu', got {probe_counter['qemu']}. The cache is not working — probe ran more than once."
        )

    def test_successful_result_returned_consistently(self) -> None:
        """Cached successful result is returned on every subsequent call."""
        manager = _make_manager()

        def fake_probe(_sandbox_type: SandboxType) -> bool:
            return True

        async def run_test() -> list[list[SandboxType]]:
            with patch.object(manager, "_probe_type", side_effect=fake_probe):
                return [await manager.get_available_types() for _ in range(3)]

        all_results = _run(run_test())
        for result in all_results:
            assert "windows" in result
            assert "qemu" in result


# ---------------------------------------------------------------------------
# F-0032: WindowsSandbox.is_available result is cached (success path)
# ---------------------------------------------------------------------------


class TestIsAvailableCachesSuccess:
    """F-0032: A successful availability probe must be cached indefinitely."""

    def test_success_entry_not_re_probed_even_when_ancient(self) -> None:
        """A successful cache entry is never re-probed regardless of age.

        The caching strategy treats successes as permanent: _get_type_available
        returns True immediately when available=True, bypassing the TTL check
        entirely. Only an explicit invalidate_availability_cache() call clears it.
        """
        manager = _make_manager()
        probe_calls: list[SandboxType] = []

        ancient = datetime.now(UTC) - timedelta(days=365)
        _inject_cache(manager, "windows", AvailabilityCacheEntry(available=True, probed_at=ancient))

        def counting_probe(sandbox_type: SandboxType) -> bool:
            probe_calls.append(sandbox_type)
            return True

        async def run_test() -> list[SandboxType]:
            with patch.object(manager, "_probe_type", side_effect=counting_probe):
                return await manager.get_available_types()

        result = _run(run_test())

        assert "windows" in result, "Stale but successful cache entry must still return 'windows' as available."
        assert probe_calls.count("windows") == 0, (
            f"A year-old successful entry must NOT trigger a re-probe, got {probe_calls.count('windows')} probes. "
            "Success entries are permanent until invalidated."
        )

    def test_get_available_types_hits_cache_on_second_call(self) -> None:
        """get_available_types does not call _probe_type on second call after success."""
        manager = _make_manager()
        probe_calls: list[SandboxType] = []

        def counting_probe(sandbox_type: SandboxType) -> bool:
            probe_calls.append(sandbox_type)
            return True

        async def run_test() -> None:
            with patch.object(manager, "_probe_type", side_effect=counting_probe):
                await manager.get_available_types()
                await manager.get_available_types()
                await manager.get_available_types()

        _run(run_test())

        assert probe_calls.count("windows") == 1, (
            f"Expected 1 probe call for 'windows', got {probe_calls.count('windows')}. Successful availability result is not being cached."
        )

    def test_cached_success_stored_in_dict(self) -> None:
        """After a successful probe the result is stored in availability_cache."""
        manager = _make_manager()

        async def run_test() -> None:
            with patch.object(manager, "_probe_type", new_callable=AsyncMock) as mock_probe:
                mock_probe.return_value = True
                await manager.get_available_types()

        _run(run_test())

        assert "qemu" in manager.availability_cache
        entry = manager.availability_cache["qemu"]
        assert entry.available is True


# ---------------------------------------------------------------------------
# F-0032: Failure probe re-runs after TTL expires (clock injection, no freezegun)
# ---------------------------------------------------------------------------


class TestIsAvailableReProbesFailureAfterTtl:
    """F-0032: Failed probe must be re-tried after FAILURE_CACHE_TTL_SECONDS seconds."""

    def test_failure_entry_not_expired_within_ttl(self) -> None:
        """A fresh failed cache entry is not expired within its TTL."""
        entry = AvailabilityCacheEntry(available=False, probed_at=datetime.now(UTC))
        assert not entry.is_expired(FAILURE_CACHE_TTL_SECONDS), "A fresh failure entry should not be expired immediately."

    def test_failure_entry_expired_after_ttl(self) -> None:
        """A failed cache entry is expired once it is older than FAILURE_CACHE_TTL_SECONDS."""
        past = datetime.now(UTC) - timedelta(seconds=FAILURE_CACHE_TTL_SECONDS + 1)
        entry = AvailabilityCacheEntry(available=False, probed_at=past)
        assert entry.is_expired(FAILURE_CACHE_TTL_SECONDS), "A failure entry older than TTL should be expired."

    def test_failure_does_not_re_probe_within_ttl(self) -> None:
        """Repeated calls within the TTL window do not trigger a second probe."""
        manager = _make_manager()
        probe_calls: list[SandboxType] = []

        def counting_probe(sandbox_type: SandboxType) -> bool:
            probe_calls.append(sandbox_type)
            return False

        async def run_test() -> None:
            with patch.object(manager, "_probe_type", side_effect=counting_probe):
                await manager.get_available_types()
                await manager.get_available_types()
                await manager.get_available_types()

        _run(run_test())

        assert probe_calls.count("windows") == 1, (
            f"Expected 1 probe within TTL, got {probe_calls.count('windows')}. Failure result is not being cached correctly."
        )

    def test_failure_re_probes_after_ttl_via_backdated_entry(self) -> None:
        """After TTL expires, the next call runs a new probe.

        Clock injection: we directly insert a backdated cache entry to simulate
        the passage of time without patching time or requiring freezegun.
        """
        manager = _make_manager()
        probe_calls: list[SandboxType] = []

        expired_past = datetime.now(UTC) - timedelta(seconds=FAILURE_CACHE_TTL_SECONDS + 5)
        _inject_cache(
            manager,
            "windows",
            AvailabilityCacheEntry(available=False, probed_at=expired_past),
        )

        def counting_probe(sandbox_type: SandboxType) -> bool:
            probe_calls.append(sandbox_type)
            return False

        async def run_test() -> list[SandboxType]:
            with patch.object(manager, "_probe_type", side_effect=counting_probe):
                return await manager.get_available_types()

        _run(run_test())

        assert probe_calls.count("windows") == 1, (
            f"After TTL expiry a new probe must be triggered. Probe count was {probe_calls.count('windows')}."
        )


# ---------------------------------------------------------------------------
# invalidate_availability_cache forces re-probe
# ---------------------------------------------------------------------------


class TestInvalidateCacheForcesReProbe:
    """invalidate_availability_cache must remove entries, causing fresh probes."""

    def test_invalidate_all_clears_entire_cache(self) -> None:
        """Calling invalidate_availability_cache(None) removes all entries."""
        manager = _make_manager()
        _inject_cache(manager, "windows", AvailabilityCacheEntry(available=True))
        _inject_cache(manager, "qemu", AvailabilityCacheEntry(available=True))

        manager.invalidate_availability_cache()

        assert len(manager.availability_cache) == 0, "invalidate_availability_cache() with no argument must clear all entries."

    def test_invalidate_specific_type_removes_only_that_entry(self) -> None:
        """Invalidating a specific type leaves other entries intact."""
        manager = _make_manager()
        _inject_cache(manager, "windows", AvailabilityCacheEntry(available=True))
        _inject_cache(manager, "qemu", AvailabilityCacheEntry(available=True))

        manager.invalidate_availability_cache("windows")

        assert "windows" not in manager.availability_cache, "'windows' entry should have been removed."
        assert "qemu" in manager.availability_cache, "'qemu' entry should remain after invalidating only 'windows'."

    def test_invalidate_forces_re_probe_on_next_call(self) -> None:
        """After invalidation, get_available_types probes again."""
        manager = _make_manager()
        probe_calls: list[SandboxType] = []

        def counting_probe(sandbox_type: SandboxType) -> bool:
            probe_calls.append(sandbox_type)
            return True

        async def run_test() -> None:
            with patch.object(manager, "_probe_type", side_effect=counting_probe):
                await manager.get_available_types()
                assert probe_calls.count("windows") == 1

                manager.invalidate_availability_cache()

                await manager.get_available_types()

        _run(run_test())

        assert probe_calls.count("windows") == 2, (
            f"Expected 2 probes for 'windows' (one before, one after invalidate), got {probe_calls.count('windows')}."
        )
        assert probe_calls.count("qemu") == 2, (
            f"Expected 2 probes for 'qemu' (one before, one after invalidate), got {probe_calls.count('qemu')}."
        )

    def test_invalidate_single_type_probes_only_that_type_again(self) -> None:
        """Invalidating one type triggers a fresh probe for that type only."""
        manager = _make_manager()
        probe_calls: list[SandboxType] = []

        def counting_probe(sandbox_type: SandboxType) -> bool:
            probe_calls.append(sandbox_type)
            return True

        async def run_test() -> None:
            with patch.object(manager, "_probe_type", side_effect=counting_probe):
                await manager.get_available_types()
                assert probe_calls.count("windows") == 1
                assert probe_calls.count("qemu") == 1

                manager.invalidate_availability_cache("windows")

                await manager.get_available_types()

        _run(run_test())

        assert probe_calls.count("windows") == 2, f"Expected 2 probes for invalidated 'windows', got {probe_calls.count('windows')}."
        assert probe_calls.count("qemu") == 1, f"Expected qemu probe count to remain 1, got {probe_calls.count('qemu')}."

    def test_invalidate_nonexistent_entry_is_noop(self) -> None:
        """Calling invalidate on a type with no cached entry does not raise."""
        manager = _make_manager()
        manager.invalidate_availability_cache("windows")
        assert "windows" not in manager.availability_cache
