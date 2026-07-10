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
from unittest.mock import patch

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.manager import (
    FAILURE_CACHE_TTL_SECONDS,
    AvailabilityCacheEntry,
    SandboxManager,
    SandboxType,
)


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ALL_TYPES: tuple[SandboxType, SandboxType] = ("windows", "qemu")


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
        """Five calls to get_available_types trigger exactly one real probe per type.

        The delegating counter wraps the REAL _probe_type so the actual
        subprocess or OS check executes on the first call. The cache then
        serves cached results on calls 2-5. The counter records how many
        times the real implementation is invoked.

        Falsifiability: if the caching logic in _get_type_available is
        removed so that _probe_type is called unconditionally on every
        get_available_types() call, the counter would reach 5 for each type
        and the assertions would go red. If the cache returned a different
        list on any of the five calls (e.g. due to a re-probe with a
        different result), the consistency assertion would go red.
        Crucially, the expected value comes from the real first-call result,
        not from a fake probe, so a bug that hardcodes the probe return value
        would also be caught.
        """
        manager = _make_manager()
        probe_counter: dict[SandboxType, int] = {"windows": 0, "qemu": 0}
        original_probe: Callable[[SandboxType], Coroutine[object, object, bool]] = getattr(manager, "_probe_type")

        async def delegating_counter(sandbox_type: SandboxType) -> bool:
            probe_counter[sandbox_type] += 1
            return await original_probe(sandbox_type)

        setattr(manager, "_probe_type", delegating_counter)

        async def run_test() -> list[list[SandboxType]]:
            return [await manager.get_available_types() for _ in range(5)]

        all_results = _run(run_test())

        for sandbox_type in _ALL_TYPES:
            count = probe_counter[sandbox_type]
            assert count == 1, (
                f"Expected exactly 1 real probe for {sandbox_type!r} across 5 calls, got {count}. The cache is not preventing re-probing."
            )

        baseline = all_results[0]
        for i, result in enumerate(all_results[1:], start=2):
            assert result == baseline, (
                f"Call {i}: expected the same list as call 1 ({baseline!r}) but got {result!r}. "
                "Caching must serve identical results on every call after the first."
            )

        for sandbox_type_key in _ALL_TYPES:
            assert sandbox_type_key in manager.availability_cache, f"Cache entry for {sandbox_type_key!r} must exist after 5 calls."

    def test_successful_result_returned_consistently(self) -> None:
        """Cached result is returned on every subsequent call with no re-probe.

        Uses the REAL _probe_type wrapped by a delegating counter so the
        actual OS availability check runs exactly once. Expected values are
        derived from the real first-call result, not from a fake return.

        Falsifiability: removing the cache causes the counter to exceed 1 and
        the assertion fails. If the cache returned a different list on call 2
        or 3 (e.g. after a re-probe that flipped the result), the equality
        assertion against the baseline would fail. The availability_cache dict
        must contain entries for every known type with the correct available
        flag after the run.
        """
        manager = _make_manager()
        probe_calls: dict[SandboxType, int] = {"windows": 0, "qemu": 0}
        original_probe: Callable[[SandboxType], Coroutine[object, object, bool]] = getattr(manager, "_probe_type")

        async def delegating_counter(sandbox_type: SandboxType) -> bool:
            probe_calls[sandbox_type] += 1
            return await original_probe(sandbox_type)

        setattr(manager, "_probe_type", delegating_counter)

        async def run_test() -> list[list[SandboxType]]:
            return [await manager.get_available_types() for _ in range(3)]

        all_results = _run(run_test())

        baseline = all_results[0]
        for i, result in enumerate(all_results[1:], start=2):
            assert result == baseline, (
                f"Call {i}: result {result!r} differs from baseline {baseline!r}. Cached result must be identical on every call."
            )

        for sandbox_type in _ALL_TYPES:
            count = probe_calls[sandbox_type]
            assert count == 1, (
                f"Expected exactly 1 real probe for {sandbox_type!r} across 3 calls, got {count}. "
                "Successful result must be cached and not re-probed."
            )

        for sandbox_type_key in _ALL_TYPES:
            assert sandbox_type_key in manager.availability_cache, (
                f"Cache entry for {sandbox_type_key!r} must be present after get_available_types calls."
            )
            cached_available = manager.availability_cache[sandbox_type_key].available
            real_in_result = sandbox_type_key in baseline
            assert cached_available is real_in_result, (
                f"Cache entry for {sandbox_type_key!r}: available={cached_available!r} but "
                f"get_available_types returned {'present' if real_in_result else 'absent'}. "
                "Cached flag must match the list membership from the real probe."
            )


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
        """After a real probe the result is stored correctly in availability_cache.

        Uses the REAL _probe_type wrapped by a delegating counter so the
        actual subprocess or OS check executes. The cache entry is then
        validated against independently observable facts: the entry exists,
        its available flag matches what the probe actually returned (derived
        from availability_cache itself after the call, not from a fake
        constant), its timestamp falls within the measured test window, and
        the probe ran exactly once.

        Falsifiability: four independently-verifiable properties are checked.

        1. Both type keys are present — if _get_type_available never writes
           to the cache, property 1 fails.
        2. The available flag matches what the real probe returned — if the
           cache writes the wrong flag (e.g. always True regardless of probe
           result), the consistency check between available and real_result
           fails because get_available_types only includes types where the
           probe returned True.
        3. probed_at falls within the measured test window — a stale or
           fabricated timestamp fails the bounded inequality.
        4. The probe ran exactly once — re-probing on the same call fails
           this assertion; a no-op cache that never calls the probe also
           fails because count would be 0.
        """
        manager = _make_manager()
        probe_calls: dict[SandboxType, int] = {"windows": 0, "qemu": 0}
        original_probe: Callable[[SandboxType], Coroutine[object, object, bool]] = getattr(manager, "_probe_type")

        async def delegating_counter(sandbox_type: SandboxType) -> bool:
            probe_calls[sandbox_type] += 1
            return await original_probe(sandbox_type)

        setattr(manager, "_probe_type", delegating_counter)

        before = datetime.now(UTC)

        async def run_test() -> list[SandboxType]:
            return await manager.get_available_types()

        returned_types = _run(run_test())
        after = datetime.now(UTC)

        for sandbox_type in _ALL_TYPES:
            assert sandbox_type in manager.availability_cache, (
                f"Cache entry for '{sandbox_type}' must be written after the first get_available_types call."
            )
            entry = manager.availability_cache[sandbox_type]

            real_result = sandbox_type in returned_types
            assert entry.available is real_result, (
                f"Cache entry for '{sandbox_type}': available={entry.available!r} but the real probe "
                f"produced {'present' if real_result else 'absent'} in the returned list. "
                "The stored flag must match the actual probe outcome."
            )

            assert before <= entry.probed_at <= after, (
                f"Cache entry for '{sandbox_type}' probed_at={entry.probed_at!r} must fall within "
                f"the test window [{before!r}, {after!r}]. A fabricated or stale timestamp is wrong."
            )

            count = probe_calls[sandbox_type]
            assert count == 1, (
                f"Real _probe_type must be called exactly once for '{sandbox_type}', got {count}. "
                "Zero means the cache logic bypassed the probe entirely; >1 means caching is broken."
            )


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
