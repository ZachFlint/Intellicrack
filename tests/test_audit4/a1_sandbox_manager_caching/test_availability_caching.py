# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for F-0024 and F-0032: availability caching in SandboxManager.

These tests exercise the real availability-probe path end to end. The
production :meth:`SandboxManager._probe_type` runs the genuine OS detection
(``where WindowsSandboxClient.exe`` + CIM feature query for the Windows
sandbox, and ``qemu-system-x86_64`` discovery for QEMU). No part of the probe
is mocked or stubbed.

To assert the caching contract (each type is probed at most once, results are
reused, failures expire, invalidation forces a re-probe) the tests use a thin
:class:`_RecordingManager` subclass that records every invocation of the real
``_probe_type`` by calling ``super()._probe_type`` and counting. The real
production probe still executes for every recorded call, so the probe count is
the genuine number of times the caching layer reached the live detection code.

The expected availability values are derived from an independent oracle: a
fresh, real :class:`WindowsSandbox` / :class:`QEMUSandbox` instance whose
``is_available()`` is queried directly, never from the manager's own cache.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.manager import (
    FAILURE_CACHE_TTL_SECONDS,
    AvailabilityCacheEntry,
    SandboxManager,
    SandboxType,
)
from intellicrack.sandbox.qemu import QEMUSandbox
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from collections.abc import Coroutine


# ---------------------------------------------------------------------------
# Real probe-recording manager (no mocks: the production probe still runs)
# ---------------------------------------------------------------------------


class _RecordingManager(SandboxManager):
    """SandboxManager that records every real ``_probe_type`` invocation.

    The override delegates to the production :meth:`SandboxManager._probe_type`
    via ``super()`` so the genuine OS-level availability detection executes for
    every recorded call. The recording exists only to observe how many times
    the caching layer reached the live probe; it never substitutes a fake
    result for the real one.

    The ``probe_calls`` instance attribute records, in order, every sandbox
    type passed to the real probe.
    """

    def __init__(self, default_config: SandboxConfig | None = None) -> None:
        """Initialize the recording manager.

        Args:
            default_config: Default sandbox configuration forwarded to the base
                manager. If None, a default :class:`SandboxConfig` is used.
        """
        super().__init__(default_config=default_config)
        self.probe_calls: list[SandboxType] = []

    async def _probe_type(self, sandbox_type: SandboxType) -> bool:
        """Record the call and run the real production probe.

        Args:
            sandbox_type: The sandbox type to probe.

        Returns:
            bool: The genuine availability result from the production probe.
        """
        self.probe_calls.append(sandbox_type)
        return await super()._probe_type(sandbox_type)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_manager() -> _RecordingManager:
    """Return a fresh recording manager wrapping the real probe path.

    Returns:
        _RecordingManager: A new manager whose ``_probe_type`` runs the real
        OS detection while recording invocations.
    """
    return _RecordingManager(default_config=SandboxConfig())


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


def _oracle_availability() -> dict[SandboxType, bool]:
    """Compute ground-truth availability from fresh, real sandbox instances.

    This is an independent oracle: it constructs brand-new
    :class:`WindowsSandbox` and :class:`QEMUSandbox` objects and queries their
    real ``is_available()`` directly, with no involvement of the manager or its
    cache. The manager-under-test must agree with these values.

    Returns:
        dict[SandboxType, bool]: Mapping of each sandbox type to its real,
        host-determined availability.
    """

    async def probe() -> dict[SandboxType, bool]:
        config = SandboxConfig()
        windows_available = await WindowsSandbox(config).is_available()
        qemu_available = await QEMUSandbox(config, None).is_available()
        return {"windows": windows_available, "qemu": qemu_available}

    return _run(probe())


# ---------------------------------------------------------------------------
# F-0024: get_available_types caches probes (real probe path)
# ---------------------------------------------------------------------------


class TestGetAvailableTypesSubprocessCalledOnce:
    """F-0024: Repeated calls to get_available_types must not re-run the real probe."""

    def test_probe_called_once_per_available_type_across_five_calls(self) -> None:
        """Five calls to get_available_types reach the real probe at most once per type.

        The real production ``_probe_type`` (live ``where``/CIM/QEMU detection)
        runs through the caching layer. Available types are cached permanently,
        so a type that probes True must be probed exactly once across all five
        calls. A type that probes False is allowed to re-probe after the failure
        TTL, but within this sub-second loop it must also stay at one probe.
        Without the cache every call would re-probe, so the count would be five.
        """
        oracle = _oracle_availability()
        manager = _make_manager()

        results: list[list[SandboxType]] = _run(_collect_five(manager))

        for sandbox_type in ("windows", "qemu"):
            assert manager.probe_calls.count(sandbox_type) == 1, (
                f"Expected exactly 1 real probe for {sandbox_type!r} across five calls, "
                f"got {manager.probe_calls.count(sandbox_type)}. The cache is not suppressing re-probes."
            )

        expected_available: list[SandboxType] = [t for t in ("windows", "qemu") if oracle[t]]
        for result in results:
            assert result == expected_available, (
                f"get_available_types must report exactly the real-oracle availability {expected_available}, got {result}."
            )

    def test_successful_result_returned_consistently(self) -> None:
        """Three repeated calls return lists identical to the independent oracle.

        The lists must be byte-for-byte equal to each other and equal to the
        ground truth computed from fresh real sandbox instances, proving the
        cached value is reused without drift.
        """
        oracle = _oracle_availability()
        expected_available: list[SandboxType] = [t for t in ("windows", "qemu") if oracle[t]]
        manager = _make_manager()

        all_results: list[list[SandboxType]] = _run(_collect_n(manager, 3))

        assert all_results[0] == all_results[1] == all_results[2], (
            f"Repeated get_available_types calls must return identical lists, got {all_results}."
        )
        assert all_results[0] == expected_available, (
            f"Cached availability {all_results[0]} must equal the independent oracle {expected_available}."
        )


# ---------------------------------------------------------------------------
# F-0032: a successful availability probe is cached (success path)
# ---------------------------------------------------------------------------


class TestIsAvailableCachesSuccess:
    """F-0032: A successful availability probe must be cached indefinitely."""

    def test_success_entry_not_re_probed_even_when_ancient(self) -> None:
        """A year-old successful cache entry is never re-probed.

        Success entries are permanent until invalidated: ``_get_type_available``
        returns True immediately when ``available=True``, bypassing the TTL. A
        backdated successful entry must therefore yield zero real probes for
        that type while still reporting it as available.
        """
        manager = _make_manager()

        ancient = datetime.now(UTC) - timedelta(days=365)
        _inject_cache(manager, "windows", AvailabilityCacheEntry(available=True, probed_at=ancient))

        result: list[SandboxType] = _run(manager.get_available_types())

        assert "windows" in result, "Stale-but-successful cache entry must still report 'windows' as available."
        assert manager.probe_calls.count("windows") == 0, (
            f"A year-old successful entry must NOT trigger a re-probe, got {manager.probe_calls.count('windows')} real probes."
        )

    def test_get_available_types_hits_cache_on_second_call(self) -> None:
        """An available type is probed exactly once across three calls.

        The first call runs the real probe; the cached success must satisfy the
        next two calls with no further probe.
        """
        oracle = _oracle_availability()
        available_type: SandboxType | None = next((t for t in ("windows", "qemu") if oracle[t]), None)
        assert available_type is not None, (
            "This host exposes no available sandbox type; the real-probe cache-hit gate cannot run. "
            "Provision QEMU on PATH or enable the Windows Sandbox optional feature."
        )

        manager = _make_manager()
        _run(_collect_n(manager, 3))

        assert manager.probe_calls.count(available_type) == 1, (
            f"Expected 1 real probe for available type {available_type!r} across three calls, "
            f"got {manager.probe_calls.count(available_type)}. The successful result is not being cached."
        )

    def test_cached_success_stored_in_dict_matches_real_probe(self) -> None:
        """After the real probe runs, the cache stores the genuine probe result.

        Drives the real probe path (no mocks) and asserts every available type
        named by the independent oracle is present in ``availability_cache`` with
        ``available=True``, and every unavailable type that was probed is stored
        with ``available=False``. The cached values must equal the oracle.
        """
        oracle = _oracle_availability()
        manager = _make_manager()

        _run(manager.get_available_types())

        for sandbox_type in ("windows", "qemu"):
            assert sandbox_type in manager.availability_cache, f"Real probe for {sandbox_type!r} ran but its result was not cached."
            entry = manager.availability_cache[sandbox_type]
            assert entry.available is oracle[sandbox_type], (
                f"Cached availability for {sandbox_type!r} is {entry.available}, "
                f"but the independent real probe says {oracle[sandbox_type]}."
            )


# ---------------------------------------------------------------------------
# F-0032: Failure probe re-runs after TTL expires (clock injection)
# ---------------------------------------------------------------------------


class TestIsAvailableReProbesFailureAfterTtl:
    """F-0032: A failed probe must be re-tried after FAILURE_CACHE_TTL_SECONDS seconds."""

    def test_failure_entry_not_expired_within_ttl(self) -> None:
        """A fresh failed cache entry is not expired within its TTL."""
        entry = AvailabilityCacheEntry(available=False, probed_at=datetime.now(UTC))
        assert not entry.is_expired(FAILURE_CACHE_TTL_SECONDS), "A fresh failure entry should not be expired immediately."

    def test_failure_entry_expired_after_ttl(self) -> None:
        """A failed cache entry is expired once it is older than FAILURE_CACHE_TTL_SECONDS."""
        past = datetime.now(UTC) - timedelta(seconds=FAILURE_CACHE_TTL_SECONDS + 1)
        entry = AvailabilityCacheEntry(available=False, probed_at=past)
        assert entry.is_expired(FAILURE_CACHE_TTL_SECONDS), "A failure entry older than TTL should be expired."

    def test_fresh_failure_entry_not_re_probed_within_ttl(self) -> None:
        """A fresh injected failure entry suppresses the real probe within its TTL.

        A failure cached at the current time must be reused (no real probe) on
        subsequent calls until the TTL elapses, and the type must be absent from
        the reported availability list.
        """
        manager = _make_manager()
        _inject_cache(manager, "windows", AvailabilityCacheEntry(available=False, probed_at=datetime.now(UTC)))

        result: list[SandboxType] = _run(manager.get_available_types())

        assert "windows" not in result, "A cached failure must keep 'windows' out of the available list."
        assert manager.probe_calls.count("windows") == 0, (
            f"A fresh failure entry must suppress the real probe within TTL, got {manager.probe_calls.count('windows')} probes."
        )

    def test_failure_re_probes_after_ttl_via_backdated_entry(self) -> None:
        """After TTL expires, the next call runs a fresh real probe.

        Clock injection: a backdated failure entry (older than the TTL) simulates
        elapsed time without patching the clock. The next call must reach the real
        probe exactly once, and the freshly cached result must equal the
        independent oracle for that type.
        """
        oracle = _oracle_availability()
        manager = _make_manager()

        expired_past = datetime.now(UTC) - timedelta(seconds=FAILURE_CACHE_TTL_SECONDS + 5)
        _inject_cache(manager, "windows", AvailabilityCacheEntry(available=False, probed_at=expired_past))

        _run(manager.get_available_types())

        assert manager.probe_calls.count("windows") == 1, (
            f"An expired failure entry must trigger exactly one fresh real probe, got {manager.probe_calls.count('windows')}."
        )
        refreshed = manager.availability_cache["windows"]
        assert refreshed.available is oracle["windows"], (
            f"Re-probed 'windows' availability {refreshed.available} must equal the independent oracle {oracle['windows']}."
        )
        assert refreshed.probed_at > expired_past, "The re-probe must overwrite the backdated timestamp with a fresh one."


# ---------------------------------------------------------------------------
# invalidate_availability_cache forces re-probe
# ---------------------------------------------------------------------------


class TestInvalidateCacheForcesReProbe:
    """invalidate_availability_cache must remove entries, causing fresh real probes."""

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
        """After invalidation, get_available_types runs the real probe again.

        Available types are probed once, cached, then invalidated; the next call
        must reach the real probe a second time, proving invalidation clears the
        cache rather than merely no-opping.
        """
        oracle = _oracle_availability()
        manager = _make_manager()

        async def run_test() -> None:
            await manager.get_available_types()
            manager.invalidate_availability_cache()
            await manager.get_available_types()

        _run(run_test())

        for sandbox_type in ("windows", "qemu"):
            expected = 2 if oracle[sandbox_type] else manager.probe_calls.count(sandbox_type)
            assert manager.probe_calls.count(sandbox_type) == expected, (
                f"Expected {expected} real probes for {sandbox_type!r} (one before, one after invalidate), "
                f"got {manager.probe_calls.count(sandbox_type)}."
            )
            assert manager.probe_calls.count(sandbox_type) >= 2, (
                f"Invalidation must force at least a second real probe for {sandbox_type!r}, got {manager.probe_calls.count(sandbox_type)}."
            )

    def test_invalidate_single_type_probes_only_that_type_again(self) -> None:
        """Invalidating one available type triggers a fresh real probe for it only.

        Requires at least two available sandbox types so the gate can prove the
        non-invalidated type keeps its cached result while the invalidated one is
        re-probed.
        """
        oracle = _oracle_availability()
        available: list[SandboxType] = [t for t in ("windows", "qemu") if oracle[t]]
        assert len(available) == 2, (
            "This host must expose both Windows Sandbox and QEMU for the per-type invalidation gate. "
            f"Available types from the real oracle: {available}."
        )
        invalidated, retained = available[0], available[1]
        manager = _make_manager()

        async def run_test() -> None:
            await manager.get_available_types()
            manager.invalidate_availability_cache(invalidated)
            await manager.get_available_types()

        _run(run_test())

        assert manager.probe_calls.count(invalidated) == 2, (
            f"Expected 2 real probes for invalidated {invalidated!r}, got {manager.probe_calls.count(invalidated)}."
        )
        assert manager.probe_calls.count(retained) == 1, (
            f"Expected the retained type {retained!r} to stay cached at 1 probe, got {manager.probe_calls.count(retained)}."
        )

    def test_invalidate_nonexistent_entry_is_noop(self) -> None:
        """Calling invalidate on a type with no cached entry does not raise."""
        manager = _make_manager()
        manager.invalidate_availability_cache("windows")
        assert "windows" not in manager.availability_cache


# ---------------------------------------------------------------------------
# Shared async drivers
# ---------------------------------------------------------------------------


async def _collect_five(manager: SandboxManager) -> list[list[SandboxType]]:
    """Call get_available_types five times and collect each result.

    Args:
        manager: The manager under test.

    Returns:
        list[list[SandboxType]]: The result of each of the five calls in order.
    """
    return [await manager.get_available_types() for _ in range(5)]


async def _collect_n(manager: SandboxManager, count: int) -> list[list[SandboxType]]:
    """Call get_available_types ``count`` times and collect each result.

    Args:
        manager: The manager under test.
        count: Number of calls to make.

    Returns:
        list[list[SandboxType]]: The result of each call in order.
    """
    return [await manager.get_available_types() for _ in range(count)]
