# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for ``intellicrack.sandbox.manager`` (FIX UNIT 12a).

The audit notes that every manager test uses ``_TestableManager`` with
``InMemorySandbox`` stubs and never manages a real sandbox implementation. These
tests drive the REAL :class:`SandboxManager` against the REAL
:class:`QEMUSandbox` / :class:`WindowsSandbox` classes:

* ``get_available_types`` / availability probing query the REAL host and return
  only types whose ``is_available`` truly succeeds (no mocked availability).
* ``SandboxInstance`` wraps a REAL ``QEMUSandbox`` and the manager's lifecycle
  operations (``get``, ``destroy``, ``destroy_all``, ``cleanup_stale``,
  ``get_status``, ``active_count``) act on that real instance and its real
  ``SandboxState`` — exercising the real teardown path through
  ``QEMUSandbox.stop`` rather than an in-memory stub.

Booting an actual VM is out of scope for the unit suite (it needs a prepared
disk image and nested virtualisation), so the running-VM state is established by
the real ``SandboxState`` object the real sandbox exposes; teardown then routes
through the real ``QEMUSandbox.stop`` implementation, whose ``stopped`` early
return is the genuine no-VM path.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.manager import (
    SandboxInstance,
    SandboxManager,
    SandboxType,
)
from intellicrack.sandbox.qemu import QEMUConfig, QEMUSandbox
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from collections.abc import Coroutine


_VALID_TYPES: frozenset[SandboxType] = frozenset({"windows", "qemu"})


class _RealManager(SandboxManager):
    """``SandboxManager`` subclass exposing instance registration for tests.

    The helpers mutate the private instance registry from inside the class
    hierarchy so ``basedpyright``'s ``reportPrivateUsage`` rule stays satisfied
    without any inline suppression, while still letting tests register real
    sandbox instances and check cache state.
    """

    def register(self, instance: SandboxInstance) -> None:
        """Register a pre-built real instance directly with the manager.

        Args:
            instance: Real sandbox instance to track.
        """
        self._instances[instance.id] = instance

    def has_instance(self, instance_id: str) -> bool:
        """Report whether ``instance_id`` is still tracked.

        Args:
            instance_id: Instance identifier to check.

        Returns:
            bool: ``True`` if the instance remains registered.
        """
        return instance_id in self._instances

    async def probe_and_cache(self, sandbox_type: SandboxType) -> tuple[bool, bool]:
        """Probe ``sandbox_type`` for real, returning probe result and cache value.

        Args:
            sandbox_type: Sandbox type to probe on the real host.

        Returns:
            tuple[bool, bool]: ``(probe_result, cached_value)`` where both come
            from the real availability path.
        """
        probed = await self._get_type_available(sandbox_type)
        cached = self.availability_cache[sandbox_type].available
        return probed, cached


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Execute ``coro`` on a dedicated event loop for test isolation.

    Args:
        coro: Awaitable to run to completion.

    Returns:
        T: The coroutine's return value.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _real_qemu_instance() -> SandboxInstance:
    """Build a managed instance wrapping a REAL ``QEMUSandbox``.

    The wrapped sandbox is a genuine :class:`QEMUSandbox` whose
    :class:`SandboxState` is marked ``running`` so the manager's running-instance
    accounting and teardown route through the real object.

    Returns:
        SandboxInstance: Instance wrapping a real QEMU sandbox in ``running``
        state.
    """
    sandbox = QEMUSandbox(SandboxConfig(), QEMUConfig())
    sandbox.state.status = "running"
    return SandboxInstance(sandbox=sandbox, sandbox_type="qemu")


class TestRealAvailabilityProbing:
    """``get_available_types`` must reflect REAL host probes, never fabrication."""

    @pytest.mark.spawns_process
    def test_available_types_are_a_subset_of_real_probes(self) -> None:
        """Reported types match independent real ``is_available`` probes.

        The manager probes the real host for ``windows`` and ``qemu``. Each
        reported type is cross-checked against an independent real
        ``is_available`` call on a freshly constructed sandbox of that type, so
        a fabricated availability would surface as a mismatch.
        """
        manager = _RealManager(default_config=SandboxConfig())

        async def _go() -> list[SandboxType]:
            return await manager.get_available_types()

        reported = _run(_go())

        assert all(t in _VALID_TYPES for t in reported), f"reported types must be valid; got {reported}"

        async def _probe_windows() -> bool:
            return await WindowsSandbox(SandboxConfig()).is_available()

        async def _probe_qemu() -> bool:
            return await QEMUSandbox(SandboxConfig(), QEMUConfig()).is_available()

        windows_real = _run(_probe_windows())
        qemu_real = _run(_probe_qemu())

        assert ("windows" in reported) == windows_real, "windows availability must match a real WindowsSandbox probe"
        assert ("qemu" in reported) == qemu_real, "qemu availability must match a real QEMUSandbox probe"

    @pytest.mark.spawns_process
    def test_probe_result_is_cached_after_real_probe(self) -> None:
        """A real probe result is written to the availability cache verbatim."""
        manager = _RealManager(default_config=SandboxConfig())

        async def _go() -> tuple[bool, bool]:
            return await manager.probe_and_cache("qemu")

        probed, cached = _run(_go())
        assert probed == cached, "the real probe result must be cached unchanged for reuse"


class TestRealInstanceLifecycle:
    """Manager lifecycle must operate on REAL ``QEMUSandbox`` instances."""

    def test_get_returns_the_real_managed_instance(self) -> None:
        """``get`` returns the exact real instance registered with the manager."""
        manager = _RealManager(default_config=SandboxConfig())
        instance = _real_qemu_instance()
        manager.register(instance)

        async def _go() -> SandboxInstance | None:
            return await manager.get(instance.id)

        found = _run(_go())
        assert found is not None, "get must return the registered instance, not None"
        assert found is instance, "get must return the same real instance object"
        assert isinstance(found.sandbox, QEMUSandbox), "managed sandbox must be a real QEMUSandbox"
        assert found.state.status == "running", "real instance state must reflect the running sandbox"

    def test_active_count_counts_real_running_instances(self) -> None:
        """``active_count`` reflects the real running ``SandboxState`` objects."""
        manager = _RealManager(default_config=SandboxConfig())
        running = _real_qemu_instance()
        stopped = _real_qemu_instance()
        stopped.sandbox.state.status = "stopped"
        manager.register(running)
        manager.register(stopped)

        assert manager.active_count == 1, "only the real running sandbox must count toward active_count"

    def test_destroy_routes_through_real_qemu_stop(self) -> None:
        """``destroy`` invokes the real ``QEMUSandbox.stop`` and removes the instance."""
        manager = _RealManager(default_config=SandboxConfig())
        instance = _real_qemu_instance()
        manager.register(instance)

        async def _go() -> None:
            await manager.destroy(instance.id)

        _run(_go())

        assert not manager.has_instance(instance.id), "destroy must remove the real instance from the manager"
        assert instance.sandbox.state.status == "stopped", "the real QEMUSandbox.stop must drive the state to stopped"

    def test_destroy_all_stops_every_real_instance(self) -> None:
        """``destroy_all`` tears down all real instances via real ``stop``."""
        manager = _RealManager(default_config=SandboxConfig())
        first = _real_qemu_instance()
        second = _real_qemu_instance()
        manager.register(first)
        manager.register(second)

        async def _go() -> None:
            await manager.destroy_all()

        _run(_go())

        assert manager.instances == [], "destroy_all must clear every real instance"
        assert first.sandbox.state.status == "stopped"
        assert second.sandbox.state.status == "stopped"

    def test_cleanup_stale_removes_real_idle_instance(self) -> None:
        """``cleanup_stale`` destroys a real instance idle beyond the threshold."""
        manager = _RealManager(default_config=SandboxConfig())
        stale = _real_qemu_instance()
        fresh = _real_qemu_instance()
        stale.last_used = datetime.now(UTC) - timedelta(seconds=7200)
        manager.register(stale)
        manager.register(fresh)

        async def _go() -> int:
            return await manager.cleanup_stale(max_idle_seconds=3600)

        removed = _run(_go())

        assert removed == 1, "exactly the stale real instance must be cleaned up"
        assert not manager.has_instance(stale.id)
        assert manager.has_instance(fresh.id), "a recently-used real instance must survive cleanup"
        assert stale.sandbox.state.status == "stopped", "the cleaned real sandbox must have been stopped"

    @pytest.mark.spawns_process
    def test_get_status_reports_real_instances_and_real_availability(self) -> None:
        """``get_status`` summarises real instances and real host availability."""
        manager = _RealManager(default_config=SandboxConfig())
        instance = _real_qemu_instance()
        manager.register(instance)

        async def _go() -> dict[str, object]:
            return await manager.get_status()

        status = _run(_go())

        assert status["total_count"] == 1, "status must count the one real managed instance"
        assert status["active_count"] == 1, "the real running instance must be reported active"
        instances = status["instances"]
        assert isinstance(instances, list)
        instance_records = cast("list[dict[str, object]]", instances)
        instance_record = instance_records[0]
        assert instance_record["id"] == instance.id, "status must report the real instance id"
        assert instance_record["type"] == "qemu", "status must report the real sandbox type"
        available = status["available_types"]
        assert isinstance(available, list)
        available_types = cast("list[object]", available)
        assert all(value in _VALID_TYPES for value in available_types), "available_types must come from real host probing"
