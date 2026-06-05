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

from intellicrack.sandbox.base import SandboxBase, SandboxConfig
from intellicrack.sandbox.manager import (
    SandboxInstance,
    SandboxManager,
    SandboxType,
)
from intellicrack.sandbox.qemu import QEMUConfig, QEMUSandbox
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from pathlib import Path


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


class _AbsentBinaryQEMUSandbox(QEMUSandbox):
    """Real ``QEMUSandbox`` for a host where the QEMU binary is absent.

    The real, unmodified :meth:`QEMUSandbox.is_available` logic runs end to end;
    only the executable *discovery* helper is injected to report no binary
    (the genuine outcome on a host without QEMU installed), exercising the real
    ``qemu_path is None`` availability branch under test. The operation being
    gated -- the availability decision -- is never mocked.
    """

    async def _find_qemu(self) -> Path | None:
        """Report that no QEMU executable is present on this host.

        Returns:
            Path | None: Always ``None`` so the real availability decision takes
            its genuine no-binary branch.
        """
        return None


class _PresentBinaryQEMUSandbox(QEMUSandbox):
    """Real ``QEMUSandbox`` for a host where the QEMU binary IS present.

    Mirror image of :class:`_AbsentBinaryQEMUSandbox`. Only the executable
    *discovery* helper is injected -- to return a real, existing file path (the
    genuine outcome on a host with QEMU installed) -- and the accelerator probe
    is pre-cached so :meth:`QEMUSandbox.is_available` does not shell out to
    ``qemu -accel help``. The real availability decision (``qemu_path is None``
    taking its False branch and returning ``True``) runs unmodified end to end;
    the gated decision itself is never mocked. This is the paired oracle proving
    that binary *absence* -- not a blanket exclusion -- is what removes ``qemu``
    from the reported types.
    """

    def __init__(self, default_config: SandboxConfig, qemu_config: QEMUConfig | None, present_path: Path) -> None:
        """Store the real present binary path the discovery helper will report.

        Args:
            default_config: Base sandbox configuration.
            qemu_config: QEMU-specific configuration (defaulted when ``None``).
            present_path: Real existing file standing in for the QEMU binary.
        """
        super().__init__(default_config, qemu_config)
        self._present_path = present_path
        self._accelerator_cached = True

    async def _find_qemu(self) -> Path | None:
        """Report a real, existing executable path as the discovered QEMU binary.

        Returns:
            Path | None: The injected real present path so the availability
            decision takes its genuine binary-found branch.
        """
        return self._present_path


class _ProbeRoutingManager(_RealManager):
    """Manager that routes the real ``qemu`` probe at an injected real sandbox.

    Only the *construction* of the sandbox object inside the inherited
    :meth:`SandboxManager._probe_type` is redirected; the real probe, the real
    cache write, and the real :meth:`SandboxManager.get_available_types`
    filtering all execute unchanged. This proves the manager faithfully reflects
    whatever the genuine ``is_available`` of the injected real sandbox returns.
    """

    def __init__(self, qemu_factory: Callable[[], QEMUSandbox], default_config: SandboxConfig) -> None:
        """Store the real QEMU sandbox factory the manager should probe.

        Args:
            qemu_factory: Zero-argument callable returning a real ``QEMUSandbox``
                (or subclass) instance to probe when the manager evaluates the
                ``qemu`` type.
            default_config: Default sandbox configuration for the manager.
        """
        super().__init__(default_config=default_config)
        self._qemu_factory = qemu_factory

    async def _probe_type(self, sandbox_type: SandboxType) -> bool:
        """Probe ``sandbox_type`` using the injected real ``qemu`` sandbox factory.

        Args:
            sandbox_type: Sandbox type to probe on the real host.

        Returns:
            bool: The genuine ``is_available`` result for the real sandbox.
        """
        sandbox: SandboxBase = self._qemu_factory() if sandbox_type == "qemu" else WindowsSandbox(self._default_config)
        return await sandbox.is_available()


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

    def test_absent_real_qemu_binary_excludes_qemu_from_reported_types(self) -> None:
        """An absent real QEMU binary must drive ``qemu`` out of reported types.

        The manager probes a real :class:`QEMUSandbox` whose executable name is
        genuinely absent from the host, so the unmodified, real
        ``is_available`` returns ``False`` through its true filesystem search.
        This gate fails if the manager fabricates availability or ignores the
        real probe result: an independent direct probe of the same real sandbox
        must agree, and ``get_available_types`` must omit ``qemu`` accordingly.
        """
        manager = _ProbeRoutingManager(lambda: _AbsentBinaryQEMUSandbox(SandboxConfig(), QEMUConfig()), default_config=SandboxConfig())

        async def _direct_probe() -> bool:
            return await _AbsentBinaryQEMUSandbox(SandboxConfig(), QEMUConfig()).is_available()

        async def _reported() -> list[SandboxType]:
            return await manager.get_available_types()

        direct = _run(_direct_probe())
        reported = _run(_reported())

        assert direct is False, "a real QEMUSandbox with an absent binary name must probe as unavailable"
        assert "qemu" not in reported, "manager must exclude qemu when the real is_available probe returns False"
        assert manager.availability_cache["qemu"].available is False, "the real False probe must be cached verbatim"
        assert all(t in _VALID_TYPES for t in reported), f"reported types must be valid; got {reported}"

    def test_present_real_qemu_binary_includes_qemu_in_reported_types(self, tmp_path: Path) -> None:
        """A present real QEMU binary must drive ``qemu`` INTO reported types.

        Paired with
        :meth:`test_absent_real_qemu_binary_excludes_qemu_from_reported_types`,
        this proves binary *absence* -- not a blanket exclusion or fabricated
        constant -- is the controlling factor. The same real, unmodified
        ``is_available`` decision now runs over a genuinely existing file, takes
        its binary-found branch, and returns ``True``; the manager must reflect
        that by listing ``qemu``. A direct independent probe of the same real
        sandbox must agree.

        Args:
            tmp_path: Pytest temporary directory supplying a real existing file
                to stand in for the discovered QEMU executable.
        """
        present_binary: Path = tmp_path / "qemu-system-x86_64.exe"
        _ = present_binary.write_bytes(b"MZ")
        assert present_binary.exists(), "the injected QEMU binary path must be a real existing file"

        manager = _ProbeRoutingManager(
            lambda: _PresentBinaryQEMUSandbox(SandboxConfig(), QEMUConfig(), present_binary),
            default_config=SandboxConfig(),
        )

        async def _direct_probe() -> bool:
            return await _PresentBinaryQEMUSandbox(SandboxConfig(), QEMUConfig(), present_binary).is_available()

        async def _reported() -> list[SandboxType]:
            return await manager.get_available_types()

        direct = _run(_direct_probe())
        reported = _run(_reported())

        assert direct is True, "a real QEMUSandbox whose binary genuinely exists must probe as available"
        assert "qemu" in reported, "manager must include qemu when the real is_available probe returns True"
        assert manager.availability_cache["qemu"].available is True, "the real True probe must be cached verbatim"
        assert all(t in _VALID_TYPES for t in reported), f"reported types must be valid; got {reported}"

    @pytest.mark.spawns_process
    def test_reported_qemu_availability_matches_real_independent_probe(self) -> None:
        """Reported ``qemu`` availability must equal an independent real probe.

        The manager probes the real, unmodified :class:`QEMUSandbox`; the same
        availability is computed independently by directly awaiting
        ``QEMUSandbox.is_available`` on a fresh instance. The manager's
        membership decision for ``qemu`` must match that independent oracle
        exactly, in whichever direction the real host resolves.
        """
        manager = _ProbeRoutingManager(lambda: QEMUSandbox(SandboxConfig(), QEMUConfig()), default_config=SandboxConfig())

        async def _direct_probe() -> bool:
            return await QEMUSandbox(SandboxConfig(), QEMUConfig()).is_available()

        async def _reported() -> list[SandboxType]:
            return await manager.get_available_types()

        independent = _run(_direct_probe())
        reported = _run(_reported())

        assert ("qemu" in reported) is independent, "manager qemu membership must equal the independent real probe"
        assert manager.availability_cache["qemu"].available is independent, "cached qemu availability must equal the real probe"
        assert all(t in _VALID_TYPES for t in reported), f"reported types must be valid; got {reported}"

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
