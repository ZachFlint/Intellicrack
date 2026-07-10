# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit7 F-0001: ``SandboxManager.create()`` deadlock.

The original defect: when the manager reached ``_max_instances`` running
sandboxes, the eviction branch inside :meth:`SandboxManager.create` called the
public :meth:`SandboxManager.destroy` while still holding the manager's
``asyncio.Lock``. Since :class:`asyncio.Lock` is non-reentrant, ``destroy``
would block forever trying to re-acquire it, hanging ``create()`` indefinitely.

These tests exercise the eviction path through the real ``create()`` method
and assert that:

* the call completes within a short timeout (no deadlock), and
* the oldest idle instance has been evicted while the new instance is present.

The tests rely on a real (not mocked) :class:`SandboxBase` subclass injected by
substituting :class:`intellicrack.sandbox.manager.WindowsSandbox` at module
scope via :class:`pytest.MonkeyPatch`. That keeps the manager's eviction logic
under test while replacing only the platform-specific sandbox factory it would
otherwise instantiate.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox import manager as manager_module
from intellicrack.sandbox.base import SandboxBase, SandboxConfig


if TYPE_CHECKING:
    from intellicrack.sandbox.manager import SandboxInstance


_EVICTION_TIMEOUT_SECONDS: Final[float] = 5.0
_MAX_INSTANCES: Final[int] = 2
_TIMESTAMP_SKEW_SECONDS: Final[float] = 0.01


class _FakeSandbox(SandboxBase):
    """In-process sandbox stand-in used to drive ``SandboxManager`` under test.

    The class implements only the surface that
    :class:`intellicrack.sandbox.manager.SandboxManager` exercises during a
    ``create()`` -> capacity eviction -> ``create()`` flow:

    * :meth:`is_available` returns ``True`` so creation proceeds.
    * :meth:`start` transitions the state to ``running`` so ``active_count``
      reflects the new instance and ``_find_oldest_idle`` can select it later.
    * :meth:`stop` transitions the state to ``stopped`` and records that the
      teardown ran (the test asserts on this to confirm eviction happened).

    No subprocess, file system or network resources are used. This is a real
    Python class, not a mock; the deadlock under test is purely about lock
    acquisition order inside the manager, so a faithful in-process double is
    sufficient.

    Attributes:
        stop_calls: Number of times :meth:`stop` has been invoked. Tests
            assert on this counter to confirm the manager's eviction path
            actually performed teardown rather than skipping it.
    """

    stop_calls: int

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialize the fake sandbox in the stopped state.

        Args:
            config: Optional sandbox configuration forwarded to the base class.
        """
        super().__init__(config)
        self.stop_calls = 0

    async def is_available(self) -> bool:
        """Report this fake sandbox as available for the manager.

        Returns:
            bool: Always ``True`` so ``SandboxManager.create`` proceeds.
        """
        return True

    async def start(self) -> None:
        """Mark the fake sandbox as running and record the start time."""
        self._state.status = "running"
        self._state.started_at = datetime.now(UTC)

    async def stop(self) -> None:
        """Mark the fake sandbox as stopped and count teardown invocations."""
        self._state.status = "stopped"
        self.stop_calls += 1


@pytest.fixture
def fake_windows_sandbox(
    monkeypatch: pytest.MonkeyPatch,
) -> type[_FakeSandbox]:
    """Replace the ``WindowsSandbox`` factory used by ``SandboxManager``.

    ``SandboxManager.create`` directly instantiates the concrete sandbox class
    imported as ``WindowsSandbox`` in the manager module. Substituting that
    name at module scope keeps the manager's real eviction logic on the test
    path while ensuring sandbox construction has no platform requirements.

    Args:
        monkeypatch: pytest-provided monkeypatch fixture used to swap the
            ``WindowsSandbox`` reference inside the manager module for the
            duration of the test.

    Returns:
        type[_FakeSandbox]: The fake sandbox class now used by the manager.
    """
    monkeypatch.setattr(manager_module, "WindowsSandbox", _FakeSandbox)
    return _FakeSandbox


async def _fill_manager_to_capacity(
    manager: manager_module.SandboxManager,
    capacity: int,
) -> list[SandboxInstance]:
    """Create ``capacity`` sandboxes through the real ``create`` path.

    Each instance is left in the idle/running state so that the next call to
    ``create`` triggers the capacity eviction branch.

    Args:
        manager: The sandbox manager under test.
        capacity: Number of instances to create, which should match the
            manager's configured ``max_instances`` so the next ``create`` call
            triggers eviction.

    Returns:
        list[SandboxInstance]: Instances created, in creation order. The first
        element is the oldest and is the eviction candidate.
    """
    created: list[SandboxInstance] = []
    for _ in range(capacity):
        instance = await manager.create(
            sandbox_type="windows",
            auto_start=True,
            mark_busy=False,
        )
        created.append(instance)
        # Force a strictly monotonic ``last_used`` so ``_find_oldest_idle``
        # has a well-defined winner. ``datetime.now`` resolution on Windows is
        # coarse enough that back-to-back creates can share a timestamp.
        await asyncio.sleep(_TIMESTAMP_SKEW_SECONDS)
    return created


@pytest.mark.asyncio
@pytest.mark.usefixtures("fake_windows_sandbox")
async def test_create_eviction_does_not_deadlock() -> None:
    """Capacity eviction inside ``create`` must complete without deadlock.

    Before the fix, ``create`` acquired ``self._lock`` and then awaited
    ``self.destroy(...)``, which tried to re-acquire the same non-reentrant
    lock and hung forever. This test fills the manager, then issues one more
    ``create`` under :func:`asyncio.wait_for` with a short timeout. A timeout
    here proves the deadlock is present; a clean return proves it is fixed.
    """
    manager = manager_module.SandboxManager(max_instances=_MAX_INSTANCES)
    created = await _fill_manager_to_capacity(manager, _MAX_INSTANCES)
    oldest = created[0]

    new_instance = await asyncio.wait_for(
        manager.create(
            sandbox_type="windows",
            auto_start=True,
            mark_busy=False,
        ),
        timeout=_EVICTION_TIMEOUT_SECONDS,
    )

    assert new_instance.id != oldest.id
    assert oldest.id not in {inst.id for inst in manager.instances}
    assert new_instance.id in {inst.id for inst in manager.instances}
    assert len(manager.instances) == _MAX_INSTANCES


@pytest.mark.asyncio
@pytest.mark.usefixtures("fake_windows_sandbox")
async def test_create_eviction_invokes_sandbox_stop() -> None:
    """Eviction must call ``sandbox.stop()`` on the evicted instance exactly once.

    This guards against a regression where the deadlock fix bypasses teardown:
    if ``_destroy_locked`` were skipped, the evicted instance's sandbox would
    leak resources. Counting ``stop_calls`` on the fake sandbox verifies the
    real teardown path ran.
    """
    manager = manager_module.SandboxManager(max_instances=_MAX_INSTANCES)
    created = await _fill_manager_to_capacity(manager, _MAX_INSTANCES)
    oldest = created[0]
    assert isinstance(oldest.sandbox, _FakeSandbox)
    assert oldest.sandbox.stop_calls == 0

    await asyncio.wait_for(
        manager.create(
            sandbox_type="windows",
            auto_start=True,
            mark_busy=False,
        ),
        timeout=_EVICTION_TIMEOUT_SECONDS,
    )

    assert oldest.sandbox.stop_calls == 1
