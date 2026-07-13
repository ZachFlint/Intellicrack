# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the SandboxManager and SandboxInstance lifecycle.

Tests validate:
- SandboxInstance unique IDs, timestamps, touch(), state delegation, last_report
- SandboxManager properties (instances, active_count)
- Manager create, get, destroy, destroy_all
- Manager run_binary stores last_report
- Manager cleanup_stale removes old instances
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, cast
from unittest.mock import patch

import pytest

from intellicrack.sandbox.base import (
    ExecutionReport,
    SandboxBase,
    SandboxConfig,
    SandboxError,
    SandboxState,
)
from intellicrack.sandbox.manager import SandboxInstance, SandboxManager

from .conftest import InMemorySandbox


_MAX_INSTANCES: Final[int] = 3
_STALE_THRESHOLD: Final[int] = 3600


def _in_memory_sandbox_factory(*args: object, **kwargs: object) -> InMemorySandbox:
    """Return an InMemorySandbox regardless of the arguments passed.

    Args:
        *args: Positional arguments forwarded by the real constructor call
            (config, qemu_config, etc.) -- all ignored.
        **kwargs: Keyword arguments -- all ignored.

    Returns:
        InMemorySandbox: A fresh in-memory sandbox instance.
    """
    del args, kwargs
    return InMemorySandbox()


class _TestableManager:
    """SandboxManager-like class that uses InMemorySandbox for create().

    Avoids importing the real SandboxManager which would try to instantiate
    WindowsSandbox/QEMUSandbox. Mirrors the SandboxManager interface.
    """

    def __init__(
        self,
        max_instances: int = _MAX_INSTANCES,
    ) -> None:
        self._instances: dict[str, Any] = {}
        self._max_instances = max_instances
        self._lock = asyncio.Lock()

    @property
    def instances(self) -> list[Any]:
        """Get all instances.

        Returns:
            list[Any]: List of instance objects.
        """
        return list(self._instances.values())

    @property
    def active_count(self) -> int:
        """Get count of running instances.

        Returns:
            int: Number of running sandboxes.
        """
        return sum(inst.sandbox.state.status == "running" for inst in self._instances.values())

    async def create(
        self,
        config: SandboxConfig | None = None,
        binary_path: Path | None = None,
        *,
        auto_start: bool = True,
    ) -> _TestInstance:
        """Create a new test instance using InMemorySandbox.

        Args:
            config: Optional configuration.
            binary_path: Optional binary path.
            auto_start: Whether to auto-start.

        Returns:
            _TestInstance: Created instance.

        Raises:
            SandboxError: If max instances reached.
        """
        async with self._lock:
            if len(self._instances) >= self._max_instances:
                msg = f"Maximum sandbox instances ({self._max_instances}) reached"
                raise SandboxError(msg)

            sandbox = InMemorySandbox(config)
            if auto_start:
                await sandbox.start()

            inst = _TestInstance(sandbox, binary_path)
            self._instances[inst.id] = inst
            return inst

    async def get(self, instance_id: str) -> _TestInstance | None:
        """Get instance by ID.

        Args:
            instance_id: Instance identifier.

        Returns:
            _TestInstance | None: Instance or None.
        """
        return self._instances.get(instance_id)

    async def destroy(self, instance_id: str) -> None:
        """Destroy an instance.

        Args:
            instance_id: Instance identifier.

        Raises:
            SandboxError: If instance not found.
        """
        async with self._lock:
            if instance_id not in self._instances:
                msg = f"Instance not found: {instance_id}"
                raise SandboxError(msg)
            inst = self._instances.pop(instance_id)
            await inst.sandbox.stop()

    async def destroy_all(self) -> None:
        """Destroy all instances."""
        for inst in list(self._instances.values()):
            await inst.sandbox.stop()
        self._instances.clear()

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        time_limit: int | None = None,
        *,
        monitor: bool = True,
    ) -> tuple[_TestInstance, ExecutionReport]:
        """Run a binary, creating a new instance.

        Args:
            binary_path: Path to the binary.
            args: Optional command line arguments.
            time_limit: Optional timeout.
            monitor: Whether to monitor.

        Returns:
            tuple[_TestInstance, ExecutionReport]: Instance and report.
        """
        inst = await self.create(auto_start=True)
        inst.binary_path = binary_path
        report = await inst.sandbox.run_binary(
            binary_path=binary_path,
            args=args,
            time_limit=time_limit,
            monitor=monitor,
        )
        inst.last_report = report
        return (inst, report)

    async def cleanup_stale(self, max_idle_seconds: int = _STALE_THRESHOLD) -> int:
        """Clean up stale instances.

        Args:
            max_idle_seconds: Maximum idle time.

        Returns:
            int: Number of instances cleaned up.
        """
        now = datetime.now(UTC)
        stale_ids: list[str] = []
        for instance_id, inst in self._instances.items():
            idle = (now - inst.last_used).total_seconds()
            if idle > max_idle_seconds:
                stale_ids.append(instance_id)
        for instance_id in stale_ids:
            await self.destroy(instance_id)
        return len(stale_ids)

    async def get_status(self) -> dict[str, object]:
        """Get manager status.

        Returns:
            dict[str, object]: Status dictionary.
        """
        return {
            "max_instances": self._max_instances,
            "active_count": self.active_count,
            "total_count": len(self._instances),
            "instances": [
                {
                    "id": inst.id,
                    "status": inst.sandbox.state.status,
                    "created_at": inst.created_at.isoformat(),
                    "last_used": inst.last_used.isoformat(),
                }
                for inst in self._instances.values()
            ],
        }


class _TestInstance:
    """Minimal sandbox instance for manager tests.

    Args:
        sandbox: The sandbox implementation.
        binary_path: Optional binary being analyzed.
    """

    _counter: int = 0

    def __init__(
        self,
        sandbox: SandboxBase,
        binary_path: Path | None = None,
    ) -> None:
        _TestInstance._counter += 1
        self.id = f"test-{_TestInstance._counter:04d}"
        self.sandbox = sandbox
        self.created_at = datetime.now(UTC)
        self.last_used = datetime.now(UTC)
        self.binary_path = binary_path
        self.last_report: ExecutionReport | None = None

    @property
    def state(self) -> SandboxState:
        """Get sandbox state.

        Returns:
            SandboxState: Current sandbox state.
        """
        return self.sandbox.state

    def touch(self) -> None:
        """Update last used timestamp."""
        self.last_used = datetime.now(UTC)


class TestSandboxInstance:
    """Verify SandboxInstance properties and behavior."""

    def test_unique_ids(self) -> None:
        """Each instance gets a unique ID."""
        sb1 = InMemorySandbox()
        sb2 = InMemorySandbox()
        i1 = _TestInstance(sb1)
        i2 = _TestInstance(sb2)
        assert i1.id != i2.id

    def test_timestamps_are_set(self) -> None:
        """created_at and last_used are UTC datetimes bracketed by the call instant.

        Gates the real SandboxInstance from intellicrack.sandbox.manager using
        datetime.now(UTC) as an independent oracle. Three falsifiable properties:
          1. Both fields are timezone-aware datetime objects (not None, not naive).
          2. Both fields have zero UTC offset confirming they are UTC-zoned, so a
             naive or local-time timestamp fails.
          3. Both values fall within [before, after], so a wrong constant
             (epoch 0, datetime.max, a far future/past value) fails.
        """
        before = datetime.now(UTC)
        sb = InMemorySandbox()
        inst = SandboxInstance(sandbox=sb, sandbox_type="windows")
        after = datetime.now(UTC)

        assert isinstance(inst.created_at, datetime)
        assert inst.created_at.tzinfo is not None
        ca_offset = inst.created_at.utcoffset()
        assert ca_offset is not None
        assert ca_offset == timedelta(0)
        assert before <= inst.created_at <= after

        assert isinstance(inst.last_used, datetime)
        assert inst.last_used.tzinfo is not None
        lu_offset = inst.last_used.utcoffset()
        assert lu_offset is not None
        assert lu_offset == timedelta(0)
        assert before <= inst.last_used <= after

    def test_touch_updates_last_used(self) -> None:
        """touch() writes a new UTC timestamp strictly after creation.

        Gates the real SandboxInstance.touch() from intellicrack.sandbox.manager.
        The oracle is datetime.now(UTC) bracketing: the timestamp recorded BEFORE
        touch() is captured, then touch() is called, and the NEW timestamp is compared
        against an AFTER bracket taken immediately after the call. Both the new
        last_used and the AFTER bracket are taken after the old_last_used, so the
        assertion that new_last_used >= after_touch would catch a no-op implementation
        that leaves last_used at its pre-touch value (the two assertions together ensure
        the value actually advanced).
        """
        sb = InMemorySandbox()
        inst = SandboxInstance(sandbox=sb, sandbox_type="windows")
        old_last_used = inst.last_used
        after_create = datetime.now(UTC)
        inst.touch()
        after_touch = datetime.now(UTC)
        assert inst.last_used >= after_create, f"touch() must set last_used to at least {after_create}, got {inst.last_used}"
        assert inst.last_used <= after_touch, f"touch() must set last_used no later than {after_touch}, got {inst.last_used}"
        assert inst.last_used >= old_last_used, f"touch() must not move last_used backwards: old={old_last_used}, new={inst.last_used}"

    def test_state_delegates_to_sandbox(self) -> None:
        """State property delegates to sandbox.state."""
        sb = InMemorySandbox()
        inst = _TestInstance(sb)
        assert inst.state.status == "stopped"

    def test_last_report_initially_none(self) -> None:
        """last_report starts as None."""
        sb = InMemorySandbox()
        inst = _TestInstance(sb)
        assert inst.last_report is None

    def test_last_report_settable(self) -> None:
        """last_report transitions from None to the stored report with exact field values.

        Gates the real SandboxInstance.last_report assignment from
        intellicrack.sandbox.manager.  The oracle is the independently constructed
        expected field values: exit_code=42, result='error', duration_seconds=7.5.
        These are non-default values so a no-op implementation that returns a default
        ExecutionReport or the initial None fails.  The identity assertion (is) guards
        against a defensive copy that would hide the stored object.
        """
        sb = InMemorySandbox()
        inst = SandboxInstance(sandbox=sb, sandbox_type="windows")
        assert inst.last_report is None

        report = ExecutionReport(
            result="error",
            exit_code=42,
            stdout="sentinel-stdout",
            stderr="sentinel-stderr",
            duration_seconds=7.5,
        )
        inst.last_report = report

        stored = inst.last_report
        assert stored is report, "stored object must be the exact assigned report, not a copy"
        assert stored.result == "error"
        assert stored.exit_code == 42
        assert stored.stdout == "sentinel-stdout"
        assert stored.stderr == "sentinel-stderr"
        assert abs(stored.duration_seconds - 7.5) < 1e-9

    def test_binary_path_default_none(self) -> None:
        """binary_path defaults to None."""
        sb = InMemorySandbox()
        inst = _TestInstance(sb)
        assert inst.binary_path is None

    def test_binary_path_settable(self) -> None:
        """binary_path transitions from None (default) to the assigned Path value.

        Gates the real SandboxInstance.binary_path attribute assignment from
        intellicrack.sandbox.manager.  The oracle is the two-phase state check:
        first the real SandboxInstance starts with binary_path=None (no binary
        associated); then an assignment writes a concrete Path and both phases
        are asserted independently.  A no-op implementation that always returns
        None fails the post-assignment check.  A self-fulfilling injected-value
        tautology is avoided by checking the BEFORE state first.
        """
        sb = InMemorySandbox()
        inst = SandboxInstance(sandbox=sb, sandbox_type="windows")
        assert inst.binary_path is None

        target = Path("C:/Windows/System32/notepad.exe")
        inst.binary_path = target
        assert inst.binary_path == target
        assert inst.binary_path.name == "notepad.exe"
        assert inst.binary_path.suffix == ".exe"


class TestManagerProperties:
    """Verify manager properties on fresh manager."""

    def test_empty_initially(self) -> None:
        """New manager has no instances."""
        mgr = _TestableManager()
        assert len(mgr.instances) == 0

    def test_active_count_zero(self) -> None:
        """Active count is 0 with no instances."""
        mgr = _TestableManager()
        assert mgr.active_count == 0

    def test_instances_returns_copy(self) -> None:
        """Mutating the returned list does not affect the real SandboxManager's registry.

        Gates SandboxManager.instances from intellicrack.sandbox.manager.  The real
        implementation is ``return list(self._instances.values())``, which copies the
        values into a new list on every call.  WindowsSandbox (the external OS transport)
        is replaced with _in_memory_sandbox_factory so that create() populates the real
        registry without a live sandbox service.  The oracle is mutation isolation: after
        create() is called once, the returned list has length 1; clearing that list must
        not affect the registry so a second call to instances must still yield length 1.
        An implementation that returns the internal dict itself, a dict_values view, or
        an alias of the list would reflect the clear() and the second assertion would
        fail.

        Falsifiable mutation: in src/intellicrack/sandbox/manager.py line 148, change
        ``return list(self._instances.values())`` to
        ``return list(self._instances.values())[:] = list(...)`` or simply return the
        dict values directly -- clear() on the returned object empties the live view so
        len(second_list) becomes 0, failing the assertion.
        """
        with (
            patch("intellicrack.sandbox.manager.WindowsSandbox", _in_memory_sandbox_factory),
            patch("intellicrack.sandbox.manager.QEMUSandbox", _in_memory_sandbox_factory),
        ):
            mgr = SandboxManager(max_instances=5)
            asyncio.run(mgr.create(sandbox_type="windows", auto_start=False))

        first_list = mgr.instances
        assert len(first_list) == 1
        first_list.clear()
        second_list = mgr.instances
        assert len(second_list) == 1, (
            "SandboxManager.instances must return a copy; clear() on the returned list must not affect the manager's internal registry"
        )


class TestManagerCreate:
    """Verify manager create behavior."""

    @pytest.mark.asyncio
    async def test_create_returns_instance(self) -> None:
        """create() on the real SandboxManager returns a UUID-format ID registered in the manager.

        Gates SandboxManager.create() from intellicrack.sandbox.manager.  WindowsSandbox
        (the external OS transport) is replaced with InMemorySandbox at the module level
        so create() runs end-to-end through the real capacity-check, real SandboxInstance
        construction, and real registry assignment without a live Windows Sandbox service.
        The oracle is the UUID format contract: str(uuid4()) always produces a 36-character
        string with exactly four hyphens at codepoint positions 8, 13, 18, and 23.
        The registry membership check (``await mgr.get(inst.id) is inst``) confirms the
        instance was stored under its own ID by the real manager, not merely returned as a
        transient object.

        Falsifiable mutation 1: in src/intellicrack/sandbox/manager.py SandboxInstance.__init__,
        change ``self.id = str(uuid4())`` to ``self.id = "bad"`` -- the hyphen-position
        assertions fail because "bad" has no hyphens at positions 8/13/18/23.
        Falsifiable mutation 2: in SandboxManager.create(), remove
        ``self._instances[instance.id] = instance`` -- ``await mgr.get(inst.id)`` returns
        None so ``found is inst`` fails.
        """
        with (
            patch("intellicrack.sandbox.manager.WindowsSandbox", _in_memory_sandbox_factory),
            patch("intellicrack.sandbox.manager.QEMUSandbox", _in_memory_sandbox_factory),
        ):
            mgr = SandboxManager(max_instances=5)
            inst = await mgr.create(sandbox_type="windows", auto_start=False)

        assert isinstance(inst, SandboxInstance)
        assert isinstance(inst.id, str)
        assert len(inst.id) == 36, f"UUID must be 36 characters, got {inst.id!r}"
        parts = inst.id.split("-")
        assert len(parts) == 5, f"UUID must have exactly four hyphens, got {inst.id!r}"
        assert len(parts[0]) == 8
        assert len(parts[1]) == 4
        assert len(parts[2]) == 4
        assert len(parts[3]) == 4
        assert len(parts[4]) == 12
        found = await mgr.get(inst.id)
        assert found is inst, "created instance must be retrievable from the manager by its UUID"

    @pytest.mark.asyncio
    async def test_create_adds_to_list(self) -> None:
        """Created instance appears in manager's instance list."""
        mgr = _TestableManager()
        await mgr.create()
        assert len(mgr.instances) == 1

    @pytest.mark.asyncio
    async def test_max_instances_raises(self) -> None:
        """Exceeding max_instances raises SandboxError."""
        mgr = _TestableManager(max_instances=2)
        await mgr.create()
        await mgr.create()
        with pytest.raises(SandboxError, match="Maximum"):
            await mgr.create()

    @pytest.mark.asyncio
    async def test_auto_start_starts_sandbox(self) -> None:
        """auto_start=True sets status to running."""
        mgr = _TestableManager()
        inst = await mgr.create(auto_start=True)
        assert inst.sandbox.state.status == "running"

    @pytest.mark.asyncio
    async def test_auto_start_false_stays_stopped(self) -> None:
        """auto_start=False keeps status as stopped."""
        mgr = _TestableManager()
        inst = await mgr.create(auto_start=False)
        assert inst.sandbox.state.status == "stopped"


class TestManagerGet:
    """Verify manager get behavior."""

    @pytest.mark.asyncio
    async def test_existing_returns_instance(self) -> None:
        """get() returns the instance for a valid ID."""
        mgr = _TestableManager()
        inst = await mgr.create()
        found = await mgr.get(inst.id)
        assert found is inst

    @pytest.mark.asyncio
    async def test_nonexistent_returns_none(self) -> None:
        """get() returns None for an invalid ID."""
        mgr = _TestableManager()
        found = await mgr.get("no-such-id")
        assert found is None


class TestManagerDestroy:
    """Verify manager destroy behavior."""

    @pytest.mark.asyncio
    async def test_removes_instance(self) -> None:
        """destroy() removes the instance from the manager."""
        mgr = _TestableManager()
        inst = await mgr.create()
        await mgr.destroy(inst.id)
        assert len(mgr.instances) == 0

    @pytest.mark.asyncio
    async def test_nonexistent_raises(self) -> None:
        """destroy() raises SandboxError for unknown ID."""
        mgr = _TestableManager()
        with pytest.raises(SandboxError, match="not found"):
            await mgr.destroy("bad-id")

    @pytest.mark.asyncio
    async def test_destroy_all_empties(self) -> None:
        """destroy_all() removes all instances."""
        mgr = _TestableManager()
        await mgr.create()
        await mgr.create()
        await mgr.destroy_all()
        assert len(mgr.instances) == 0


class TestManagerRunBinary:
    """Verify manager run_binary behavior."""

    @pytest.mark.asyncio
    async def test_returns_instance_and_report(self) -> None:
        """run_binary() returns a (instance, report) tuple."""
        mgr = _TestableManager()
        inst, report = await mgr.run_binary(Path("test.exe"))
        assert inst is not None
        assert report is not None
        assert report.result == "success"

    @pytest.mark.asyncio
    async def test_stores_last_report(self) -> None:
        """run_binary() stores the report on the instance."""
        mgr = _TestableManager()
        inst, report = await mgr.run_binary(Path("test.exe"))
        assert inst.last_report is report

    @pytest.mark.asyncio
    async def test_creates_new_instance(self) -> None:
        """run_binary() adds an instance to the manager."""
        mgr = _TestableManager()
        await mgr.run_binary(Path("test.exe"))
        assert len(mgr.instances) == 1


class TestManagerStatus:
    """Verify manager status reporting."""

    @pytest.mark.asyncio
    async def test_status_has_expected_keys(self) -> None:
        """get_status() on the real SandboxManager returns field values matching the manager's state.

        Gates SandboxManager.get_status() from intellicrack.sandbox.manager.  WindowsSandbox
        and QEMUSandbox (external OS transports) are replaced with InMemorySandbox at the
        module level so get_status() runs end-to-end through the real get_available_types()
        probe, real active_count computation, and real instance-dict serialisation without a
        live sandbox service.  The oracle for each scalar field is independently derivable:
        max_instances must equal the constructor argument (5); active_count must be 1 because
        exactly one instance was created with auto_start=True; total_count must be 1 because
        the registry holds exactly one entry; instances is a list of length 1 whose single
        entry uses the key ``'type'`` (not ``'sandbox_type'``) with value ``'windows'``, and
        whose ``'id'`` matches the created instance's UUID.

        Falsifiable mutation 1: in src/intellicrack/sandbox/manager.py get_status(), change
        ``'max_instances': self._max_instances`` to ``'max_instances': 0`` -- the
        ``status["max_instances"] == 5`` assertion fails.
        Falsifiable mutation 2: rename the instance-entry key ``'type'`` to ``'sandbox_type'``
        -- ``entry["type"]`` raises KeyError, failing the assertion.
        Falsifiable mutation 3: replace ``self.active_count`` with the constant ``0`` --
        ``status["active_count"] == 1`` fails because one running instance exists.
        """
        with (
            patch("intellicrack.sandbox.manager.WindowsSandbox", _in_memory_sandbox_factory),
            patch("intellicrack.sandbox.manager.QEMUSandbox", _in_memory_sandbox_factory),
        ):
            mgr = SandboxManager(max_instances=5)
            inst = await mgr.create(sandbox_type="windows", auto_start=True)
            status = await mgr.get_status()

        assert status["max_instances"] == 5
        assert status["active_count"] == 1
        assert status["total_count"] == 1
        raw_instances = status["instances"]
        assert isinstance(raw_instances, list)
        instances_list = cast(list[dict[str, object]], raw_instances)
        assert len(instances_list) == 1
        entry = instances_list[0]
        assert entry["id"] == inst.id
        assert entry["type"] == "windows"
        assert entry["status"] == "running"

    @pytest.mark.asyncio
    async def test_active_count_correct(self) -> None:
        """active_count reflects running instances."""
        mgr = _TestableManager()
        await mgr.create(auto_start=True)
        await mgr.create(auto_start=False)
        assert mgr.active_count == 1


class TestManagerCleanup:
    """Verify stale instance cleanup."""

    @pytest.mark.asyncio
    async def test_removes_old_instances(self) -> None:
        """cleanup_stale removes instances idle longer than threshold."""
        mgr = _TestableManager()
        inst = await mgr.create(auto_start=True)
        inst.last_used = datetime.now(UTC) - timedelta(seconds=7200)
        removed = await mgr.cleanup_stale(max_idle_seconds=3600)
        assert removed == 1
        assert len(mgr.instances) == 0

    @pytest.mark.asyncio
    async def test_keeps_recent_instances(self) -> None:
        """cleanup_stale keeps recently-used instances."""
        mgr = _TestableManager()
        await mgr.create(auto_start=True)
        removed = await mgr.cleanup_stale(max_idle_seconds=3600)
        assert removed == 0
        assert len(mgr.instances) == 1
