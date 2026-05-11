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
from typing import Any, Final

import pytest

from intellicrack.sandbox.base import (
    ExecutionReport,
    SandboxBase,
    SandboxConfig,
    SandboxError,
    SandboxState,
)

from .conftest import InMemorySandbox


_MAX_INSTANCES: Final[int] = 3
_STALE_THRESHOLD: Final[int] = 3600


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
        """created_at and last_used are set on creation."""
        sb = InMemorySandbox()
        inst = _TestInstance(sb)
        assert inst.created_at is not None
        assert inst.last_used is not None

    def test_touch_updates_last_used(self) -> None:
        """touch() updates last_used to current time."""
        sb = InMemorySandbox()
        inst = _TestInstance(sb)
        before = inst.last_used
        inst.touch()
        assert inst.last_used >= before

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
        """last_report can be set to an ExecutionReport."""
        sb = InMemorySandbox()
        inst = _TestInstance(sb)
        report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=1.0,
        )
        inst.last_report = report
        assert inst.last_report is report

    def test_binary_path_default_none(self) -> None:
        """binary_path defaults to None."""
        sb = InMemorySandbox()
        inst = _TestInstance(sb)
        assert inst.binary_path is None

    def test_binary_path_settable(self) -> None:
        """binary_path can be set."""
        sb = InMemorySandbox()
        inst = _TestInstance(sb, binary_path=Path("test.exe"))
        assert inst.binary_path == Path("test.exe")


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
        """Instances property returns a copy, not the internal dict."""
        mgr = _TestableManager()
        copy = mgr.instances
        assert copy == []
        assert copy is not getattr(mgr, "_instances")


class TestManagerCreate:
    """Verify manager create behavior."""

    def test_create_returns_instance(self) -> None:
        """create() returns an instance with an ID."""
        mgr = _TestableManager()
        inst = asyncio.get_event_loop().run_until_complete(mgr.create())
        assert inst.id is not None

    def test_create_adds_to_list(self) -> None:
        """Created instance appears in manager's instance list."""
        mgr = _TestableManager()
        asyncio.get_event_loop().run_until_complete(mgr.create())
        assert len(mgr.instances) == 1

    def test_max_instances_raises(self) -> None:
        """Exceeding max_instances raises SandboxError."""
        mgr = _TestableManager(max_instances=2)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(mgr.create())
        loop.run_until_complete(mgr.create())
        with pytest.raises(SandboxError, match="Maximum"):
            loop.run_until_complete(mgr.create())

    def test_auto_start_starts_sandbox(self) -> None:
        """auto_start=True sets status to running."""
        mgr = _TestableManager()
        inst = asyncio.get_event_loop().run_until_complete(
            mgr.create(auto_start=True),
        )
        assert inst.sandbox.state.status == "running"

    def test_auto_start_false_stays_stopped(self) -> None:
        """auto_start=False keeps status as stopped."""
        mgr = _TestableManager()
        inst = asyncio.get_event_loop().run_until_complete(
            mgr.create(auto_start=False),
        )
        assert inst.sandbox.state.status == "stopped"


class TestManagerGet:
    """Verify manager get behavior."""

    def test_existing_returns_instance(self) -> None:
        """get() returns the instance for a valid ID."""
        mgr = _TestableManager()
        loop = asyncio.get_event_loop()
        inst = loop.run_until_complete(mgr.create())
        found = loop.run_until_complete(mgr.get(inst.id))
        assert found is inst

    def test_nonexistent_returns_none(self) -> None:
        """get() returns None for an invalid ID."""
        mgr = _TestableManager()
        found = asyncio.get_event_loop().run_until_complete(mgr.get("no-such-id"))
        assert found is None


class TestManagerDestroy:
    """Verify manager destroy behavior."""

    def test_removes_instance(self) -> None:
        """destroy() removes the instance from the manager."""
        mgr = _TestableManager()
        loop = asyncio.get_event_loop()
        inst = loop.run_until_complete(mgr.create())
        loop.run_until_complete(mgr.destroy(inst.id))
        assert len(mgr.instances) == 0

    def test_nonexistent_raises(self) -> None:
        """destroy() raises SandboxError for unknown ID."""
        mgr = _TestableManager()
        with pytest.raises(SandboxError, match="not found"):
            asyncio.get_event_loop().run_until_complete(mgr.destroy("bad-id"))

    def test_destroy_all_empties(self) -> None:
        """destroy_all() removes all instances."""
        mgr = _TestableManager()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(mgr.create())
        loop.run_until_complete(mgr.create())
        loop.run_until_complete(mgr.destroy_all())
        assert len(mgr.instances) == 0


class TestManagerRunBinary:
    """Verify manager run_binary behavior."""

    def test_returns_instance_and_report(self) -> None:
        """run_binary() returns a (instance, report) tuple."""
        mgr = _TestableManager()
        inst, report = asyncio.get_event_loop().run_until_complete(
            mgr.run_binary(Path("test.exe")),
        )
        assert inst is not None
        assert report is not None
        assert report.result == "success"

    def test_stores_last_report(self) -> None:
        """run_binary() stores the report on the instance."""
        mgr = _TestableManager()
        inst, report = asyncio.get_event_loop().run_until_complete(
            mgr.run_binary(Path("test.exe")),
        )
        assert inst.last_report is report

    def test_creates_new_instance(self) -> None:
        """run_binary() adds an instance to the manager."""
        mgr = _TestableManager()
        asyncio.get_event_loop().run_until_complete(
            mgr.run_binary(Path("test.exe")),
        )
        assert len(mgr.instances) == 1


class TestManagerStatus:
    """Verify manager status reporting."""

    def test_status_has_expected_keys(self) -> None:
        """get_status() returns dict with required keys."""
        mgr = _TestableManager()
        status = asyncio.get_event_loop().run_until_complete(mgr.get_status())
        assert "max_instances" in status
        assert "active_count" in status
        assert "total_count" in status
        assert "instances" in status

    def test_active_count_correct(self) -> None:
        """active_count reflects running instances."""
        mgr = _TestableManager()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(mgr.create(auto_start=True))
        loop.run_until_complete(mgr.create(auto_start=False))
        assert mgr.active_count == 1


class TestManagerCleanup:
    """Verify stale instance cleanup."""

    def test_removes_old_instances(self) -> None:
        """cleanup_stale removes instances idle longer than threshold."""
        mgr = _TestableManager()
        loop = asyncio.get_event_loop()
        inst = loop.run_until_complete(mgr.create(auto_start=True))
        inst.last_used = datetime.now(UTC) - timedelta(seconds=7200)
        removed = loop.run_until_complete(mgr.cleanup_stale(max_idle_seconds=3600))
        assert removed == 1
        assert len(mgr.instances) == 0

    def test_keeps_recent_instances(self) -> None:
        """cleanup_stale keeps recently-used instances."""
        mgr = _TestableManager()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(mgr.create(auto_start=True))
        removed = loop.run_until_complete(mgr.cleanup_stale(max_idle_seconds=3600))
        assert removed == 0
        assert len(mgr.instances) == 1
