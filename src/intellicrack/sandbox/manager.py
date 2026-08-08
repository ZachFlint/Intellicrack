# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Sandbox manager for coordinating sandbox instances.

This module provides a manager for creating, tracking, and coordinating multiple sandbox instances for binary analysis workflows.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, assert_never
from uuid import uuid4

from intellicrack.core.logging import get_logger
from intellicrack.sandbox.base import (
    ExecutionReport,
    SandboxBase,
    SandboxConfig,
    SandboxError,
    SandboxState,
)
from intellicrack.sandbox.qemu import QEMUConfig, QEMUSandbox
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from pathlib import Path


_logger = get_logger(__name__)

SandboxType = Literal["windows", "qemu"]

FAILURE_CACHE_TTL_SECONDS: float = 60.0

_RUNNING_STATUS = "running"


@dataclass
class AvailabilityCacheEntry:
    """Single cached availability result for one sandbox type.

    Attributes:
        available: Whether the sandbox type is available.
        probed_at: When the probe was executed.
    """

    available: bool
    probed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def is_expired(self, ttl_seconds: float) -> bool:
        """Return True if the entry has exceeded its TTL.

        Args:
            ttl_seconds: Maximum age in seconds before the entry is stale.

        Returns:
            bool: True if the entry age exceeds ttl_seconds.
        """
        age = (datetime.now(UTC) - self.probed_at).total_seconds()
        return age > ttl_seconds


class SandboxInstance:
    """Represents a managed sandbox instance."""

    def __init__(
        self,
        sandbox: SandboxBase,
        sandbox_type: SandboxType,
        binary_path: Path | None = None,
    ) -> None:
        """Initialize the SandboxInstance with a sandbox implementation.

        Args:
            sandbox: The sandbox implementation to manage.
            sandbox_type: Type of sandbox being managed.
            binary_path: Path to the binary being analyzed in this sandbox.
        """
        self.id = str(uuid4())
        self.sandbox_type: SandboxType = sandbox_type
        self.sandbox = sandbox
        self.created_at = datetime.now(UTC)
        self.last_used = datetime.now(UTC)
        self.binary_path = binary_path
        self.last_report: ExecutionReport | None = None
        self.is_busy: bool = False
        _logger.debug(
            "sandbox_instance_initialized",
            instance_id=self.id,
            sandbox_type=sandbox_type,
            binary_path=str(binary_path) if binary_path else None,
        )

    @property
    def state(self) -> SandboxState:
        """Current sandbox state.

        Returns:
            SandboxState: Current sandbox state.
        """
        return self.sandbox.state

    def touch(self) -> None:
        """Update last used timestamp."""
        self.last_used = datetime.now(UTC)


class SandboxManager:
    """Manager for sandbox instances.

    Provides creation, lifecycle management, and coordination of
    multiple sandbox instances for binary analysis.

    Attributes:
        DEFAULT_MAX_INSTANCES: Maximum concurrent sandbox instances allowed.
    """

    DEFAULT_MAX_INSTANCES = 3

    def __init__(
        self,
        default_config: SandboxConfig | None = None,
        max_instances: int = DEFAULT_MAX_INSTANCES,
    ) -> None:
        """Initialize the SandboxManager with default configuration and instance limits.

        Args:
            default_config: Default configuration for new sandboxes. If None, uses SandboxConfig defaults.
            max_instances: Maximum number of concurrent sandbox instances allowed.
        """
        self._instances: dict[str, SandboxInstance] = {}
        self._default_config = default_config or SandboxConfig()
        self._max_instances = max_instances
        self._lock = asyncio.Lock()
        self._availability_cache: dict[SandboxType, AvailabilityCacheEntry] = {}
        _logger.info("sandbox_manager_initialized", max_instances=max_instances)

    @property
    def instances(self) -> list[SandboxInstance]:
        """All managed instances.

        Returns:
            list[SandboxInstance]: List of sandbox instances.
        """
        return list(self._instances.values())

    @property
    def active_count(self) -> int:
        """Number of running instances.

        Returns:
            int: Number of running sandboxes.
        """
        return sum(inst.state.status == "running" for inst in self._instances.values())

    @property
    def availability_cache(self) -> dict[SandboxType, AvailabilityCacheEntry]:
        """Read-only view of the current availability cache.

        Returns:
            dict[SandboxType, AvailabilityCacheEntry]: Current cache entries keyed by sandbox type.
        """
        return self._availability_cache

    def _build_sandbox(
        self,
        sandbox_type: SandboxType,
        config: SandboxConfig | None = None,
        qemu_config: QEMUConfig | None = None,
    ) -> SandboxBase:
        """Construct the backend implementation for one sandbox type.

        Single point of truth for mapping a sandbox type onto a concrete
        backend class, shared by availability probing and instance creation so
        the two can never drift apart.

        Args:
            sandbox_type: The sandbox type to construct.
            config: Generic sandbox configuration handed to the backend. When
                omitted the manager's default configuration is used.
            qemu_config: QEMU-specific configuration. Consumed only by the QEMU
                backend; the Windows backend takes no such settings.

        Returns:
            SandboxBase: A freshly constructed, unstarted backend instance.
        """
        effective_config = config or self._default_config
        if sandbox_type == "windows":
            return WindowsSandbox(effective_config)
        if sandbox_type == "qemu":
            return QEMUSandbox(effective_config, qemu_config)
        assert_never(sandbox_type)

    async def _probe_type(self, sandbox_type: SandboxType) -> bool:
        """Execute a live availability check for one sandbox type without touching the cache.

        This method performs the actual subprocess or OS query to determine
        whether a sandbox type is usable. It has no caching side-effects so that
        callers (primarily :meth:`_get_type_available`) can control cache writes.

        Args:
            sandbox_type: The sandbox type to probe.

        Returns:
            bool: True if the sandbox type is currently available.
        """
        sandbox = self._build_sandbox(sandbox_type)

        available = await sandbox.is_available()
        _logger.debug(
            "sandbox_availability_probed",
            sandbox_type=sandbox_type,
            available=available,
        )
        return available

    async def _get_type_available(self, sandbox_type: SandboxType) -> bool:
        """Return cached availability, re-probing only when the cached entry is stale.

        Successful results are returned immediately regardless of age. Failed results
        are re-probed after :data:`FAILURE_CACHE_TTL_SECONDS` seconds so transient
        unavailability does not lock out a type permanently. The result of any
        re-probe is written to the cache by this method.

        Args:
            sandbox_type: The sandbox type to check.

        Returns:
            bool: True if the sandbox type is available.
        """
        entry = self._availability_cache.get(sandbox_type)

        if entry is not None:
            if entry.available:
                return True
            if not entry.is_expired(FAILURE_CACHE_TTL_SECONDS):
                return False

        available = await self._probe_type(sandbox_type)
        self._availability_cache[sandbox_type] = AvailabilityCacheEntry(available=available)
        return available

    async def get_available_types(self) -> list[SandboxType]:
        """Get list of available sandbox types.

        Results are cached per type: successes are retained until
        :meth:`invalidate_availability_cache` is called; failures are
        re-probed after :data:`FAILURE_CACHE_TTL_SECONDS` seconds (60 s by default)
        so that transient errors do not permanently hide a recoverable type.

        Returns:
            list[SandboxType]: List of sandbox types that can be used.
        """
        all_types: list[SandboxType] = ["windows", "qemu"]
        return [sandbox_type for sandbox_type in all_types if await self._get_type_available(sandbox_type)]

    def invalidate_availability_cache(self, sandbox_type: SandboxType | None = None) -> None:
        """Invalidate the availability cache to force re-probing on the next call.

        Args:
            sandbox_type: If given, only the entry for this type is removed.
                If None, the entire cache is cleared.
        """
        if sandbox_type is None:
            self._availability_cache.clear()
            _logger.info("sandbox_availability_cache_cleared")
        else:
            self._availability_cache.pop(sandbox_type, None)
            _logger.debug("sandbox_availability_cache_invalidated", sandbox_type=sandbox_type)

    async def create(
        self,
        sandbox_type: SandboxType = "windows",
        config: SandboxConfig | None = None,
        binary_path: Path | None = None,
        qemu_config: QEMUConfig | None = None,
        *,
        auto_start: bool = True,
        mark_busy: bool = False,
    ) -> SandboxInstance:
        """Create a new sandbox instance.

        Args:
            sandbox_type: Type of sandbox to create.
            config: Optional configuration override.
            binary_path: Optional binary to associate.
            qemu_config: Optional QEMU-specific configuration.
            auto_start: Whether to start the sandbox immediately.
            mark_busy: When true, the newly created instance is registered
                with ``is_busy = True`` inside the manager lock, preventing
                a concurrent caller from claiming it via
                :meth:`_find_idle_instance` before the original caller can.

        Returns:
            SandboxInstance: Created sandbox instance.

        Raises:
            SandboxError: If creation fails.
        """
        _logger.debug(
            "sandbox_create_called",
            sandbox_type=sandbox_type,
            binary_path=str(binary_path) if binary_path else None,
            auto_start=auto_start,
            mark_busy=mark_busy,
        )
        async with self._lock:
            if self.active_count >= self._max_instances:
                oldest = await self._find_oldest_idle()
                if oldest is not None:
                    await self._destroy_locked(oldest.id)
                else:
                    error_message = f"All {self._max_instances} sandboxes busy"
                    _logger.error("sandbox_create_capacity_exhausted", max_instances=self._max_instances)
                    raise SandboxError(error_message)

            sandbox = self._build_sandbox(sandbox_type, config, qemu_config)

            if not await sandbox.is_available():
                error_message = f"Sandbox type not available: {sandbox_type}"
                _logger.error("sandbox_create_type_unavailable", sandbox_type=sandbox_type)
                raise SandboxError(error_message)

            instance = SandboxInstance(
                sandbox=sandbox,
                sandbox_type=sandbox_type,
                binary_path=binary_path,
            )
            instance.is_busy = mark_busy

            self._instances[instance.id] = instance
            _logger.info("sandbox_instance_created", instance_id=instance.id, sandbox_type=sandbox_type)

            if auto_start:
                try:
                    if sandbox_type == "qemu" and isinstance(sandbox, QEMUSandbox):
                        sandbox.enable_vnc_display()
                    await sandbox.start()
                    _logger.info("sandbox_instance_started", instance_id=instance.id)
                except (OSError, RuntimeError, SandboxError) as e:
                    _logger.warning("sandbox_auto_start_failed", instance_id=instance.id, error=str(e))
                    del self._instances[instance.id]
                    error_message = f"Failed to start sandbox: {e}"
                    raise SandboxError(error_message) from e

            return instance

    async def get(self, instance_id: str) -> SandboxInstance | None:
        """Get a sandbox instance by ID.

        Args:
            instance_id: Instance identifier.

        Returns:
            SandboxInstance | None: Sandbox instance or None if not found.
        """
        return self._instances.get(instance_id)

    async def destroy(self, instance_id: str) -> None:
        """Destroy a sandbox instance.

        Acquires the manager lock and delegates teardown to
        :meth:`_destroy_locked`, which performs the sandbox stop, dictionary
        removal, and structured logging. Any :class:`SandboxError` raised by
        :meth:`_destroy_locked` (for example when ``instance_id`` is unknown)
        propagates to the caller unchanged.

        Args:
            instance_id: Instance identifier.
        """
        _logger.info("sandbox_destroy_called", instance_id=instance_id)
        async with self._lock:
            await self._destroy_locked(instance_id)

    async def _destroy_locked(self, instance_id: str) -> None:
        """Destroy a sandbox instance while the manager lock is already held.

        This is the inner implementation of :meth:`destroy`. It assumes the
        caller already holds ``self._lock`` and therefore must not attempt to
        re-acquire it. This split exists so that flows already holding the lock
        (such as capacity eviction inside :meth:`create`) can perform teardown
        without re-entering the non-reentrant :class:`asyncio.Lock` and
        deadlocking.

        Args:
            instance_id: Instance identifier.

        Raises:
            SandboxError: If instance not found.
        """
        instance = self._instances.get(instance_id)
        if instance is None:
            error_message = f"Sandbox instance not found: {instance_id}"
            _logger.error("sandbox_destroy_not_found", instance_id=instance_id)
            raise SandboxError(error_message)

        try:
            await instance.sandbox.stop()
        except (OSError, RuntimeError, SandboxError) as e:
            _logger.warning("sandbox_stop_error", instance_id=instance_id, error=str(e))

        del self._instances[instance_id]
        _logger.info("sandbox_instance_destroyed", instance_id=instance_id)

    async def restart(
        self,
        instance_id: str,
        config: SandboxConfig | None = None,
        qemu_config: QEMUConfig | None = None,
    ) -> SandboxInstance:
        """Tear a sandbox instance down and bring an equivalent one back up.

        The teardown and the recreate are owned by the manager so callers do not
        have to chain :meth:`destroy` and :meth:`create` themselves and reinvent
        the failure handling for the window between the two. The replacement
        reuses the original instance's sandbox type and associated binary path,
        so the only observable difference is the new instance identifier.

        Failure semantics are total: once this call returns the original
        instance is gone in every outcome. If the recreate step fails, no
        replacement is registered either, so no caller can be left holding an
        identifier that maps to a torn-down sandbox.

        Args:
            instance_id: Identifier of the instance to restart.
            config: Optional configuration override applied to the replacement.
                When omitted the manager default configuration is used.
            qemu_config: Optional QEMU backend configuration for the
                replacement. A QEMU sandbox needs it to receive its disk image;
                the Windows backend ignores it.

        Returns:
            SandboxInstance: The freshly created replacement instance.

        Raises:
            SandboxError: If ``instance_id`` is unknown, or if the replacement
                could not be created after the original was torn down.
        """
        instance = self._instances.get(instance_id)
        if instance is None:
            error_message = f"Sandbox instance not found: {instance_id}"
            _logger.error("sandbox_restart_not_found", instance_id=instance_id)
            raise SandboxError(error_message)

        sandbox_type = instance.sandbox_type
        binary_path = instance.binary_path
        _logger.info("sandbox_restart_started", instance_id=instance_id, sandbox_type=sandbox_type)

        await self.destroy(instance_id)

        try:
            replacement = await self.create(
                sandbox_type=sandbox_type,
                config=config,
                binary_path=binary_path,
                qemu_config=qemu_config,
                auto_start=True,
            )
        except SandboxError:
            _logger.warning(
                "sandbox_restart_recreate_failed",
                instance_id=instance_id,
                sandbox_type=sandbox_type,
            )
            raise

        _logger.info(
            "sandbox_restarted",
            previous_instance_id=instance_id,
            instance_id=replacement.id,
            sandbox_type=sandbox_type,
        )
        return replacement

    async def destroy_all(self) -> None:
        """Destroy all sandbox instances."""
        instance_ids = list(self._instances.keys())
        for instance_id in instance_ids:
            try:
                await self.destroy(instance_id)
            except (OSError, RuntimeError, SandboxError) as e:
                _logger.warning("sandbox_destroy_error", instance_id=instance_id, error=str(e))

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        sandbox_type: SandboxType = "windows",
        config: SandboxConfig | None = None,
        time_limit: int | None = None,
        qemu_config: QEMUConfig | None = None,
        instance_id: str | None = None,
        *,
        monitor: bool = True,
        reuse_instance: bool = False,
    ) -> tuple[SandboxInstance, ExecutionReport]:
        """Run a binary in a sandbox.

        Creates a new sandbox (or uses an existing one), runs the binary, and
        returns the execution report.

        There are three ways to choose where the binary runs, in descending
        order of precedence. ``instance_id`` names one exactly. Failing that,
        ``reuse_instance`` takes whichever idle instance of the right type
        comes first. Failing both, a new sandbox is created.

        Naming an instance is the only option that can produce two comparable
        runs, because ``reuse_instance`` cannot express a preference: with
        several sandboxes running it always lands on the same one, so a caller
        wanting to diff two runs got two reports from a single instance.

        Args:
            binary_path: Path to the binary to run.
            args: Optional command line arguments.
            sandbox_type: Type of sandbox to use.
            config: Optional configuration override.
            time_limit: Optional timeout override in seconds.
            qemu_config: Optional QEMU-specific configuration.
            instance_id: Identifier of an existing instance to run in.
            monitor: Whether to monitor behavior.
            reuse_instance: Whether to reuse an existing idle instance.

        Returns:
            tuple[SandboxInstance, ExecutionReport]: Tuple of (sandbox instance, execution report).

        Raises:
            OSError: If a system-level I/O error occurs.
            RuntimeError: If a runtime error occurs during sandbox operations.
            SandboxError: If binary execution fails in the sandbox, or the
                named instance does not exist, is not running, or is busy.
        """
        instance: SandboxInstance | None = None

        if instance_id is not None:
            async with self._lock:
                instance = self._claim_named_instance(instance_id, binary_path)
        elif reuse_instance:
            async with self._lock:
                candidate = await self._find_idle_instance(sandbox_type)
                if candidate is not None:
                    candidate.is_busy = True
                    candidate.binary_path = binary_path
                    candidate.touch()
                    instance = candidate

        if instance is None:
            instance = await self.create(
                sandbox_type=sandbox_type,
                config=config,
                binary_path=binary_path,
                auto_start=True,
                qemu_config=qemu_config,
                mark_busy=True,
            )
            instance.touch()

        try:
            report = await instance.sandbox.run_binary(
                binary_path=binary_path,
                args=args,
                time_limit=time_limit,
                monitor=monitor,
            )

        except (OSError, RuntimeError, SandboxError):
            _logger.warning("binary_execution_failed", instance_id=instance.id)
            raise
        finally:
            instance.is_busy = False

        instance.last_report = report
        return (instance, report)

    def _claim_named_instance(self, instance_id: str, binary_path: Path) -> SandboxInstance:
        """Take an existing instance for a run, by name.

        Must be called with the manager lock held, so that checking an
        instance is free and marking it busy cannot interleave with another
        caller doing the same.

        Args:
            instance_id: Identifier of the instance to run in.
            binary_path: Binary the instance is about to run.

        Returns:
            SandboxInstance: The claimed instance, marked busy.

        Raises:
            SandboxError: If no such instance exists, it is not running, or
                another run already holds it.
        """
        instance = self._instances.get(instance_id)
        if instance is None:
            error_message = f"Sandbox instance not found: {instance_id}"
            _logger.warning("sandbox_run_instance_not_found", instance_id=instance_id)
            raise SandboxError(error_message)

        if instance.state.status != _RUNNING_STATUS:
            error_message = f"Sandbox instance {instance_id} is {instance.state.status}, not running"
            _logger.warning("sandbox_run_instance_not_running", instance_id=instance_id, status=instance.state.status)
            raise SandboxError(error_message)

        if instance.is_busy:
            error_message = f"Sandbox instance {instance_id} is already running a binary"
            _logger.warning("sandbox_run_instance_busy", instance_id=instance_id)
            raise SandboxError(error_message)

        instance.is_busy = True
        instance.binary_path = binary_path
        instance.touch()
        return instance

    async def _find_idle_instance(
        self,
        sandbox_type: SandboxType,
    ) -> SandboxInstance | None:
        """Find an idle instance of the specified type.

        Args:
            sandbox_type: Type of sandbox to find.

        Returns:
            SandboxInstance | None: Idle instance or None if not found.
        """
        found = next(
            (
                instance
                for instance in self._instances.values()
                if instance.sandbox_type == sandbox_type and instance.state.status == "running" and not instance.is_busy
            ),
            None,
        )
        _logger.debug("idle_instance_search", sandbox_type=sandbox_type, found=found is not None)
        return found

    async def _find_oldest_idle(self) -> SandboxInstance | None:
        """Find the oldest idle sandbox instance.

        Returns:
            SandboxInstance | None: Oldest idle instance or None if none idle.
        """
        oldest: SandboxInstance | None = None
        oldest_time: datetime | None = None

        for instance in self._instances.values():
            if instance.state.status == "running" and not instance.is_busy and (oldest_time is None or instance.last_used < oldest_time):
                oldest = instance
                oldest_time = instance.last_used

        _logger.debug("oldest_idle_search", found=oldest is not None)
        return oldest

    async def cleanup_stale(self, max_idle_seconds: int = 3600) -> int:
        """Clean up stale sandbox instances.

        Args:
            max_idle_seconds: Maximum idle time before cleanup.

        Returns:
            int: Number of instances cleaned up.
        """
        _logger.debug("stale_cleanup_starting", max_idle_seconds=max_idle_seconds, total_instances=len(self._instances))
        now = datetime.now(UTC)
        stale_ids: list[str] = []

        for instance_id, instance in self._instances.items():
            idle_seconds = (now - instance.last_used).total_seconds()
            if idle_seconds > max_idle_seconds:
                stale_ids.append(instance_id)

        for instance_id in stale_ids:
            try:
                await self.destroy(instance_id)
            except (OSError, RuntimeError, SandboxError) as e:
                _logger.warning("stale_sandbox_cleanup_error", instance_id=instance_id, error=str(e))

        return len(stale_ids)

    async def get_status(self) -> dict[str, object]:
        """Get manager status summary.

        Returns:
            dict[str, object]: Status dictionary with instance information.
        """
        _logger.debug(
            "sandbox_status_queried",
            total_count=len(self._instances),
            active_count=sum(i.state.status == "running" for i in self._instances.values()),
        )
        available_types = await self.get_available_types()

        instance_info = [
            {
                "id": inst.id,
                "type": inst.sandbox_type,
                "status": inst.state.status,
                "created_at": inst.created_at.isoformat(),
                "last_used": inst.last_used.isoformat(),
                "binary": str(inst.binary_path) if inst.binary_path else None,
            }
            for inst in self._instances.values()
        ]

        return {
            "available_types": available_types,
            "max_instances": self._max_instances,
            "active_count": self.active_count,
            "total_count": len(self._instances),
            "instances": instance_info,
        }
