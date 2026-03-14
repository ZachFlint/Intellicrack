# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Sandbox manager for coordinating sandbox instances.

This module provides a manager for creating, tracking, and coordinating
multiple sandbox instances for binary analysis workflows.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import TYPE_CHECKING, Literal, assert_never
from uuid import uuid4

from ..core.logging import get_logger
from .base import (
    ExecutionReport,
    SandboxBase,
    SandboxConfig,
    SandboxError,
    SandboxState,
)
from .qemu import QEMUConfig, QEMUSandbox
from .windows import WindowsSandbox


if TYPE_CHECKING:
    from pathlib import Path


_logger = get_logger("sandbox.manager")

SandboxType = Literal["windows", "qemu"]


class SandboxInstance:
    """Represents a managed sandbox instance.

    Attributes:
        id: Unique instance identifier.
        sandbox_type: Type of sandbox.
        sandbox: The sandbox implementation.
        created_at: When the instance was created.
        last_used: When the instance was last used.
        binary_path: Path to binary being analyzed.
    """

    def __init__(
        self,
        sandbox: SandboxBase,
        sandbox_type: SandboxType,
        binary_path: Path | None = None,
    ) -> None:
        """Initialize a sandbox instance.

        Args:
            sandbox: The sandbox implementation.
            sandbox_type: Type of sandbox.
            binary_path: Optional binary being analyzed.
        """
        self.id = str(uuid4())
        self.sandbox_type = sandbox_type
        self.sandbox = sandbox
        self.created_at = datetime.now()
        self.last_used = datetime.now()
        self.binary_path = binary_path

    @property
    def state(self) -> SandboxState:
        """Get sandbox state.

        Returns:
            Current sandbox state.
        """
        return self.sandbox.state

    def touch(self) -> None:
        """Update last used timestamp."""
        self.last_used = datetime.now()


class SandboxManager:
    """Manager for sandbox instances.

    Provides creation, lifecycle management, and coordination of
    multiple sandbox instances for binary analysis.

    Attributes:
        _instances: Active sandbox instances.
        _default_config: Default sandbox configuration.
        _max_instances: Maximum concurrent instances.
    """

    DEFAULT_MAX_INSTANCES = 3

    def __init__(
        self,
        default_config: SandboxConfig | None = None,
        max_instances: int = DEFAULT_MAX_INSTANCES,
    ) -> None:
        """Initialize the sandbox manager.

        Args:
            default_config: Default configuration for new sandboxes.
            max_instances: Maximum number of concurrent instances.
        """
        self._instances: dict[str, SandboxInstance] = {}
        self._default_config = default_config or SandboxConfig()
        self._max_instances = max_instances
        self._lock = asyncio.Lock()

    @property
    def instances(self) -> list[SandboxInstance]:
        """Get all managed instances.

        Returns:
            List of sandbox instances.
        """
        return list(self._instances.values())

    @property
    def active_count(self) -> int:
        """Get count of running instances.

        Returns:
            Number of running sandboxes.
        """
        return sum(inst.state.status == "running" for inst in self._instances.values())

    async def get_available_types(self) -> list[SandboxType]:
        """Get list of available sandbox types.

        Returns:
            List of sandbox types that can be used.
        """
        available: list[SandboxType] = []

        windows_sandbox = WindowsSandbox(self._default_config)
        if await windows_sandbox.is_available():
            available.append("windows")

        qemu_sandbox = QEMUSandbox(self._default_config, None)
        if await qemu_sandbox.is_available():
            available.append("qemu")

        return available

    async def create(
        self,
        sandbox_type: SandboxType = "windows",
        config: SandboxConfig | None = None,
        binary_path: Path | None = None,
        auto_start: bool = True,
        qemu_config: QEMUConfig | None = None,
    ) -> SandboxInstance:
        """Create a new sandbox instance.

        Args:
            sandbox_type: Type of sandbox to create.
            config: Optional configuration override.
            binary_path: Optional binary to associate.
            auto_start: Whether to start the sandbox immediately.
            qemu_config: Optional QEMU-specific configuration.

        Returns:
            Created sandbox instance.

        Raises:
            SandboxError: If creation fails.
        """
        async with self._lock:
            if self.active_count >= self._max_instances:
                oldest = await self._find_oldest_idle()
                if oldest is not None:
                    await self.destroy(oldest.id)
                else:
                    error_message = f"Maximum sandbox instances ({self._max_instances}) reached"
                    raise SandboxError(error_message)

            effective_config = config or self._default_config

            sandbox: SandboxBase
            if sandbox_type == "windows":
                sandbox = WindowsSandbox(effective_config)
            elif sandbox_type == "qemu":
                sandbox = QEMUSandbox(effective_config, qemu_config)
            else:
                assert_never(sandbox_type)

            if not await sandbox.is_available():
                error_message = f"Sandbox type not available: {sandbox_type}"
                raise SandboxError(error_message)

            instance = SandboxInstance(
                sandbox=sandbox,
                sandbox_type=sandbox_type,
                binary_path=binary_path,
            )

            self._instances[instance.id] = instance
            _logger.info("sandbox_instance_created", instance_id=instance.id, sandbox_type=sandbox_type)

            if auto_start:
                try:
                    await sandbox.start()
                    _logger.info("sandbox_instance_started", instance_id=instance.id)
                except Exception as e:
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
            Sandbox instance or None if not found.
        """
        return self._instances.get(instance_id)

    async def destroy(self, instance_id: str) -> None:
        """Destroy a sandbox instance.

        Args:
            instance_id: Instance identifier.

        Raises:
            SandboxError: If instance not found.
        """
        async with self._lock:
            instance = self._instances.get(instance_id)
            if instance is None:
                error_message = f"Sandbox instance not found: {instance_id}"
                raise SandboxError(error_message)

            try:
                await instance.sandbox.stop()
            except Exception as e:
                _logger.warning("sandbox_stop_error", instance_id=instance_id, error=str(e))

            del self._instances[instance_id]
            _logger.info("sandbox_instance_destroyed", instance_id=instance_id)

    async def destroy_all(self) -> None:
        """Destroy all sandbox instances."""
        instance_ids = list(self._instances.keys())
        for instance_id in instance_ids:
            try:
                await self.destroy(instance_id)
            except Exception as e:
                _logger.warning("sandbox_destroy_error", instance_id=instance_id, error=str(e))

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        sandbox_type: SandboxType = "windows",
        config: SandboxConfig | None = None,
        timeout: int | None = None,
        monitor: bool = True,
        reuse_instance: bool = False,
        qemu_config: QEMUConfig | None = None,
    ) -> tuple[SandboxInstance, ExecutionReport]:
        """Run a binary in a sandbox.

        Creates a new sandbox (or reuses an existing one), runs the binary,
        and returns the execution report.

        Args:
            binary_path: Path to the binary to run.
            args: Optional command line arguments.
            sandbox_type: Type of sandbox to use.
            config: Optional configuration override.
            timeout: Optional timeout override.
            monitor: Whether to monitor behavior.
            reuse_instance: Whether to reuse an existing idle instance.
            qemu_config: Optional QEMU-specific configuration.

        Returns:
            Tuple of (sandbox instance, execution report).

        Raises:
            Exception: If binary execution fails in the sandbox.
        """
        instance: SandboxInstance | None = None

        if reuse_instance:
            instance = await self._find_idle_instance(sandbox_type)

        if instance is None:
            instance = await self.create(
                sandbox_type=sandbox_type,
                config=config,
                binary_path=binary_path,
                auto_start=True,
                qemu_config=qemu_config,
            )
        else:
            instance.binary_path = binary_path

        instance.touch()

        try:
            report = await instance.sandbox.run_binary(
                binary_path=binary_path,
                args=args,
                timeout=timeout,
                monitor=monitor,
            )

        except Exception:
            _logger.warning("binary_execution_failed", instance_id=instance.id)
            raise

        return (instance, report)

    async def _find_idle_instance(
        self,
        sandbox_type: SandboxType,
    ) -> SandboxInstance | None:
        """Find an idle instance of the specified type.

        Args:
            sandbox_type: Type of sandbox to find.

        Returns:
            Idle instance or None if not found.
        """
        return next(
            (
                instance
                for instance in self._instances.values()
                if instance.sandbox_type == sandbox_type and instance.state.status == "running"
            ),
            None,
        )

    async def _find_oldest_idle(self) -> SandboxInstance | None:
        """Find the oldest idle sandbox instance.

        Returns:
            Oldest idle instance or None if none idle.
        """
        oldest: SandboxInstance | None = None
        oldest_time: datetime | None = None

        for instance in self._instances.values():
            if instance.state.status == "running" and (oldest_time is None or instance.last_used < oldest_time):
                oldest = instance
                oldest_time = instance.last_used

        return oldest

    async def cleanup_stale(self, max_idle_seconds: int = 3600) -> int:
        """Clean up stale sandbox instances.

        Args:
            max_idle_seconds: Maximum idle time before cleanup.

        Returns:
            Number of instances cleaned up.
        """
        now = datetime.now()
        stale_ids: list[str] = []

        for instance_id, instance in self._instances.items():
            idle_seconds = (now - instance.last_used).total_seconds()
            if idle_seconds > max_idle_seconds:
                stale_ids.append(instance_id)

        for instance_id in stale_ids:
            try:
                await self.destroy(instance_id)
            except Exception as e:
                _logger.warning("stale_sandbox_cleanup_error", instance_id=instance_id, error=str(e))

        return len(stale_ids)

    async def get_status(self) -> dict[str, object]:
        """Get manager status summary.

        Returns:
            Status dictionary with instance information.
        """
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
