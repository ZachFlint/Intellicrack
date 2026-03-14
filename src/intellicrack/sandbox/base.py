# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Base sandbox protocol and types.

This module defines the base class for sandbox implementations
that provide isolated execution environments for binary analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, TypedDict


if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path

from ..core.logging import get_logger
from ..core.types import SandboxError, SandboxTimeoutError


__all__ = ["SandboxError", "SandboxTimeoutError"]


_logger = get_logger("sandbox.base")

_ERR_SANDBOX_NOT_IMPL = "Sandbox not implemented"
_ERR_SANDBOX_NOT_IMPL_DETAIL = "Use a concrete sandbox implementation like WindowsSandbox"
_ERR_EXEC_NOT_IMPL = "Sandbox execution not implemented"
_ERR_BINARY_EXEC_NOT_IMPL = "Binary execution not implemented"
_ERR_FILE_COPY_NOT_IMPL = "File copy not implemented"
_ERR_SNAPSHOTS_NOT_SUPPORTED = "Snapshots not supported by this sandbox type"

SandboxStatus = Literal["stopped", "starting", "running", "stopping", "error"]
ExecutionResult = Literal["success", "timeout", "error", "crashed"]

FileOperation = Literal["created", "modified", "deleted", "renamed"]
RegistryOperation = Literal["created", "modified", "deleted"]
ProcessOperation = Literal["created", "terminated"]


def validate_file_operation(op: str) -> FileOperation:
    """Validate and convert a string to a FileOperation.

    Args:
        op: The operation string to validate.

    Returns:
        A valid FileOperation literal.
    """
    op_lower = op.lower()
    if op_lower in {"created", "create", "add", "new"}:
        return "created"
    if op_lower in {"modified", "modify", "change", "update", "write"}:
        return "modified"
    if op_lower in {"deleted", "delete", "remove", "unlink"}:
        return "deleted"
    return "renamed" if op_lower in {"renamed", "rename", "move"} else "modified"


def validate_registry_operation(op: str) -> RegistryOperation:
    """Validate and convert a string to a RegistryOperation.

    Args:
        op: The operation string to validate.

    Returns:
        A valid RegistryOperation literal.
    """
    op_lower = op.lower()
    if op_lower in {"created", "create", "add", "new", "setvalue"}:
        return "created"
    if op_lower in {"modified", "modify", "change", "update", "write"}:
        return "modified"
    if op_lower in {"deleted", "delete", "remove", "deletevalue"}:
        return "deleted"
    return "modified"


def validate_process_operation(op: str) -> ProcessOperation:
    """Validate and convert a string to a ProcessOperation.

    Args:
        op: The operation string to validate.

    Returns:
        A valid ProcessOperation literal.
    """
    op_lower = op.lower()
    if op_lower in {"created", "create", "start", "spawn", "launched"}:
        return "created"
    if op_lower in {
        "terminated",
        "terminate",
        "exit",
        "stopped",
        "killed",
        "ended",
    }:
        return "terminated"
    return "created"


class FileChange(TypedDict):
    """Represents a file system change in the sandbox."""

    path: str
    operation: Literal["created", "modified", "deleted", "renamed"]
    old_path: str | None
    timestamp: str
    size: int | None


class RegistryChange(TypedDict):
    """Represents a registry change in the sandbox."""

    key: str
    value_name: str | None
    operation: Literal["created", "modified", "deleted"]
    value_type: str | None
    value_data: str | None
    timestamp: str


class NetworkActivity(TypedDict):
    """Represents network activity in the sandbox."""

    protocol: Literal["tcp", "udp", "icmp", "other"]
    direction: Literal["inbound", "outbound"]
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    timestamp: str
    bytes_sent: int
    bytes_received: int


class ProcessActivity(TypedDict):
    """Represents process activity in the sandbox."""

    pid: int
    name: str
    path: str | None
    command_line: str | None
    parent_pid: int | None
    operation: Literal["created", "terminated"]
    exit_code: int | None
    timestamp: str


@dataclass
class SandboxConfig:
    """Configuration for sandbox execution.

    Attributes:
        timeout_seconds: Maximum execution time.
        memory_limit_mb: Memory limit in megabytes.
        network_enabled: Whether network access is allowed.
        clipboard_enabled: Whether clipboard sharing is allowed.
        audio_enabled: Whether audio is enabled.
        video_enabled: Whether video/GPU is enabled.
        printer_enabled: Whether printing is allowed.
        shared_folders: Folders shared with the sandbox.
        startup_commands: Commands to run at startup.
        environment_variables: Environment variables to set.
    """

    timeout_seconds: int = 300
    memory_limit_mb: int = 2048
    network_enabled: bool = False
    clipboard_enabled: bool = False
    audio_enabled: bool = False
    video_enabled: bool = False
    printer_enabled: bool = False
    shared_folders: list[tuple[Path, str, bool]] = field(default_factory=list)
    startup_commands: list[str] = field(default_factory=list)
    environment_variables: dict[str, str] = field(default_factory=dict)


@dataclass
class SandboxState:
    """Current state of the sandbox.

    Attributes:
        status: Current sandbox status.
        started_at: When the sandbox was started.
        pid: Process ID of the sandbox.
        last_error: Last error message if any.
    """

    status: SandboxStatus = "stopped"
    started_at: datetime | None = None
    pid: int | None = None
    last_error: str | None = None


@dataclass
class ExecutionReport:
    """Report of a binary execution in the sandbox.

    Attributes:
        result: Execution result status.
        exit_code: Process exit code.
        stdout: Standard output.
        stderr: Standard error.
        duration_seconds: Execution duration.
        file_changes: File system changes detected.
        registry_changes: Registry changes detected.
        network_activity: Network activity detected.
        process_activity: Process activity detected.
    """

    result: ExecutionResult
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    file_changes: list[FileChange] = field(default_factory=list)
    registry_changes: list[RegistryChange] = field(default_factory=list)
    network_activity: list[NetworkActivity] = field(default_factory=list)
    process_activity: list[ProcessActivity] = field(default_factory=list)


class SandboxBase:
    """Base class for sandbox implementations.

    Provides common functionality for all sandbox types.
    Subclasses should override methods to provide actual sandbox functionality.

    Attributes:
        _config: Sandbox configuration.
        _state: Current sandbox state.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialize the sandbox.

        Args:
            config: Optional sandbox configuration.
        """
        self._config = config or SandboxConfig()
        self._state = SandboxState()

    @property
    def state(self) -> SandboxState:
        """Get current sandbox state.

        Returns:
            Current SandboxState.
        """
        return self._state

    @property
    def config(self) -> SandboxConfig:
        """Get sandbox configuration.

        Returns:
            Current SandboxConfig.
        """
        return self._config

    @property
    def vnc_port(self) -> int | None:
        """Get the VNC port if available.

        Returns:
            VNC port number, or None if not supported.
        """
        return None

    async def is_available(self) -> bool:
        """Check if this sandbox type is available.

        Returns:
            True if sandbox can be used.
        """
        _logger.debug("base_sandbox_is_available_called", class_name=type(self).__name__)
        return False

    async def start(self) -> None:
        """Start the sandbox environment.

        Raises:
            SandboxError: If sandbox cannot be started.
        """
        _logger.debug("base_sandbox_start_called", class_name=type(self).__name__)
        raise SandboxError(
            _ERR_SANDBOX_NOT_IMPL,
            _ERR_SANDBOX_NOT_IMPL_DETAIL,
        )

    async def stop(self) -> None:
        """Stop the sandbox environment.

        Raises:
            SandboxError: If sandbox cannot be stopped.
        """
        if self._state.status == "stopped":
            _logger.debug("sandbox_already_stopped", sandbox_type="base")
            return

        raise SandboxError(
            _ERR_SANDBOX_NOT_IMPL,
            _ERR_SANDBOX_NOT_IMPL_DETAIL,
        )

    async def restart(self) -> None:
        """Restart the sandbox environment."""
        await self.stop()
        await self.start()

    async def run_command(
        self,
        command: str,
        timeout: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """Execute a command in the sandbox.

        Args:
            command: Command to execute.
            timeout: Optional timeout override.
            working_directory: Optional working directory.

        Note:
            Subclasses must override to return tuple of (exit_code, stdout, stderr).

        Raises:
            SandboxError: If execution fails.
        """
        _logger.debug(
            "base_sandbox_execute_called",
            class_name=type(self).__name__,
            command=command,
        )
        del timeout, working_directory
        raise SandboxError(
            _ERR_EXEC_NOT_IMPL,
            _ERR_SANDBOX_NOT_IMPL_DETAIL,
        )

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        timeout: int | None = None,
        monitor: bool = True,
    ) -> ExecutionReport:
        """Run a binary in the sandbox with monitoring.

        Args:
            binary_path: Path to the binary to run.
            args: Optional command line arguments.
            timeout: Optional timeout override.
            monitor: Whether to monitor behavior.

        Note:
            Subclasses must override to return ExecutionReport with results and activity.

        Raises:
            SandboxError: If execution fails.
        """
        _logger.debug(
            "base_sandbox_run_binary_called",
            class_name=type(self).__name__,
            binary_path=str(binary_path),
        )
        del args, timeout, monitor
        raise SandboxError(
            _ERR_BINARY_EXEC_NOT_IMPL,
            _ERR_SANDBOX_NOT_IMPL_DETAIL,
        )

    async def copy_to_sandbox(self, source: Path, dest: str) -> None:
        """Copy a file into the sandbox.

        Args:
            source: Local source path.
            dest: Destination path in sandbox.

        Raises:
            SandboxError: If copy fails.
        """
        _logger.debug(
            "base_sandbox_copy_to_sandbox_called",
            class_name=type(self).__name__,
            source=str(source),
            dest=dest,
        )
        raise SandboxError(
            _ERR_FILE_COPY_NOT_IMPL,
            _ERR_SANDBOX_NOT_IMPL_DETAIL,
        )

    async def copy_from_sandbox(self, source: str, dest: Path) -> None:
        """Copy a file from the sandbox.

        Args:
            source: Source path in sandbox.
            dest: Local destination path.

        Raises:
            SandboxError: If copy fails.
        """
        _logger.debug(
            "base_sandbox_copy_from_sandbox_called",
            class_name=type(self).__name__,
            source=source,
            dest=str(dest),
        )
        raise SandboxError(
            _ERR_FILE_COPY_NOT_IMPL,
            _ERR_SANDBOX_NOT_IMPL_DETAIL,
        )

    async def take_snapshot(self, name: str) -> str:
        """Take a snapshot of the sandbox state.

        Args:
            name: Snapshot name.

        Note:
            Subclasses must override to return the snapshot identifier.

        Raises:
            SandboxError: If not supported.
        """
        _logger.debug(
            "base_sandbox_take_snapshot_called",
            class_name=type(self).__name__,
            snapshot_name=name,
        )
        raise SandboxError(_ERR_SNAPSHOTS_NOT_SUPPORTED)

    async def restore_snapshot(self, snapshot_id: str) -> None:
        """Restore a sandbox snapshot.

        Args:
            snapshot_id: Snapshot identifier.

        Raises:
            SandboxError: If not supported.
        """
        _logger.debug(
            "base_sandbox_restore_snapshot_called",
            class_name=type(self).__name__,
            snapshot_id=snapshot_id,
        )
        raise SandboxError(_ERR_SNAPSHOTS_NOT_SUPPORTED)

    async def list_snapshots(self) -> list[str]:
        """List available snapshots.

        Raises:
            SandboxError: If not supported.
        """
        _logger.debug(
            "base_sandbox_list_snapshots_called",
            class_name=type(self).__name__,
        )
        raise SandboxError(_ERR_SNAPSHOTS_NOT_SUPPORTED)

    async def delete_snapshot(self, name: str) -> None:
        """Delete a snapshot.

        Args:
            name: Snapshot name to delete.

        Raises:
            SandboxError: If not supported.
        """
        _logger.debug(
            "base_sandbox_delete_snapshot_called",
            class_name=type(self).__name__,
            snapshot_name=name,
        )
        raise SandboxError(_ERR_SNAPSHOTS_NOT_SUPPORTED)
