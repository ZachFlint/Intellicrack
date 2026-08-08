# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Base sandbox protocol and types.

This module defines the base class for sandbox implementations that provide isolated execution environments for binary analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, TypedDict

from intellicrack.core.logging import get_logger
from intellicrack.core.types import SandboxError, SandboxTimeoutError


if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path


__all__ = ["SandboxError", "SandboxTimeoutError"]


_logger = get_logger(__name__)

_ERR_SANDBOX_NOT_IMPL = "Sandbox not implemented"
_ERR_SANDBOX_NOT_IMPL_DETAIL = "Use a concrete sandbox implementation like WindowsSandbox"
_ERR_EXEC_NOT_IMPL = "Sandbox execution not implemented"
_ERR_BINARY_EXEC_NOT_IMPL = "Binary execution not implemented"
_ERR_FILE_COPY_NOT_IMPL = "File copy not implemented"
_ERR_SNAPSHOTS_NOT_SUPPORTED = "Snapshots not supported by this sandbox type"
_ERR_PCAP_NOT_IMPL = "Packet capture not implemented"
_ERR_SCREENSHOT_NOT_IMPL = "Screenshot capture not implemented"
_ERR_ANTI_EVASION_NOT_IMPL = "Anti-evasion not implemented"
_ERR_MEMORY_DUMP_NOT_IMPL = "Memory dump not implemented"
_ERR_EXTRACT_FILES_NOT_IMPL = "Dropped file extraction not implemented"
_ERR_YARA_SCAN_NOT_IMPL = "YARA scan not implemented"

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
        FileOperation: A valid FileOperation literal.
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
        RegistryOperation: A valid RegistryOperation literal.
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
        ProcessOperation: A valid ProcessOperation literal.
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


class ApiCall(TypedDict):
    """Represents a captured API call in the sandbox."""

    timestamp: str
    process_name: str
    pid: int
    api_name: str
    module: str
    arguments: list[str]
    return_value: str


class ServiceChange(TypedDict):
    """Represents a Windows service change in the sandbox."""

    service_name: str
    display_name: str
    binary_path: str
    start_type: str
    operation: str
    timestamp: str


class KernelObjectActivity(TypedDict):
    """Represents kernel object activity in the sandbox."""

    object_type: str
    name: str
    pid: int
    process_name: str
    operation: str
    timestamp: str


class DllLoadEvent(TypedDict):
    """Represents a DLL load event in the sandbox.

    The trailing ``event_id`` and ``payload_schema`` fields are populated by the F-0019 dll_monitor.ps1 image-load handler. For parsed
    image-load events ``dll_path`` is non-empty, ``event_id`` carries the ETW event ID, and ``payload_schema`` is empty. For F-0019 unparsed
    records ``dll_path`` is empty and ``payload_schema`` carries the observed payload field names, so the report consumer can still see the
    dropped event and the host can tune its heuristics.
    """

    timestamp: str
    pid: int
    process_name: str
    dll_path: str
    base_address: str
    size: int
    event_id: int
    payload_schema: str


class InjectionEvent(TypedDict):
    """Represents a process injection event detected in the sandbox."""

    timestamp: str
    source_pid: int
    source_name: str
    target_pid: int
    target_name: str
    injection_type: str
    api_calls: list[str]


class ResourceSample(TypedDict):
    """Represents a resource usage sample from the sandbox."""

    timestamp: str
    cpu_percent: float
    memory_mb: float
    disk_read_bytes: int
    disk_write_bytes: int
    net_sent_bytes: int
    net_recv_bytes: int


class ClipboardEvent(TypedDict):
    """Represents clipboard activity in the sandbox."""

    timestamp: str
    operation: str
    format: str
    content_preview: str
    size_bytes: int
    pid: int
    process_name: str


class CollectorOutage(TypedDict):
    """Represents a monitoring collector that did not observe for the full run.

    A recorder that never reported starting, or that reported stopping while
    the sandboxed process was still being monitored, produced no trustworthy
    observations for its report section. Surfacing that distinctly lets a
    report consumer tell "the sample made no calls this collector watches
    for" apart from "this collector never watched", which a collector's own
    data log cannot express on its own.
    """

    collector: str
    reason: str
    exit_code: int | None


class IOCEntry(TypedDict):
    """Represents an Indicator of Compromise extracted from sandbox analysis."""

    ioc_type: str
    value: str
    source: str
    context: str
    timestamp: str


class TimelineEvent(TypedDict):
    """Represents a unified timeline event from sandbox execution."""

    timestamp: str
    category: str
    summary: str
    details: dict[str, str]


class BehaviorMatch(TypedDict):
    """Represents a behavioral signature match from sandbox analysis."""

    signature_name: str
    category: str
    severity: str
    description: str
    evidence: list[str]
    mitre_attack_id: str


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
        result: Outcome of the execution.
        exit_code: Process exit code.
        stdout: Standard output captured from the binary.
        stderr: Standard error captured from the binary.
        duration_seconds: Total execution duration in seconds.
        file_changes: File system changes detected.
        registry_changes: Registry changes detected.
        network_activity: Network activity detected.
        process_activity: Process activity detected.
        api_calls: API calls captured during execution.
        service_changes: Windows service changes detected.
        kernel_objects: Kernel object activity detected.
        dll_loads: DLL load events detected.
        injection_events: Process injection events detected.
        resource_samples: Resource usage samples collected.
        clipboard_events: Clipboard activity detected.
        collector_outages: Monitoring collectors that did not observe for
            the full run - never started, or stopped early - so the
            corresponding report section(s) should be shown as unavailable
            rather than as a record of what the sample did.
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
    api_calls: list[ApiCall] = field(default_factory=list)
    service_changes: list[ServiceChange] = field(default_factory=list)
    kernel_objects: list[KernelObjectActivity] = field(default_factory=list)
    dll_loads: list[DllLoadEvent] = field(default_factory=list)
    injection_events: list[InjectionEvent] = field(default_factory=list)
    resource_samples: list[ResourceSample] = field(default_factory=list)
    clipboard_events: list[ClipboardEvent] = field(default_factory=list)
    collector_outages: list[CollectorOutage] = field(default_factory=list)


class SandboxBase:
    """Base class for sandbox implementations.

    Provides common functionality for all sandbox types. Subclasses should override methods to provide actual sandbox functionality.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialize the SandboxBase with optional configuration.

        Args:
            config: Optional sandbox configuration.
        """
        self._config = config or SandboxConfig()
        self._state = SandboxState()

    @property
    def state(self) -> SandboxState:
        """Current sandbox state.

        Returns:
            SandboxState: Current SandboxState.
        """
        return self._state

    @property
    def config(self) -> SandboxConfig:
        """Sandbox configuration this instance was built with.

        Returns:
            SandboxConfig: Current SandboxConfig.
        """
        return self._config

    @property
    def vnc_port(self) -> int | None:
        """VNC port this backend exposes, if it exposes one at all.

        Returns:
            int | None: VNC port number, or None if not supported.
        """
        return None

    async def is_available(self) -> bool:
        """Check if this sandbox type is available.

        Returns:
            bool: True if sandbox can be used.
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
        time_limit: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """Execute a command in the sandbox.

        Args:
            command: Command to execute.
            time_limit: Optional timeout override in seconds.
            working_directory: Optional working directory.

        Returns:
            tuple[int, str, str]: Tuple of (exit_code, stdout, stderr) from the command execution.

        Raises:
            SandboxError: If execution fails.
        """
        _logger.debug(
            "base_sandbox_execute_called",
            class_name=type(self).__name__,
            command=command,
        )
        del time_limit, working_directory
        raise SandboxError(
            _ERR_EXEC_NOT_IMPL,
            _ERR_SANDBOX_NOT_IMPL_DETAIL,
        )

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        time_limit: int | None = None,
        *,
        monitor: bool = True,
    ) -> ExecutionReport:
        """Run a binary in the sandbox with monitoring.

        Args:
            binary_path: Path to the binary to run.
            args: Optional command line arguments.
            time_limit: Optional timeout override in seconds.
            monitor: Whether to monitor behavior.

        Returns:
            ExecutionReport: Execution report with results, behavioral artifacts, and resource samples.

        Raises:
            SandboxError: If execution fails.
        """
        _logger.debug(
            "base_sandbox_run_binary_called",
            class_name=type(self).__name__,
            binary_path=str(binary_path),
        )
        del args, time_limit, monitor
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

        Returns:
            str: Identifier of the created snapshot.

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

        Returns:
            list[str]: List of snapshot identifiers known to the sandbox.

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
        _logger.info(
            "base_sandbox_delete_snapshot_called",
            class_name=type(self).__name__,
            snapshot_name=name,
        )
        raise SandboxError(_ERR_SNAPSHOTS_NOT_SUPPORTED)

    async def start_pcap_capture(self) -> str:
        """Start packet capture on the sandbox network.

        Returns:
            str: Identifier for the active capture session, used by stop_pcap_capture.

        Raises:
            SandboxError: If capture cannot be started.
        """
        _logger.debug("base_sandbox_start_pcap_called", class_name=type(self).__name__)
        raise SandboxError(_ERR_PCAP_NOT_IMPL)

    async def stop_pcap_capture(
        self,
        capture_id: str,
        output_path: Path | None = None,
    ) -> Path:
        """Stop packet capture and retrieve the PCAP file.

        Args:
            capture_id: Capture identifier from start_pcap_capture.
            output_path: Optional path to save the PCAP file.

        Returns:
            Path: Filesystem path to the saved PCAP file on the host.

        Raises:
            SandboxError: If capture cannot be stopped.
        """
        _logger.debug("base_sandbox_stop_pcap_called", class_name=type(self).__name__)
        del capture_id, output_path
        raise SandboxError(_ERR_PCAP_NOT_IMPL)

    async def capture_screenshot(
        self,
        output_path: Path | None = None,
    ) -> Path:
        """Capture a screenshot of the sandbox display.

        Args:
            output_path: Optional path to save the screenshot.

        Returns:
            Path: Filesystem path to the screenshot image on the host.

        Raises:
            SandboxError: If screenshot cannot be captured.
        """
        _logger.debug("base_sandbox_capture_screenshot_called", class_name=type(self).__name__)
        del output_path
        raise SandboxError(_ERR_SCREENSHOT_NOT_IMPL)

    async def apply_anti_evasion(
        self,
        profile: str = "default",
    ) -> dict[str, Any]:
        """Apply anti-evasion techniques to make the sandbox less detectable.

        Args:
            profile: Anti-evasion profile name.

        Returns:
            dict[str, Any]: Mapping of evasion technique name to whether it was successfully applied.

        Raises:
            SandboxError: If anti-evasion cannot be applied.
        """
        _logger.debug("base_sandbox_apply_anti_evasion_called", class_name=type(self).__name__)
        del profile
        raise SandboxError(_ERR_ANTI_EVASION_NOT_IMPL)

    async def dump_memory(
        self,
        output_path: Path | None = None,
        target_pid: int | None = None,
    ) -> Path:
        """Dump guest memory to a file.

        Args:
            output_path: Optional path to save the memory dump.
            target_pid: Guest-side PID of the process to dump. Concrete
                sandbox types that target individual processes (Windows
                Sandbox via ``MiniDumpWriteDump``) require this argument;
                whole-VM dumpers (QEMU) may ignore it.

        Returns:
            Path: Filesystem path to the memory dump file on the host.

        Raises:
            SandboxError: If memory dump fails.
        """
        _logger.debug("base_sandbox_dump_memory_called", class_name=type(self).__name__)
        del output_path, target_pid
        raise SandboxError(_ERR_MEMORY_DUMP_NOT_IMPL)

    async def extract_dropped_files(
        self,
        output_path: Path | None = None,
    ) -> Path:
        """Extract files created by the binary during execution.

        Args:
            output_path: Optional path to save the ZIP archive.

        Returns:
            Path: Filesystem path to the ZIP archive containing dropped files.

        Raises:
            SandboxError: If extraction fails.
        """
        _logger.info("base_sandbox_extract_dropped_files_called", class_name=type(self).__name__)
        del output_path
        raise SandboxError(_ERR_EXTRACT_FILES_NOT_IMPL)

    async def yara_scan(
        self,
        rules_path: str | None = None,
        scan_target: str = "files",
    ) -> list[dict[str, Any]]:
        """Run YARA rules against sandbox artifacts.

        Args:
            rules_path: Path to YARA rules file. Uses built-in rules if None.
            scan_target: What to scan - 'files' for dropped files, 'memory' for memory dump.

        Returns:
            list[dict[str, Any]]: List of YARA match dictionaries describing rule hits and matched strings.

        Raises:
            SandboxError: If scan fails.
        """
        _logger.debug("base_sandbox_yara_scan_called", class_name=type(self).__name__)
        del rules_path, scan_target
        raise SandboxError(_ERR_YARA_SCAN_NOT_IMPL)
