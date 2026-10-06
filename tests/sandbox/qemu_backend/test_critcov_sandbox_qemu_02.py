# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Coverage for the QEMU sandbox's launch, shutdown, cleanup, file-transfer and snapshot paths.

QEMU is not installed in the test container and no virtual machine is started. What can be reached
honestly is reached with real objects: the command line the backend builds, the process model around a
real child process that stands in for the launcher, the guest-agent file and command primitives against
the real loopback ``GuestAgentProtocolServer`` that models a guest, the temp-tree teardown against real
files and a real locked file, and the monitor-protocol bookkeeping driven through subclasses of the
production ``QMPClient`` and ``QemuGuestAgentClient`` that answer from a script instead of a socket.
Every sandbox here is a subclass of the production ``QEMUSandbox`` that only exposes protected state.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import re
import shutil
import sys
import winreg
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal

import pytest
import structlog.testing

from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.sandbox.base import SandboxConfig, SandboxError, SandboxTimeoutError
from intellicrack.sandbox.qemu import (
    MONITOR_SCRIPT_NAMES,
    GuestAgentClient,
    GuestOS,
    QEMUConfig,
    QemuGuestAgentClient,
    QemuOutputRecorder,
    QEMUSandbox,
    QMPClient,
    QMPResponse,
)
from tests._helpers.polling import wait_until
from tests.sandbox.qemu.guest_agent_server import GuestAgentProtocolServer, GuestCommandResult


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable, Generator, Mapping, Sequence

    from structlog.typing import EventDict

    from intellicrack.sandbox.base import SandboxStatus
    from intellicrack.sandbox.qemu import QemuTermination


_UNUSED_PORT: Final[int] = 9
_CONNECT_BUDGET_S: Final[float] = 10.0
_EXIT_BUDGET_S: Final[float] = 20.0
_POLL_INTERVAL_S: Final[float] = 0.05
_IDLE_CHILD: Final[str] = "import time; time.sleep(600)"
_ABSENT_BUNDLE_ROOT: Final[Path] = Path(__file__).resolve().parent / "absent-agent-bundle"
_WORK_ROOT: Final[str] = "C:\\intellicrack"
_BLOCK_MARKER: Final[str] = "INTELLICRACK_TELEMETRY_BLOCK"
_BLOCK_RECORD: Final[str] = f"{_BLOCK_MARKER}|31|2|netsecurity|C:\\Windows\\System32\\drivers\\etc\\hosts|\r\n"
_SESSION_MANAGER_KEY: Final[str] = r"SYSTEM\CurrentControlSet\Control\Session Manager"
_PENDING_RENAMES_VALUE: Final[str] = "PendingFileRenameOperations"
_MIB: Final[int] = 1024 * 1024
_DISPLAY_PORT_FIRST: Final[int] = 5900
_DISPLAY_PORT_LAST: Final[int] = 5999
_READ_LIMIT_BYTES: Final[int] = 64 * _MIB
_REMOVE_ATTEMPTS: Final[int] = 10
_QUIET_SUCCESS: Final[GuestCommandResult] = GuestCommandResult(exit_code=0, stdout="", stderr="")


@dataclass(frozen=True)
class _CannedGuest:
    """Guest model answering each ``guest-exec`` by matching a fragment of its command line.

    Attributes:
        rules: Pairs of a command-line fragment and the outcome returned when it appears.
        fallback: Outcome returned when no fragment matches.
    """

    rules: tuple[tuple[str, GuestCommandResult], ...] = ()
    fallback: GuestCommandResult = _QUIET_SUCCESS

    def __call__(self, path: str, args: Sequence[str]) -> GuestCommandResult:
        """Return the outcome of running ``path`` with ``args`` inside the modelled guest.

        Args:
            path: Executable the host asked the guest to run.
            args: Argument list passed with it.

        Returns:
            GuestCommandResult: The first matching rule's outcome, or the fallback.
        """
        line = " ".join([path, *args])
        for fragment, result in self.rules:
            if fragment in line:
                return result
        return self.fallback


class _ReplyScript:
    """Per-command reply queues shared by the scripted channel clients.

    The last reply queued for a command repeats for every later request of it.

    Attributes:
        sent: Every command the client was asked to send, in order.
    """

    sent: list[dict[str, object]]

    def __init__(self, replies: Mapping[str, Sequence[QMPResponse]]) -> None:
        """Queue the replies.

        Args:
            replies: Replies to hand back, keyed by the command's ``execute`` name.
        """
        self.sent = []
        self._queues: dict[str, deque[QMPResponse]] = {name: deque(items) for name, items in replies.items()}

    def next_reply(self, command: dict[str, object]) -> QMPResponse:
        """Record ``command`` and return the reply scripted for it.

        Args:
            command: Command dictionary the client was asked to send.

        Returns:
            QMPResponse: The next scripted reply for the command's name.
        """
        self.sent.append(command)
        queue = self._queues[str(command["execute"])]
        return queue.popleft() if len(queue) > 1 else queue[0]

    def names(self) -> list[str]:
        """Return the ``execute`` name of every command sent so far.

        Returns:
            list[str]: Command names in the order they were sent.
        """
        return [str(command["execute"]) for command in self.sent]


class _ScriptedMonitor(QMPClient):
    """Real ``QMPClient`` whose commands are answered from a script instead of a socket."""

    def __init__(self, replies: Mapping[str, Sequence[QMPResponse]]) -> None:
        """Mark the client connected and queue its replies.

        Args:
            replies: Replies to hand back, keyed by the command's ``execute`` name.
        """
        super().__init__(port=_UNUSED_PORT)
        self.script = _ReplyScript(replies)
        self.connected = True

    async def _send_command(self, command: dict[str, object], time_limit: float = 10.0) -> QMPResponse:
        """Answer one command from the script.

        Args:
            command: Command dictionary the sandbox asked to send.
            time_limit: Ignored; nothing is awaited.

        Returns:
            QMPResponse: The scripted reply.
        """
        del time_limit
        await asyncio.sleep(0)
        return self.script.next_reply(command)


class _ScriptedAgentChannel(QemuGuestAgentClient):
    """Real ``QemuGuestAgentClient`` whose commands are answered from a script instead of a socket."""

    def __init__(self, replies: Mapping[str, Sequence[QMPResponse]]) -> None:
        """Mark the client connected and queue its replies.

        Args:
            replies: Replies to hand back, keyed by the command's ``execute`` name.
        """
        super().__init__(port=_UNUSED_PORT)
        self.script = _ReplyScript(replies)
        self.connected = True

    async def _send_command(self, command: dict[str, object], time_limit: float = 10.0) -> QMPResponse:
        """Answer one command from the script.

        Args:
            command: Command dictionary the sandbox asked to send.
            time_limit: Ignored; nothing is awaited.

        Returns:
            QMPResponse: The scripted reply.
        """
        del time_limit
        await asyncio.sleep(0)
        return self.script.next_reply(command)


class _RefusingAgent(GuestAgentClient):
    """Real ``GuestAgentClient`` whose socket close fails outright."""

    async def disconnect(self) -> None:
        """Fail the way a broken transport does.

        Raises:
            OSError: Always.
        """
        await asyncio.sleep(0)
        message = "disconnect refused by the transport"
        raise OSError(message)


class _StateProbe(QEMUSandbox):
    """``QEMUSandbox`` whose protected state and launch, shutdown and log helpers are reachable from tests.

    Nothing here replaces behavior. Each wrapper forwards to the production member of the same name, and
    the setters assign the plain data attributes a started sandbox would hold.
    """

    def set_qemu_path(self, path: Path | None) -> None:
        """Set the resolved QEMU executable path.

        Args:
            path: Path to record, or None.
        """
        self._qemu_path = path

    def set_temp_dir(self, path: Path | None) -> None:
        """Set the instance's temporary directory.

        Args:
            path: Directory to record, or None.
        """
        self._temp_dir = path

    def set_shared_folder(self, path: Path | None) -> None:
        """Set the host-side shared folder.

        Args:
            path: Folder to record, or None.
        """
        self._shared_folder = path

    def set_qga(self, client: QemuGuestAgentClient | None) -> None:
        """Set the qemu-guest-agent channel client.

        Args:
            client: Client to attach, or None.
        """
        self._qga = client

    def set_qmp(self, client: QMPClient | None) -> None:
        """Set the QMP monitor client.

        Args:
            client: Client to attach, or None.
        """
        self._qmp = client

    def set_agent(self, client: GuestAgentClient | None) -> None:
        """Set the in-guest monitor agent client.

        Args:
            client: Client to attach, or None.
        """
        self._agent = client

    def set_process(self, process: asyncio.subprocess.Process | None) -> None:
        """Set the foreground QEMU child.

        Args:
            process: Process to record, or None.
        """
        self.process = process

    def set_recorder(self, recorder: QemuOutputRecorder | None) -> None:
        """Set the QEMU output recorder.

        Args:
            recorder: Recorder to attach, or None.
        """
        self._output_recorder = recorder

    def set_qemu_pid(self, pid: int | None) -> None:
        """Set the recorded QEMU process id.

        Args:
            pid: Process id to record, or None.
        """
        self._qemu_pid = pid

    def set_vnc_port(self, port: int | None) -> None:
        """Set the recorded VNC port.

        Args:
            port: Port to record, or None.
        """
        self._vnc_port = port

    def set_qemu_config(self, config: QEMUConfig) -> None:
        """Replace the QEMU configuration.

        Args:
            config: Configuration to install.
        """
        self._qemu_config = config

    def temp_dir(self) -> Path | None:
        """Return the instance's temporary directory.

        Returns:
            Path | None: The recorded directory.
        """
        return self._temp_dir

    def recorder(self) -> QemuOutputRecorder | None:
        """Return the attached output recorder.

        Returns:
            QemuOutputRecorder | None: The recorder, or None.
        """
        return self._output_recorder

    def recorded_pid(self) -> int | None:
        """Return the recorded QEMU process id.

        Returns:
            int | None: The recorded id.
        """
        return self._qemu_pid

    def claimed_ports(self) -> set[int]:
        """Return the host ports this sandbox allocated.

        Returns:
            set[int]: Copy of the claimed-port set.
        """
        return set(self._claimed_host_ports)

    @staticmethod
    def reserved_ports() -> set[int]:
        """Return every host port currently reserved process-wide.

        Returns:
            set[int]: Copy of the process-wide reservation set.
        """
        return set(QEMUSandbox._reserved_host_ports)

    def allocate_port(self) -> int:
        """Forward to :meth:`QEMUSandbox._allocate_host_port`.

        Returns:
            int: The claimed port.
        """
        return self._allocate_host_port()

    def get_free_port(self) -> int:
        """Forward to :meth:`QEMUSandbox._get_free_port` over the VNC range.

        Returns:
            int: The claimed port.
        """
        return self._get_free_port(_DISPLAY_PORT_FIRST, _DISPLAY_PORT_LAST)

    def release_ports(self) -> None:
        """Forward to :meth:`QEMUSandbox._release_claimed_host_ports`."""
        self._release_claimed_host_ports()

    async def build_command(self, disk_path: Path | None = None) -> list[str]:
        """Forward to :meth:`QEMUSandbox._build_qemu_command`.

        Args:
            disk_path: Disk image to attach, or None for the configured one.

        Returns:
            list[str]: The assembled argv.
        """
        return await self._build_qemu_command(disk_path)

    @staticmethod
    def ensure_started(qemu_pid: int | None) -> None:
        """Forward to :meth:`QEMUSandbox._ensure_qemu_started`.

        Args:
            qemu_pid: Process id, or None when startup failed.
        """
        QEMUSandbox._ensure_qemu_started(qemu_pid)

    async def spawn(self) -> None:
        """Forward to :meth:`QEMUSandbox._spawn_qemu_process`."""
        await self._spawn_qemu_process()

    async def register_pid(self, qemu_pid: int | None) -> int:
        """Forward to :meth:`QEMUSandbox._register_qemu_pid`.

        Args:
            qemu_pid: Process id to verify and register.

        Returns:
            int: The verified process id.
        """
        return await self._register_qemu_pid(qemu_pid)

    async def apply_telemetry(self) -> None:
        """Forward to :meth:`QEMUSandbox._apply_telemetry_blocking`."""
        await self._apply_telemetry_blocking()

    async def request_agent_shutdown(self) -> bool:
        """Forward to :meth:`QEMUSandbox._request_agent_shutdown`.

        Returns:
            bool: Whether the request was written.
        """
        return await self._request_agent_shutdown()

    async def request_acpi_powerdown(self) -> bool:
        """Forward to :meth:`QEMUSandbox._request_acpi_powerdown`.

        Returns:
            bool: Whether QEMU accepted the request.
        """
        return await self._request_acpi_powerdown()

    async def await_exit(self, time_limit: float) -> bool:
        """Forward to :meth:`QEMUSandbox._await_qemu_exit`.

        Args:
            time_limit: Seconds to wait.

        Returns:
            bool: Whether QEMU is no longer running.
        """
        return await self._await_qemu_exit(time_limit)

    async def shut_down(self) -> bool:
        """Forward to :meth:`QEMUSandbox._shut_down_guest`.

        Returns:
            bool: Whether QEMU is no longer running.
        """
        return await self._shut_down_guest()

    async def cleanup(self) -> None:
        """Forward to :meth:`QEMUSandbox._cleanup`."""
        await self._cleanup()

    @classmethod
    def schedule_tree(cls, temp_dir: Path) -> bool:
        """Forward to :meth:`QEMUSandbox._schedule_temp_tree_delete_on_reboot`.

        Args:
            temp_dir: Directory to schedule.

        Returns:
            bool: Whether the root directory was scheduled.
        """
        return cls._schedule_temp_tree_delete_on_reboot(temp_dir)

    @classmethod
    async def remove_tree(cls, temp_dir: Path) -> None:
        """Forward to :meth:`QEMUSandbox._remove_temp_tree`.

        Args:
            temp_dir: Directory to remove.
        """
        await cls._remove_temp_tree(temp_dir)

    async def create_script(self) -> None:
        """Forward to :meth:`QEMUSandbox._create_guest_agent_script`."""
        await self._create_guest_agent_script()

    @staticmethod
    async def poll_for_result(
        *,
        result_path: Path,
        time_limit: int,
        vm_terminated: Callable[[], QemuTermination | None] | None = None,
    ) -> tuple[int, str, str]:
        """Forward to :meth:`QEMUSandbox._poll_for_result`.

        Args:
            result_path: Path of the expected result file.
            time_limit: Seconds to wait.
            vm_terminated: Probe answering whether QEMU has stopped.

        Returns:
            tuple[int, str, str]: Exit code, stdout and stderr.
        """
        return await QEMUSandbox._poll_for_result(result_path=result_path, time_limit=time_limit, vm_terminated=vm_terminated)

    @staticmethod
    async def read_sidecar(path: Path | None) -> str:
        """Forward to :meth:`QEMUSandbox._read_sidecar`.

        Args:
            path: Sidecar file, or None.

        Returns:
            str: The decoded contents, or an empty string.
        """
        return await QEMUSandbox._read_sidecar(path)

    @staticmethod
    async def cleanup_artifacts(
        *,
        result_path: Path,
        stdout_path: Path | None,
        stderr_path: Path | None,
        script_path: Path | None,
    ) -> None:
        """Forward to :meth:`QEMUSandbox._cleanup_result_artifacts`.

        Args:
            result_path: Result file.
            stdout_path: Stdout sidecar, or None.
            stderr_path: Stderr sidecar, or None.
            script_path: Generated script, or None.
        """
        await QEMUSandbox._cleanup_result_artifacts(
            result_path=result_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            script_path=script_path,
        )

    async def collect_logs(self) -> None:
        """Forward to :meth:`QEMUSandbox._collect_guest_logs`."""
        await self._collect_guest_logs()

    async def collect_output(self) -> int:
        """Forward to :meth:`QEMUSandbox._collect_guest_output`.

        Returns:
            int: Number of files brought across.
        """
        return await self._collect_guest_output()

    async def mirror_output(self) -> int:
        """Forward to :meth:`QEMUSandbox._mirror_output_to_configured_folder`.

        Returns:
            int: Number of files copied.
        """
        return await self._mirror_output_to_configured_folder()

    async def wait_logs_stable(self) -> None:
        """Forward to :meth:`QEMUSandbox._wait_for_logs_stable` with its defaults."""
        await self._wait_for_logs_stable()

    async def guest_log_sizes(self) -> dict[str, int]:
        """Forward to :meth:`QEMUSandbox._guest_log_sizes`.

        Returns:
            dict[str, int]: Log file name to size in bytes.
        """
        return await self._guest_log_sizes()


class _Probe(_StateProbe):
    """State probe extended with the guest-file, snapshot and monitor-bookkeeping helpers."""

    async def open_file(self, path: str) -> int:
        """Forward to :meth:`QEMUSandbox._open_guest_file`.

        Args:
            path: In-guest path to create.

        Returns:
            int: The agent's handle.
        """
        return await self._open_guest_file(path)

    async def write_chunk(self, handle: int, chunk: bytes, path: str) -> None:
        """Forward to :meth:`QEMUSandbox._write_guest_file_chunk`.

        Args:
            handle: Agent handle.
            chunk: Bytes to append.
            path: In-guest path for messages.
        """
        await self._write_guest_file_chunk(handle, chunk, path)

    async def open_read(self, path: str) -> int:
        """Forward to :meth:`QEMUSandbox._open_guest_file_for_read`.

        Args:
            path: In-guest path to open.

        Returns:
            int: The agent's handle.
        """
        return await self._open_guest_file_for_read(path)

    async def read_chunk(self, handle: int, path: str) -> tuple[bytes, bool]:
        """Forward to :meth:`QEMUSandbox._read_guest_file_chunk`.

        Args:
            handle: Agent handle.
            path: In-guest path for messages.

        Returns:
            tuple[bytes, bool]: The bytes read and whether the file ended.
        """
        return await self._read_guest_file_chunk(handle, path)

    async def read_file(self, guest_path: str) -> bytes:
        """Forward to :meth:`QEMUSandbox._read_guest_file`.

        Args:
            guest_path: In-guest path to read.

        Returns:
            bytes: The file's contents.
        """
        return await self._read_guest_file(guest_path)

    async def close_file(self, handle: int) -> None:
        """Forward to :meth:`QEMUSandbox._close_guest_file`.

        Args:
            handle: Agent handle.
        """
        await self._close_guest_file(handle)

    async def stage_file(self, source: Path, dest: str) -> None:
        """Forward to :meth:`QEMUSandbox._stage_file_in_guest`.

        Args:
            source: Host file to write into the guest.
            dest: Destination relative to the guest work root.
        """
        await self._stage_file_in_guest(source, dest)

    async def ensure_dir(self, guest_dir: str) -> None:
        """Forward to :meth:`QEMUSandbox._ensure_guest_directory`.

        Args:
            guest_dir: In-guest directory to create.
        """
        await self._ensure_guest_directory(guest_dir)

    async def query_devices(self) -> list[dict[str, object]]:
        """Forward to :meth:`QEMUSandbox._query_guest_block_devices`.

        Returns:
            list[dict[str, object]]: One inserted-medium record per device with media.
        """
        return await self._query_guest_block_devices()

    async def target_devices(self) -> list[str]:
        """Forward to :meth:`QEMUSandbox._snapshot_target_devices`.

        Returns:
            list[str]: Device ids a disk-only snapshot may target.
        """
        return await self._snapshot_target_devices()

    async def target_nodes(self) -> list[str]:
        """Forward to :meth:`QEMUSandbox._snapshot_target_nodes`.

        Returns:
            list[str]: Node names an internal snapshot may target.
        """
        return await self._snapshot_target_nodes()

    async def take_disk_snapshot(self, name: str) -> None:
        """Forward to :meth:`QEMUSandbox._take_disk_only_snapshot`.

        Args:
            name: Snapshot name.
        """
        await self._take_disk_only_snapshot(name)

    @staticmethod
    def new_job_id(action: str) -> str:
        """Forward to :meth:`QEMUSandbox._new_snapshot_job_id`.

        Args:
            action: Verb naming the operation.

        Returns:
            str: A job identifier.
        """
        return QEMUSandbox._new_snapshot_job_id(action)

    async def await_job(self, job_id: str, failure: str) -> None:
        """Forward to :meth:`QEMUSandbox._await_snapshot_job`.

        Args:
            job_id: Identifier the job was started with.
            failure: Message prefix describing the operation.
        """
        await self._await_snapshot_job(job_id, failure)

    @staticmethod
    def find_job(payload: object, job_id: str) -> dict[str, object] | None:
        """Forward to :meth:`QEMUSandbox._find_job`.

        Args:
            payload: The ``return`` member of a ``query-jobs`` reply.
            job_id: Identifier to look for.

        Returns:
            dict[str, object] | None: The job record, or None.
        """
        return QEMUSandbox._find_job(payload, job_id)

    async def machine_running(self) -> bool:
        """Forward to :meth:`QEMUSandbox._machine_is_running`.

        Returns:
            bool: Whether QEMU says the processors are executing.
        """
        return await self._machine_is_running()

    async def resume_failed(self, action: str, *, was_running: bool) -> str:
        """Forward to :meth:`QEMUSandbox._resume_after_failed_snapshot_job`.

        Args:
            action: Verb naming the operation.
            was_running: Whether the machine was executing before the job.

        Returns:
            str: A clause naming the machine's fate, or an empty string.
        """
        return await self._resume_after_failed_snapshot_job(action, was_running=was_running)


class _UnbundledSandbox(_Probe):
    """Probe whose bundled monitor scripts and vendored ETW assemblies are absent from disk."""

    @staticmethod
    def bundled_scripts_dir() -> Path:
        """Point at a bundled-scripts directory that does not exist.

        Returns:
            Path: A directory holding no monitor scripts.
        """
        return _ABSENT_BUNDLE_ROOT / "scripts"

    @staticmethod
    def traceevent_assemblies_dir() -> Path:
        """Point at a vendored-assemblies directory that does not exist.

        Returns:
            Path: A directory holding no assemblies.
        """
        return _ABSENT_BUNDLE_ROOT / "traceevent"


def _probe(qemu_config: QEMUConfig | None = None, config: SandboxConfig | None = None) -> _Probe:
    """Build a probe sandbox.

    Args:
        qemu_config: QEMU configuration, or None for the defaults.
        config: General sandbox configuration, or None for the defaults.

    Returns:
        _Probe: The sandbox.
    """
    return _Probe(config or SandboxConfig(), qemu_config or QEMUConfig())


def _qcow2(tmp_path: Path) -> Path:
    """Write a minimal qcow2 v3 header the command builder can point at.

    Args:
        tmp_path: Directory to write into.

    Returns:
        Path: The image file.
    """
    image = tmp_path / "guest.qcow2"
    image.write_bytes(b"QFI\xfb" + (3).to_bytes(4, "big") + bytes(64))
    return image


def _launchable(
    tmp_path: Path,
    *,
    display: Literal["none", "vnc", "sdl", "spice"] = "none",
    snapshot_name: str | None = None,
    qemu_path: Path | None = None,
) -> _Probe:
    """Build a probe primed to assemble a launch command without a disk overlay.

    Args:
        tmp_path: Directory holding the image and the placeholder executable.
        display: Display mode to configure.
        snapshot_name: Snapshot to restore at launch, if any.
        qemu_path: Resolved QEMU executable, or None for a placeholder path.

    Returns:
        _Probe: The primed sandbox.
    """
    sandbox = _probe(
        QEMUConfig(
            guest_os=GuestOS.WINDOWS,
            image_path=_qcow2(tmp_path),
            display=display,
            snapshot_name=snapshot_name,
            disk_overlay=False,
        ),
    )
    sandbox.set_qemu_path(qemu_path if qemu_path is not None else tmp_path / "qemu-system-x86_64.exe")
    return sandbox


def _events(captured: list[EventDict], name: str) -> list[EventDict]:
    """Return the captured log records carrying one event name.

    Args:
        captured: Records collected by ``structlog.testing.capture_logs``.
        name: Event name to select.

    Returns:
        list[EventDict]: The matching records, in emission order.
    """
    return [record for record in captured if record.get("event") == name]


async def _spawn_python(source: str, *, piped: bool = False) -> asyncio.subprocess.Process:
    """Start a real Python child running ``source``.

    Args:
        source: Program text passed with ``-c``.
        piped: Whether stdin, stdout and stderr are pipes rather than the null device.

    Returns:
        asyncio.subprocess.Process: The running child.
    """
    if piped:
        return await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            source,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    return await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        source,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )


async def _end_process(process: asyncio.subprocess.Process) -> None:
    """Make sure a child is gone and its handle released.

    Args:
        process: The child to end.
    """
    if process.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
    await process.wait()


@contextlib.asynccontextmanager
async def _guest(
    sandbox: _Probe,
    server: GuestAgentProtocolServer,
    *,
    status: SandboxStatus = "running",
) -> AsyncGenerator[None]:
    """Attach a real guest-agent client to a real loopback guest model.

    Args:
        sandbox: Sandbox to attach the channel to.
        server: Guest model to start and stop.
        status: Status to give the sandbox while attached.

    Yields:
        None: Control while the channel is connected.
    """
    await server.start()
    client = QemuGuestAgentClient(port=server.port)
    try:
        connected = await client.connect(time_limit=_CONNECT_BUDGET_S)
        assert connected, "the guest-agent client could not reach the modelled agent"
        sandbox.set_qga(client)
        sandbox.state.status = status
        yield
    finally:
        await client.disconnect()
        sandbox.set_qga(None)
        await server.stop()


@contextlib.contextmanager
def _held_open(path: Path) -> Generator[None]:
    """Hold a file open the way a process that has not released its handle does.

    Args:
        path: File to keep open for reading.

    Yields:
        None: Control while the handle is held.
    """
    with path.open("rb"):
        yield


def _read_pending_renames() -> tuple[str, ...]:
    """Read the real ``PendingFileRenameOperations`` registry value.

    Returns:
        tuple[str, ...]: Every entry scheduled for the next reboot, or an empty tuple when none exists.
    """
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _SESSION_MANAGER_KEY) as key:
        try:
            value, _ = winreg.QueryValueEx(key, _PENDING_RENAMES_VALUE)
        except FileNotFoundError:
            return ()
    return tuple(value)


def _pending_position(entries: tuple[str, ...], path: Path) -> int:
    """Find where one path was recorded in the pending-rename list.

    Args:
        entries: The registry entries, in recorded order.
        path: Host path that was scheduled.

    Returns:
        int: Index of the single entry naming the path.
    """
    needle = str(path).lower()
    matches = [index for index, entry in enumerate(entries) if entry.lower().endswith(needle)]
    assert len(matches) == 1, f"{path} must appear exactly once in the pending list; found {matches}"
    return matches[0]


def _ok(data: object | None = None) -> QMPResponse:
    """Build a successful scripted reply.

    Args:
        data: The reply's ``return`` member.

    Returns:
        QMPResponse: A successful response.
    """
    return QMPResponse(success=True, data=data)


def _refused(error: str | None) -> QMPResponse:
    """Build a refused scripted reply.

    Args:
        error: The reply's error description, if any.

    Returns:
        QMPResponse: A failed response.
    """
    return QMPResponse(success=False, error=error)


@pytest.mark.asyncio
async def test_building_a_command_without_a_qemu_path_is_refused(tmp_path: Path) -> None:
    """A sandbox that never resolved QEMU cannot assemble a launch command."""
    sandbox = _probe(QEMUConfig(image_path=_qcow2(tmp_path)))

    with structlog.testing.capture_logs() as captured, pytest.raises(SandboxError, match="path not set"):
        await sandbox.build_command()

    assert [record["log_level"] for record in _events(captured, "qemu_command_build_failed_no_path")] == ["error"]


@pytest.mark.asyncio
async def test_sdl_display_requests_an_sdl_window_and_no_other_display_option(tmp_path: Path) -> None:
    """The sdl display adds ``-display sdl`` and neither a VNC nor a SPICE listener."""
    sandbox = _launchable(tmp_path, display="sdl")
    try:
        argv = await sandbox.build_command()
    finally:
        await sandbox.cleanup()

    assert argv[argv.index("-display") + 1] == "sdl"
    assert argv.count("-display") == 1
    assert "-vnc" not in argv
    assert "-spice" not in argv


@pytest.mark.asyncio
async def test_spice_display_claims_a_port_in_the_display_range_and_binds_it(tmp_path: Path) -> None:
    """The spice display opens ticket-less SPICE on a port the sandbox reserved for itself."""
    sandbox = _launchable(tmp_path, display="spice")
    try:
        argv = await sandbox.build_command()
        claimed = sandbox.claimed_ports()
        reserved = sandbox.reserved_ports()
    finally:
        await sandbox.cleanup()

    spice = argv[argv.index("-spice") + 1]
    matched = re.fullmatch(r"port=(\d+),disable-ticketing=on", spice)
    assert matched is not None, f"unexpected -spice argument {spice!r}"
    port = int(matched.group(1))
    assert _DISPLAY_PORT_FIRST <= port <= _DISPLAY_PORT_LAST
    assert port in claimed
    assert port in reserved
    assert "-display" not in argv
    assert "-vnc" not in argv
    assert port not in sandbox.reserved_ports()


@pytest.mark.asyncio
async def test_a_configured_snapshot_is_loaded_at_launch(tmp_path: Path) -> None:
    """A configured snapshot name becomes a ``-loadvm`` pair, and no snapshot means no such option."""
    with_snapshot = _launchable(tmp_path, snapshot_name="clean-state")
    without_snapshot = _launchable(tmp_path)
    try:
        restoring = await with_snapshot.build_command()
        plain = await without_snapshot.build_command()
    finally:
        await with_snapshot.cleanup()
        await without_snapshot.cleanup()

    assert restoring[restoring.index("-loadvm") + 1] == "clean-state"
    assert "-loadvm" not in plain


def test_a_missing_qemu_pid_is_reported_as_a_failed_start() -> None:
    """A launch that produced no process id is a failed start, and says so in the log."""
    with structlog.testing.capture_logs() as captured, pytest.raises(SandboxError, match="QEMU start failed"):
        _Probe.ensure_started(None)

    assert [record["log_level"] for record in _events(captured, "qemu_start_failed_no_pid")] == ["error"]


def test_a_present_qemu_pid_passes_the_start_check() -> None:
    """A real process id is accepted without complaint."""
    with structlog.testing.capture_logs() as captured:
        _Probe.ensure_started(4321)

    assert _events(captured, "qemu_start_failed_no_pid") == []


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_spawn_logs_the_command_it_builds_and_reports_a_binary_that_cannot_launch(tmp_path: Path) -> None:
    """The launcher argv is logged before the spawn, and an unlaunchable binary surfaces as the OS error."""
    missing = tmp_path / "absent-qemu.exe"
    sandbox = _launchable(tmp_path, qemu_path=missing)
    try:
        with structlog.testing.capture_logs() as captured, pytest.raises(FileNotFoundError):
            await sandbox.spawn()
    finally:
        await sandbox.cleanup()

    starting = _events(captured, "qemu_starting")
    assert len(starting) == 1
    assert str(starting[0]["command"]).startswith(f"{missing} -machine ")
    spawning = _events(captured, "subprocess_spawning")
    assert len(spawning) == 1
    assert spawning[0]["executable"] == str(missing)
    argv = spawning[0]["argv"]
    assert argv[0] == str(missing)
    assert f"file={sandbox.qemu_config.image_path},format=qcow2,if=virtio" in argv
    assert sandbox.process is None


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_spawn_reports_a_launcher_that_exits_with_failure(tmp_path: Path) -> None:
    """A launcher that rejects its arguments and exits non-zero is reported as a failed start."""
    sandbox = _launchable(tmp_path, qemu_path=Path(sys.executable))
    try:
        with pytest.raises(SandboxError, match="QEMU start failed"):
            await sandbox.spawn()
        process = sandbox.process
        assert process is not None
        assert process.returncode is not None
        assert process.returncode != 0
    finally:
        await sandbox.cleanup()

    assert sandbox.process is None


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_registering_a_qemu_pid_records_it_on_the_sandbox_and_in_the_process_manager(tmp_path: Path) -> None:
    """A live pid becomes the sandbox's pid and a tracked sandbox process with its guest and image."""
    image = _qcow2(tmp_path)
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.LINUX, image_path=image))
    child = await _spawn_python(_IDLE_CHILD)
    manager = ProcessManager.get_instance()
    try:
        verified = await sandbox.register_pid(child.pid)

        assert verified == child.pid
        assert sandbox.state.pid == child.pid
        assert sandbox.recorded_pid() == child.pid
        entries = [entry for entry in manager.get_all_tracked_entries() if entry.pid == child.pid]
        assert len(entries) == 1
        assert entries[0].name == "qemu-vm"
        assert entries[0].process_type is ProcessType.SANDBOX
        assert entries[0].is_running is True
        assert entries[0].metadata == {"guest_os": "linux", "image": str(image)}
    finally:
        manager.unregister_external_pid(child.pid)
        await _end_process(child)


@pytest.mark.asyncio
async def test_registering_no_pid_reports_the_unreadable_pidfile() -> None:
    """With no pid to register the start fails and records nothing."""
    sandbox = _probe()

    with pytest.raises(SandboxError, match="pidfile unreadable"):
        await sandbox.register_pid(None)

    assert sandbox.state.pid is None
    assert sandbox.recorded_pid() is None


@pytest.mark.asyncio
async def test_telemetry_blocking_is_skipped_when_not_requested() -> None:
    """With blocking switched off no command reaches the guest."""
    server = GuestAgentProtocolServer(responder=_CannedGuest())
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS), SandboxConfig(block_telemetry=False))

    async with _guest(sandbox, server):
        with structlog.testing.capture_logs() as captured:
            await sandbox.apply_telemetry()
        assert server.exec_records == []

    assert [record["sandbox_type"] for record in _events(captured, "telemetry_blocking_not_requested")] == ["qemu"]


@pytest.mark.asyncio
async def test_telemetry_blocking_is_skipped_for_a_linux_guest() -> None:
    """A Linux guest has no Microsoft telemetry, so nothing is run in it even when blocking is requested."""
    server = GuestAgentProtocolServer(responder=_CannedGuest())
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.LINUX), SandboxConfig(block_telemetry=True))

    async with _guest(sandbox, server):
        with structlog.testing.capture_logs() as captured:
            await sandbox.apply_telemetry()
        assert server.exec_records == []

    assert [record["guest_os"] for record in _events(captured, "telemetry_blocking_not_applicable")] == ["linux"]


@pytest.mark.asyncio
async def test_telemetry_blocking_reports_the_guest_summary_when_it_succeeds() -> None:
    """A guest script that exits cleanly with a whole summary record is reported as applied."""
    guest = _CannedGuest(rules=(("powershell.exe", GuestCommandResult(exit_code=0, stdout=_BLOCK_RECORD, stderr="")),))
    server = GuestAgentProtocolServer(responder=guest)
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS), SandboxConfig(block_telemetry=True))

    async with _guest(sandbox, server):
        with structlog.testing.capture_logs() as captured:
            await sandbox.apply_telemetry()
        assert [record.path for record in server.exec_records] == ["powershell.exe"]

    applied = _events(captured, "telemetry_blocking_applied")
    assert len(applied) == 1
    assert applied[0]["hosts_entries"] == 31
    assert applied[0]["firewall_rules"] == 2
    assert applied[0]["firewall_backend"] == "netsecurity"
    assert applied[0]["problems"] == []
    assert _events(captured, "telemetry_blocking_incomplete") == []


@pytest.mark.asyncio
async def test_telemetry_blocking_reports_a_failing_guest_script_as_incomplete() -> None:
    """A non-zero exit is incomplete even when a summary was printed, and its stderr is cut to an excerpt."""
    failing = GuestCommandResult(exit_code=1, stdout=_BLOCK_RECORD, stderr="x" * 600)
    server = GuestAgentProtocolServer(responder=_CannedGuest(rules=(("powershell.exe", failing),)))
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS), SandboxConfig(block_telemetry=True))

    async with _guest(sandbox, server):
        with structlog.testing.capture_logs() as captured:
            await sandbox.apply_telemetry()

    incomplete = _events(captured, "telemetry_blocking_incomplete")
    assert len(incomplete) == 1
    assert incomplete[0]["exit_code"] == 1
    assert incomplete[0]["stderr"] == "x" * 500
    assert _events(captured, "telemetry_blocking_applied") == []


@pytest.mark.asyncio
async def test_telemetry_blocking_reports_a_missing_summary_as_incomplete() -> None:
    """A guest that exits zero without printing a summary record did not demonstrably do anything."""
    quiet = GuestCommandResult(exit_code=0, stdout="Windows PowerShell\r\nblocking started\r\n", stderr="")
    server = GuestAgentProtocolServer(responder=_CannedGuest(rules=(("powershell.exe", quiet),)))
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS), SandboxConfig(block_telemetry=True))

    async with _guest(sandbox, server):
        with structlog.testing.capture_logs() as captured:
            await sandbox.apply_telemetry()

    incomplete = _events(captured, "telemetry_blocking_incomplete")
    assert len(incomplete) == 1
    assert incomplete[0]["exit_code"] == 0
    assert _events(captured, "telemetry_blocking_applied") == []


@pytest.mark.asyncio
async def test_start_on_a_running_sandbox_does_nothing() -> None:
    """Starting a sandbox that is already running warns and leaves it untouched."""
    sandbox = _probe()
    sandbox.state.status = "running"

    with structlog.testing.capture_logs() as captured:
        await sandbox.start()

    assert sandbox.state.status == "running"
    assert [record["state"] for record in _events(captured, "qemu_sandbox_already_running")] == ["running"]
    assert _events(captured, "qemu_sandbox_started_successfully") == []


@pytest.mark.asyncio
async def test_start_without_qemu_installed_is_refused() -> None:
    """With no QEMU on the host the start is refused before the sandbox leaves the stopped state."""
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.LINUX))

    with pytest.raises(SandboxError, match="QEMU not available"):
        await sandbox.start()

    assert sandbox.state.status == "stopped"
    assert sandbox.state.last_error is None


@pytest.mark.asyncio
async def test_stop_on_a_stopped_sandbox_does_nothing() -> None:
    """Stopping a sandbox that is already stopped is a debug-level no-op."""
    sandbox = _probe()

    with structlog.testing.capture_logs() as captured:
        await sandbox.stop()

    assert sandbox.state.status == "stopped"
    assert [record["state"] for record in _events(captured, "qemu_sandbox_already_stopped")] == ["stopped"]
    assert _events(captured, "qemu_sandbox_stopped") == []


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_stop_releases_every_resource_the_running_sandbox_holds(tmp_path: Path) -> None:
    """Stopping drops the agent, both channels, the pid registration and the recorder, and ends in stopped."""
    server = GuestAgentProtocolServer()
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.LINUX, image_path=_qcow2(tmp_path)))
    qemu = await _spawn_python("pass", piped=True)
    await qemu.wait()
    sleeper = await _spawn_python(_IDLE_CHILD)
    recorder = QemuOutputRecorder(qemu)
    recorder.start()
    manager = ProcessManager.get_instance()
    try:
        await sandbox.register_pid(sleeper.pid)
        sandbox.set_process(qemu)
        sandbox.set_recorder(recorder)
        sandbox.set_agent(GuestAgentClient(port=_UNUSED_PORT))
        async with _guest(sandbox, server):
            assert sandbox.agent is not None
            assert sandbox.qemu_guest_agent is not None

            await sandbox.stop()

            assert "guest-shutdown" not in server.commands
        assert sandbox.state.status == "stopped"
        assert sandbox.state.pid is None
        assert sandbox.agent is None
        assert sandbox.qemu_guest_agent is None
        assert sandbox.recorder() is None
        assert sandbox.process is None
        assert sandbox.recorded_pid() is None
        assert all(entry.pid != sleeper.pid for entry in manager.get_all_tracked_entries())
        assert sleeper.returncode is None
    finally:
        manager.unregister_external_pid(sleeper.pid)
        await recorder.aclose()
        await _end_process(sleeper)
        await _end_process(qemu)


@pytest.mark.asyncio
async def test_stop_failure_marks_the_sandbox_errored_and_chains_the_cause() -> None:
    """A teardown step that fails leaves the sandbox in error with the cause attached."""
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.LINUX))
    sandbox.set_agent(_RefusingAgent(port=_UNUSED_PORT))
    sandbox.state.status = "running"

    with pytest.raises(SandboxError, match="sandbox stop failed") as excinfo:
        await sandbox.stop()

    assert isinstance(excinfo.value.__cause__, OSError)
    assert sandbox.state.status == "error"
    assert sandbox.state.last_error == "disconnect refused by the transport"


@pytest.mark.asyncio
async def test_agent_shutdown_is_not_requested_without_an_open_channel() -> None:
    """No qemu-guest-agent request is made while the channel is absent or not connected."""
    sandbox = _probe()
    assert await sandbox.request_agent_shutdown() is False

    sandbox.set_qga(QemuGuestAgentClient(port=_UNUSED_PORT))
    assert await sandbox.request_agent_shutdown() is False


@pytest.mark.asyncio
async def test_acpi_powerdown_is_not_requested_without_an_open_monitor() -> None:
    """No power-button request is made while the monitor is absent or not connected."""
    sandbox = _probe()
    assert await sandbox.request_acpi_powerdown() is False

    sandbox.set_qmp(QMPClient(port=_UNUSED_PORT))
    assert await sandbox.request_acpi_powerdown() is False


@pytest.mark.asyncio
async def test_acpi_powerdown_reports_a_refusal() -> None:
    """QEMU refusing ``system_powerdown`` is reported as not accepted and logged with its reason."""
    refusing = _ScriptedMonitor({"system_powerdown": [_refused("guest is not listening")]})
    accepting = _ScriptedMonitor({"system_powerdown": [_ok({})]})
    sandbox = _probe()

    sandbox.set_qmp(refusing)
    with structlog.testing.capture_logs() as captured:
        refused = await sandbox.request_acpi_powerdown()
    sandbox.set_qmp(accepting)
    accepted = await sandbox.request_acpi_powerdown()

    assert refused is False
    assert accepted is True
    assert refusing.script.sent == [{"execute": "system_powerdown"}]
    assert [record["error"] for record in _events(captured, "qemu_system_powerdown_failed")] == ["guest is not listening"]


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_await_exit_reports_an_already_exited_process() -> None:
    """A foreground child that has already exited needs no waiting."""
    sandbox = _probe()
    child = await _spawn_python("pass")
    await child.wait()
    sandbox.set_process(child)

    assert await sandbox.await_exit(0.0) is True


@pytest.mark.asyncio
async def test_await_exit_without_a_process_or_pid_reports_not_exited() -> None:
    """With nothing to watch the guest is not known to have exited."""
    sandbox = _probe()
    assert await sandbox.await_exit(0.0) is False

    sandbox.set_qemu_pid(-1)
    assert await sandbox.await_exit(0.0) is False


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_await_exit_waits_for_a_pid_only_qemu_to_finish() -> None:
    """A daemonized QEMU known only by pid is waited on until it exits."""
    sandbox = _probe()
    child = await _spawn_python("import time; time.sleep(1.0)")
    sandbox.set_qemu_pid(child.pid)
    try:
        exited = await sandbox.await_exit(_EXIT_BUDGET_S)
        returncode = await asyncio.wait_for(child.wait(), timeout=_EXIT_BUDGET_S)
    finally:
        await _end_process(child)

    assert exited is True
    assert returncode == 0


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_shutdown_with_no_budget_still_marks_the_recorder() -> None:
    """Even a shutdown that skips the request marks the exit as expected, so it is not logged as a crash."""
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.LINUX, guest_shutdown_timeout=0.0))
    child = await _spawn_python("import sys; sys.stdin.read()", piped=True)
    recorder = QemuOutputRecorder(child)
    sandbox.set_process(child)
    sandbox.set_recorder(recorder)
    recorder.start()
    try:
        with structlog.testing.capture_logs() as captured:
            assert await sandbox.shut_down() is False
            assert child.stdin is not None
            child.stdin.close()
            await wait_until(lambda: recorder.termination is not None, budget=_EXIT_BUDGET_S, interval=_POLL_INTERVAL_S)
        assert recorder.termination is not None
        assert recorder.termination.returncode == 0
    finally:
        await recorder.aclose()
        await _end_process(child)

    assert _events(captured, "qemu_process_exited") != []
    assert _events(captured, "qemu_process_exited_unexpectedly") == []


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_shutdown_does_not_ask_an_already_exited_guest_to_power_off() -> None:
    """When QEMU is already gone no shutdown request is sent down the open agent channel."""
    server = GuestAgentProtocolServer()
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.LINUX))
    child = await _spawn_python("pass")
    await child.wait()
    sandbox.set_process(child)

    async with _guest(sandbox, server):
        with structlog.testing.capture_logs() as captured:
            exited = await sandbox.shut_down()
        assert "guest-shutdown" not in server.commands

    assert exited is True
    assert _events(captured, "qemu_already_exited_before_shutdown_request") != []


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_termination_prefers_the_recorders_account_of_the_exit() -> None:
    """The recorder's exit status and parting output are what the sandbox reports."""
    sandbox = _probe()
    child = await _spawn_python("import sys; print('boot ok'); sys.stderr.write('fault\\n'); sys.exit(3)", piped=True)
    recorder = QemuOutputRecorder(child)
    recorder.start()
    sandbox.set_recorder(recorder)
    try:
        await wait_until(lambda: recorder.termination is not None, budget=_EXIT_BUDGET_S, interval=_POLL_INTERVAL_S)
        termination = sandbox.qemu_termination()
    finally:
        await recorder.aclose()
        await _end_process(child)

    assert termination is not None
    assert termination is recorder.termination
    assert termination.returncode == 3
    assert set(termination.output_tail) == {"stdout: boot ok", "stderr: fault"}


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_cleanup_terminates_the_orphan_named_in_the_pidfile_and_removes_the_tree(tmp_path: Path) -> None:
    """The process named in a leftover pidfile is ended and the instance's whole temp tree is deleted."""
    temp_dir = tmp_path / "intellicrack_qemu_orphan"
    temp_dir.mkdir()
    (temp_dir / "disk-overlay.qcow2").write_bytes(b"overlay")
    orphan = await _spawn_python(_IDLE_CHILD)
    (temp_dir / "qemu.pid").write_text(f"{orphan.pid}\n", encoding="utf-8")
    sandbox = _probe()
    sandbox.set_temp_dir(temp_dir)
    try:
        with structlog.testing.capture_logs() as captured:
            await sandbox.cleanup()
        returncode = await asyncio.wait_for(orphan.wait(), timeout=_EXIT_BUDGET_S)
    finally:
        await _end_process(orphan)

    assert returncode is not None
    assert not temp_dir.exists()
    assert sandbox.temp_dir() is None
    assert [record["pid"] for record in _events(captured, "cleanup_terminated_orphan_qemu_tree")] == [orphan.pid]


@pytest.mark.asyncio
async def test_cleanup_survives_an_unreadable_pidfile(tmp_path: Path) -> None:
    """A pidfile that does not hold a number is reported and the temp tree is still removed."""
    temp_dir = tmp_path / "intellicrack_qemu_garbled"
    temp_dir.mkdir()
    (temp_dir / "qemu.pid").write_text("not-a-pid", encoding="utf-8")
    sandbox = _probe()
    sandbox.set_temp_dir(temp_dir)

    with structlog.testing.capture_logs() as captured:
        await sandbox.cleanup()

    assert not temp_dir.exists()
    assert len(_events(captured, "cleanup_pid_check_failed")) == 1
    assert _events(captured, "cleanup_terminated_orphan_qemu_tree") == []


def test_release_keeps_ports_the_caller_pinned() -> None:
    """Only the ports the sandbox allocated are given back; a pinned VNC and monitor port are left alone."""
    pinned_vnc = 5990
    pinned_monitor = 45555
    sandbox = _probe()
    allocated = sandbox.allocate_port()
    sandbox.set_qemu_config(replace(sandbox.qemu_config, ssh_port=allocated, monitor_port=pinned_monitor))
    sandbox.set_vnc_port(pinned_vnc)
    assert allocated in sandbox.reserved_ports()

    sandbox.release_ports()

    assert sandbox.qemu_config.ssh_port == 0
    assert sandbox.qemu_config.monitor_port == pinned_monitor
    assert sandbox.vnc_port == pinned_vnc
    assert sandbox.claimed_ports() == set()
    assert allocated not in sandbox.reserved_ports()


def test_release_clears_a_vnc_port_the_sandbox_claimed() -> None:
    """A VNC port the sandbox itself claimed is forgotten when its ports are released."""
    sandbox = _probe()
    claimed = sandbox.get_free_port()
    sandbox.set_vnc_port(claimed)

    sandbox.release_ports()

    assert sandbox.vnc_port is None
    assert claimed not in sandbox.reserved_ports()


def test_tree_scheduling_records_children_before_their_parents(tmp_path: Path) -> None:
    """Every entry of a stuck tree is registered with Windows, leaves first, and the root last."""
    root = tmp_path / "intellicrack_qemu_tree"
    nested = root / "collected"
    nested.mkdir(parents=True)
    leaf = nested / "leaf.bin"
    leaf.write_bytes(b"leaf")
    top = root / "top.bin"
    top.write_bytes(b"top")
    try:
        accepted = _Probe.schedule_tree(root)
        pending = _read_pending_renames()
    finally:
        shutil.rmtree(root, ignore_errors=True)

    assert accepted is True
    leaf_at = _pending_position(pending, leaf)
    nested_at = _pending_position(pending, nested)
    top_at = _pending_position(pending, top)
    root_at = _pending_position(pending, root)
    assert leaf_at < nested_at < root_at
    assert top_at < root_at


@pytest.mark.asyncio
@pytest.mark.slow
async def test_a_tree_that_resists_every_retry_is_deferred_to_reboot(tmp_path: Path) -> None:
    """A file that stays locked through every retry is handed to Windows to delete at the next boot."""
    victim = tmp_path / "intellicrack_qemu_locked"
    victim.mkdir()
    locked = victim / "memory.dump"
    locked.write_bytes(b"unreleased handle")
    try:
        with _held_open(locked), structlog.testing.capture_logs() as captured:
            await _Probe.remove_tree(victim)
            assert locked.exists()
        pending = _read_pending_renames()
        scheduled = _pending_position(pending, locked)
    finally:
        shutil.rmtree(victim, ignore_errors=True)

    deferred = _events(captured, "temp_dir_cleanup_deferred_to_reboot")
    assert len(deferred) == 1
    assert deferred[0]["path"] == str(victim)
    assert deferred[0]["attempts"] == _REMOVE_ATTEMPTS
    assert _events(captured, "temp_dir_cleanup_failed") == []
    assert scheduled < _pending_position(pending, victim)


@pytest.mark.asyncio
async def test_agent_script_is_skipped_without_a_shared_folder() -> None:
    """With no shared folder there is nowhere to stage a launcher, so nothing happens."""
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS))

    await sandbox.create_script()

    assert sandbox.temp_dir() is None


@pytest.mark.asyncio
async def test_missing_bundled_monitor_scripts_and_assemblies_are_reported(tmp_path: Path) -> None:
    """Absent bundled scripts and ETW assemblies are warned about by name, while the launcher is still staged."""
    share = tmp_path / "shared"
    (share / "monitor").mkdir(parents=True)
    sandbox = _UnbundledSandbox(SandboxConfig(), QEMUConfig(guest_os=GuestOS.WINDOWS))
    sandbox.set_shared_folder(share)

    with structlog.testing.capture_logs() as captured:
        await sandbox.create_script()

    missing = _events(captured, "monitor_script_missing")
    assert {record["script"] for record in missing} == set(MONITOR_SCRIPT_NAMES)
    assert len(missing) == len(MONITOR_SCRIPT_NAMES)
    assert [record["path"] for record in _events(captured, "traceevent_assemblies_missing")] == [str(_ABSENT_BUNDLE_ROOT / "traceevent")]
    staged = {entry.name for entry in (share / "monitor").iterdir()}
    assert staged == {"agent.ps1", "start_agent.cmd"}
    launcher = (share / "monitor" / "start_agent.cmd").read_bytes()
    assert launcher.startswith(b"@echo off\r\n")
    assert b"agent.ps1" in launcher


@pytest.mark.asyncio
async def test_poll_keeps_waiting_while_the_vm_is_up(tmp_path: Path) -> None:
    """A running VM that never writes a result ends in a timeout, not in a premature VM-gone error."""
    sandbox = _probe()

    with pytest.raises(SandboxTimeoutError, match="command timed out") as excinfo:
        await sandbox.poll_for_result(
            result_path=tmp_path / "result_never.txt",
            time_limit=1,
            vm_terminated=sandbox.qemu_termination,
        )

    assert excinfo.value.timeout_seconds == 1


@pytest.mark.asyncio
async def test_poll_survives_an_unreadable_result_file(tmp_path: Path) -> None:
    """A result path that exists but cannot be read is reported and polling continues until the deadline."""
    unreadable = tmp_path / "result_dir"
    unreadable.mkdir()

    with structlog.testing.capture_logs() as captured, pytest.raises(SandboxTimeoutError, match="command timed out"):
        await _Probe.poll_for_result(result_path=unreadable, time_limit=1)

    assert len(_events(captured, "result_read_failed")) >= 1


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_poll_stops_waiting_once_the_vm_is_gone(tmp_path: Path) -> None:
    """A VM that has exited ends the wait immediately, naming its exit status."""
    sandbox = _probe()
    child = await _spawn_python("import sys; sys.exit(7)")
    await child.wait()
    sandbox.set_process(child)

    with structlog.testing.capture_logs() as captured, pytest.raises(SandboxError) as excinfo:
        await sandbox.poll_for_result(
            result_path=tmp_path / "result_never.txt",
            time_limit=30,
            vm_terminated=sandbox.qemu_termination,
        )

    assert type(excinfo.value) is SandboxError
    assert str(excinfo.value) == (
        "the QEMU process is no longer running, so the guest it hosted no longer exists: "
        "QEMU exited with code 7; QEMU produced no output before it stopped"
    )
    assert [record["returncode"] for record in _events(captured, "qemu_stopped_while_awaiting_result")] == [7]


@pytest.mark.asyncio
async def test_sidecar_that_cannot_be_read_is_reported_empty(tmp_path: Path) -> None:
    """A sidecar path that exists but cannot be read yields no text, and a readable one is decoded leniently."""
    unreadable = tmp_path / "sidecar_dir"
    unreadable.mkdir()
    readable = tmp_path / "stdout.txt"
    readable.write_bytes(b"ok\xff")

    with structlog.testing.capture_logs() as captured:
        assert not await _Probe.read_sidecar(unreadable)
    assert await _Probe.read_sidecar(readable) == "ok\ufffd"
    assert not await _Probe.read_sidecar(None)
    assert not await _Probe.read_sidecar(tmp_path / "absent.txt")

    assert [record["path"] for record in _events(captured, "sidecar_read_failed")] == [str(unreadable)]


@pytest.mark.asyncio
async def test_one_undeletable_artifact_does_not_stop_the_rest_being_cleaned(tmp_path: Path) -> None:
    """A per-invocation artifact that cannot be deleted is logged and the remaining ones are still removed."""
    result = tmp_path / "result.txt"
    result.write_text("0", encoding="utf-8")
    stdout = tmp_path / "stdout_dir"
    stdout.mkdir()
    stderr = tmp_path / "stderr.txt"
    stderr.write_text("err", encoding="utf-8")
    script = tmp_path / "exec.cmd"
    script.write_text("@echo off", encoding="utf-8")

    with structlog.testing.capture_logs() as captured:
        await _Probe.cleanup_artifacts(result_path=result, stdout_path=stdout, stderr_path=stderr, script_path=script)

    assert not result.exists()
    assert not stderr.exists()
    assert not script.exists()
    assert stdout.is_dir()
    assert [record["path"] for record in _events(captured, "result_artifact_cleanup_failed")] == [str(stdout)]


@pytest.mark.asyncio
async def test_run_binary_refuses_a_sandbox_that_is_not_running(tmp_path: Path) -> None:
    """A sandbox that is not running refuses to run anything."""
    sandbox = _probe()

    with pytest.raises(SandboxError, match="not running"):
        await sandbox.run_binary(tmp_path / "prog.exe")


@pytest.mark.asyncio
async def test_run_binary_names_a_missing_binary(tmp_path: Path) -> None:
    """A binary that does not exist on the host is refused and the missing path is logged."""
    sandbox = _probe()
    sandbox.state.status = "running"
    missing = tmp_path / "absent.exe"

    with structlog.testing.capture_logs() as captured, pytest.raises(SandboxError, match="binary not found"):
        await sandbox.run_binary(missing)

    assert [record["path"] for record in _events(captured, "binary_not_found")] == [str(missing)]


@pytest.mark.asyncio
async def test_run_binary_requires_a_shared_folder(tmp_path: Path) -> None:
    """A running sandbox with no shared folder cannot stage a binary."""
    binary = tmp_path / "prog.exe"
    binary.write_bytes(b"MZ")
    sandbox = _probe()
    sandbox.state.status = "running"

    with pytest.raises(SandboxError, match="shared folder not init"):
        await sandbox.run_binary(binary)


@pytest.mark.asyncio
async def test_run_binary_stages_the_target_runs_it_and_clears_stale_logs(tmp_path: Path) -> None:
    """The target and its companions land in the guest, the program runs, and last run's host logs are cleared."""
    work = tmp_path / "work"
    shared = work / "shared"
    shared.mkdir(parents=True)
    logs = work / "collected" / "logs"
    logs.mkdir(parents=True)
    stale = logs / "stale.log"
    stale.write_text("old run", encoding="utf-8")
    notes = logs / "notes.txt"
    notes.write_text("keep", encoding="utf-8")
    binary = tmp_path / "prog.exe"
    binary.write_bytes(b"MZ\x90\x00prog")
    library = tmp_path / "lib.dll"
    library.write_bytes(b"dll-bytes")
    resources = tmp_path / "res"
    (resources / "deep").mkdir(parents=True)
    (resources / "deep" / "a.txt").write_bytes(b"alpha")
    guest = _CannedGuest(rules=(("prog.exe", GuestCommandResult(exit_code=0, stdout="ran-ok", stderr="")),))
    server = GuestAgentProtocolServer(responder=guest)
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS), SandboxConfig(timeout_seconds=30))
    sandbox.set_temp_dir(work)
    sandbox.set_shared_folder(shared)

    async with _guest(sandbox, server):
        report = await sandbox.run_binary(binary, args=["--flag"], companions=[library, resources], monitor=True)

    assert report.result == "success"
    assert report.exit_code == 0
    assert report.stdout == "ran-ok"
    assert not report.stderr
    assert report.duration_seconds >= 0.0
    assert bytes(server.guest_files[f"{_WORK_ROOT}\\input\\prog.exe"]) == b"MZ\x90\x00prog"
    assert bytes(server.guest_files[f"{_WORK_ROOT}\\input\\lib.dll"]) == b"dll-bytes"
    assert bytes(server.guest_files[f"{_WORK_ROOT}\\input\\res\\deep\\a.txt"]) == b"alpha"
    assert ("cmd.exe", ("/c", f'"{_WORK_ROOT}\\input\\prog.exe" "--flag"')) in [
        (record.path, record.args) for record in server.exec_records
    ]
    assert not stale.exists()
    assert notes.exists()


@pytest.mark.asyncio
async def test_run_binary_reports_a_guest_that_cannot_launch_the_program(tmp_path: Path) -> None:
    """When the agent cannot launch the program the report is an error with the agent's reason, not an exception."""
    shared = tmp_path / "work" / "shared"
    shared.mkdir(parents=True)
    binary = tmp_path / "prog.exe"
    binary.write_bytes(b"MZ")
    server = GuestAgentProtocolServer(unsupported_commands=frozenset({"guest-exec"}))
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS))
    sandbox.set_shared_folder(shared)

    async with _guest(sandbox, server):
        with structlog.testing.capture_logs() as captured:
            report = await sandbox.run_binary(binary, monitor=False)

    assert report.result == "error"
    assert report.exit_code == -1
    assert not report.stdout
    assert report.stderr == "qemu-guest-agent guest-exec failed to launch the monitor agent script"
    assert [record["binary"] for record in _events(captured, "sandbox_execution_error")] == ["prog.exe"]


@pytest.mark.asyncio
async def test_collecting_guest_logs_does_nothing_without_an_agent(tmp_path: Path) -> None:
    """With no agent channel there is nothing to fetch, so no collection directory is created."""
    work = tmp_path / "work"
    work.mkdir()
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS))
    sandbox.set_temp_dir(work)

    await sandbox.collect_logs()

    assert not (work / "collected").exists()


@pytest.mark.asyncio
async def test_collect_guest_output_pulls_the_output_tree_when_a_mirror_folder_is_configured(tmp_path: Path) -> None:
    """The guest's output directory is reproduced under the host collection root when a writable folder is configured."""
    analyst = tmp_path / "analyst"
    analyst.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    listing = f"{_WORK_ROOT}\\output\\a.txt\r\n{_WORK_ROOT}\\output\\sub\\b.bin\r\n"
    guest = _CannedGuest(rules=(("dir /b /s /a-d", GuestCommandResult(exit_code=0, stdout=listing, stderr="")),))
    server = GuestAgentProtocolServer(responder=guest)
    server.guest_files[f"{_WORK_ROOT}\\output\\a.txt"] = bytearray(b"alpha")
    server.guest_files[f"{_WORK_ROOT}\\output\\sub\\b.bin"] = bytearray(b"\x00\x01\x02beta")
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS), SandboxConfig(shared_folders=[(analyst, "Z:\\anything", False)]))
    sandbox.set_temp_dir(work)

    async with _guest(sandbox, server):
        pulled = await sandbox.collect_output()

    assert pulled == 2
    assert (work / "collected" / "output" / "a.txt").read_bytes() == b"alpha"
    assert (work / "collected" / "output" / "sub" / "b.bin").read_bytes() == b"\x00\x01\x02beta"


@pytest.mark.asyncio
async def test_mirroring_into_an_unwritable_destination_copies_nothing(tmp_path: Path) -> None:
    """A mirror destination that cannot be created is reported and leaves the analyst's folder as it was."""
    analyst = tmp_path / "analyst"
    analyst.mkdir()
    blocker = analyst / "intellicrack-output"
    blocker.write_bytes(b"the analyst's own file")
    work = tmp_path / "work"
    (work / "collected" / "output").mkdir(parents=True)
    (work / "collected" / "output" / "a.txt").write_bytes(b"alpha")
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS), SandboxConfig(shared_folders=[(analyst, "Z:\\anything", False)]))
    sandbox.set_temp_dir(work)

    with structlog.testing.capture_logs() as captured:
        copied = await sandbox.mirror_output()

    assert copied == 0
    assert blocker.read_bytes() == b"the analyst's own file"
    assert [record["destination"] for record in _events(captured, "configured_share_mirror_failed")] == [str(blocker)]


@pytest.mark.asyncio
async def test_waiting_for_logs_requires_a_shared_folder() -> None:
    """Waiting for the monitor logs to settle needs a shared folder to watch."""
    sandbox = _probe()

    with structlog.testing.capture_logs() as captured, pytest.raises(SandboxError, match="shared folder not init"):
        await sandbox.wait_logs_stable()

    assert len(_events(captured, "wait_for_logs_stable_no_shared_folder")) == 1


@pytest.mark.asyncio
async def test_guest_log_sizes_parse_the_windows_listing(tmp_path: Path) -> None:
    """The Windows size probe is a cmd ``for`` loop, and only well-formed ``name size`` lines are kept."""
    listing = "agent.log 120\r\nnoise words\r\nlonely\r\nweird.log 12x\r\nmonitor.log 7\r\n"
    guest = _CannedGuest(rules=(("for %I", GuestCommandResult(exit_code=0, stdout=listing, stderr="")),))
    server = GuestAgentProtocolServer(responder=guest)
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS))
    sandbox.set_shared_folder(tmp_path)

    async with _guest(sandbox, server):
        sizes = await sandbox.guest_log_sizes()

    assert sizes == {"agent.log": 120, "monitor.log": 7}
    expected_command = f'for %I in ("{_WORK_ROOT}\\logs\\*.log") do @echo %~nxI %~zI'
    assert [(record.path, record.args) for record in server.exec_records] == [("cmd.exe", ("/c", expected_command))]


@pytest.mark.asyncio
async def test_guest_log_sizes_are_empty_when_the_probe_exits_with_failure() -> None:
    """A failing size probe contributes no sizes, even if it printed numbers."""
    failing = GuestCommandResult(exit_code=1, stdout="agent.log 5\r\n", stderr="")
    server = GuestAgentProtocolServer(responder=_CannedGuest(rules=(("for %I", failing),)))
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS))

    async with _guest(sandbox, server):
        sizes = await sandbox.guest_log_sizes()

    assert sizes == {}


@pytest.mark.asyncio
async def test_guest_log_sizes_are_empty_when_the_guest_cannot_be_asked() -> None:
    """A guest agent that cannot run commands means the sizes are unknown, not an error."""
    server = GuestAgentProtocolServer(unsupported_commands=frozenset({"guest-exec"}))
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS))

    async with _guest(sandbox, server):
        with structlog.testing.capture_logs() as captured:
            sizes = await sandbox.guest_log_sizes()

    assert sizes == {}
    assert len(_events(captured, "guest_log_sizes_unavailable")) == 1


@pytest.mark.asyncio
async def test_copy_to_sandbox_requires_a_shared_folder(tmp_path: Path) -> None:
    """A sandbox with no shared folder cannot accept a file."""
    source = tmp_path / "sample.bin"
    source.write_bytes(b"sample")
    sandbox = _probe()

    with pytest.raises(SandboxError, match="shared folder not init"):
        await sandbox.copy_to_sandbox(source, "input/sample.bin")


@pytest.mark.asyncio
async def test_copy_to_sandbox_names_a_missing_source(tmp_path: Path) -> None:
    """A source file that does not exist is refused and its path is logged."""
    sandbox = _probe()
    sandbox.set_shared_folder(tmp_path / "shared")
    missing = tmp_path / "absent.bin"

    with structlog.testing.capture_logs() as captured, pytest.raises(SandboxError, match="source not found"):
        await sandbox.copy_to_sandbox(missing, "input/absent.bin")

    assert [record["path"] for record in _events(captured, "source_file_not_found")] == [str(missing)]


@pytest.mark.asyncio
async def test_copy_to_a_running_guest_without_an_agent_is_refused(tmp_path: Path) -> None:
    """A running guest that cannot be reached over the agent is not given a host-side copy it could not see."""
    source = tmp_path / "sample.bin"
    source.write_bytes(b"sample")
    shared = tmp_path / "shared"
    shared.mkdir()
    sandbox = _probe()
    sandbox.set_shared_folder(shared)
    sandbox.state.status = "running"

    with pytest.raises(SandboxError, match="qemu-guest-agent channel not connected"):
        await sandbox.copy_to_sandbox(source, "input/sample.bin")

    assert list(shared.rglob("*")) == []


@pytest.mark.asyncio
async def test_copy_to_sandbox_reports_a_source_that_cannot_be_read(tmp_path: Path) -> None:
    """A source the host cannot read is reported as a failed copy with the OS error attached."""
    source = tmp_path / "a-directory"
    source.mkdir()
    shared = tmp_path / "shared"
    shared.mkdir()
    sandbox = _probe()
    sandbox.set_shared_folder(shared)

    with structlog.testing.capture_logs() as captured, pytest.raises(SandboxError, match="copy to sandbox failed") as excinfo:
        await sandbox.copy_to_sandbox(source, "input/a-directory")

    assert isinstance(excinfo.value.__cause__, OSError)
    assert [record["dest"] for record in _events(captured, "copy_to_sandbox_failed")] == ["input/a-directory"]


@pytest.mark.asyncio
async def test_copy_from_sandbox_requires_a_shared_folder_when_no_guest_is_running(tmp_path: Path) -> None:
    """With no running guest the host side of the share is read, and it must exist."""
    sandbox = _probe()

    with pytest.raises(SandboxError, match="shared folder not init"):
        await sandbox.copy_from_sandbox("output/result.txt", tmp_path / "result.txt")


@pytest.mark.asyncio
async def test_copy_from_sandbox_names_a_missing_source(tmp_path: Path) -> None:
    """A file that is not on the share is refused and its relative path is logged."""
    shared = tmp_path / "shared"
    shared.mkdir()
    sandbox = _probe()
    sandbox.set_shared_folder(shared)

    with structlog.testing.capture_logs() as captured, pytest.raises(SandboxError, match="source not found"):
        await sandbox.copy_from_sandbox("output/absent.txt", tmp_path / "out.txt")

    assert [record["path"] for record in _events(captured, "sandbox_source_file_not_found")] == ["output/absent.txt"]


@pytest.mark.asyncio
async def test_copy_from_sandbox_reports_a_source_that_cannot_be_read(tmp_path: Path) -> None:
    """A share entry the host cannot read is reported as a failed copy with the OS error attached."""
    shared = tmp_path / "shared"
    (shared / "output" / "a-directory").mkdir(parents=True)
    sandbox = _probe()
    sandbox.set_shared_folder(shared)

    with structlog.testing.capture_logs() as captured, pytest.raises(SandboxError, match="copy from sandbox failed") as excinfo:
        await sandbox.copy_from_sandbox("output/a-directory", tmp_path / "out.bin")

    assert isinstance(excinfo.value.__cause__, OSError)
    assert [record["source"] for record in _events(captured, "copy_from_sandbox_failed")] == ["output/a-directory"]


@pytest.mark.asyncio
async def test_copy_from_a_running_guest_reports_a_destination_that_cannot_be_written(tmp_path: Path) -> None:
    """A guest file that cannot be written to the host destination is reported as a failed copy."""
    server = GuestAgentProtocolServer()
    server.guest_files[f"{_WORK_ROOT}\\output\\result.txt"] = bytearray(b"guest result")
    destination = tmp_path / "already-a-directory"
    destination.mkdir()
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS))

    async with _guest(sandbox, server):
        with structlog.testing.capture_logs() as captured, pytest.raises(SandboxError, match="copy from sandbox failed") as excinfo:
            await sandbox.copy_from_sandbox("output/result.txt", destination)

    assert isinstance(excinfo.value.__cause__, OSError)
    assert [record["source"] for record in _events(captured, "copy_from_sandbox_failed")] == ["output/result.txt"]


async def _drive_primitive(sandbox: _Probe, operation: str, path: str) -> object:
    """Run one guest-file primitive by name.

    Args:
        sandbox: Sandbox to drive.
        operation: One of ``open``, ``write``, ``open_read``, ``read_chunk`` or ``read_file``.
        path: In-guest path handed to the primitive.

    Returns:
        object: Whatever the primitive returned.
    """
    if operation == "open":
        return await sandbox.open_file(path)
    if operation == "write":
        return await sandbox.write_chunk(1, b"abc", path)
    if operation == "open_read":
        return await sandbox.open_read(path)
    if operation == "read_chunk":
        return await sandbox.read_chunk(1, path)
    return await sandbox.read_file(path)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["open", "write", "open_read", "read_chunk", "read_file"])
async def test_guest_file_primitives_refuse_without_an_agent(operation: str) -> None:
    """Every guest-file primitive refuses to run when no agent channel exists.

    Args:
        operation: Which primitive to drive.
    """
    sandbox = _probe()

    with pytest.raises(SandboxError, match="qemu-guest-agent channel not connected"):
        await _drive_primitive(sandbox, operation, f"{_WORK_ROOT}\\input\\x.bin")


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["open", "open_read"])
@pytest.mark.parametrize("handle", [{"handle": 7}, "seven", None], ids=["mapping", "string", "null"])
async def test_an_open_answered_without_a_handle_is_refused(operation: str, handle: object) -> None:
    """An agent that accepts an open but returns no integer handle is reported as such.

    Args:
        operation: Whether the file is opened for writing or for reading.
        handle: The non-integer value the agent returns in place of a handle.
    """
    channel = _ScriptedAgentChannel({"guest-file-open": [_ok(handle)]})
    sandbox = _probe()
    sandbox.set_qga(channel)
    path = f"{_WORK_ROOT}\\input\\x.bin"

    with pytest.raises(SandboxError, match="returned no file handle") as excinfo:
        await _drive_primitive(sandbox, operation, path)

    assert path in str(excinfo.value)


@pytest.mark.asyncio
async def test_a_refused_guest_write_names_the_path() -> None:
    """An agent that refuses ``guest-file-write`` fails the write with the in-guest path in the message."""
    server = GuestAgentProtocolServer(unsupported_commands=frozenset({"guest-file-write"}))
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS))
    path = f"{_WORK_ROOT}\\input\\x.bin"

    async with _guest(sandbox, server):
        handle = await sandbox.open_file(path)
        with pytest.raises(SandboxError, match="could not write") as excinfo:
            await sandbox.write_chunk(handle, b"abc", path)

    assert path in str(excinfo.value)


@pytest.mark.asyncio
async def test_a_short_guest_write_is_refused() -> None:
    """An agent that accepts fewer bytes than were sent fails the write, and an exact count passes."""
    short = _ScriptedAgentChannel({"guest-file-write": [_ok({"count": 1, "eof": False})]})
    exact = _ScriptedAgentChannel({"guest-file-write": [_ok({"count": 3, "eof": False})]})
    uncounted = _ScriptedAgentChannel({"guest-file-write": [_ok({})]})
    sandbox = _probe()
    path = f"{_WORK_ROOT}\\input\\x.bin"

    sandbox.set_qga(short)
    with pytest.raises(SandboxError) as excinfo:
        await sandbox.write_chunk(7, b"abc", path)
    sandbox.set_qga(exact)
    await sandbox.write_chunk(7, b"abc", path)
    sandbox.set_qga(uncounted)
    await sandbox.write_chunk(7, b"abc", path)

    assert str(excinfo.value) == f"qemu-guest-agent wrote 1 of 3 bytes to {path} inside the guest"
    assert short.script.sent[0] == {
        "execute": "guest-file-write",
        "arguments": {"handle": 7, "buf-b64": base64.b64encode(b"abc").decode("ascii")},
    }


@pytest.mark.asyncio
async def test_reading_a_handle_the_agent_never_opened_names_the_path() -> None:
    """An agent that refuses a read fails it with the in-guest path in the message."""
    server = GuestAgentProtocolServer()
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS))
    path = f"{_WORK_ROOT}\\logs\\x.log"

    async with _guest(sandbox, server):
        with pytest.raises(SandboxError, match="could not read") as excinfo:
            await sandbox.read_chunk(424242, path)

    assert path in str(excinfo.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer",
    [
        None,
        "plain text",
        {"eof": True},
        {"buf-b64": "AAAA"},
        {"buf-b64": "AAAA", "eof": "yes"},
        {"buf-b64": 1234, "eof": True},
    ],
    ids=["null", "text", "no-buffer", "no-eof", "string-eof", "numeric-buffer"],
)
async def test_a_malformed_read_answer_is_refused(answer: object) -> None:
    """An agent whose read reply lacks the documented buffer and end-of-file pair is reported as unreadable.

    Args:
        answer: The malformed ``return`` member the agent sends.
    """
    channel = _ScriptedAgentChannel({"guest-file-read": [_ok(answer)]})
    sandbox = _probe()
    sandbox.set_qga(channel)
    path = f"{_WORK_ROOT}\\logs\\x.log"

    with pytest.raises(SandboxError, match="unreadable answer while reading") as excinfo:
        await sandbox.read_chunk(7, path)

    assert path in str(excinfo.value)


@pytest.mark.asyncio
async def test_a_read_answer_that_is_not_base64_is_refused_and_a_valid_one_is_decoded() -> None:
    """A buffer that is not valid base64 is reported as unreadable, while a valid one round-trips."""
    garbled = _ScriptedAgentChannel({"guest-file-read": [_ok({"buf-b64": "!!!not-base64!!!", "eof": True})]})
    valid = _ScriptedAgentChannel({"guest-file-read": [_ok({"buf-b64": base64.b64encode(b"payload").decode("ascii"), "eof": True})]})
    sandbox = _probe()
    path = f"{_WORK_ROOT}\\logs\\x.log"

    sandbox.set_qga(garbled)
    with pytest.raises(SandboxError, match="unreadable answer while reading") as excinfo:
        await sandbox.read_chunk(7, path)
    sandbox.set_qga(valid)
    chunk = await sandbox.read_chunk(7, path)

    assert excinfo.value.__cause__ is not None
    assert chunk == (b"payload", True)


@pytest.mark.asyncio
async def test_a_guest_file_larger_than_the_collection_limit_is_refused() -> None:
    """A file that keeps producing data past 64 MiB is refused rather than collected without bound."""
    block = base64.b64encode(bytes(24 * _MIB)).decode("ascii")
    channel = _ScriptedAgentChannel(
        {
            "guest-file-open": [_ok(11)],
            "guest-file-read": [_ok({"buf-b64": block, "eof": False})],
            "guest-file-close": [_ok({})],
        },
    )
    sandbox = _probe()
    sandbox.set_qga(channel)
    path = f"{_WORK_ROOT}\\output\\huge.bin"

    with pytest.raises(SandboxError, match="larger than") as excinfo:
        await sandbox.read_file(path)

    assert str(excinfo.value) == f"{path} inside the guest is larger than the {_READ_LIMIT_BYTES} bytes the host will collect in one read"
    assert channel.script.names() == ["guest-file-open", "guest-file-read", "guest-file-read", "guest-file-read", "guest-file-close"]


@pytest.mark.asyncio
async def test_a_refused_close_is_logged_and_does_not_raise() -> None:
    """An agent that refuses to close a handle is warned about, not treated as fatal."""
    server = GuestAgentProtocolServer(unsupported_commands=frozenset({"guest-file-close"}))
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS))

    async with _guest(sandbox, server):
        with structlog.testing.capture_logs() as captured:
            await sandbox.close_file(1000)

    assert [record["handle"] for record in _events(captured, "guest_file_close_failed")] == [1000]


@pytest.mark.asyncio
async def test_closing_a_guest_file_without_an_agent_does_nothing() -> None:
    """With no agent channel there is nothing to close and nothing is logged as a failure."""
    sandbox = _probe()

    with structlog.testing.capture_logs() as captured:
        await sandbox.close_file(1)

    assert _events(captured, "guest_file_close_failed") == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("dest", "expected_directory", "expected_file"),
    [
        ("solo.bin", f"{_WORK_ROOT}", f"{_WORK_ROOT}\\solo.bin"),
        ("input/tool.bin", f"{_WORK_ROOT}\\input", f"{_WORK_ROOT}\\input\\tool.bin"),
    ],
    ids=["work-root", "nested"],
)
async def test_staging_creates_the_destination_directory_before_writing(
    tmp_path: Path,
    dest: str,
    expected_directory: str,
    expected_file: str,
) -> None:
    """The directory a staged file lands in is created in the guest first, including the work root itself.

    Args:
        tmp_path: Directory holding the host source.
        dest: Destination relative to the guest work root.
        expected_directory: Directory the guest should be asked to create.
        expected_file: In-guest path the bytes should arrive at.
    """
    source = tmp_path / "payload.bin"
    source.write_bytes(b"staged bytes")
    server = GuestAgentProtocolServer()
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS))

    async with _guest(sandbox, server):
        await sandbox.stage_file(source, dest)

    assert [(record.path, record.args) for record in server.exec_records] == [("cmd.exe", ("/c", "mkdir", expected_directory))]
    assert bytes(server.guest_files[expected_file]) == b"staged bytes"


@pytest.mark.asyncio
async def test_a_directory_that_cannot_be_created_is_tolerated() -> None:
    """Directory creation is best-effort: a missing agent is logged at debug level and not raised."""
    sandbox = _probe(QEMUConfig(guest_os=GuestOS.WINDOWS))

    with structlog.testing.capture_logs() as captured:
        await sandbox.ensure_dir(f"{_WORK_ROOT}\\input")

    failed = _events(captured, "guest_directory_create_failed")
    assert [record["guest_dir"] for record in failed] == [f"{_WORK_ROOT}\\input"]
    assert failed[0]["error"] == "qemu-guest-agent channel not connected"


_BLOCK_DEVICES: Final[list[object]] = [
    "not-a-record",
    {"device": "ide1-cd0", "locked": False},
    {"device": "virtio0", "inserted": {"drv": "qcow2", "ro": False, "node-name": "overlay0"}},
    {"device": "install", "inserted": {"drv": "qcow2", "ro": True, "node-name": "media0"}},
    {"device": "", "inserted": {"drv": "qcow2", "ro": False, "node-name": "anonymous"}},
    {"device": "raw0", "inserted": {"drv": "raw", "ro": False, "node-name": "rawnode"}},
    {"device": "vdb", "inserted": {"drv": "qcow2", "ro": False}},
]


@pytest.mark.asyncio
async def test_block_devices_without_a_monitor_are_refused() -> None:
    """The device queries need a connected monitor."""
    sandbox = _probe()

    with pytest.raises(SandboxError, match="QMP not connected"):
        await sandbox.query_devices()
    with pytest.raises(SandboxError, match="QMP not connected"):
        await sandbox.target_devices()
    with pytest.raises(SandboxError, match="QMP not connected"):
        await sandbox.target_nodes()


@pytest.mark.asyncio
async def test_block_device_query_keeps_only_devices_with_media() -> None:
    """Entries that are not records, or hold no medium, are skipped; every inserted medium is returned."""
    monitor = _ScriptedMonitor({"query-block": [_ok(_BLOCK_DEVICES)]})
    sandbox = _probe()
    sandbox.set_qmp(monitor)

    media = await sandbox.query_devices()

    assert [(medium.get("drv"), medium.get("ro"), medium.get("node-name")) for medium in media] == [
        ("qcow2", False, "overlay0"),
        ("qcow2", True, "media0"),
        ("qcow2", False, "anonymous"),
        ("raw", False, "rawnode"),
        ("qcow2", False, None),
    ]


@pytest.mark.asyncio
async def test_snapshot_targets_are_the_writable_qcow2_devices_and_nodes() -> None:
    """Only a writable qcow2 can hold a snapshot, addressed by device id or by node name as the command needs."""
    monitor = _ScriptedMonitor({"query-block": [_ok(_BLOCK_DEVICES)]})
    sandbox = _probe()
    sandbox.set_qmp(monitor)

    devices = await sandbox.target_devices()
    nodes = await sandbox.target_nodes()

    assert devices == ["virtio0", "vdb"]
    assert nodes == ["overlay0", "anonymous"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reply",
    [
        _refused("monitor busy"),
        _ok(None),
        _ok([]),
        _ok("not a list"),
        _ok([{"device": "install", "inserted": {"drv": "qcow2", "ro": True}}]),
    ],
)
async def test_snapshot_targets_are_refused_when_no_disk_can_hold_one(reply: QMPResponse) -> None:
    """A refused query, an empty list, or only read-only media all mean there is nothing to snapshot.

    Args:
        reply: The scripted ``query-block`` reply.
    """
    sandbox = _probe()
    sandbox.set_qmp(_ScriptedMonitor({"query-block": [reply]}))
    expected = "the running guest exposes no writable qcow2 disk, so there is nothing that can hold a snapshot"

    with pytest.raises(SandboxError) as devices_error:
        await sandbox.target_devices()
    with pytest.raises(SandboxError) as nodes_error:
        await sandbox.target_nodes()

    assert str(devices_error.value) == expected
    assert str(nodes_error.value) == expected


@pytest.mark.asyncio
async def test_a_refused_block_query_is_logged_with_its_reason() -> None:
    """A monitor that refuses ``query-block`` is logged with its own reason by each query."""
    sandbox = _probe()
    sandbox.set_qmp(_ScriptedMonitor({"query-block": [_refused("monitor busy")]}))

    with structlog.testing.capture_logs() as captured:
        with pytest.raises(SandboxError):
            await sandbox.query_devices()
        with pytest.raises(SandboxError):
            await sandbox.target_devices()

    assert [record["error"] for record in _events(captured, "query_block_failed")] == ["monitor busy", "monitor busy"]


@pytest.mark.asyncio
async def test_disk_only_snapshot_is_taken_on_every_writable_device_in_order() -> None:
    """A disk-only snapshot sends one synchronous command per target device, naming the device and the snapshot."""
    monitor = _ScriptedMonitor({"query-block": [_ok(_BLOCK_DEVICES)], "blockdev-snapshot-internal-sync": [_ok({})]})
    sandbox = _probe()
    sandbox.set_qmp(monitor)

    await sandbox.take_disk_snapshot("before-run")

    assert monitor.script.sent[1:] == [
        {"execute": "blockdev-snapshot-internal-sync", "arguments": {"device": "virtio0", "name": "before-run"}},
        {"execute": "blockdev-snapshot-internal-sync", "arguments": {"device": "vdb", "name": "before-run"}},
    ]


@pytest.mark.asyncio
async def test_disk_only_snapshot_stops_at_the_first_refusal() -> None:
    """A device that refuses the snapshot fails the whole operation with its id and reason."""
    monitor = _ScriptedMonitor(
        {
            "query-block": [_ok(_BLOCK_DEVICES)],
            "blockdev-snapshot-internal-sync": [_ok({}), _refused("no space left")],
        },
    )
    sandbox = _probe()
    sandbox.set_qmp(monitor)

    with structlog.testing.capture_logs() as captured, pytest.raises(SandboxError) as excinfo:
        await sandbox.take_disk_snapshot("before-run")

    assert str(excinfo.value) == "disk-only snapshot of device 'vdb' failed: no space left"
    assert [record["device"] for record in _events(captured, "snapshot_disk_only_failed")] == ["vdb"]


@pytest.mark.asyncio
async def test_disk_only_snapshot_names_a_refusal_that_carries_no_reason() -> None:
    """A refusal with no description is reported as QEMU refusing the request."""
    monitor = _ScriptedMonitor(
        {
            "query-block": [_ok(_BLOCK_DEVICES)],
            "blockdev-snapshot-internal-sync": [_refused(None)],
        },
    )
    sandbox = _probe()
    sandbox.set_qmp(monitor)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.take_disk_snapshot("before-run")

    assert str(excinfo.value) == "disk-only snapshot of device 'virtio0' failed: QEMU refused the request"


@pytest.mark.asyncio
async def test_disk_only_snapshot_without_a_monitor_is_refused() -> None:
    """Taking a disk-only snapshot needs a connected monitor."""
    sandbox = _probe()

    with pytest.raises(SandboxError, match="QMP not connected"):
        await sandbox.take_disk_snapshot("before-run")


def test_snapshot_job_ids_carry_their_action_and_differ() -> None:
    """A job id is ``intellicrack-<action>-`` plus eight hex digits, and successive ids differ."""
    ids = [_Probe.new_job_id("save") for _ in range(5)]

    assert all(re.fullmatch(r"intellicrack-save-[0-9a-f]{8}", job_id) for job_id in ids)
    assert len(set(ids)) == len(ids)
    assert re.fullmatch(r"intellicrack-delete-[0-9a-f]{8}", _Probe.new_job_id("delete"))


def test_finding_a_job_skips_entries_that_are_not_the_one_asked_for() -> None:
    """Only the record whose id matches is returned; junk entries and other jobs are skipped."""
    wanted = {"id": "job-2", "status": "running"}
    payload: list[object] = ["junk", 5, {"id": "job-1", "status": "concluded"}, wanted]

    assert _Probe.find_job(payload, "job-2") is wanted
    assert _Probe.find_job(payload, "job-9") is None
    assert _Probe.find_job(None, "job-2") is None
    assert _Probe.find_job("not a list", "job-2") is None


@pytest.mark.asyncio
async def test_waiting_for_a_job_without_a_monitor_is_refused() -> None:
    """Waiting on a snapshot job needs a connected monitor."""
    sandbox = _probe()

    with pytest.raises(SandboxError, match="QMP not connected"):
        await sandbox.await_job("job-1", "snapshot create failed")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        (_refused("monitor gone"), "snapshot create failed: monitor gone"),
        (_refused(None), "snapshot create failed: the job list could not be read, so the outcome is unknown"),
    ],
    ids=["with-reason", "without-reason"],
)
async def test_an_unreadable_job_list_fails_the_wait(reply: QMPResponse, expected: str) -> None:
    """A job list that cannot be read fails the wait with the monitor's reason, or an explanation of the unknown outcome.

    Args:
        reply: The scripted ``query-jobs`` reply.
        expected: The failure message the caller should see.
    """
    sandbox = _probe()
    sandbox.set_qmp(_ScriptedMonitor({"query-jobs": [reply]}))

    with structlog.testing.capture_logs() as captured, pytest.raises(SandboxError) as excinfo:
        await sandbox.await_job("job-1", "snapshot create failed")

    assert str(excinfo.value) == expected
    assert [record["job_id"] for record in _events(captured, "snapshot_job_query_failed")] == ["job-1"]


@pytest.mark.asyncio
async def test_a_job_that_vanishes_from_the_list_fails_the_wait() -> None:
    """A job QEMU stops reporting before it concluded is a failure, not a success."""
    sandbox = _probe()
    sandbox.set_qmp(_ScriptedMonitor({"query-jobs": [_ok([{"id": "other-job", "status": "running"}])]}))

    with structlog.testing.capture_logs() as captured, pytest.raises(SandboxError) as excinfo:
        await sandbox.await_job("job-1", "snapshot create failed")

    assert str(excinfo.value) == "snapshot create failed: QEMU stopped reporting job job-1 before it finished"
    assert [record["job_id"] for record in _events(captured, "snapshot_job_vanished")] == ["job-1"]


@pytest.mark.asyncio
async def test_a_concluded_job_that_carries_an_error_fails_the_wait_and_is_dismissed() -> None:
    """A job that concluded with an error fails the wait with that error, and is still dismissed."""
    monitor = _ScriptedMonitor(
        {
            "query-jobs": [_ok([{"id": "job-1", "status": "concluded", "error": "disk full"}])],
            "job-dismiss": [_ok({})],
        },
    )
    sandbox = _probe()
    sandbox.set_qmp(monitor)

    with structlog.testing.capture_logs() as captured, pytest.raises(SandboxError) as excinfo:
        await sandbox.await_job("job-1", "snapshot create failed")

    assert str(excinfo.value) == "snapshot create failed: disk full"
    assert monitor.script.sent[-1] == {"execute": "job-dismiss", "arguments": {"id": "job-1"}}
    assert [record["error"] for record in _events(captured, "snapshot_job_failed")] == ["disk full"]


@pytest.mark.asyncio
async def test_a_job_that_concludes_after_running_succeeds_and_is_dismissed() -> None:
    """A running job is polled again, and once it concludes without an error the wait returns and dismisses it."""
    monitor = _ScriptedMonitor(
        {
            "query-jobs": [
                _ok([{"id": "job-1", "status": "running"}]),
                _ok([{"id": "job-1", "status": "concluded"}]),
            ],
            "job-dismiss": [_ok({})],
        },
    )
    sandbox = _probe()
    sandbox.set_qmp(monitor)

    await sandbox.await_job("job-1", "snapshot create failed")

    assert monitor.script.names() == ["query-jobs", "query-jobs", "job-dismiss"]


@pytest.mark.asyncio
async def test_a_job_that_never_concludes_times_out_naming_the_budget() -> None:
    """A job still running when the snapshot budget is spent fails the wait with the budget in the message."""
    monitor = _ScriptedMonitor({"query-jobs": [_ok([{"id": "job-1", "status": "running"}])]})
    sandbox = _probe(QEMUConfig(snapshot_timeout=0.3))
    sandbox.set_qmp(monitor)

    with structlog.testing.capture_logs() as captured, pytest.raises(SandboxError) as excinfo:
        await sandbox.await_job("job-1", "snapshot create failed")

    assert str(excinfo.value) == "snapshot create failed: job job-1 had not finished after 0s"
    assert [record["budget"] for record in _events(captured, "snapshot_job_timed_out")] == [0.3]
    assert "job-dismiss" not in monitor.script.names()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("monitor_state", "expected"),
    [
        (_ok({"status": "running", "running": True}), True),
        (_ok({"status": "paused", "running": False}), False),
        (_ok({"status": "running", "running": "yes"}), False),
        (_ok("not a mapping"), False),
        (_ok(None), False),
        (_refused("monitor busy"), False),
    ],
    ids=["running", "paused", "non-boolean", "text", "null", "refused"],
)
async def test_machine_run_state_is_true_only_when_qemu_says_so(*, monitor_state: QMPResponse, expected: bool) -> None:
    """Only an explicit boolean ``running: true`` counts as running; everything else is not.

    Args:
        monitor_state: The scripted ``query-status`` reply.
        expected: Whether the machine should be reported as running.
    """
    sandbox = _probe()
    sandbox.set_qmp(_ScriptedMonitor({"query-status": [monitor_state]}))

    assert await sandbox.machine_running() is expected


@pytest.mark.asyncio
async def test_machine_run_state_without_a_monitor_is_not_running() -> None:
    """With no monitor the machine is not reported as running."""
    sandbox = _probe()

    assert await sandbox.machine_running() is False


@pytest.mark.asyncio
async def test_an_unreadable_run_state_is_logged_with_its_reason() -> None:
    """A refused status query is warned about, so the unknown state is visible."""
    sandbox = _probe()
    sandbox.set_qmp(_ScriptedMonitor({"query-status": [_refused("monitor busy")]}))

    with structlog.testing.capture_logs() as captured:
        running = await sandbox.machine_running()

    assert running is False
    assert [record["error"] for record in _events(captured, "snapshot_run_state_unreadable")] == ["monitor busy"]


@pytest.mark.asyncio
async def test_a_machine_that_was_not_running_is_left_alone() -> None:
    """A machine the operator had stopped is not started by a failed job, and no command is sent."""
    monitor = _ScriptedMonitor({"query-status": [_ok({"running": False})], "cont": [_ok({})]})
    sandbox = _probe()
    sandbox.set_qmp(monitor)

    clause = await sandbox.resume_failed("restore", was_running=False)

    assert not clause
    assert monitor.script.sent == []


@pytest.mark.asyncio
async def test_resuming_without_a_monitor_leaves_no_clause() -> None:
    """With no monitor there is nothing to resume and nothing to report."""
    sandbox = _probe()

    assert not await sandbox.resume_failed("restore", was_running=True)


@pytest.mark.asyncio
async def test_a_machine_that_is_still_running_is_not_resumed() -> None:
    """A job that left the machine running needs no resume, and no ``cont`` is sent."""
    monitor = _ScriptedMonitor({"query-status": [_ok({"running": True})], "cont": [_ok({})]})
    sandbox = _probe()
    sandbox.set_qmp(monitor)

    clause = await sandbox.resume_failed("restore", was_running=True)

    assert not clause
    assert monitor.script.names() == ["query-status"]


@pytest.mark.asyncio
async def test_a_machine_stopped_by_a_failed_job_is_resumed_and_the_clause_says_so() -> None:
    """A machine the failed job stopped is continued, and the failure message gains a clause saying so."""
    monitor = _ScriptedMonitor(
        {
            "query-status": [_ok({"running": False}), _ok({"running": True})],
            "cont": [_ok({})],
        },
    )
    sandbox = _probe()
    sandbox.set_qmp(monitor)

    with structlog.testing.capture_logs() as captured:
        clause = await sandbox.resume_failed("restore", was_running=True)

    assert clause == "; the machine was left stopped by the failed job and has been resumed"
    assert monitor.script.names() == ["query-status", "cont", "query-status"]
    assert [record["action"] for record in _events(captured, "snapshot_machine_resumed")] == ["restore"]


@pytest.mark.asyncio
async def test_a_machine_that_cannot_be_resumed_is_reported_with_the_reason() -> None:
    """A refused ``cont`` leaves the machine stopped, and the clause carries QEMU's reason."""
    monitor = _ScriptedMonitor({"query-status": [_ok({"running": False})], "cont": [_refused("no memory")]})
    sandbox = _probe()
    sandbox.set_qmp(monitor)

    with structlog.testing.capture_logs() as captured:
        clause = await sandbox.resume_failed("restore", was_running=True)

    assert clause == "; the machine was left stopped by the failed job and could not be resumed: no memory"
    assert [record["error"] for record in _events(captured, "snapshot_machine_left_stopped")] == ["no memory"]


@pytest.mark.asyncio
async def test_a_machine_that_stays_stopped_after_cont_is_reported_as_unresumed() -> None:
    """A ``cont`` that is accepted but does not start the machine is still reported as not resumed."""
    monitor = _ScriptedMonitor({"query-status": [_ok({"running": False})], "cont": [_ok({})]})
    sandbox = _probe()
    sandbox.set_qmp(monitor)

    clause = await sandbox.resume_failed("restore", was_running=True)

    assert clause == (
        "; the machine was left stopped by the failed job and could not be resumed: "
        "the job list could not be read, so the outcome is unknown"
    )
    assert monitor.script.names() == ["query-status", "cont", "query-status"]
