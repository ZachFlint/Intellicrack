# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Coverage for the QEMU transports, accelerator probes and host-side guest helpers.

None of this needs QEMU itself. The monitor and guest-agent clients are driven
against the real loopback protocol servers the QEMU test package already ships,
or against a real ``asyncio.StreamReader`` fed the bytes a peer would have
written, so the shipped line framing, resynchronisation and recovery logic does
the work. Host-side helpers run on real files in ``tmp_path`` and on the host's
own PowerShell, ``bcdedit`` and ``cmd`` tools, and every expectation about their
output is computed independently of the product code.
"""

from __future__ import annotations

import asyncio
import base64
import os
import re
import shutil
import socket
import struct
import sys
import tempfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final, Protocol, cast, override

import pytest
import structlog.testing

from intellicrack.core.process_manager import ProcessManager
from intellicrack.core.subprocess_compat import run as run_process
from intellicrack.sandbox import qemu as qemu_module
from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import (
    AcceleratorType,
    GuestAgentClient,
    GuestAgentMessage,
    GuestExecStatus,
    GuestOS,
    QEMUConfig,
    QemuGuestAgentClient,
    QemuJsonProtocolClient,
    QemuOutputRecorder,
    QEMUSandbox,
    QemuTermination,
    QMPClient,
    QMPResponse,
    enumerate_traceevent_assembly_files,
)
from tests.sandbox.qemu.guest_agent_server import (
    GuestAgentProtocolServer,
    GuestCommandResult,
    IntellicrackAgentServer,
    QmpProtocolServer,
    SilentGuestAgentServer,
    free_port,
)


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable, Sequence

    from tests.sandbox.qemu.guest_agent_server import GuestCommandResponder

_STEP_TIMEOUT: Final[float] = 5.0
_BRIEF_TIMEOUT: Final[float] = 0.3
_QEMU_EXE_NAME: Final[str] = "qemu-system-x86_64.exe"
_QEMU_IMG_NAME: Final[str] = "qemu-img.exe"
_LOOPBACK: Final[str] = "127.0.0.1"
_WILDCARD: Final[str] = socket.inet_ntoa(struct.pack("!I", socket.INADDR_ANY))
_RESERVED_PORT_WINDOW: Final[int] = 2
_VNC_RANGE_FIRST: Final[int] = 5900
_VNC_RANGE_LAST: Final[int] = 5999
_STATUS_POLL_PID: Final[int] = 4242

_file_size_or_zero = cast("Callable[[Path], int]", getattr(qemu_module, "_file_size_or_zero"))
_read_ppm_token = cast("Callable[[bytes, int], tuple[str, int]]", getattr(qemu_module, "_read_ppm_token"))
_parse_ppm_p6 = cast("Callable[[bytes], tuple[int, int, bytes]]", getattr(qemu_module, "_parse_ppm_p6"))


class _Server(Protocol):
    """Lifecycle shared by every loopback protocol server used here."""

    port: int

    async def start(self) -> int:
        """Bind the server.

        Returns:
            int: The bound port.
        """
        ...

    async def stop(self) -> None:
        """Close the server."""
        ...


@asynccontextmanager
async def _serving[ServerT: _Server](server: ServerT) -> AsyncGenerator[ServerT]:
    """Run a loopback protocol server for the length of a ``with`` block.

    Args:
        server: The server to start.

    Yields:
        ServerT: The started server.
    """
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


class _ExposedTransport(QemuJsonProtocolClient):
    """The shared JSON transport with its private entry points made callable."""

    def attach_reader(self, reader: asyncio.StreamReader) -> None:
        """Make ``reader`` the stream replies are read from.

        Args:
            reader: A real stream reader holding the bytes to read.
        """
        self._reader = reader

    async def exchange(self, command: dict[str, object], time_limit: float) -> QMPResponse:
        """Forward to ``_exchange_command``.

        Args:
            command: Command dictionary.
            time_limit: Reply deadline in seconds.

        Returns:
            QMPResponse: The transport's answer.
        """
        return await self._exchange_command(command, time_limit)

    async def read_line(self, time_limit: float) -> bytes:
        """Forward to ``_read_line``.

        Args:
            time_limit: Read deadline in seconds.

        Returns:
            bytes: The raw frame.
        """
        return await self._read_line(time_limit)

    @staticmethod
    def decode_reply(payload: dict[str, Any]) -> QMPResponse:
        """Forward to ``_decode_reply``.

        Args:
            payload: Decoded reply mapping.

        Returns:
            QMPResponse: The decoded response.
        """
        return QemuJsonProtocolClient._decode_reply(payload)


class _RetainingStuckClient(QemuJsonProtocolClient):
    """A transport on a hand-out-once channel whose resync never gets answered."""

    _retain_socket_on_handshake_failure: ClassVar[bool] = True

    @override
    async def _on_command_timeout(self) -> None:
        """Report the resync as unanswered, as a silent guest would.

        Raises:
            SandboxError: Always.
        """
        message = "resync unanswered"
        raise SandboxError(message)


class _DiscardingStuckClient(QemuJsonProtocolClient):
    """A transport on a re-listening channel whose resync never gets answered."""

    @override
    async def _on_command_timeout(self) -> None:
        """Report the resync as unanswered.

        Raises:
            SandboxError: Always.
        """
        message = "resync unanswered"
        raise SandboxError(message)


class _RefusedHandshakeClient(QemuJsonProtocolClient):
    """A transport whose protocol handshake is refused after the socket opens."""

    @override
    async def _handshake(self, time_limit: float) -> None:
        """Refuse the handshake.

        Args:
            time_limit: Handshake deadline, unused.

        Raises:
            SandboxError: Always.
        """
        del time_limit
        message = "handshake refused"
        raise SandboxError(message)


class _ExposedQmp(QMPClient):
    """The monitor client with its private entry points made callable."""

    def attach_reader(self, reader: asyncio.StreamReader) -> None:
        """Make ``reader`` the stream replies are read from.

        Args:
            reader: A real stream reader holding the bytes to read.
        """
        self._reader = reader

    async def exchange(self, command: dict[str, object], time_limit: float) -> QMPResponse:
        """Forward to ``_exchange_command``.

        Args:
            command: Command dictionary.
            time_limit: Reply deadline in seconds.

        Returns:
            QMPResponse: The client's answer.
        """
        return await self._exchange_command(command, time_limit)

    async def read_tagged_reply(self, token: str, time_limit: float) -> dict[str, Any]:
        """Forward to ``_read_tagged_reply``.

        Args:
            token: Command id to match.
            time_limit: Reply deadline in seconds.

        Returns:
            dict[str, Any]: The matching frame.
        """
        return await self._read_tagged_reply(token, time_limit)

    async def handshake(self, time_limit: float) -> None:
        """Forward to ``_handshake``.

        Args:
            time_limit: Handshake deadline in seconds.
        """
        await self._handshake(time_limit)


class _ExposedQga(QemuGuestAgentClient):
    """The guest-agent channel client with its private entry points made callable."""

    def attach_reader(self, reader: asyncio.StreamReader) -> None:
        """Make ``reader`` the stream replies are read from.

        Args:
            reader: A real stream reader holding the bytes to read.
        """
        self._reader = reader

    async def close_writer_locally(self) -> None:
        """Close this end of the socket while keeping the client's references to it."""
        writer = self._writer
        assert writer is not None
        writer.close()
        await writer.wait_closed()

    async def read_line(self, time_limit: float) -> bytes:
        """Forward to ``_read_line``.

        Args:
            time_limit: Read deadline in seconds.

        Returns:
            bytes: The raw frame.
        """
        return await self._read_line(time_limit)

    async def read_reply(self, time_limit: float) -> dict[str, Any]:
        """Forward to ``_read_reply``.

        Args:
            time_limit: Reply deadline in seconds.

        Returns:
            dict[str, Any]: The first reply-shaped frame.
        """
        return await self._read_reply(time_limit)

    async def synchronise(self, time_limit: float) -> None:
        """Forward to ``_synchronise``.

        Args:
            time_limit: Sync deadline in seconds.
        """
        await self._synchronise(time_limit)

    async def attempt_sync(self, command: str, time_limit: float) -> tuple[bool, bool]:
        """Forward to ``_attempt_sync``.

        Args:
            command: Sync command name.
            time_limit: Deadline for this attempt.

        Returns:
            tuple[bool, bool]: Whether the id matched and whether the agent
            rejected the command as unsupported.
        """
        outcome = await self._attempt_sync(command, time_limit)
        return outcome.matched, outcome.unsupported

    async def await_sync_id(self, sync_id: int, time_limit: float) -> tuple[bool, bool]:
        """Forward to ``_await_sync_id``.

        Args:
            sync_id: Sync id to wait for.
            time_limit: Deadline in seconds.

        Returns:
            tuple[bool, bool]: Whether the id matched and whether the agent
            rejected the command as unsupported.
        """
        outcome = await self._await_sync_id(sync_id, time_limit)
        return outcome.matched, outcome.unsupported

    async def on_command_timeout(self) -> None:
        """Forward to ``_on_command_timeout``."""
        await self._on_command_timeout()

    async def on_channel_reset(self, error: Exception) -> None:
        """Forward to ``_on_channel_reset``.

        Args:
            error: The socket error that ended the previous exchange.
        """
        await self._on_channel_reset(error)

    @classmethod
    def decode_exec_status(cls, payload: dict[str, object]) -> GuestExecStatus:
        """Forward to ``_decode_exec_status``.

        Args:
            payload: ``return`` mapping from a ``guest-exec-status`` reply.

        Returns:
            GuestExecStatus: The decoded status.
        """
        return cls._decode_exec_status(payload)


class _UnansweredHandshakeQga(_ExposedQga):
    """A channel client whose socket opens but whose sync handshake is never answered."""

    @override
    async def _handshake(self, time_limit: float) -> None:
        """Leave the handshake unanswered.

        Args:
            time_limit: Handshake deadline, unused.

        Raises:
            SandboxError: Always.
        """
        del time_limit
        message = "sync unanswered"
        raise SandboxError(message)


class _ExposedAgent(GuestAgentClient):
    """The in-guest agent client with its private entry points made callable."""

    def attach_reader(self, reader: asyncio.StreamReader) -> None:
        """Make ``reader`` the stream messages are read from.

        Args:
            reader: A real stream reader holding the bytes to read.
        """
        self._reader = reader

    async def close_writer_locally(self) -> None:
        """Close this end of the socket while keeping the client's references to it."""
        writer = self._writer
        assert writer is not None
        writer.close()
        await writer.wait_closed()

    @classmethod
    def is_pong(cls, line: bytes) -> bool:
        """Forward to ``_is_pong_line``.

        Args:
            line: One received line.

        Returns:
            bool: Whether the line is the readiness reply.
        """
        return cls._is_pong_line(line)

    async def await_readiness_reply(self, reader: asyncio.StreamReader, time_limit: float) -> None:
        """Forward to ``_await_readiness_reply``.

        Args:
            reader: Stream to read the reply from.
            time_limit: Handshake budget in seconds.
        """
        await self._await_readiness_reply(reader, time_limit)

    async def handshake(self, time_limit: float) -> None:
        """Forward to ``_handshake``.

        Args:
            time_limit: Handshake budget in seconds.
        """
        await self._handshake(time_limit)

    async def abandon_socket(self) -> None:
        """Forward to ``_abandon_socket``."""
        await self._abandon_socket()

    async def enqueue_line(self, line: bytes) -> None:
        """Forward to ``_enqueue_agent_line``.

        Args:
            line: One raw agent line.
        """
        await self._enqueue_agent_line(line)

    async def read_messages(self) -> None:
        """Forward to ``_read_messages``."""
        await self._read_messages()

    def put_message(self, message: GuestAgentMessage) -> None:
        """Queue a message the way the reader task would.

        Args:
            message: The message to queue.
        """
        self._message_queue.put_nowait(message)

    def discard_orphaned_results(self) -> int:
        """Forward to ``_discard_orphaned_results``.

        Returns:
            int: How many results were discarded.
        """
        return self._discard_orphaned_results()

    def take_queued_result(self) -> GuestAgentMessage | None:
        """Forward to ``_take_queued_result``.

        Returns:
            GuestAgentMessage | None: The first queued result, if any.
        """
        return self._take_queued_result()

    async def await_guest_result(self, time_limit: float) -> GuestAgentMessage | None:
        """Forward to ``_await_guest_result``.

        Args:
            time_limit: Wall-clock deadline in seconds.

        Returns:
            GuestAgentMessage | None: The result message, if one arrived.
        """
        return await self._await_guest_result(time_limit)

    async def run_with_recovery(self, request: dict[str, object], time_limit: float) -> tuple[int, str, str]:
        """Forward to ``_run_with_channel_recovery``.

        Args:
            request: Request payload.
            time_limit: Reply deadline in seconds.

        Returns:
            tuple[int, str, str]: ``(exit_code, stdout, stderr)``.
        """
        return await self._run_with_channel_recovery(request, time_limit)


class _SingleAttemptAgent(_ExposedAgent):
    """An agent client that allows one dispatch attempt per command."""

    MAX_DISPATCH_ATTEMPTS: ClassVar[int] = 1


class _ImpatientAgent(_ExposedAgent):
    """An agent client that gives up re-opening a lost channel almost at once."""

    RECONNECT_TIME_LIMIT: ClassVar[float] = _BRIEF_TIMEOUT
    RECONNECT_RETRY_INTERVAL: ClassVar[float] = 0.1


class _ExposedRecorder(QemuOutputRecorder):
    """The output recorder with its background task made observable."""

    def current_task(self) -> asyncio.Task[None] | None:
        """Return the draining task.

        Returns:
            asyncio.Task[None] | None: The task, or None when none is running.
        """
        return self._task

    async def wait_recorded(self) -> None:
        """Wait for the draining task to record how the process ended."""
        task = self._task
        assert task is not None
        await task


class _ExposedSandbox(QEMUSandbox):
    """The QEMU sandbox with its private state and helpers made callable."""

    def set_qga(self, client: QemuGuestAgentClient | None) -> None:
        """Install the guest-agent channel client.

        Args:
            client: The client, or None to clear it.
        """
        self._qga = client

    def set_qemu_path(self, path: Path | None) -> None:
        """Record where the QEMU binary is.

        Args:
            path: The binary's path, or None.
        """
        self._qemu_path = path

    def peek_qemu_path(self) -> Path | None:
        """Return the recorded QEMU binary path.

        Returns:
            Path | None: The path, or None.
        """
        return self._qemu_path

    def set_temp_dir(self, path: Path | None) -> None:
        """Record the instance's temporary directory.

        Args:
            path: The directory, or None.
        """
        self._temp_dir = path

    def peek_temp_dir(self) -> Path | None:
        """Return the instance's temporary directory.

        Returns:
            Path | None: The directory, or None.
        """
        return self._temp_dir

    def peek_claimed_ports(self) -> set[int]:
        """Return a copy of the ports this sandbox has claimed.

        Returns:
            set[int]: The claimed ports.
        """
        return set(self._claimed_host_ports)

    def release_claimed_ports(self) -> None:
        """Hand every claimed port back to the process-wide allocator."""
        QEMUSandbox._release_host_ports(set(self._claimed_host_ports))
        self._claimed_host_ports.clear()

    def set_accelerator_cached(self, *, cached: bool) -> None:
        """Set whether the accelerator probe result is cached.

        Args:
            cached: The cache flag.
        """
        self._accelerator_cached = cached

    def peek_accelerator_cached(self) -> bool:
        """Return whether the accelerator probe result is cached.

        Returns:
            bool: The cache flag.
        """
        return self._accelerator_cached

    def peek_accelerator(self) -> AcceleratorType:
        """Return the recorded accelerator.

        Returns:
            AcceleratorType: The accelerator.
        """
        return self._accelerator

    async def find_qemu(self) -> Path | None:
        """Forward to ``_find_qemu``.

        Returns:
            Path | None: The executable, if found.
        """
        return await self._find_qemu()

    @staticmethod
    def hypervisor_present_unelevated() -> bool | None:
        """Forward to ``_hypervisor_present_unelevated``.

        Returns:
            bool | None: The hypervisor-present flag, or None.
        """
        return QEMUSandbox._hypervisor_present_unelevated()

    @staticmethod
    def probe_whpx_prerequisites() -> bool:
        """Forward to ``_probe_whpx_host_prerequisites``.

        Returns:
            bool: Whether the host can run WHPX.
        """
        return QEMUSandbox._probe_whpx_host_prerequisites()

    @staticmethod
    def bcdedit_reports_auto(bcdedit_path: str) -> bool:
        """Forward to ``_bcdedit_reports_hypervisor_auto``.

        Args:
            bcdedit_path: Path to ``bcdedit``.

        Returns:
            bool: Whether the hypervisor launch type is ``auto``.
        """
        return QEMUSandbox._bcdedit_reports_hypervisor_auto(bcdedit_path)

    async def try_whpx(self, process_manager: ProcessManager, output_lower: str) -> AcceleratorType | None:
        """Forward to ``_try_whpx_accelerator``.

        Args:
            process_manager: Process manager used for probes.
            output_lower: Lower-cased ``-accel help`` output.

        Returns:
            AcceleratorType | None: The accelerator when usable.
        """
        return await self._try_whpx_accelerator(process_manager, output_lower)

    async def try_kvm(self, process_manager: ProcessManager, output_lower: str) -> AcceleratorType | None:
        """Forward to ``_try_kvm_accelerator``.

        Args:
            process_manager: Process manager used for probes.
            output_lower: Lower-cased ``-accel help`` output.

        Returns:
            AcceleratorType | None: The accelerator when usable.
        """
        return await self._try_kvm_accelerator(process_manager, output_lower)

    async def detect_accelerator(self) -> AcceleratorType:
        """Forward to ``_detect_accelerator``.

        Returns:
            AcceleratorType: The best accelerator found.
        """
        return await self._detect_accelerator()

    def resolve_vnc_port(self) -> int:
        """Forward to ``_resolve_vnc_port``.

        Returns:
            int: The port QEMU should bind.
        """
        return self._resolve_vnc_port()

    @classmethod
    def claim_free_port(cls, span: int, start: int, end: int) -> int:
        """Forward to ``_claim_free_port``.

        Args:
            span: Consecutive ports wanted.
            start: First port of the range.
            end: One past the last port of the range.

        Returns:
            int: First port of the claimed run.
        """
        return cls._claim_free_port(span, start, end)

    @classmethod
    def release_ports(cls, ports: set[int]) -> None:
        """Forward to ``_release_host_ports``.

        Args:
            ports: Ports previously returned by ``claim_free_port``.
        """
        cls._release_host_ports(ports)

    def resolve_qemu_img(self) -> Path:
        """Forward to ``_resolve_qemu_img``.

        Returns:
            Path: The qemu-img executable.
        """
        return self._resolve_qemu_img()

    async def create_disk_overlay(self, image_path: Path) -> Path:
        """Forward to ``_create_disk_overlay``.

        Args:
            image_path: Backing image.

        Returns:
            Path: The overlay.
        """
        return await self._create_disk_overlay(image_path)

    async def launch_disk_path(self) -> Path:
        """Forward to ``_launch_disk_path``.

        Returns:
            Path: The disk QEMU should attach.
        """
        return await self._launch_disk_path()

    @staticmethod
    def check_qemu_started(returncode: int | None, stderr: bytes | None) -> None:
        """Forward to ``_check_qemu_started``.

        Args:
            returncode: Process return code.
            stderr: Standard error output.
        """
        QEMUSandbox._check_qemu_started(returncode, stderr)

    async def verify_qemu_pid(self, qemu_pid: int | None) -> None:
        """Forward to ``_verify_qemu_pid``.

        Args:
            qemu_pid: PID read from the pidfile.
        """
        await self._verify_qemu_pid(qemu_pid)

    async def connect_and_verify_qmp(self) -> None:
        """Forward to ``_connect_and_verify_qmp``."""
        await self._connect_and_verify_qmp()

    async def attempt_guest_agent_connect(self, channel_port: int, attempt_timeout: float) -> bool:
        """Forward to ``_attempt_guest_agent_connect``.

        Args:
            channel_port: Host port of the channel.
            attempt_timeout: Deadline for this attempt.

        Returns:
            bool: True when the socket opened but the sync was not answered.
        """
        return await self._attempt_guest_agent_connect(channel_port, attempt_timeout)

    async def wait_for_qemu_ga(self) -> None:
        """Forward to ``_wait_for_qemu_ga``."""
        await self._wait_for_qemu_ga()

    async def guest_agent_exec(self, path: str, args: list[str]) -> int:
        """Forward to ``_guest_agent_exec``.

        Args:
            path: Executable path inside the guest.
            args: Arguments.

        Returns:
            int: The guest pid.
        """
        return await self._guest_agent_exec(path, args)

    @staticmethod
    def guest_exit_code(status: GuestExecStatus, command: str) -> int:
        """Forward to ``_guest_exit_code``.

        Args:
            status: Terminal guest-exec status.
            command: Command the status belongs to.

        Returns:
            int: The exit code.
        """
        return QEMUSandbox._guest_exit_code(status, command)

    @staticmethod
    def decode_lsblk_value(raw: str) -> str:
        """Forward to ``_decode_lsblk_value``.

        Args:
            raw: One escaped column value.

        Returns:
            str: The decoded value.
        """
        return QEMUSandbox._decode_lsblk_value(raw)

    @classmethod
    def parse_block_devices(cls, listing: str) -> list[tuple[str, str, str, str]]:
        """Forward to ``_parse_guest_block_devices``.

        Args:
            listing: ``lsblk --raw`` output.

        Returns:
            list[tuple[str, str, str, str]]: ``(path, fs_type, label, mountpoint)`` per row.
        """
        return [(row.path, row.fs_type, row.label, row.mountpoint) for row in cls._parse_guest_block_devices(listing)]

    async def discover_guest_vfat_device(self) -> str:
        """Forward to ``_discover_guest_vfat_device``.

        Returns:
            str: Device path of the shared volume.
        """
        return await self._discover_guest_vfat_device()

    async def mount_linux_shared_volume(self) -> str:
        """Forward to ``_mount_linux_shared_volume``.

        Returns:
            str: Guest-side mount point.
        """
        return await self._mount_linux_shared_volume()

    async def resolve_windows_shared_drive(self) -> str:
        """Forward to ``_resolve_windows_shared_drive``.

        Returns:
            str: Guest-side root of the shared volume.
        """
        return await self._resolve_windows_shared_drive()

    async def guest_bootstrap_diagnostic(self) -> str:
        """Forward to ``_guest_bootstrap_diagnostic``.

        Returns:
            str: The bootstrap diagnostic text.
        """
        return await self._guest_bootstrap_diagnostic()

    async def await_bootstrap_death(self, guest_pid: int) -> str:
        """Forward to ``_await_bootstrap_death``.

        Args:
            guest_pid: Guest pid of the launcher.

        Returns:
            str: Description of how the launcher exited.
        """
        return await self._await_bootstrap_death(guest_pid)

    def shared_folder_args(self) -> list[str]:
        """Forward to ``_shared_folder_args``.

        Returns:
            list[str]: Drive or fsdev arguments.
        """
        return self._shared_folder_args()

    def configured_shares(self) -> list[tuple[Path, bool]]:
        """Forward to ``_configured_shares``.

        Returns:
            list[tuple[Path, bool]]: Each existing configured folder and its read-only flag.
        """
        return self._configured_shares()

    @staticmethod
    def link_or_copy_tree(source: Path, destination: Path) -> None:
        """Forward to ``_link_or_copy_tree``.

        Args:
            source: Directory to expose.
            destination: Where to expose it.
        """
        QEMUSandbox._link_or_copy_tree(source, destination)

    @staticmethod
    def make_junction(source: Path, destination: Path) -> bool:
        """Forward to ``_make_junction``.

        Args:
            source: Existing directory.
            destination: Junction to create.

        Returns:
            bool: Whether the junction exists afterwards.
        """
        return QEMUSandbox._make_junction(source, destination)


def _new_sandbox(*, guest_os: GuestOS = GuestOS.WINDOWS) -> _ExposedSandbox:
    """Build a sandbox with default settings for the given guest family.

    Args:
        guest_os: Guest family to configure.

    Returns:
        _ExposedSandbox: A sandbox that has not started anything.
    """
    return _ExposedSandbox(SandboxConfig(), QEMUConfig(guest_os=guest_os))


@asynccontextmanager
async def _qmp_session() -> AsyncGenerator[tuple[_ExposedQmp, QmpProtocolServer]]:
    """Connect a monitor client to a real QMP protocol server.

    Yields:
        tuple[_ExposedQmp, QmpProtocolServer]: The connected client and its server.
    """
    server = QmpProtocolServer()
    await server.start()
    client = _ExposedQmp(port=server.port)
    try:
        assert await client.connect(time_limit=_STEP_TIMEOUT)
        yield client, server
    finally:
        await client.disconnect()
        await server.stop()


@asynccontextmanager
async def _guest_sandbox(responder: GuestCommandResponder | None, guest_os: GuestOS) -> AsyncGenerator[_ExposedSandbox]:
    """Build a sandbox whose guest-agent channel talks to a modelled guest.

    Args:
        responder: Guest model deciding the outcome of every command.
        guest_os: Guest family to configure.

    Yields:
        _ExposedSandbox: A sandbox with an open guest-agent channel.
    """
    server = GuestAgentProtocolServer(responder)
    await server.start()
    client = QemuGuestAgentClient(port=server.port)
    try:
        assert await client.connect(time_limit=_STEP_TIMEOUT)
        sandbox = _new_sandbox(guest_os=guest_os)
        sandbox.set_qga(client)
        yield sandbox
    finally:
        await client.disconnect()
        await server.stop()


def _result_message(payload: dict[str, object]) -> GuestAgentMessage:
    """Build a ``result`` message as the reader task would queue it.

    Args:
        payload: The message's data.

    Returns:
        GuestAgentMessage: The message.
    """
    return GuestAgentMessage(message_type="result", timestamp=datetime.now(UTC), data=payload)


def _telemetry_message(payload: dict[str, object]) -> GuestAgentMessage:
    """Build a message the agent volunteered that is not a command result.

    Args:
        payload: The message's data.

    Returns:
        GuestAgentMessage: The message.
    """
    return GuestAgentMessage(message_type="telemetry", timestamp=datetime.now(UTC), data=payload)


def _logged_events(captured: list[Any]) -> list[str]:
    """List the event names of a structlog capture.

    Args:
        captured: Records collected by ``structlog.testing.capture_logs``.

    Returns:
        list[str]: Event names in emission order.
    """
    return [str(record.get("event")) for record in captured]


def test_file_size_or_zero_reports_size_and_treats_absent_file_as_empty(tmp_path: Path) -> None:
    """A present file reports its byte size; an absent one counts as empty.

    Args:
        tmp_path: Scratch directory.
    """
    present = tmp_path / "log.bin"
    present.write_bytes(b"0123456")

    assert _file_size_or_zero(present) == len(b"0123456")
    assert _file_size_or_zero(tmp_path / "never-written.bin") == 0


def test_ppm_token_reader_skips_comment_lines() -> None:
    """A ``#`` comment runs to the end of its line and is not part of any token."""
    data = b"# a comment\nP6 1 1"

    token, position = _read_ppm_token(data, 0)

    assert token == "P6"
    assert position == data.index(b"P6") + len("P6")


@pytest.mark.parametrize(
    "data",
    [b"#unterminated comment", b" \t\r\n", b""],
    ids=["comment-without-newline", "only-whitespace", "empty"],
)
def test_ppm_token_reader_returns_nothing_when_header_runs_out(data: bytes) -> None:
    """A header that ends before any token yields an empty token at the end.

    Args:
        data: Header bytes holding no token.
    """
    assert _read_ppm_token(data, 0) == ("", len(data))


def test_ppm_parser_accepts_comments_between_header_fields() -> None:
    """Comment lines between header fields do not disturb width, height or pixels."""
    pixels = bytes(range(6))
    ppm = b"P6\n# made by a test\n2 1\n# second note\n255\n" + pixels

    assert _parse_ppm_p6(ppm) == (2, 1, pixels)


def test_ppm_parser_rejects_sixteen_bit_images() -> None:
    """A maxval other than 255 means 16-bit samples, which the parser refuses."""
    ppm = b"P6\n1 1\n65535\n" + bytes(6)

    with pytest.raises(ValueError, match="maxval"):
        _parse_ppm_p6(ppm)


def test_ppm_parser_reports_truncation_when_header_ends_at_maxval() -> None:
    """A file that stops right after the maxval has no pixel data at all."""
    with pytest.raises(ValueError, match="truncated"):
        _parse_ppm_p6(b"P6 1 1 255")


def test_traceevent_enumeration_of_missing_directory_is_empty(tmp_path: Path) -> None:
    """A vendor directory that does not exist contributes no files.

    Args:
        tmp_path: Scratch directory.
    """
    assert enumerate_traceevent_assembly_files(tmp_path / "vendor-not-here") == ()


def test_qmp_client_exposes_its_configured_endpoint() -> None:
    """The client reports the host and port it was built for."""
    client = QMPClient(host="127.0.0.2", port=4567)

    assert client.host == "127.0.0.2"
    assert client.port == 4567


@pytest.mark.asyncio
async def test_qmp_convenience_commands_send_the_documented_command_names() -> None:
    """Each monitor helper puts its QMP command name on the wire."""
    async with _qmp_session() as (client, server):
        responses = [
            await client.stop(),
            await client.cont(),
            await client.savevm("snap"),
            await client.loadvm("snap"),
            await client.delvm("snap"),
            await client.info_snapshots(),
            await client.query_block(),
            await client.query_jobs(),
            await client.job_dismiss("job0"),
            await client.snapshot_save("job1", "snap", "vmstate0", ["disk0"]),
            await client.snapshot_load("job2", "snap", "vmstate0", ["disk0"]),
            await client.snapshot_delete("job3", "snap", ["disk0"]),
            await client.blockdev_snapshot_internal_sync("ide0-hd0", "snap"),
        ]

    expected = [
        "stop",
        "cont",
        "human-monitor-command",
        "human-monitor-command",
        "human-monitor-command",
        "human-monitor-command",
        "query-block",
        "query-jobs",
        "job-dismiss",
        "snapshot-save",
        "snapshot-load",
        "snapshot-delete",
        "blockdev-snapshot-internal-sync",
    ]
    assert server.commands == ["qmp_capabilities", *expected]
    assert [response.error for response in responses] == [f"The command {name} has not been found" for name in expected]


@pytest.mark.asyncio
async def test_unanswered_resync_on_one_shot_channel_refuses_the_next_command() -> None:
    """After a resync the guest never answered, no reply may be attributed to a new command."""
    async with _serving(SilentGuestAgentServer()) as server:
        client = _RetainingStuckClient(port=server.port)
        try:
            assert await client.connect(time_limit=_STEP_TIMEOUT)

            first = await client.execute_command({"execute": "guest-ping"}, time_limit=_BRIEF_TIMEOUT)
            second = await client.execute_command({"execute": "guest-ping"}, time_limit=_BRIEF_TIMEOUT)
        finally:
            await client.disconnect()

    assert first.success is False
    assert first.error == "Command timed out"
    assert second.success is False
    assert second.error is not None
    assert "unread reply" in second.error
    assert "no reply can be attributed" in second.error


@pytest.mark.asyncio
async def test_unanswered_resync_on_relistening_channel_closes_the_socket() -> None:
    """A re-listening peer costs nothing to drop, so an unanswered resync closes the socket."""
    async with _serving(SilentGuestAgentServer()) as server:
        client = _DiscardingStuckClient(port=server.port)
        try:
            assert await client.connect(time_limit=_STEP_TIMEOUT)

            response = await client.execute_command({"execute": "query-status"}, time_limit=_BRIEF_TIMEOUT)
            socket_open = client.socket_open
        finally:
            await client.disconnect()

    assert response.success is False
    assert response.error == "Command timed out"
    assert socket_open is False


@pytest.mark.asyncio
async def test_failed_handshake_closes_the_socket_of_a_relistening_peer() -> None:
    """A socket whose handshake was refused is closed again before the failure propagates."""
    async with _serving(SilentGuestAgentServer()) as server:
        client = _RefusedHandshakeClient(port=server.port)
        try:
            with pytest.raises(SandboxError, match="handshake refused"):
                await client.connect(time_limit=_STEP_TIMEOUT)
            socket_open = client.socket_open
            connected = client.connected
        finally:
            await client.disconnect()

    assert socket_open is False
    assert connected is False


@pytest.mark.asyncio
async def test_transport_reports_a_peer_that_hangs_up_mid_command() -> None:
    """A peer that closes the connection turns the command into a failed reply."""
    async with _serving(IntellicrackAgentServer(dead_connections=1)) as server:
        client = _ExposedTransport(port=server.port)
        try:
            assert await client.connect(time_limit=_STEP_TIMEOUT)

            response = await client.execute_command({"execute": "anything"}, time_limit=_STEP_TIMEOUT)
        finally:
            await client.disconnect()

    assert response.success is False
    assert response.error


@pytest.mark.asyncio
async def test_transport_reports_a_reply_that_is_not_json() -> None:
    """A reply line that is not JSON becomes a failed reply carrying the parser's complaint."""
    async with _serving(SilentGuestAgentServer()) as server:
        client = _ExposedTransport(port=server.port)
        reader = asyncio.StreamReader()
        reader.feed_data(b"this is not json\n")
        try:
            assert await client.connect(time_limit=_STEP_TIMEOUT)
            client.attach_reader(reader)

            response = await client.execute_command({"execute": "anything"}, time_limit=_STEP_TIMEOUT)
        finally:
            await client.disconnect()

    assert response.success is False
    assert response.error is not None
    assert response.error.startswith("Expecting value")


@pytest.mark.asyncio
async def test_unconnected_transport_refuses_to_exchange_or_read() -> None:
    """Without a socket the transport answers ``Not connected`` and cannot read a frame."""
    client = _ExposedTransport()

    response = await client.exchange({"execute": "query-status"}, _STEP_TIMEOUT)

    assert response.success is False
    assert response.error == "Not connected"
    with pytest.raises(ConnectionError, match="socket is not open"):
        await client.read_line(_STEP_TIMEOUT)


@pytest.mark.asyncio
async def test_unconnected_monitor_refuses_to_exchange_a_command() -> None:
    """The tagged exchange answers ``Not connected`` instead of writing nowhere."""
    client = _ExposedQmp()

    response = await client.exchange({"execute": "query-status"}, _STEP_TIMEOUT)

    assert response.success is False
    assert response.error == "Not connected"


@pytest.mark.asyncio
async def test_monitor_skips_events_and_foreign_replies_before_its_own() -> None:
    """Only the frame carrying the command's id is returned; events and other ids are skipped."""
    reader = asyncio.StreamReader()
    reader.feed_data(b'{"event": "JOB_STATUS_CHANGE", "data": {"status": "running"}}\n')
    reader.feed_data(b'{"return": {}, "id": "someone-else"}\n')
    reader.feed_data(b'{"return": {"ok": true}, "id": "tok"}\n')
    client = _ExposedQmp()
    client.attach_reader(reader)

    frame = await client.read_tagged_reply("tok", _STEP_TIMEOUT)

    assert frame == {"return": {"ok": True}, "id": "tok"}


@pytest.mark.asyncio
async def test_monitor_gives_up_when_the_reply_deadline_has_already_passed() -> None:
    """A zero deadline expires before any frame is read."""
    client = _ExposedQmp()

    with pytest.raises(TimeoutError):
        await client.read_tagged_reply("tok", 0.0)


@pytest.mark.asyncio
async def test_monitor_handshake_without_a_socket_does_nothing() -> None:
    """There is no greeting to read without a socket, so the handshake simply returns."""
    client = _ExposedQmp()

    await client.handshake(_STEP_TIMEOUT)

    assert client.socket_open is False


def test_error_reply_with_a_plain_string_is_reported_verbatim() -> None:
    """An ``error`` member that is not an object is used as the description."""
    response = _ExposedTransport.decode_reply({"error": "plain failure text"})

    assert response.success is False
    assert response.error == "plain failure text"
    assert response.data is None


@pytest.mark.asyncio
async def test_resynchronise_without_a_socket_reports_failure() -> None:
    """There is nothing to resynchronise on a channel that was never opened."""
    client = _ExposedQga()

    assert await client.resynchronise(_BRIEF_TIMEOUT) is False


@pytest.mark.asyncio
async def test_unanswered_resync_keeps_the_only_socket_open() -> None:
    """A guest that does not answer yet is retried on the open socket, never reconnected."""
    async with _serving(SilentGuestAgentServer()) as server:
        client = _ExposedQga(port=server.port)
        try:
            with pytest.raises(SandboxError, match="echoed no sync id"):
                await client.connect(time_limit=_BRIEF_TIMEOUT)

            resynchronised = await client.resynchronise(_BRIEF_TIMEOUT)
            socket_open = client.socket_open
            connected = client.connected
        finally:
            await client.disconnect()

    assert resynchronised is False
    assert socket_open is True
    assert connected is False


@pytest.mark.asyncio
async def test_resync_on_a_broken_socket_closes_it_and_reports_failure() -> None:
    """A socket that has genuinely broken is closed so a fresh one can be opened."""
    async with _serving(GuestAgentProtocolServer()) as server:
        client = _ExposedQga(port=server.port)
        try:
            assert await client.connect(time_limit=_STEP_TIMEOUT)
            await client.close_writer_locally()

            resynchronised = await client.resynchronise(_STEP_TIMEOUT)
            socket_open = client.socket_open
        finally:
            await client.disconnect()

    assert resynchronised is False
    assert socket_open is False


@pytest.mark.asyncio
async def test_command_timeout_reaction_without_a_socket_does_nothing() -> None:
    """With no channel open there is no stream to realign after a timeout."""
    client = _ExposedQga()

    await client.on_command_timeout()

    assert client.socket_open is False


@pytest.mark.asyncio
async def test_channel_reset_does_not_forfeit_an_accepted_but_unsynchronised_socket() -> None:
    """A reopened channel whose sync goes unanswered is kept, not torn down for another try."""
    async with _serving(GuestAgentProtocolServer()) as server:
        client = _UnansweredHandshakeQga(port=server.port)
        try:
            await client.on_channel_reset(OSError("link dropped"))
            socket_open = client.socket_open
            connected = client.connected
        finally:
            await client.disconnect()

    assert server.accepted == 1
    assert socket_open is True
    assert connected is False


@pytest.mark.asyncio
async def test_sync_without_a_socket_fails_with_the_sync_error() -> None:
    """Synchronising a channel that is not open is refused."""
    client = _ExposedQga()

    with pytest.raises(SandboxError, match="echoed no sync id"):
        await client.synchronise(_STEP_TIMEOUT)


@pytest.mark.asyncio
async def test_sync_attempt_and_wait_without_a_socket_match_nothing() -> None:
    """A sync attempt or a wait on a channel that is not open matches no id."""
    client = _ExposedQga()

    assert await client.attempt_sync("guest-sync", _STEP_TIMEOUT) == (False, False)
    assert await client.await_sync_id(7, _STEP_TIMEOUT) == (False, False)


@pytest.mark.asyncio
async def test_sync_wait_treats_an_oversized_frame_as_an_unreadable_channel() -> None:
    """A frame longer than the reader's limit ends the wait without a match."""
    reader = asyncio.StreamReader(limit=16)
    reader.feed_data(b"x" * 64 + b"\n")
    client = _ExposedQga()
    client.attach_reader(reader)

    assert await client.await_sync_id(7, _STEP_TIMEOUT) == (False, False)


@pytest.mark.asyncio
async def test_sync_wait_treats_a_closed_channel_as_no_match() -> None:
    """A peer that closed the channel never echoes the id."""
    reader = asyncio.StreamReader()
    reader.feed_eof()
    client = _ExposedQga()
    client.attach_reader(reader)

    assert await client.await_sync_id(7, _STEP_TIMEOUT) == (False, False)


@pytest.mark.asyncio
async def test_agent_reply_reader_requires_an_open_channel() -> None:
    """Reading a reply from a channel that is not open is a connection error."""
    client = _ExposedQga()

    with pytest.raises(ConnectionError, match="channel is not open"):
        await client.read_reply(_STEP_TIMEOUT)


@pytest.mark.asyncio
async def test_agent_reply_reader_gives_up_when_its_deadline_has_passed() -> None:
    """A zero deadline expires before any line is read."""
    client = _ExposedQga()
    client.attach_reader(asyncio.StreamReader())

    with pytest.raises(TimeoutError):
        await client.read_reply(0.0)


@pytest.mark.asyncio
async def test_agent_reply_reader_skips_noise_until_a_reply_arrives() -> None:
    """Fragments, bare JSON values and event-shaped objects are not replies."""
    reader = asyncio.StreamReader()
    reader.feed_data(b"{broken\n")
    reader.feed_data(b"[1, 2]\n")
    reader.feed_data(b'{"event": "noise"}\n')
    reader.feed_data(b'{"return": 7}\n')
    client = _ExposedQga()
    client.attach_reader(reader)

    assert await client.read_reply(_STEP_TIMEOUT) == {"return": 7}


@pytest.mark.asyncio
async def test_guest_shutdown_without_a_socket_reports_that_nothing_was_sent() -> None:
    """With no channel open the shutdown request cannot reach the wire."""
    client = _ExposedQga()

    assert await client.guest_shutdown() is False


@pytest.mark.asyncio
async def test_guest_shutdown_reports_a_write_that_failed() -> None:
    """A request written to a socket that is already gone is reported as not sent."""
    async with _serving(GuestAgentProtocolServer()) as server:
        client = _ExposedQga(port=server.port)
        try:
            assert await client.connect(time_limit=_STEP_TIMEOUT)
            await client.close_writer_locally()

            sent = await client.guest_shutdown()
        finally:
            await client.disconnect()

    assert sent is False
    assert server.shutdown_requested.is_set() is False


def test_exec_status_with_undecodable_stream_keeps_the_other_stream() -> None:
    """A stream that is not valid base64 decodes to empty text and spares the other one."""
    status = _ExposedQga.decode_exec_status({
        "exited": True,
        "exitcode": 0,
        "out-data": "!!!not base64!!!",
        "err-data": base64.b64encode(b"ok").decode(),
    })

    assert not status.stdout
    assert status.stderr == "ok"
    assert status.exited is True
    assert status.exit_code == 0


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (b'{"type": "pong", "data": {}}\n', True),
        (b'{"type": "ping"}\n', False),
        (b"\xff\xfe\n", False),
        (b"not json at all\n", False),
        (b"[1, 2]\n", False),
        (b'"pong"\n', False),
    ],
    ids=["pong", "other-type", "not-utf8", "not-json", "json-list", "json-string"],
)
def test_pong_detection_accepts_only_a_pong_object(line: bytes, *, expected: bool) -> None:
    """Only a JSON object whose type is ``pong`` counts as the readiness reply.

    Args:
        line: One received line.
        expected: Whether the line is the readiness reply.
    """
    assert _ExposedAgent.is_pong(line) is expected


@pytest.mark.asyncio
async def test_readiness_wait_fails_when_the_budget_is_already_spent() -> None:
    """A zero budget fails before a line is read."""
    client = _ExposedAgent()

    with pytest.raises(ConnectionError, match="did not answer the readiness handshake"):
        await client.await_readiness_reply(asyncio.StreamReader(), 0.0)


@pytest.mark.asyncio
async def test_readiness_wait_fails_when_the_channel_closes_first() -> None:
    """A peer that hangs up before answering fails the handshake."""
    reader = asyncio.StreamReader()
    reader.feed_eof()
    client = _ExposedAgent()

    with pytest.raises(ConnectionError, match="closed before answering"):
        await client.await_readiness_reply(reader, _STEP_TIMEOUT)


@pytest.mark.asyncio
async def test_readiness_wait_fails_when_a_frame_exceeds_the_stream_limit() -> None:
    """A frame longer than the reader's limit cannot be framed, so the handshake fails."""
    reader = asyncio.StreamReader(limit=16)
    reader.feed_data(b"x" * 64 + b"\n")
    client = _ExposedAgent()

    with pytest.raises(ConnectionError, match="could not be framed"):
        await client.await_readiness_reply(reader, _STEP_TIMEOUT)


@pytest.mark.asyncio
async def test_readiness_wait_queues_telemetry_that_arrives_before_the_pong() -> None:
    """Anything the agent volunteers ahead of its pong stays available to the caller."""
    reader = asyncio.StreamReader()
    reader.feed_data(b'{"type": "telemetry", "data": {"n": 1}}\n')
    reader.feed_data(b'{"type": "pong", "data": {}}\n')
    client = _ExposedAgent()

    await client.await_readiness_reply(reader, _STEP_TIMEOUT)
    pending = await client.get_pending_messages()

    assert [(message.message_type, message.data) for message in pending] == [("telemetry", {"n": 1})]
    assert await client.get_pending_messages() == []


@pytest.mark.asyncio
async def test_agent_handshake_without_a_socket_is_a_connection_error() -> None:
    """The readiness handshake cannot start without an open socket."""
    client = _ExposedAgent()

    with pytest.raises(ConnectionError, match="without an open socket"):
        await client.handshake(_STEP_TIMEOUT)


@pytest.mark.asyncio
async def test_abandoning_a_socket_that_was_never_opened_leaves_nothing_connected() -> None:
    """Abandoning a missing socket is harmless and leaves the client disconnected."""
    client = _ExposedAgent()
    client.connected = True

    await client.abandon_socket()

    assert client.connected is False


@pytest.mark.asyncio
async def test_agent_line_that_is_not_json_is_dropped() -> None:
    """One unreadable line is dropped without queueing anything."""
    client = _ExposedAgent()

    await client.enqueue_line(b"this is not json\n")

    assert await client.get_pending_messages() == []


@pytest.mark.asyncio
async def test_message_reader_does_nothing_without_a_stream() -> None:
    """With no stream attached the reader task returns at once."""
    client = _ExposedAgent()
    client.connected = True

    await asyncio.wait_for(client.read_messages(), timeout=_STEP_TIMEOUT)

    assert await client.get_pending_messages() == []


@pytest.mark.asyncio
async def test_message_reader_stops_without_reading_once_the_client_is_disconnected() -> None:
    """A reader task started on a disconnected client reads nothing."""
    reader = asyncio.StreamReader()
    reader.feed_data(b'{"type": "telemetry", "data": {}}\n')
    client = _ExposedAgent()
    client.attach_reader(reader)

    await asyncio.wait_for(client.read_messages(), timeout=_STEP_TIMEOUT)

    assert await client.get_pending_messages() == []


@pytest.mark.asyncio
async def test_single_failed_attempt_reports_that_the_dispatch_budget_is_exhausted() -> None:
    """When the only allowed attempt fails the reply names the budget and the cause."""
    client = _SingleAttemptAgent()

    exit_code, stdout, stderr = await client.run_with_recovery({"type": "execute", "command": "x"}, _STEP_TIMEOUT)

    assert exit_code == -1
    assert not stdout
    assert "all 1 dispatch attempts" in stderr
    assert "Not connected to guest agent" in stderr


@pytest.mark.asyncio
async def test_unrecoverable_channel_is_reported_as_failed_to_reconnect() -> None:
    """When nothing listens any more the command fails with the reconnect error."""
    client = _ImpatientAgent(port=free_port())

    exit_code, stdout, stderr = await client.run_with_recovery({"type": "execute", "command": "x"}, _STEP_TIMEOUT)

    assert exit_code == -1
    assert not stdout
    assert "could not be re-established" in stderr
    assert "Not connected to guest agent" in stderr


@pytest.mark.asyncio
async def test_request_that_never_left_the_host_is_sent_again_on_a_fresh_channel() -> None:
    """A write that failed on a dead channel is retried once, and the guest sees it once."""

    def respond(path: str, args: Sequence[str]) -> GuestCommandResult:
        """Model a guest that runs the command and answers with fixed output.

        Args:
            path: Executable the host asked for.
            args: Arguments it was given.

        Returns:
            GuestCommandResult: Exit code 7 with fixed stdout.
        """
        del path, args
        return GuestCommandResult(exit_code=7, stdout="hello\n", stderr="")

    async with _serving(IntellicrackAgentServer(respond)) as server:
        client = _ExposedAgent(port=server.port)
        try:
            assert await client.connect(time_limit=_STEP_TIMEOUT, retry_interval=_STEP_TIMEOUT)
            await client.close_writer_locally()
            client.connected = True

            result = await client.run_with_recovery(
                {"type": "execute", "command": "whoami", "args": [], "timeout": _STEP_TIMEOUT},
                _STEP_TIMEOUT,
            )
        finally:
            await client.disconnect()

    assert result == (7, "hello\n", "")
    assert server.requests == [("whoami", ())]
    assert server.handshakes == 2


@pytest.mark.asyncio
async def test_orphaned_results_are_dropped_and_other_messages_kept_in_order() -> None:
    """Results of a dead channel are discarded; everything else is kept in arrival order."""
    client = _ExposedAgent()
    first_note = _telemetry_message({"n": 1})
    second_note = _telemetry_message({"n": 2})
    for message in (_result_message({"exit_code": 0}), first_note, _result_message({"exit_code": 1}), second_note):
        client.put_message(message)

    discarded = client.discard_orphaned_results()
    remaining = await client.get_pending_messages()

    assert discarded == 2
    assert remaining == [first_note, second_note]


@pytest.mark.asyncio
async def test_taking_a_queued_result_removes_only_that_result() -> None:
    """The first queued result is taken and everything else stays queued in order."""
    client = _ExposedAgent()
    note = _telemetry_message({"n": 1})
    wanted = _result_message({"exit_code": 3})
    later = _result_message({"exit_code": 4})
    for message in (note, wanted, later):
        client.put_message(message)

    taken = client.take_queued_result()
    remaining = await client.get_pending_messages()

    assert taken is wanted
    assert remaining == [note, later]


def test_taking_a_queued_result_from_an_empty_queue_finds_nothing() -> None:
    """With nothing queued there is no result to take."""
    client = _ExposedAgent()

    assert client.take_queued_result() is None


@pytest.mark.asyncio
async def test_waiting_for_a_result_returns_it_past_unrelated_messages() -> None:
    """A connected client returns the result message even when other messages arrive first."""
    client = _ExposedAgent()
    client.connected = True
    wanted = _result_message({"exit_code": 5})
    client.put_message(_telemetry_message({"n": 1}))
    client.put_message(wanted)

    assert await client.await_guest_result(_STEP_TIMEOUT) is wanted


@pytest.mark.asyncio
async def test_result_queued_before_the_channel_died_is_still_returned() -> None:
    """A reply that reached the queue ahead of the failure remains that command's answer."""
    client = _ExposedAgent()
    note = _telemetry_message({"n": 1})
    wanted = _result_message({"exit_code": 6})
    client.put_message(note)
    client.put_message(wanted)

    assert await client.await_guest_result(_STEP_TIMEOUT) is wanted
    assert await client.get_pending_messages() == [note]


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_recorder_keeps_whole_and_trailing_lines_and_drops_blank_ones() -> None:
    """Every non-blank line, including one with no terminator, is kept; a deliberate exit is not a failure."""
    script = "import sys; sys.stdout.write('a\\n\\n   \\nb\\npartial'); sys.stdout.flush()"
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        script,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    recorder = _ExposedRecorder(process)
    try:
        recorder.expect_exit()
        with structlog.testing.capture_logs() as captured:
            recorder.start()
            first_task = recorder.current_task()
            recorder.start()
            second_task = recorder.current_task()
            await asyncio.wait_for(recorder.wait_recorded(), timeout=30.0)
        await recorder.aclose()
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()

    assert first_task is not None
    assert second_task is first_task
    assert recorder.termination == QemuTermination(
        returncode=0,
        output_tail=("stdout: a", "stdout: b", "stdout: partial"),
    )
    events = _logged_events(captured)
    assert "qemu_process_exited" in events
    assert "qemu_process_exited_unexpectedly" not in events


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_recorder_reports_an_unplanned_exit_with_its_parting_output() -> None:
    """A process that exits without the exit being announced is logged as unexpected."""
    script = "import sys; sys.stderr.write('warning: boom\\n'); sys.exit(3)"
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        script,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    recorder = _ExposedRecorder(process)
    try:
        with structlog.testing.capture_logs() as captured:
            recorder.start()
            await asyncio.wait_for(recorder.wait_recorded(), timeout=30.0)
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()
        await recorder.aclose()

    termination = recorder.termination
    assert termination is not None
    assert termination.returncode == 3
    assert termination.describe() == "QEMU exited with code 3; stderr: warning: boom"
    events = _logged_events(captured)
    assert "qemu_process_exited_unexpectedly" in events
    assert "qemu_process_exited" not in events


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_recorder_handles_a_process_whose_streams_were_never_piped() -> None:
    """With no pipes there is nothing to drain, and the exit status is still recorded."""
    process = await asyncio.create_subprocess_exec(sys.executable, "-c", "pass")
    recorder = _ExposedRecorder(process)
    try:
        recorder.start()
        await asyncio.wait_for(recorder.wait_recorded(), timeout=30.0)
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()
        await recorder.aclose()

    assert recorder.termination == QemuTermination(returncode=0, output_tail=())


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_closing_a_recorder_cancels_a_drain_that_is_still_running() -> None:
    """Closing a recorder that never started returns; closing a live one stops it without waiting for the process."""
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "import time; time.sleep(60)",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    recorder = _ExposedRecorder(process)
    try:
        await asyncio.wait_for(recorder.aclose(), timeout=_STEP_TIMEOUT)
        recorder.start()
        await asyncio.wait_for(recorder.aclose(), timeout=_STEP_TIMEOUT)
        task = recorder.current_task()
        termination = recorder.termination
        process_still_running = process.returncode is None
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()

    assert task is None
    assert termination is None
    assert process_still_running is True


def test_invalidating_the_accelerator_cache_forces_the_next_probe() -> None:
    """Invalidating clears the cache flag so the next availability check probes again."""
    sandbox = _new_sandbox()
    sandbox.set_accelerator_cached(cached=True)

    sandbox.invalidate_accelerator_cache()

    assert sandbox.peek_accelerator_cached() is False


@pytest.mark.asyncio
async def test_availability_check_probes_and_caches_the_accelerator(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A binary found in the bundled location is available; a probe that cannot run it falls back to TCG.

    Args:
        tmp_path: Scratch directory.
        monkeypatch: Used to point the bundled QEMU directory at ``tmp_path``.
    """
    tools = tmp_path / "bundled"
    tools.mkdir()
    binary = tools / _QEMU_EXE_NAME
    binary.write_bytes(b"")
    monkeypatch.setattr(QEMUSandbox, "TOOLS_PATH", tools)
    sandbox = _new_sandbox()

    available = await sandbox.is_available()

    assert available is True
    assert sandbox.peek_qemu_path() == binary
    assert sandbox.peek_accelerator() == AcceleratorType.TCG
    assert sandbox.peek_accelerator_cached() is True


@pytest.mark.asyncio
async def test_qemu_found_on_the_search_path_is_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no bundled copy, the binary found on ``PATH`` is the one reported.

    Args:
        tmp_path: Scratch directory.
        monkeypatch: Used to set ``PATH`` and the bundled directory.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / _QEMU_EXE_NAME).write_bytes(b"")
    monkeypatch.setattr(QEMUSandbox, "TOOLS_PATH", tmp_path / "no-bundled-copy")
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.chdir(tmp_path)

    found = await _new_sandbox().find_qemu()

    assert found == bin_dir / _QEMU_EXE_NAME


def test_hypervisor_probe_without_powershell_cannot_answer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no PowerShell on the search path the unelevated probe returns no answer.

    Args:
        tmp_path: Scratch directory used as the whole ``PATH``.
        monkeypatch: Used to set ``PATH`` and the working directory.
    """
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.chdir(tmp_path)

    assert _ExposedSandbox.hypervisor_present_unelevated() is None


def test_whpx_prerequisites_are_not_met_without_powershell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without PowerShell neither probe can run, so the host is not reported WHPX-capable.

    Args:
        tmp_path: Scratch directory used as the whole ``PATH``.
        monkeypatch: Used to set ``PATH`` and the working directory.
    """
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.chdir(tmp_path)

    assert _ExposedSandbox.probe_whpx_prerequisites() is False


def _independent_hypervisor_present() -> bool | None:
    """Ask the host whether a hypervisor is running, without using the product.

    Returns:
        bool | None: The ``HypervisorPresent`` property, or None when it cannot be read.
    """
    powershell = shutil.which("pwsh") or shutil.which("powershell")
    if powershell is None:
        return None
    completed = run_process(
        [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).HypervisorPresent",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return {"true": True, "false": False}.get(completed.stdout.strip().lower())


@pytest.mark.spawns_process
def test_hypervisor_probe_agrees_with_an_independent_query() -> None:
    """The unelevated probe reports the same flag the host's own CIM query does."""
    assert _ExposedSandbox.hypervisor_present_unelevated() == _independent_hypervisor_present()


@pytest.mark.spawns_process
def test_whpx_prerequisites_follow_the_hypervisor_flag_when_it_can_be_read() -> None:
    """When the CIM flag is readable it alone decides whether the host is WHPX-capable."""
    expected = _independent_hypervisor_present()

    verdict = _ExposedSandbox.probe_whpx_prerequisites()

    if expected is None:
        assert isinstance(verdict, bool)
    else:
        assert verdict is expected


@pytest.mark.spawns_process
def test_bcdedit_probe_agrees_with_the_real_boot_configuration() -> None:
    """The launch-type check gives the verdict an independent reading of ``bcdedit`` output gives."""
    bcdedit = Path(os.environ["SYSTEMROOT"]) / "System32" / "bcdedit.exe"
    assert bcdedit.is_file()
    completed = run_process(
        [str(bcdedit), "/enum", "{current}"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    output = completed.stdout.lower()
    expected = "hypervisorlaunchtype" in output and re.search(r"hypervisorlaunchtype\s+auto", output) is not None

    assert _ExposedSandbox.bcdedit_reports_auto(str(bcdedit)) is expected


@pytest.mark.asyncio
async def test_accelerator_probes_skip_accelerators_the_binary_does_not_advertise() -> None:
    """An accelerator missing from ``-accel help`` is not probed and not reported."""
    sandbox = _new_sandbox()
    manager = ProcessManager.get_instance()

    assert await sandbox.try_whpx(manager, "accel: tcg") is None
    assert await sandbox.try_kvm(manager, "accel: tcg") is None


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_kvm_probe_whose_smoke_test_fails_reports_no_accelerator() -> None:
    """An advertised accelerator whose smoke test exits non-zero is not usable."""
    sandbox = _new_sandbox()
    sandbox.set_qemu_path(Path(sys.executable))

    assert await sandbox.try_kvm(ProcessManager.get_instance(), "accel: kvm") is None


@pytest.mark.asyncio
async def test_detection_without_a_binary_falls_back_to_software_emulation() -> None:
    """With no QEMU path recorded there is nothing to probe, so TCG is chosen."""
    assert await _new_sandbox().detect_accelerator() == AcceleratorType.TCG


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_detection_with_an_unrunnable_binary_falls_back_to_software_emulation(tmp_path: Path) -> None:
    """A binary the operating system cannot start leaves TCG as the accelerator.

    Args:
        tmp_path: Scratch directory holding the path of a binary that does not exist.
    """
    sandbox = _new_sandbox()
    sandbox.set_qemu_path(tmp_path / "missing" / _QEMU_EXE_NAME)

    assert await sandbox.detect_accelerator() == AcceleratorType.TCG


def test_vnc_port_taken_by_someone_else_is_replaced() -> None:
    """A port chosen earlier that is no longer bindable is swapped for a free one in the VNC range."""
    sandbox = _new_sandbox()
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sandbox.enable_vnc_display()
        taken = sandbox.vnc_port
        assert taken is not None
        claimed_before = sandbox.peek_claimed_ports()
        holder.bind((_WILDCARD, taken))
        holder.listen(1)

        replacement = sandbox.resolve_vnc_port()
        claimed_after = sandbox.peek_claimed_ports()
    finally:
        holder.close()
        sandbox.release_claimed_ports()

    assert taken in claimed_before
    assert replacement != taken
    assert _VNC_RANGE_FIRST <= replacement <= _VNC_RANGE_LAST
    assert replacement in claimed_after
    assert taken not in claimed_after


def test_port_search_gives_up_when_every_candidate_is_unbindable() -> None:
    """A range whose only candidate is occupied exhausts the search and raises."""
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        holder.bind((_WILDCARD, 0))
        holder.listen(1)
        taken = int(holder.getsockname()[1])

        with pytest.raises(SandboxError, match="no free ports"):
            _ExposedSandbox.claim_free_port(1, taken, taken + _RESERVED_PORT_WINDOW)
    finally:
        holder.close()


def test_port_search_refuses_a_run_that_another_sandbox_has_reserved() -> None:
    """A range holding exactly one candidate run cannot be claimed twice; releasing it makes it claimable again.

    With a range one wider than the span the search can only ever pick the first port, so the second
    claim collides with the first claim's reservation on every attempt and ends in the documented
    ``SandboxError``. The port itself stays bindable the whole time, which is what tells this failure
    apart from the unbindable-candidate one tested above.

    Falsifiable: without the reservation check the second claim succeeds and hands the same port to two
    sandboxes, so ``pytest.raises`` fails.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((_WILDCARD, 0))
        port = int(probe.getsockname()[1])
    finally:
        probe.close()

    claimed: set[int] = set()
    try:
        first = _ExposedSandbox.claim_free_port(1, port, port + _RESERVED_PORT_WINDOW)
        claimed.add(first)
        assert first == port

        with pytest.raises(SandboxError, match="no free ports"):
            _ExposedSandbox.claim_free_port(1, port, port + _RESERVED_PORT_WINDOW)

        _ExposedSandbox.release_ports({first})
        claimed.discard(first)

        again = _ExposedSandbox.claim_free_port(1, port, port + _RESERVED_PORT_WINDOW)
        claimed.add(again)
        assert again == port
    finally:
        _ExposedSandbox.release_ports(claimed)


def test_qemu_img_is_looked_for_beside_the_qemu_binary(tmp_path: Path) -> None:
    """The overlay tool is the one that sits next to the configured QEMU binary.

    Args:
        tmp_path: Scratch directory holding the placeholder install.
    """
    qemu_dir = tmp_path / "qemu"
    qemu_dir.mkdir()
    (qemu_dir / _QEMU_IMG_NAME).write_bytes(b"")
    sandbox = _new_sandbox()
    sandbox.set_qemu_path(qemu_dir / _QEMU_EXE_NAME)

    assert sandbox.resolve_qemu_img() == qemu_dir / _QEMU_IMG_NAME


def test_missing_qemu_img_is_refused_rather_than_attaching_the_image_directly(tmp_path: Path) -> None:
    """Without qemu-img beside the binary no overlay can be made, and that is an error.

    Args:
        tmp_path: Scratch directory holding a QEMU directory with no qemu-img.
    """
    sandbox = _new_sandbox()
    sandbox.set_qemu_path(tmp_path / _QEMU_EXE_NAME)

    with pytest.raises(SandboxError, match="qemu-img was not found"):
        sandbox.resolve_qemu_img()


def test_qemu_img_cannot_be_located_without_a_qemu_path() -> None:
    """Without a QEMU path there is no directory to look in."""
    with pytest.raises(SandboxError, match="path not set"):
        _new_sandbox().resolve_qemu_img()


@pytest.mark.asyncio
async def test_overlay_creation_makes_the_instance_directory_before_running_qemu_img(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The instance directory is created under the temp root before qemu-img is started.

    The placeholder ``qemu-img`` is an empty file, so the operating system
    refuses to start it and the failure surfaces as an ``OSError``.

    Args:
        tmp_path: Scratch directory used as the temp root and install directory.
        monkeypatch: Used to make ``tmp_path`` the temp root.
    """
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    qemu_dir = tmp_path / "qemu"
    qemu_dir.mkdir()
    (qemu_dir / _QEMU_IMG_NAME).write_bytes(b"")
    image = tmp_path / "base.qcow2"
    image.write_bytes(b"")
    sandbox = _new_sandbox()
    sandbox.set_qemu_path(qemu_dir / _QEMU_EXE_NAME)

    refusal: OSError | None = None
    try:
        await sandbox.create_disk_overlay(image)
    except OSError as error:
        refusal = error

    assert refusal is not None
    instance_dir = sandbox.peek_temp_dir()
    assert instance_dir is not None
    assert instance_dir.parent == tmp_path
    assert instance_dir.name.startswith("intellicrack_qemu_")
    assert instance_dir.is_dir()


@pytest.mark.asyncio
async def test_launch_without_a_configured_image_is_refused() -> None:
    """A launch needs a disk image to attach."""
    with pytest.raises(SandboxError, match="No QEMU disk image is configured"):
        await _new_sandbox().launch_disk_path()


@pytest.mark.asyncio
async def test_launch_without_an_overlay_attaches_the_configured_image(tmp_path: Path) -> None:
    """With overlays disabled the configured image itself is what is attached.

    Args:
        tmp_path: Scratch directory holding the image.
    """
    image = tmp_path / "base.qcow2"
    sandbox = _ExposedSandbox(SandboxConfig(), QEMUConfig(image_path=image, disk_overlay=False))

    assert await sandbox.launch_disk_path() == image


@pytest.mark.asyncio
async def test_launch_with_an_overlay_needs_a_located_qemu(tmp_path: Path) -> None:
    """With overlays enabled the overlay is built, which needs the QEMU path first.

    Args:
        tmp_path: Scratch directory holding the image and instance directory.
    """
    sandbox = _ExposedSandbox(SandboxConfig(), QEMUConfig(image_path=tmp_path / "base.qcow2"))
    sandbox.set_temp_dir(tmp_path)

    with pytest.raises(SandboxError, match="path not set"):
        await sandbox.launch_disk_path()


def test_clean_qemu_exit_status_is_not_a_start_failure() -> None:
    """A zero return code means QEMU started, whatever it printed."""
    _ExposedSandbox.check_qemu_started(0, b"some noise")


@pytest.mark.asyncio
async def test_a_known_pid_passes_verification() -> None:
    """A pid that was read from the pidfile needs no cleanup."""
    await _new_sandbox().verify_qemu_pid(4321)


@pytest.mark.asyncio
async def test_monitor_that_never_accepts_a_connection_fails_the_start() -> None:
    """A monitor port nothing listens on fails the connect step with the QMP error."""
    sandbox = _ExposedSandbox(SandboxConfig(), QEMUConfig(monitor_port=free_port()))

    with pytest.raises(SandboxError, match="QMP connect failed"):
        await sandbox.connect_and_verify_qmp()


@pytest.mark.asyncio
async def test_unanswered_resync_on_an_open_channel_is_reported_as_a_sync_failure() -> None:
    """An open channel whose guest has not answered the sync yet is retried on the same socket."""
    async with _serving(SilentGuestAgentServer()) as server:
        client = QemuGuestAgentClient(port=server.port)
        sandbox = _new_sandbox()
        sandbox.set_qga(client)
        try:
            with pytest.raises(SandboxError, match="echoed no sync id"):
                await client.connect(time_limit=_BRIEF_TIMEOUT)

            sync_failed = await sandbox.attempt_guest_agent_connect(server.port, _BRIEF_TIMEOUT)
        finally:
            await client.disconnect()

    assert sync_failed is True


@pytest.mark.asyncio
async def test_guest_agent_operations_require_an_open_channel() -> None:
    """Pinging or running a command without a channel fails with the not-connected error."""
    sandbox = _new_sandbox()

    with pytest.raises(SandboxError, match="channel not connected"):
        await sandbox.wait_for_qemu_ga()
    with pytest.raises(SandboxError, match="channel not connected"):
        await sandbox.guest_agent_exec("cmd.exe", ["/c", "exit"])


@pytest.mark.asyncio
async def test_guest_exec_reply_with_a_non_integer_pid_is_refused() -> None:
    """A pid that is not an integer cannot be tracked, so the launch is reported as failed."""
    async with _serving(GuestAgentProtocolServer()) as server:
        client = _ExposedQga(port=server.port)
        reader = asyncio.StreamReader()
        reader.feed_data(b'{"return": {"pid": "not-a-number"}}\n')
        sandbox = _new_sandbox()
        sandbox.set_qga(client)
        try:
            assert await client.connect(time_limit=_STEP_TIMEOUT)
            client.attach_reader(reader)

            with pytest.raises(SandboxError, match="did not include a process id"):
                await sandbox.guest_agent_exec("cmd.exe", ["/c", "exit"])
        finally:
            await client.disconnect()


def test_exit_code_is_the_code_the_guest_reported() -> None:
    """A status that carries an exit code reports exactly that code."""
    status = GuestExecStatus(exited=True, exit_code=3)

    assert _ExposedSandbox.guest_exit_code(status, "cmd") == 3


def test_exit_code_of_a_signalled_process_follows_the_shell_convention() -> None:
    """A process the guest killed with signal 9 reports 128 plus the signal number."""
    status = GuestExecStatus(exited=True, signal=9)

    assert _ExposedSandbox.guest_exit_code(status, "cmd") == 128 + 9


def test_status_without_code_or_signal_is_refused() -> None:
    """A finished process with neither an exit code nor a signal is the agent contradicting itself."""
    with pytest.raises(SandboxError, match="gave it no exit status"):
        _ExposedSandbox.guest_exit_code(GuestExecStatus(exited=True), "cmd")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("QEMU\\x20VVFAT", "QEMU VVFAT"),
        ("bad\\xZZescape", "bad\\xZZescape"),
        ("short\\x2", "short\\x2"),
        ("plain", "plain"),
    ],
    ids=["valid-escape", "non-hex-escape", "truncated-escape", "no-escape"],
)
def test_lsblk_escapes_are_expanded_and_malformed_ones_kept(raw: str, expected: str) -> None:
    r"""A well-formed ``\xNN`` escape is expanded; a malformed one is kept verbatim.

    Args:
        raw: Column value as ``lsblk --raw`` printed it.
        expected: The decoded value.
    """
    assert _ExposedSandbox.decode_lsblk_value(raw) == expected


def test_block_device_listing_skips_rows_that_are_not_devices() -> None:
    """Only rows that name a device node and a filesystem column become devices."""
    listing = "garbage\r\n/dev/vdb1 vfat QEMU\\x20VVFAT\r\nnot-a-path vfat\r\n/dev/vdc\r\n/dev/vda15 vfat UEFI /boot/efi\r\n"

    assert _ExposedSandbox.parse_block_devices(listing) == [
        ("/dev/vdb1", "vfat", "QEMU VVFAT", ""),
        ("/dev/vda15", "vfat", "UEFI", "/boot/efi"),
    ]


def _linux_guest_where_lsblk_fails(path: str, args: Sequence[str]) -> GuestCommandResult:
    """Model a Linux guest whose block-device listing fails.

    Args:
        path: Executable the host asked for.
        args: Arguments it was given.

    Returns:
        GuestCommandResult: Failure for ``lsblk``, success otherwise.
    """
    del args
    if path == "lsblk":
        return GuestCommandResult(exit_code=1, stdout="", stderr="lsblk: not found\n")
    return GuestCommandResult(exit_code=0, stdout="", stderr="")


def _linux_guest_where_mkdir_fails(path: str, args: Sequence[str]) -> GuestCommandResult:
    """Model a Linux guest that has no launcher and cannot create the mount point.

    Args:
        path: Executable the host asked for.
        args: Arguments it was given.

    Returns:
        GuestCommandResult: Failure for ``test`` and ``mkdir``, success otherwise.
    """
    del args
    if path in {"test", "mkdir"}:
        return GuestCommandResult(exit_code=1, stdout="", stderr="denied\n")
    return GuestCommandResult(exit_code=0, stdout="", stderr="")


@pytest.mark.asyncio
async def test_failed_block_device_listing_is_reported_as_an_enumeration_failure() -> None:
    """When the guest cannot list its block devices the shared volume cannot be located."""
    async with _guest_sandbox(_linux_guest_where_lsblk_fails, GuestOS.LINUX) as sandbox:
        with pytest.raises(SandboxError, match="could not enumerate guest block devices"):
            await sandbox.discover_guest_vfat_device()


@pytest.mark.asyncio
async def test_mount_point_that_cannot_be_created_fails_the_mount() -> None:
    """A guest that refuses to create ``/mnt/shared`` cannot mount the volume there."""
    async with _guest_sandbox(_linux_guest_where_mkdir_fails, GuestOS.LINUX) as sandbox:
        with pytest.raises(SandboxError, match=re.escape("mount point /mnt/shared inside the guest")):
            await sandbox.mount_linux_shared_volume()


def _windows_guest(drives_exit_code: int, drives_listing: str) -> GuestCommandResponder:
    """Build a model of a Windows guest that answers the drive-letter probes.

    Args:
        drives_exit_code: Exit code of ``fsutil fsinfo drives``.
        drives_listing: Standard output of ``fsutil fsinfo drives``.

    Returns:
        GuestCommandResponder: The guest model.
    """

    def respond(path: str, args: Sequence[str]) -> GuestCommandResult:
        """Answer one command the way the modelled guest would.

        Args:
            path: Executable the host asked for.
            args: Arguments it was given.

        Returns:
            GuestCommandResult: The modelled outcome.
        """
        if path == "cmd.exe" and "fsutil" in args:
            return GuestCommandResult(exit_code=drives_exit_code, stdout=drives_listing, stderr="")
        if path == "cmd.exe" and "%SystemDrive%" in args:
            return GuestCommandResult(exit_code=0, stdout="C:\r\n", stderr="")
        if path == "cmd.exe" and "%SystemRoot%" in args:
            return GuestCommandResult(exit_code=0, stdout="C:\\Windows\r\n", stderr="")
        return GuestCommandResult(exit_code=1, stdout="", stderr="unexpected command\n")

    return respond


@pytest.mark.asyncio
async def test_failed_drive_listing_is_reported_as_an_enumeration_failure() -> None:
    """When the guest cannot list its drives the shared volume cannot be located."""
    async with _guest_sandbox(_windows_guest(1, ""), GuestOS.WINDOWS) as sandbox:
        with (
            structlog.testing.capture_logs() as captured,
            pytest.raises(SandboxError, match="could not enumerate guest drive letters"),
        ):
            await sandbox.resolve_windows_shared_drive()

    events = _logged_events(captured)
    assert "guest_drive_enumeration_failed" in events
    assert "guest_drive_enumeration_empty" not in events


@pytest.mark.asyncio
async def test_guest_with_only_its_system_drive_has_no_candidate_for_the_share() -> None:
    """A guest whose only drive is the boot volume offers no drive that could hold the share."""
    async with _guest_sandbox(_windows_guest(0, "Drives: C:\\ \r\n"), GuestOS.WINDOWS) as sandbox:
        with (
            structlog.testing.capture_logs() as captured,
            pytest.raises(SandboxError, match="could not enumerate guest drive letters"),
        ):
            await sandbox.resolve_windows_shared_drive()

    events = _logged_events(captured)
    assert "guest_drive_enumeration_empty" in events
    assert "guest_drive_enumeration_failed" not in events


@pytest.mark.asyncio
async def test_windows_guest_keeps_no_bootstrap_log() -> None:
    """Only the Linux launcher records a bootstrap log, so a Windows guest has nothing to read back."""
    diagnostic = await _new_sandbox(guest_os=GuestOS.WINDOWS).guest_bootstrap_diagnostic()

    assert diagnostic == "this guest OS keeps no bootstrap log"


@pytest.mark.asyncio
async def test_bootstrap_death_is_reported_once_the_launcher_has_exited() -> None:
    """The wait polls past a launcher that is still running and reports how it ended."""
    async with _serving(GuestAgentProtocolServer(status_polls_before_exit=1)) as server:
        client = QemuGuestAgentClient(port=server.port)
        sandbox = _new_sandbox(guest_os=GuestOS.WINDOWS)
        sandbox.set_qga(client)
        try:
            assert await client.connect(time_limit=_STEP_TIMEOUT)

            description = await asyncio.wait_for(sandbox.await_bootstrap_death(_STATUS_POLL_PID), timeout=30.0)
        finally:
            await client.disconnect()

    assert server.exec_status_pids == [_STATUS_POLL_PID, _STATUS_POLL_PID]
    assert "exited 0" in description
    assert "this guest OS keeps no bootstrap log" in description


def test_no_share_means_no_drive_arguments() -> None:
    """Without a work share the command line carries no shared-folder arguments."""
    assert _new_sandbox().shared_folder_args() == []


def test_configured_shares_merge_both_routes_and_keep_the_read_only_flag(tmp_path: Path) -> None:
    """A folder arriving by both routes appears once with the flag the generic list carried.

    Args:
        tmp_path: Scratch directory holding the configured folders.
    """
    first = tmp_path / "first"
    second = tmp_path / "second"
    missing = tmp_path / "missing"
    first.mkdir()
    second.mkdir()
    config = SandboxConfig(
        shared_folders=[(first, "/guest/a", True), (first, "/guest/b", False), (missing, "/guest/c", False)],
    )
    sandbox = _ExposedSandbox(config, QEMUConfig(shared_folder=second))

    assert sandbox.configured_shares() == [(first, True), (second, False)]


def test_settings_folder_that_is_also_in_the_generic_list_is_not_repeated(tmp_path: Path) -> None:
    """The settings-dialog folder is dropped when the generic list already names it.

    Args:
        tmp_path: Scratch directory holding the configured folder.
    """
    folder = tmp_path / "shared"
    folder.mkdir()
    config = SandboxConfig(shared_folders=[(folder, "/guest/a", True)])
    sandbox = _ExposedSandbox(config, QEMUConfig(shared_folder=folder))

    assert sandbox.configured_shares() == [(folder, True)]


def _directory_with_file(root: Path, name: str, file_name: str, text: str) -> Path:
    """Create a directory holding one text file.

    Args:
        root: Directory to create it under.
        name: Name of the new directory.
        file_name: Name of the file inside it.
        text: Content of the file.

    Returns:
        Path: The new directory.
    """
    directory = root / name
    directory.mkdir()
    (directory / file_name).write_text(text, encoding="utf-8")
    return directory


def test_junction_creation_exposes_the_source_contents(tmp_path: Path) -> None:
    """A real junction makes the source's files readable at the destination.

    Args:
        tmp_path: Scratch directory.
    """
    source = _directory_with_file(tmp_path, "source", "payload.txt", "payload")
    destination = tmp_path / "junction"
    try:
        created = _ExposedSandbox.make_junction(source, destination)

        assert created is True
        assert destination.is_junction()
        assert (destination / "payload.txt").read_text(encoding="utf-8") == "payload"
    finally:
        if destination.is_junction():
            destination.rmdir()


def test_junction_into_a_missing_parent_is_reported_as_not_created(tmp_path: Path) -> None:
    """When the shell refuses to make the junction the helper reports failure.

    Args:
        tmp_path: Scratch directory.
    """
    source = _directory_with_file(tmp_path, "source", "payload.txt", "payload")
    destination = tmp_path / "no-such-parent" / "junction"

    assert _ExposedSandbox.make_junction(source, destination) is False
    assert not destination.exists()


def test_staging_replaces_a_stale_directory_with_a_junction(tmp_path: Path) -> None:
    """A leftover directory is removed and replaced, and the source is left alone.

    Args:
        tmp_path: Scratch directory.
    """
    source = _directory_with_file(tmp_path, "source", "payload.txt", "payload")
    destination = _directory_with_file(tmp_path, "staged", "stale.txt", "stale")
    try:
        _ExposedSandbox.link_or_copy_tree(source, destination)

        assert destination.is_junction()
        assert (destination / "payload.txt").read_text(encoding="utf-8") == "payload"
        assert not (destination / "stale.txt").exists()
        assert sorted(entry.name for entry in source.iterdir()) == ["payload.txt"]
    finally:
        if destination.is_junction():
            destination.rmdir()


def test_staging_replaces_a_leftover_file_with_a_junction(tmp_path: Path) -> None:
    """A file sitting where the staged folder belongs is removed first.

    Args:
        tmp_path: Scratch directory.
    """
    source = _directory_with_file(tmp_path, "source", "payload.txt", "payload")
    destination = tmp_path / "staged"
    destination.write_text("in the way", encoding="utf-8")
    try:
        _ExposedSandbox.link_or_copy_tree(source, destination)

        assert destination.is_junction()
        assert (destination / "payload.txt").read_text(encoding="utf-8") == "payload"
    finally:
        if destination.is_junction():
            destination.rmdir()


def test_staging_over_an_existing_junction_removes_the_link_not_its_target(tmp_path: Path) -> None:
    """Re-staging removes the old junction as a link, so the folder it pointed at survives.

    Args:
        tmp_path: Scratch directory.
    """
    old_source = _directory_with_file(tmp_path, "old-source", "old.txt", "old")
    new_source = _directory_with_file(tmp_path, "new-source", "new.txt", "new")
    destination = tmp_path / "staged"
    try:
        assert _ExposedSandbox.make_junction(old_source, destination) is True

        _ExposedSandbox.link_or_copy_tree(new_source, destination)

        assert destination.is_junction()
        assert (destination / "new.txt").read_text(encoding="utf-8") == "new"
        assert not (destination / "old.txt").exists()
        assert (old_source / "old.txt").read_text(encoding="utf-8") == "old"
    finally:
        if destination.is_junction():
            destination.rmdir()


def test_staging_copies_the_tree_when_no_junction_can_be_made(tmp_path: Path) -> None:
    """When the shell refuses the junction the folder is copied instead.

    Args:
        tmp_path: Scratch directory.
    """
    source = _directory_with_file(tmp_path, "source", "payload.txt", "payload")
    destination = tmp_path / "no-such-parent" / "staged"

    _ExposedSandbox.link_or_copy_tree(source, destination)

    assert destination.is_dir()
    assert not destination.is_junction()
    assert (destination / "payload.txt").read_text(encoding="utf-8") == "payload"
