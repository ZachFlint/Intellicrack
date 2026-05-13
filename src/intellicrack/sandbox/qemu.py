# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""QEMU sandbox implementation for isolated binary analysis.

This module provides cross-platform sandbox functionality using QEMU virtualization for safe execution and behavioral monitoring of
binaries.
"""

from __future__ import annotations

import asyncio
import json
import platform
import secrets
import shutil
import socket
import struct
import tempfile
import time
import zipfile
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal

import psutil

from intellicrack.core._subprocess import (
    TimeoutExpired as _SubprocessTimeoutExpired,
    run as _subprocess_run,
)
from intellicrack.core.logging import get_logger, log_sandbox_operation
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.sandbox._log_helpers import format_yara_match as _format_yara_match
from intellicrack.sandbox._log_parsers import (
    parse_api_trace_log,
    parse_clipboard_log,
    parse_dll_log,
    parse_file_log,
    parse_injection_log,
    parse_kernel_object_log,
    parse_network_log,
    parse_process_log,
    parse_registry_log,
    parse_resource_log,
    parse_service_log,
)
from intellicrack.sandbox.base import (
    ApiCall,
    ClipboardEvent,
    DllLoadEvent,
    ExecutionReport,
    ExecutionResult,
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
    SandboxTimeoutError,
    ServiceChange,
)


if TYPE_CHECKING:
    from collections.abc import Sequence

_logger = get_logger(__name__)

_QMP_READ_TIMEOUT = 5.0
_QMP_CONNECT_TIMEOUT = 60.0
_AGENT_POLL_TIMEOUT = 1.0
_ACCEL_DETECT_TIMEOUT = 10
_ACCEL_TEST_TIMEOUT = 5
_PROCESS_COMMUNICATE_TIMEOUT = 30
_SNAPSHOT_LINE_MIN_PARTS = 2
_SCREENSHOT_STABILITY_POLL_DELAY_S = 0.05
_SCREENSHOT_STABILITY_MAX_POLLS = 100
_SCREENSHOT_INITIAL_DELAY_S = 0.05
_ERR_SCREENSHOT_NOT_STABLE = "PPM file did not stabilize before timeout"
_ERR_SCREENSHOT_CONVERSION_FAILED = "PPM to PNG conversion failed"
_MONITOR_SCRIPT_NAMES: Final[tuple[str, ...]] = (
    "api_trace.ps1",
    "clipboard_monitor.ps1",
    "dll_monitor.ps1",
    "injection_monitor.ps1",
    "kernel_object_monitor.ps1",
    "resource_monitor.ps1",
    "service_monitor.ps1",
)
_MONITORING_LOG_NAMES: Final[tuple[str, ...]] = (
    "file_changes.log",
    "registry_changes.log",
    "network_activity.log",
    "process_activity.log",
    "api_trace.log",
    "service_monitor.log",
    "kernel_object_monitor.log",
    "dll_monitor.log",
    "injection_monitor.log",
    "resource_monitor.log",
    "clipboard_monitor.log",
)
_LOGS_STABLE_POLL_DELAY_S: Final[float] = 0.25
_LOGS_STABLE_REQUIRED_POLLS: Final[int] = 4
_LOGS_STABLE_MAX_WAIT_S: Final[float] = 30.0
_ERR_LOGS_STABLE_POLL_DELAY = "poll_delay must be positive"
_ERR_LOGS_STABLE_STABLE_POLLS = "stable_polls must be at least 1"
_ERR_LOGS_STABLE_MAX_WAIT = "max_wait must be non-negative"
_RETURNCODE_SUCCESS = 0

_ERR_NO_FREE_PORTS = "no free ports"
_ERR_QEMU_PATH = "path not set"
_ERR_NO_IMAGE = "image not found"
_ERR_QEMU_NA = "QEMU not available"
_ERR_QMP_CONNECT = "QMP connect failed"
_ERR_NOT_RUNNING = "not running"
_ERR_NO_SHARED_FOLDER = "shared folder not init"
_ERR_QMP_NOT_CONNECTED = "QMP not connected"
_ERR_QEMU_START = "QEMU start failed"
_ERR_VM_STATUS = "VM status query failed"
_ERR_SANDBOX_START = "sandbox start failed"
_ERR_SANDBOX_STOP = "sandbox stop failed"
_ERR_CMD_TIMEOUT = "command timed out"
_ERR_PIDFILE_UNREADABLE = "QEMU pidfile unreadable after retries - daemon may be orphaned"
_ERR_BINARY_NOT_FOUND = "binary not found"
_ERR_SOURCE_NOT_FOUND = "source not found"
_ERR_COPY_TO_SANDBOX = "copy to sandbox failed"
_ERR_COPY_FROM_SANDBOX = "copy from sandbox failed"
_ERR_SNAPSHOT_CREATE = "snapshot create failed"
_ERR_SNAPSHOT_RESTORE = "snapshot restore failed"
_ERR_SNAPSHOT_DELETE = "snapshot delete failed"
_PIDFILE_MAX_RETRIES = 3
_PIDFILE_RETRY_DELAY = 2.0
PIDFILE_MAX_RETRIES: int = _PIDFILE_MAX_RETRIES
PIDFILE_RETRY_DELAY: float = _PIDFILE_RETRY_DELAY
_ERR_UNSUPPORTED_GUEST_OS = "unsupported guest OS"
_ERR_PCAP_START_FAILED = "packet capture start failed"
_ERR_PCAP_STOP_FAILED = "packet capture stop failed"
_ERR_PCAP_NOT_ACTIVE = "no active packet capture with this ID"
_ERR_SCREENSHOT_FAILED = "screenshot capture failed"
_ERR_ANTI_EVASION_FAILED = "anti-evasion application failed"
_ERR_ANTI_EVASION_PROFILE_MISMATCH = (
    "Cannot apply anti-evasion profile {requested!r} on a sandbox launched with profile "
    "{current!r}. SMBIOS/CPUID masking is fixed at QEMU launch; set "
    "QEMUConfig.anti_evasion_profile before launching to use a different profile."
)
_ERR_MEMORY_DUMP_FAILED = "memory dump failed"
_ERR_EXTRACT_FILES_FAILED = "dropped file extraction failed"
_ERR_YARA_SCAN_FAILED = "YARA scan failed"
_ERR_YARA_NOT_AVAILABLE = "yara-python not installed"
_ERR_GUEST_AGENT_NOT_CONNECTED = "Guest agent not connected"
_ERR_GUEST_SCAN_FAILED = "guest YARA scan failed"
_ERR_AGENT_CONNECT_FAILED = "guest agent failed to connect within {timeout}s"
_AGENT_CONNECT_TIMEOUT = 30.0
_AGENT_CONNECT_RETRY_INTERVAL = 2.0
_READINESS_POLL_INTERVAL = 0.5
_READINESS_POLL_TIMEOUT = 60.0
_RESULT_PAYLOAD_SEPARATOR = "|IC_RESULT|"

_ERR_PPM_INVALID_MAGIC = "invalid PPM magic; expected P6"
_ERR_PPM_UNSUPPORTED_MAXVAL = "unsupported PPM maxval; only 8-bit (255) is supported"
_ERR_PPM_TRUNCATED = "PPM pixel data is truncated"
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PPM_EXPECTED_MAXVAL = 255
_PPM_WHITESPACE: frozenset[int] = frozenset(b" \t\r\n")


def _read_ppm_token(data: bytes, pos: int) -> tuple[str, int]:
    """Read the next whitespace-delimited token from PPM header.

    Skips ASCII whitespace and `#`-prefixed comment lines per the
    Netpbm PPM specification, then returns the next token.

    Args:
        data: Raw PPM file bytes.
        pos: Current read position into ``data``.

    Returns:
        tuple[str, int]: Parsed token and updated position pointing at the
        byte immediately after the token.
    """
    while pos < len(data):
        byte = data[pos]
        if byte in _PPM_WHITESPACE:
            pos += 1
            continue
        if byte == ord("#"):
            newline = data.find(b"\n", pos)
            pos = len(data) if newline == -1 else newline + 1
            continue
        break
    start = pos
    while pos < len(data) and data[pos] not in _PPM_WHITESPACE:
        pos += 1
    return data[start:pos].decode("ascii"), pos


def _encode_png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    """Encode a single PNG chunk with length and CRC32 framing.

    Args:
        chunk_type: 4-byte PNG chunk type identifier.
        payload: Chunk data (may be empty).

    Returns:
        bytes: Full PNG chunk including length header and trailing CRC.
    """
    length = struct.pack(">I", len(payload))
    crc = struct.pack(">I", zlib.crc32(chunk_type + payload) & 0xFFFFFFFF)
    return length + chunk_type + payload + crc


def _parse_ppm_p6(data: bytes) -> tuple[int, int, bytes]:
    """Parse a Netpbm P6 PPM payload into ``(width, height, rgb_pixels)``.

    Args:
        data: Raw bytes of the PPM file.

    Returns:
        tuple[int, int, bytes]: Tuple ``(width, height, pixels)`` where ``pixels`` is raw RGB bytes.

    Raises:
        ValueError: If the PPM magic is not ``P6``, the maxval is not 255, or
            the pixel payload is truncated.
    """
    magic, pos = _read_ppm_token(data, 0)
    if magic != "P6":
        _logger.warning("ppm_invalid_magic", magic=magic, payload_size=len(data))
        raise ValueError(_ERR_PPM_INVALID_MAGIC)
    width_str, pos = _read_ppm_token(data, pos)
    height_str, pos = _read_ppm_token(data, pos)
    maxval_str, pos = _read_ppm_token(data, pos)
    if int(maxval_str) != _PPM_EXPECTED_MAXVAL:
        _logger.warning("ppm_unsupported_maxval", maxval=maxval_str)
        raise ValueError(_ERR_PPM_UNSUPPORTED_MAXVAL)
    if pos < len(data) and data[pos] in _PPM_WHITESPACE:
        pos += 1
    width = int(width_str)
    height = int(height_str)
    expected_bytes = width * height * 3
    pixels = data[pos : pos + expected_bytes]
    if len(pixels) < expected_bytes:
        _logger.warning(
            "ppm_truncated",
            expected_size=expected_bytes,
            actual_size=len(pixels),
        )
        raise ValueError(_ERR_PPM_TRUNCATED)
    return width, height, pixels


def _ppm_p6_to_png(ppm_path: Path, png_path: Path) -> None:
    """Convert a Netpbm P6 PPM image to PNG using only the stdlib.

    Reads an 8-bit RGB PPM (binary P6) produced by QEMU's ``screendump``
    and writes a compressed true-color PNG. PPM parsing errors bubble up
    from :func:`_parse_ppm_p6` as ``ValueError``.

    Args:
        ppm_path: Path to the source PPM image.
        png_path: Destination path for the PNG output.
    """
    width, height, pixels = _parse_ppm_p6(ppm_path.read_bytes())
    stride = width * 3
    raw_scanlines = b"".join(b"\x00" + pixels[row * stride : (row + 1) * stride] for row in range(height))
    png_bytes = (
        _PNG_SIGNATURE
        + _encode_png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _encode_png_chunk(b"IDAT", zlib.compress(raw_scanlines, level=9))
        + _encode_png_chunk(b"IEND", b"")
    )
    png_path.write_bytes(png_bytes)
    _logger.info(
        "screenshot_png_written",
        png_path=str(png_path),
        size=len(png_bytes),
        width=width,
        height=height,
    )


class GuestOS(Enum):
    """Guest operating system type."""

    WINDOWS = "windows"
    LINUX = "linux"


class AcceleratorType(Enum):
    """QEMU acceleration types."""

    WHPX = "whpx"
    KVM = "kvm"
    TCG = "tcg"


@dataclass
class _MonitoringLogs:
    """Aggregated monitoring log parse results.

    Attributes:
        file_changes: Parsed file-change records.
        registry_changes: Parsed registry-change records.
        network_activity: Parsed network activity records.
        process_activity: Parsed process activity records.
        api_calls: Parsed API call records.
        service_changes: Parsed service change records.
        kernel_objects: Parsed kernel-object activity records.
        dll_loads: Parsed DLL-load event records.
        injection_events: Parsed injection event records.
        resource_samples: Parsed resource usage samples.
        clipboard_events: Parsed clipboard event records.
    """

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


@dataclass
class QEMUConfig:
    """Configuration for QEMU sandbox.

    Attributes:
        guest_os: Guest operating system type.
        image_path: Path to the qcow2 disk image.
        cpu_cores: Number of CPU cores.
        memory_mb: Memory in megabytes.
        display: Display output mode.
        ssh_port: Port forwarding for SSH.
        monitor_port: Port for QMP monitor.
        agent_port: Port for guest agent.
        enable_acceleration: Whether to use hardware acceleration.
        snapshot_name: Snapshot to restore on start.
        shared_folder: Path to shared folder on host.
        anti_evasion_profile: Anti-evasion profile applied at launch via
            ``-smbios`` / ``-cpu`` command-line arguments. One of
            ``default``, ``workstation``, or ``laptop``.
        agent_connect_timeout: Total timeout in seconds that ``start()`` will
            wait for the in-guest agent TCP socket to become reachable before
            failing the sandbox launch.
    """

    guest_os: GuestOS = GuestOS.WINDOWS
    image_path: Path | None = None
    cpu_cores: int = 2
    memory_mb: int = 4096
    display: Literal["none", "vnc", "sdl", "spice"] = "none"
    ssh_port: int = 2222
    monitor_port: int = 4444
    agent_port: int = 4445
    enable_acceleration: bool = True
    snapshot_name: str | None = None
    shared_folder: Path | None = None
    anti_evasion_profile: Literal["default", "workstation", "laptop"] = "default"
    agent_connect_timeout: float = 60.0


@dataclass
class QMPResponse:
    """Response from QMP command.

    Attributes:
        success: Whether the command succeeded.
        data: Response data if successful.
        error: Error message if failed.
    """

    success: bool
    data: dict[str, object] | None = None
    error: str | None = None


@dataclass
class GuestAgentMessage:
    """Message from the guest agent.

    Attributes:
        message_type: Type of the guest agent message.
        timestamp: When the message was received.
        data: Message payload.
    """

    message_type: str
    timestamp: datetime
    data: dict[str, object] = field(default_factory=dict)


class QMPClient:
    """QEMU Machine Protocol client for VM control.

    Provides asynchronous communication with QEMU via QMP for VM control, snapshot management, and status queries.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 4444) -> None:
        """Initialize the QMP client.

        Args:
            host: Host address where the QMP server is listening.
            port: TCP port for the QMP server.
        """
        self._host = host
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self.connected = False
        self._lock = asyncio.Lock()
        _logger.debug("qmp_client_initialized", host=host, port=port)

    async def connect(self, time_limit: float = 30.0) -> bool:
        """Connect to QMP server.

        Args:
            time_limit: Connection timeout in seconds.

        Returns:
            bool: True if connected successfully.
        """
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port),
                timeout=time_limit,
            )

            greeting = await asyncio.wait_for(
                self._reader.readline(),
                timeout=_QMP_READ_TIMEOUT,
            )
            _logger.debug("qmp_greeting_received", greeting=greeting.decode().strip())

            await self._send_command({"execute": "qmp_capabilities"})
            self.connected = True
            _logger.info("qmp_connected", host=self._host, port=self._port)

        except (OSError, TimeoutError, ConnectionError) as e:
            _logger.warning("qmp_connection_failed", error=str(e))
            return False
        else:
            return True

    async def disconnect(self) -> None:
        """Disconnect from QMP server."""
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except OSError as e:
                _logger.warning("qmp_disconnect_error", error=str(e))
        self._reader = None
        self._writer = None
        self.connected = False

    async def _send_command(
        self,
        command: dict[str, object],
        time_limit: float = 10.0,
    ) -> QMPResponse:
        """Send a QMP command and get response.

        Args:
            command: QMP command dictionary.
            time_limit: Response timeout in seconds.

        Returns:
            QMPResponse: QMP response.
        """
        _logger.debug("qmp_command_send_called", command=command.get("execute"))
        if self._reader is None or self._writer is None:
            return QMPResponse(success=False, error="Not connected")

        async with self._lock:
            try:
                cmd_json = json.dumps(command) + "\n"
                self._writer.write(cmd_json.encode())
                await self._writer.drain()

                response_line = await asyncio.wait_for(
                    self._reader.readline(),
                    timeout=time_limit,
                )

                response = json.loads(response_line.decode())

                if "error" in response:
                    return QMPResponse(
                        success=False,
                        error=response["error"].get("desc", "Unknown error"),
                    )

                return QMPResponse(success=True, data=response.get("return"))

            except TimeoutError:
                _logger.warning("qmp_command_timeout")
                return QMPResponse(success=False, error="Command timed out")
            except (OSError, json.JSONDecodeError, ConnectionError) as e:
                _logger.warning("qmp_command_failed", error=str(e), exc_info=True)
                return QMPResponse(success=False, error=str(e))

    async def query_status(self) -> QMPResponse:
        """Query VM status.

        Returns:
            QMPResponse: VM status response.
        """
        return await self._send_command({"execute": "query-status"})

    async def stop(self) -> QMPResponse:
        """Pause the VM.

        Returns:
            QMPResponse: Command response.
        """
        return await self._send_command({"execute": "stop"})

    async def cont(self) -> QMPResponse:
        """Resume the VM.

        Returns:
            QMPResponse: Command response.
        """
        return await self._send_command({"execute": "cont"})

    async def quit(self) -> QMPResponse:
        """Quit QEMU.

        Returns:
            QMPResponse: Command response.
        """
        return await self._send_command({"execute": "quit"})

    async def savevm(self, name: str) -> QMPResponse:
        """Save a VM snapshot.

        Args:
            name: Snapshot name.

        Returns:
            QMPResponse: Command response.
        """
        return await self._send_command({
            "execute": "human-monitor-command",
            "arguments": {"command-line": f"savevm {name}"},
        })

    async def loadvm(self, name: str) -> QMPResponse:
        """Load a VM snapshot.

        Args:
            name: Snapshot name.

        Returns:
            QMPResponse: Command response.
        """
        return await self._send_command({
            "execute": "human-monitor-command",
            "arguments": {"command-line": f"loadvm {name}"},
        })

    async def delvm(self, name: str) -> QMPResponse:
        """Delete a VM snapshot.

        Args:
            name: Snapshot name.

        Returns:
            QMPResponse: Command response.
        """
        return await self._send_command({
            "execute": "human-monitor-command",
            "arguments": {"command-line": f"delvm {name}"},
        })

    async def info_snapshots(self) -> QMPResponse:
        """Get list of snapshots.

        Returns:
            QMPResponse: Snapshot list response.
        """
        return await self._send_command({
            "execute": "human-monitor-command",
            "arguments": {"command-line": "info snapshots"},
        })

    async def execute_command(
        self,
        command: dict[str, object],
        time_limit: float = 10.0,
    ) -> QMPResponse:
        """Execute an arbitrary QMP command.

        Public wrapper around the internal command dispatch for use by
        the sandbox implementation when QMP operations are needed that
        do not have a dedicated convenience method.

        Args:
            command: QMP command dictionary with 'execute' key.
            time_limit: Response timeout in seconds.

        Returns:
            QMPResponse: QMP response with success status and data.
        """
        return await self._send_command(command, time_limit)


class GuestAgentClient:
    """Client for communicating with the QEMU guest agent.

    Provides bidirectional communication with the guest OS for command execution, file transfer, and behavioral monitoring.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 4445) -> None:
        """Initialize the guest agent client.

        Args:
            host: Host address where the guest agent is reachable.
            port: TCP port for the guest agent server.
        """
        self._host = host
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self.connected = False
        self._lock = asyncio.Lock()
        self._message_queue: asyncio.Queue[GuestAgentMessage] = asyncio.Queue()
        self._reader_task: asyncio.Task[None] | None = None
        _logger.debug("guest_agent_client_initialized", host=host, port=port)

    @property
    def is_connected(self) -> bool:
        """Whether the client is currently connected.

        Returns:
            bool: True if the guest agent connection is active.
        """
        return self.connected

    async def connect(self, time_limit: float = 60.0, retry_interval: float = 2.0) -> bool:
        """Connect to guest agent with retry.

        Args:
            time_limit: Total timeout in seconds for connection attempts.
            retry_interval: Interval between retries.

        Returns:
            bool: True if connected successfully.
        """
        start_time = time.time()

        connected = False
        while time.time() - start_time < time_limit:
            try:
                self._reader, self._writer = await asyncio.wait_for(
                    asyncio.open_connection(self._host, self._port),
                    timeout=retry_interval,
                )
                self.connected = True

                self._reader_task = asyncio.create_task(self._read_messages())

                _logger.info("guest_agent_connected", host=self._host, port=self._port)
                connected = True
                break

            except (TimeoutError, OSError):
                _logger.debug("guest_agent_connect_retry", host=self._host, port=self._port)
                await asyncio.sleep(retry_interval)

        if not connected:
            _logger.warning("guest_agent_connection_failed", timeout_seconds=time_limit)
        return connected

    async def disconnect(self) -> None:
        """Disconnect from guest agent."""
        if self._reader_task is not None:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                _logger.debug("guest_agent_disconnect_cancelled", exc_info=True)
            self._reader_task = None

        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except OSError as e:
                _logger.warning("agent_disconnect_error", error=str(e))

        self._reader = None
        self._writer = None
        self.connected = False

    async def _read_messages(self) -> None:
        """Background task to read messages from agent."""
        if self._reader is None:
            return

        while self.connected:
            try:
                line = await self._reader.readline()
                if not line:
                    break

                try:
                    data = json.loads(line.decode())
                    msg = GuestAgentMessage(
                        message_type=data.get("type", "unknown"),
                        timestamp=datetime.now(UTC),
                        data=data.get("data", {}),
                    )
                    await self._message_queue.put(msg)
                except json.JSONDecodeError:
                    _logger.warning("agent_invalid_json", line=line.decode(errors="replace"))

            except asyncio.CancelledError:
                _logger.debug("agent_read_cancelled", exc_info=True)
                break
            except (OSError, ConnectionError) as e:
                _logger.warning("agent_read_error", error=str(e))
                break

    async def send_command(
        self,
        command: str,
        args: Sequence[str] | None = None,
        time_limit: float = 30.0,
    ) -> tuple[int, str, str]:
        """Send a command to execute in the guest.

        Args:
            command: Command to execute.
            args: Command arguments.
            time_limit: Execution timeout in seconds.

        Returns:
            tuple[int, str, str]: Tuple of (exit_code, stdout, stderr).
        """
        _logger.debug(
            "guest_send_command_called",
            command=command,
            args_count=len(args) if args else 0,
            time_limit=time_limit,
        )
        if self._writer is None or not self.connected:
            return (-1, "", "Not connected to guest agent")

        request = {
            "type": "execute",
            "command": command,
            "args": list(args) if args else [],
            "timeout": time_limit,
        }

        async with self._lock:
            result: tuple[int, str, str] = (-1, "", "Command timed out")
            try:
                self._writer.write((json.dumps(request) + "\n").encode())
                await self._writer.drain()

                start_time = time.time()
                while time.time() - start_time < time_limit:
                    try:
                        msg = await asyncio.wait_for(
                            self._message_queue.get(),
                            timeout=_AGENT_POLL_TIMEOUT,
                        )
                        if msg.message_type == "result":
                            exit_code_raw = msg.data.get("exit_code")
                            exit_code_val = (
                                int(exit_code_raw) if exit_code_raw is not None and isinstance(exit_code_raw, (int, str)) else -1
                            )
                            result = (
                                exit_code_val,
                                str(msg.data.get("stdout", "")),
                                str(msg.data.get("stderr", "")),
                            )
                            break
                    except TimeoutError:
                        _logger.debug("guest_command_poll_timeout", exc_info=True)
                        continue

            except (OSError, ConnectionError) as e:
                _logger.warning("guest_command_execution_failed", error=str(e), exc_info=True)
                result = (-1, "", str(e))

            return result

    async def get_pending_messages(self) -> list[GuestAgentMessage]:
        """Get all pending messages from the agent.

        Returns:
            list[GuestAgentMessage]: List of pending messages.
        """
        messages: list[GuestAgentMessage] = []
        while not self._message_queue.empty():
            try:
                msg = self._message_queue.get_nowait()
                messages.append(msg)
            except asyncio.QueueEmpty:
                _logger.debug("message_queue_empty", exc_info=True)
                break
        return messages


class QEMUSandbox(SandboxBase):
    """QEMU-based sandbox for cross-platform binary analysis.

    Uses QEMU virtualization with hardware acceleration (WHPX on Windows,
    KVM on Linux) or software emulation (TCG) for isolated binary execution.

    Attributes:
        QEMU_EXE: QEMU executable name.
        TOOLS_PATH: Default path to QEMU installation.
        GUEST_SHARED_PATH_WINDOWS: Shared path on Windows guest.
        GUEST_SHARED_PATH_LINUX: Shared path on Linux guest.
    """

    QEMU_EXE: Final[str] = "qemu-system-x86_64"
    TOOLS_PATH: Final[Path] = Path("D:/Intellicrack/tools/qemu")
    GUEST_SHARED_PATH_WINDOWS: Final[str] = "Z:\\"
    GUEST_SHARED_PATH_LINUX: Final[str] = "/mnt/shared"

    def __init__(
        self,
        config: SandboxConfig | None = None,
        qemu_config: QEMUConfig | None = None,
    ) -> None:
        """Initialize the QEMU sandbox.

        Args:
            config: General sandbox configuration shared across backends.
            qemu_config: QEMU-specific configuration such as memory and disk image.
        """
        super().__init__(config)
        self._qemu_config = qemu_config or QEMUConfig()
        self.process: asyncio.subprocess.Process | None = None
        self._qmp: QMPClient | None = None
        self._agent: GuestAgentClient | None = None
        self._temp_dir: Path | None = None
        self._shared_folder: Path | None = None
        self._accelerator: AcceleratorType = AcceleratorType.TCG
        self._qemu_path: Path | None = None
        self._pidfile_path: Path | None = None
        self._qemu_pid: int | None = None
        self._vnc_port: int | None = None
        self._active_captures: dict[str, Path] = {}
        self._accelerator_cached: bool = False
        _logger.info(
            "qemu_sandbox_initialized",
            guest_os=self._qemu_config.guest_os.value,
            memory_mb=self._qemu_config.memory_mb,
            cpu_cores=self._qemu_config.cpu_cores,
        )

    @property
    def qemu_config(self) -> QEMUConfig:
        """Get QEMU configuration.

        Returns:
            QEMUConfig: Current QEMU configuration.
        """
        return self._qemu_config

    @property
    def vnc_port(self) -> int | None:
        """Get the VNC port if VNC display is active.

        Returns:
            int | None: VNC port number, or None if VNC is not enabled.
        """
        return self._vnc_port

    @property
    def qmp(self) -> QMPClient | None:
        """Get the QMP client, or None if not connected.

        Returns:
            QMPClient | None: Active QMP client, or None if the VM is not running.
        """
        return self._qmp

    @property
    def agent(self) -> GuestAgentClient | None:
        """Get the guest agent client, or None if not connected.

        Returns:
            GuestAgentClient | None: Active guest agent client, or None if the agent is not connected.
        """
        return self._agent

    def enable_vnc_display(self) -> None:
        """Switch display mode to VNC for GUI embedding.

        This must be called before ``start()`` to take effect. If the sandbox is already running, restart is required.
        """
        self._qemu_config = QEMUConfig(
            guest_os=self._qemu_config.guest_os,
            image_path=self._qemu_config.image_path,
            cpu_cores=self._qemu_config.cpu_cores,
            memory_mb=self._qemu_config.memory_mb,
            display="vnc",
            ssh_port=self._qemu_config.ssh_port,
            monitor_port=self._qemu_config.monitor_port,
            agent_port=self._qemu_config.agent_port,
            enable_acceleration=self._qemu_config.enable_acceleration,
            snapshot_name=self._qemu_config.snapshot_name,
            shared_folder=self._qemu_config.shared_folder,
            anti_evasion_profile=self._qemu_config.anti_evasion_profile,
            agent_connect_timeout=self._qemu_config.agent_connect_timeout,
        )
        _logger.info("vnc_display_enabled", vnc_port=self.vnc_port)

    def invalidate_accelerator_cache(self) -> None:
        """Invalidate the cached accelerator detection result.

        Forces the next call to ``is_available`` to re-probe the host for hardware virtualisation support. Useful after a system
        configuration change (e.g. enabling Hyper-V Platform) without restarting the application.
        """
        self._accelerator_cached = False
        _logger.debug("accelerator_cache_invalidated")

    async def is_available(self) -> bool:
        """Check if QEMU is available.

        Checks for QEMU executable and determines available acceleration.
        The accelerator detection result is cached after the first successful
        probe; call :meth:`invalidate_accelerator_cache` to force re-detection.

        Returns:
            bool: True if QEMU can be used.
        """
        qemu_path = await self._find_qemu()
        if qemu_path is None:
            _logger.debug("qemu_executable_not_found", search_names=["qemu-system-x86_64"])
            return False

        self._qemu_path = qemu_path

        if not self._accelerator_cached:
            self._accelerator = await self._detect_accelerator()
            self._accelerator_cached = True
            _logger.info(
                "qemu_available",
                path=str(qemu_path),
                accelerator=self._accelerator.value,
            )
        else:
            _logger.debug(
                "qemu_available_cached_accelerator",
                path=str(qemu_path),
                accelerator=self._accelerator.value,
            )
        return True

    async def _find_qemu(self) -> Path | None:
        """Find QEMU executable.

        Returns:
            Path | None: Path to QEMU executable or None if not found.
        """
        search_paths: list[Path] = []

        if await asyncio.to_thread(self.TOOLS_PATH.exists):
            search_paths.append(self.TOOLS_PATH / f"{self.QEMU_EXE}.exe")

        if qemu_in_path := shutil.which(self.QEMU_EXE):
            search_paths.append(Path(qemu_in_path))

        common_paths = [
            Path("C:/Program Files/qemu"),
            Path("C:/Program Files (x86)/qemu"),
            Path("/usr/bin"),
            Path("/usr/local/bin"),
        ]
        for base in common_paths:
            exe_name = f"{self.QEMU_EXE}.exe" if base.drive else self.QEMU_EXE
            search_paths.append(base / exe_name)

        def _find_existing() -> Path | None:
            return next(
                (path for path in search_paths if path.exists() and path.is_file()),
                None,
            )

        return await asyncio.to_thread(_find_existing)

    @staticmethod
    def _probe_whpx_host_prerequisites() -> bool:
        """Verify that the host OS has Hyper-V Platform (WHPX) actually enabled.

        QEMU reports ``whpx`` in ``-accel help`` output whenever the binary was
        compiled with WHPX support, but the feature is useless unless the
        Hyper-V hypervisor is *running*. This method performs two independent
        checks that must both pass:

        1. ``Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform``
           must report ``Enabled``.
        2. ``bcdedit /enum {current}`` must show
           ``hypervisorlaunchtype    Auto`` (not ``Off`` and not absent).

        Returns:
            bool: ``True`` only when both signals confirm WHPX is usable.
        """
        if platform.system() != "Windows":
            return False

        pwsh = shutil.which("pwsh") or shutil.which("powershell")
        if pwsh is None:
            _logger.debug("whpx_probe_no_powershell")
            return False

        try:
            ps_result = _subprocess_run(
                [
                    pwsh,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    "(Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -ErrorAction Stop).State",
                ],
                capture_output=True,
                text=True,
                timeout=_ACCEL_DETECT_TIMEOUT,
                check=False,
            )
            feature_state = ps_result.stdout.strip().lower()
            if feature_state != "enabled":
                _logger.debug("whpx_hypervisor_platform_not_enabled", state=feature_state)
                return False
        except (OSError, _SubprocessTimeoutExpired) as e:
            _logger.debug("whpx_feature_probe_failed", error=str(e))
            return False

        bcdedit_path = shutil.which("bcdedit.exe") or shutil.which("bcdedit")
        if bcdedit_path is None:
            _logger.debug("whpx_probe_no_bcdedit")
            return False
        try:
            bcdedit_result = _subprocess_run(
                [bcdedit_path, "/enum", "{current}"],
                capture_output=True,
                text=True,
                timeout=_ACCEL_DETECT_TIMEOUT,
                check=False,
            )
            bcd_output = bcdedit_result.stdout.lower()
            if "hypervisorlaunchtype" not in bcd_output:
                _logger.debug("whpx_bcdedit_no_hypervisorlaunchtype")
                return False
            if "hypervisorlaunchtype    auto" not in bcd_output and "hypervisorlaunchtype  auto" not in bcd_output:
                _logger.debug("whpx_bcdedit_hypervisorlaunchtype_not_auto", bcd_output=bcd_output)
                return False
        except (OSError, _SubprocessTimeoutExpired) as e:
            _logger.debug("whpx_bcdedit_probe_failed", error=str(e))
            return False

        _logger.debug("whpx_host_prerequisites_satisfied")
        return True

    async def _detect_accelerator(self) -> AcceleratorType:
        """Detect available hardware acceleration.

        On Windows hosts the WHPX path additionally requires that the
        ``HypervisorPlatform`` optional feature is enabled and that
        ``bcdedit /enum {current}`` reports ``hypervisorlaunchtype Auto``.
        When either check fails the candidate is rejected and detection
        falls through to KVM (Linux) or TCG.

        Returns:
            AcceleratorType: Best available accelerator type.
        """
        if self._qemu_path is None:
            return AcceleratorType.TCG

        process_manager = ProcessManager.get_instance()

        try:
            result = await process_manager.run_tracked_async(
                [str(self._qemu_path), "-accel", "help"],
                name="qemu-accel-help",
                process_timeout=_ACCEL_DETECT_TIMEOUT,
            )
            output = result.stdout + result.stderr

            if "whpx" in output.lower():
                whpx_prereqs = await asyncio.to_thread(self._probe_whpx_host_prerequisites)
                if whpx_prereqs:
                    whpx_test = await process_manager.run_tracked_async(
                        [
                            str(self._qemu_path),
                            "-accel",
                            "whpx",
                            "-machine",
                            "q35",
                            "-m",
                            "64",
                            "-display",
                            "none",
                            "-device",
                            "?",
                        ],
                        name="qemu-whpx-test",
                        text=False,
                        process_timeout=_ACCEL_TEST_TIMEOUT,
                    )
                    stderr_bytes = whpx_test.stderr if isinstance(whpx_test.stderr, bytes) else whpx_test.stderr.encode()
                    if whpx_test.returncode == _RETURNCODE_SUCCESS or b"whpx" not in stderr_bytes.lower():
                        _logger.info("whpx_acceleration_available", accelerator="whpx")
                        return AcceleratorType.WHPX
                else:
                    _logger.info("whpx_skipped_host_prerequisites_not_met")

            if "kvm" in output.lower():
                kvm_test = await process_manager.run_tracked_async(
                    [
                        str(self._qemu_path),
                        "-accel",
                        "kvm",
                        "-machine",
                        "q35",
                        "-m",
                        "64",
                        "-display",
                        "none",
                        "-device",
                        "?",
                    ],
                    name="qemu-kvm-test",
                    text=False,
                    process_timeout=_ACCEL_TEST_TIMEOUT,
                )
                if kvm_test.returncode == _RETURNCODE_SUCCESS:
                    _logger.info("kvm_acceleration_available", accelerator="kvm")
                    return AcceleratorType.KVM

        except (OSError, RuntimeError, TimeoutError) as e:
            _logger.warning("acceleration_detection_failed", error=str(e))

        _logger.info("using_tcg_software_emulation", accelerator="tcg")
        return AcceleratorType.TCG

    @staticmethod
    def _get_free_port(start: int = 10000, end: int = 60000) -> int:
        """Find an available port.

        Args:
            start: Start of port range.
            end: End of port range.

        Returns:
            int: Available port number.

        Raises:
            SandboxError: If no free ports are available after 100 attempts.
        """
        for _ in range(100):
            port = secrets.randbelow(end - start) + start
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                if sock.connect_ex(("127.0.0.1", port)) != 0:
                    return port
        _logger.error("free_port_search_exhausted", port_start=start, port_end=end)
        raise SandboxError(_ERR_NO_FREE_PORTS)

    @staticmethod
    def _check_qemu_started(returncode: int | None, stderr: bytes | None) -> None:
        """Check if QEMU process started successfully.

        Args:
            returncode: Process return code.
            stderr: Standard error output.

        Raises:
            SandboxError: If process failed to start.
        """
        if returncode != _RETURNCODE_SUCCESS:
            error_msg = stderr.decode() if stderr else "Unknown error"
            _logger.warning("qemu_start_failed", error=error_msg)
            raise SandboxError(_ERR_QEMU_START)

    async def _verify_qemu_pid(self, qemu_pid: int | None) -> None:
        """Verify that the QEMU process started and its PID was read successfully.

        Args:
            qemu_pid: The PID read from the pidfile, or None if unreadable.

        Raises:
            SandboxError: If the PID could not be read from the pidfile.
        """
        if qemu_pid is None:
            _logger.warning("qemu_pidfile_unreadable", pidfile=str(self._pidfile_path))
            await self._cleanup()
            raise SandboxError(_ERR_PIDFILE_UNREADABLE)

    async def _connect_and_verify_qmp(self) -> None:
        """Connect to QMP and verify VM status.

        Raises:
            SandboxError: If connection or status check fails.
        """
        self._qmp = QMPClient(port=self._qemu_config.monitor_port)
        if not await self._qmp.connect(time_limit=_QMP_CONNECT_TIMEOUT):
            raise SandboxError(_ERR_QMP_CONNECT)

        status = await self._qmp.query_status()
        if not status.success:
            _logger.warning("vm_status_query_failed", error=status.error)
            raise SandboxError(_ERR_VM_STATUS)

    @staticmethod
    def _anti_evasion_smbios_entries(profile: str) -> list[dict[str, str]]:
        """Return SMBIOS entries for the selected anti-evasion profile.

        Args:
            profile: Profile name (``default``, ``workstation``, or ``laptop``).

        Returns:
            list[dict[str, str]]: SMBIOS entries suitable for ``-smbios`` argv.
        """
        if profile == "workstation":
            return [
                {"type": "1", "manufacturer": "Dell Inc.", "product": "OptiPlex 7090", "serial": f"SVC{secrets.token_hex(5).upper()}"},
                {"type": "2", "manufacturer": "Dell Inc.", "product": "0WN7Y6"},
                {"type": "3", "manufacturer": "Dell Inc.", "chassis-type": "3"},
            ]
        if profile == "laptop":
            return [
                {"type": "1", "manufacturer": "Lenovo", "product": "ThinkPad T14 Gen 3", "serial": f"PF{secrets.token_hex(5).upper()}"},
                {"type": "2", "manufacturer": "Lenovo", "product": "21AHS00000"},
                {"type": "3", "manufacturer": "Lenovo", "chassis-type": "10"},
            ]
        return [
            {"type": "1", "manufacturer": "HP", "product": "HP EliteDesk 800 G6", "serial": f"MXL{secrets.token_hex(5).upper()}"},
            {"type": "2", "manufacturer": "HP", "product": "8767"},
            {"type": "3", "manufacturer": "HP", "chassis-type": "3"},
        ]

    async def _build_qemu_command(self) -> list[str]:
        """Build QEMU command line.

        Adds ``-smbios`` entries and a masked ``-cpu`` string for
        anti-evasion. The SMBIOS profile is sourced from
        :class:`QEMUConfig.anti_evasion_profile`. The CPU argument includes
        ``hv-vendor-id``, ``kvm=off`` and ``hypervisor=off`` to reduce
        hypervisor detection via CPUID.

        Returns:
            list[str]: QEMU command as list of arguments.

        Raises:
            SandboxError: If configuration is invalid.
            ValueError: If the guest OS type is unsupported.
        """
        if self._qemu_path is None:
            _logger.error("qemu_command_build_failed_no_path")
            raise SandboxError(_ERR_QEMU_PATH)

        if self._qemu_config.image_path is None or not await asyncio.to_thread(self._qemu_config.image_path.exists):
            _logger.error(
                "qemu_command_build_failed_no_image",
                image_path=str(self._qemu_config.image_path) if self._qemu_config.image_path else None,
            )
            raise SandboxError(_ERR_NO_IMAGE)

        if self._accelerator in {AcceleratorType.KVM, AcceleratorType.WHPX}:
            cpu_arg = "host,hv-vendor-id=AuthenticAMD,kvm=off,hypervisor=off"
        else:
            cpu_arg = "max,hv-vendor-id=AuthenticAMD,hypervisor=off"

        cmd: list[str] = [
            str(self._qemu_path),
            *["-machine", f"q35,accel={self._accelerator.value}"],
            "-cpu",
            cpu_arg,
            *["-smp", f"cores={self._qemu_config.cpu_cores}"],
            *["-m", str(self._qemu_config.memory_mb)],
            *[
                "-drive",
                f"file={self._qemu_config.image_path},format=qcow2,if=virtio",
            ],
        ]

        for entry in self._anti_evasion_smbios_entries(self._qemu_config.anti_evasion_profile):
            smbios_value = ",".join(f"{k}={v}" for k, v in entry.items())
            cmd.extend(["-smbios", smbios_value])

        if self._qemu_config.display == "none":
            cmd.extend(["-display", "none"])
        elif self._qemu_config.display == "vnc":
            vnc_full_port = self._get_free_port(5900, 5999)
            vnc_display = vnc_full_port - 5900
            self._vnc_port = vnc_full_port
            cmd.extend(["-vnc", f":{vnc_display}"])
        elif self._qemu_config.display == "sdl":
            cmd.extend(["-display", "sdl"])
        elif self._qemu_config.display == "spice":
            spice_port = self._get_free_port(5900, 5999)
            cmd.extend(["-spice", f"port={spice_port},disable-ticketing=on"])

        ssh_port = self._qemu_config.ssh_port or self._get_free_port()
        monitor_port = self._qemu_config.monitor_port or self._get_free_port()
        agent_port = self._qemu_config.agent_port or self._get_free_port()

        netdev = f"user,id=net0,hostfwd=tcp::{ssh_port}-:22"
        netdev += f",hostfwd=tcp::{agent_port}-:4445"

        if self._shared_folder is not None:
            if self._qemu_config.guest_os == GuestOS.WINDOWS:
                cmd.extend([
                    "-drive",
                    f"file=fat:rw:{self._shared_folder},format=raw,if=virtio,label=SHARED",
                ])
            elif self._qemu_config.guest_os == GuestOS.LINUX:
                cmd.extend([
                    "-fsdev",
                    f"local,id=fsdev0,path={self._shared_folder},security_model=mapped-xattr",
                    "-device",
                    "virtio-9p-pci,fsdev=fsdev0,mount_tag=shared",
                ])
            else:
                _logger.error("qemu_command_build_failed_guest_os", guest_os=str(self._qemu_config.guest_os))
                raise ValueError(_ERR_UNSUPPORTED_GUEST_OS)

        cmd.extend([
            "-netdev",
            netdev,
            "-device",
            "virtio-net-pci,netdev=net0",
            "-qmp",
            f"tcp:127.0.0.1:{monitor_port},server,nowait",
            "-device",
            "virtio-serial-pci",
            "-chardev",
            f"socket,id=agent,host=127.0.0.1,port={agent_port + 1},server,nowait",
            "-device",
            "virtserialport,chardev=agent,name=org.qemu.guest_agent.0",
        ])
        if self._qemu_config.snapshot_name:
            cmd.extend(["-loadvm", self._qemu_config.snapshot_name])

        if self._temp_dir is not None:
            self._pidfile_path = self._temp_dir / "qemu.pid"
            cmd.extend(["-pidfile", str(self._pidfile_path)])

        cmd.append("-daemonize")

        self._qemu_config = QEMUConfig(
            guest_os=self._qemu_config.guest_os,
            image_path=self._qemu_config.image_path,
            cpu_cores=self._qemu_config.cpu_cores,
            memory_mb=self._qemu_config.memory_mb,
            display=self._qemu_config.display,
            ssh_port=ssh_port,
            monitor_port=monitor_port,
            agent_port=agent_port,
            enable_acceleration=self._qemu_config.enable_acceleration,
            snapshot_name=self._qemu_config.snapshot_name,
            shared_folder=self._shared_folder,
            anti_evasion_profile=self._qemu_config.anti_evasion_profile,
            agent_connect_timeout=self._qemu_config.agent_connect_timeout,
        )

        return cmd

    @staticmethod
    def _ensure_qemu_started(qemu_pid: int | None) -> None:
        """Raise SandboxError if QEMU failed to start.

        Args:
            qemu_pid: The QEMU process ID, or None if startup failed.

        Raises:
            SandboxError: If qemu_pid is None.
        """
        if qemu_pid is None:
            _logger.error("qemu_start_failed_no_pid")
            raise SandboxError(_ERR_QEMU_START)

    @staticmethod
    async def _ensure_agent_connected(agent: GuestAgentClient, time_limit: float) -> None:
        """Drive ``GuestAgentClient.connect`` and raise on failure.

        Wraps the connect call so that ``QEMUSandbox.start`` does not raise
        ``SandboxError`` from inside a ``try`` block (ruff ``TRY301``).

        Args:
            agent: Guest agent client to connect.
            time_limit: Total seconds to wait for the agent to become
                reachable before failing.

        Raises:
            SandboxError: If the agent socket cannot be reached within
                ``time_limit`` (either by ``connect`` raising or by it
                returning ``False``).
        """
        connect_error: BaseException | None = None
        try:
            connected = await agent.connect(time_limit=time_limit)
        except (OSError, asyncio.CancelledError, TimeoutError) as agent_error:
            _logger.warning(
                "guest_agent_connect_exception",
                error=str(agent_error),
                timeout_seconds=time_limit,
            )
            connect_error = agent_error
            connected = False

        if not connected:
            _logger.warning(
                "guest_agent_connect_failed",
                timeout_seconds=time_limit,
            )
            error_message = _ERR_AGENT_CONNECT_FAILED.format(timeout=time_limit)
            if connect_error is not None:
                raise SandboxError(error_message) from connect_error
            raise SandboxError(error_message)

    async def start(self) -> None:
        """Start the QEMU virtual machine.

        Raises:
            SandboxError: If VM cannot be started.
        """
        if self.state.status == "running":
            _logger.warning("qemu_sandbox_already_running", state=self.state.status)
            return

        if not await self.is_available():
            raise SandboxError(_ERR_QEMU_NA)

        log_sandbox_operation("start", "qemu", guest_os=self._qemu_config.guest_os.value)
        self.state.status = "starting"
        self.state.last_error = None

        try:
            self._temp_dir = Path(await asyncio.to_thread(tempfile.mkdtemp, prefix="intellicrack_qemu_"))
            self._shared_folder = self._temp_dir / "shared"
            await asyncio.to_thread(self._shared_folder.mkdir, parents=True, exist_ok=True)

            await asyncio.to_thread((self._shared_folder / "input").mkdir, exist_ok=True)
            await asyncio.to_thread((self._shared_folder / "output").mkdir, exist_ok=True)
            await asyncio.to_thread((self._shared_folder / "logs").mkdir, exist_ok=True)
            await asyncio.to_thread((self._shared_folder / "monitor").mkdir, exist_ok=True)

            await self._create_guest_agent_script()

            cmd = await self._build_qemu_command()
            _logger.info("qemu_starting", command=" ".join(cmd))
            _logger.info("subprocess_spawning", argv=cmd, executable=cmd[0] if cmd else None)

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            _, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=_PROCESS_COMMUNICATE_TIMEOUT,
            )

            self._check_qemu_started(process.returncode, stderr)

            qemu_pid: int | None = None
            if self._pidfile_path is not None:
                for attempt in range(_PIDFILE_MAX_RETRIES):
                    await asyncio.sleep(_PIDFILE_RETRY_DELAY)
                    if await asyncio.to_thread(self._pidfile_path.exists):
                        try:
                            pid_content = await asyncio.to_thread(
                                self._pidfile_path.read_text,
                                encoding="utf-8",
                            )
                            qemu_pid = int(pid_content.strip())
                            break
                        except (ValueError, OSError):
                            _logger.debug(
                                "pidfile_read_retry",
                                attempt=attempt + 1,
                            )

            await self._verify_qemu_pid(qemu_pid)
            self._ensure_qemu_started(qemu_pid)
            verified_pid: int = qemu_pid if qemu_pid is not None else -1

            self._qemu_pid = verified_pid
            self.state.pid = verified_pid
            _logger.info("qemu_started", pid=verified_pid)

            process_manager = ProcessManager.get_instance()
            process_manager.register_external_pid(
                verified_pid,
                name="qemu-vm",
                process_type=ProcessType.SANDBOX,
                metadata={
                    "guest_os": self._qemu_config.guest_os.value,
                    "image": str(self._qemu_config.image_path),
                },
            )

            await self._connect_and_verify_qmp()

            self._agent = GuestAgentClient(port=self._qemu_config.agent_port)
            await self._ensure_agent_connected(
                self._agent,
                self._qemu_config.agent_connect_timeout,
            )

            self.state.status = "running"
            self.state.started_at = datetime.now(UTC)
            _logger.info("qemu_sandbox_started_successfully", pid=self._qemu_pid, state=self.state.status)

        except (OSError, RuntimeError, SandboxError, TimeoutError, ValueError) as e:
            self.state.status = "error"
            self.state.last_error = str(e)
            await self._cleanup()
            _logger.warning("qemu_sandbox_start_failed", error=str(e))
            raise SandboxError(_ERR_SANDBOX_START) from e

    async def stop(self) -> None:
        """Stop the QEMU virtual machine.

        Raises:
            SandboxError: If VM cannot be stopped.
        """
        if self.state.status == "stopped":
            _logger.debug("qemu_sandbox_already_stopped", state=self.state.status)
            return

        self.state.status = "stopping"

        try:
            if self._agent is not None:
                await self._agent.disconnect()
                self._agent = None

            if self._qmp is not None:
                await self._qmp.quit()
                await self._qmp.disconnect()
                self._qmp = None

            await asyncio.sleep(2)

            if self._qemu_pid is not None:
                process_manager = ProcessManager.get_instance()
                process_manager.unregister_external_pid(self._qemu_pid)
                self._qemu_pid = None

            await self._cleanup()

            self._active_captures.clear()
            self.state.status = "stopped"
            self.state.pid = None
            self._vnc_port = None
            _logger.info("qemu_sandbox_stopped", state=self.state.status)

        except (OSError, RuntimeError, SandboxError) as e:
            self.state.status = "error"
            self.state.last_error = str(e)
            _logger.warning("qemu_sandbox_stop_failed", error=str(e))
            raise SandboxError(_ERR_SANDBOX_STOP) from e

    async def _cleanup(self) -> None:
        """Clean up temporary files and resources."""
        if self._temp_dir is not None:
            pid_path = self._temp_dir / "qemu.pid"
            if await asyncio.to_thread(pid_path.exists):
                try:
                    pid_content = await asyncio.to_thread(pid_path.read_text, encoding="utf-8")
                    pid = int(pid_content.strip())
                    try:
                        ProcessManager.terminate_tree(pid, graceful_timeout=2.0, force_timeout=2.0)
                        _logger.info("cleanup_terminated_orphan_qemu_tree", pid=pid)
                    except psutil.NoSuchProcess:
                        _logger.debug("cleanup_orphan_already_exited", pid=pid, exc_info=True)
                except (OSError, ValueError) as e:
                    _logger.warning("cleanup_pid_check_failed", error=str(e))

        if self._temp_dir is not None and await asyncio.to_thread(self._temp_dir.exists):
            try:
                await asyncio.to_thread(
                    shutil.rmtree,
                    self._temp_dir,
                    ignore_errors=True,
                )
            except OSError as e:
                _logger.warning("temp_dir_cleanup_failed", error=str(e))

        self._temp_dir = None
        self._shared_folder = None

    @staticmethod
    def _windows_agent_script_content() -> str:
        r"""Return the Windows guest agent PowerShell script body.

        The script (1) maps ``Z:`` via ``net use`` with three 2-second
        retries before any logging or file polling, (2) launches the seven
        bundled monitor scripts from ``Z:\monitor\`` with ``-LogDir Z:\logs``,
        (3) listens on ``127.0.0.1:4445`` for argv-style command requests
        validated against a short allowlist (``powershell``, ``cmd``, any
        ``.exe`` under ``Z:\``, ``System32`` or ``SysWOW64``), and
        (4) emits process, file, and extended network telemetry in the
        ten-field schema parsed by
        :func:`intellicrack.sandbox._log_parsers.parse_network_log`.

        Returns:
            str: Full PowerShell script source (UTF-8).
        """
        return r"""$ErrorActionPreference = 'SilentlyContinue'

$shareHost = '10.0.2.4'
$shareName = 'qemu'
$driveLetter = 'Z:'
$shareMapped = $false
for ($i = 0; $i -lt 3 -and -not $shareMapped; $i++) {
    & net.exe use $driveLetter ('\\' + $shareHost + '\' + $shareName) /persistent:no 2>&1 | Out-Null
    if (Test-Path $driveLetter) { $shareMapped = $true; break }
    Start-Sleep -Seconds 2
}

$logDir = 'Z:\logs'
$monitorDir = 'Z:\monitor'
if ($shareMapped) {
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    if (-not (Test-Path $monitorDir)) { New-Item -ItemType Directory -Path $monitorDir -Force | Out-Null }
}

$fileLog = Join-Path $logDir 'file_changes.log'
$netLog = Join-Path $logDir 'network_activity.log'
$procLog = Join-Path $logDir 'process_activity.log'

$monitorScripts = @(
    'api_trace.ps1',
    'clipboard_monitor.ps1',
    'dll_monitor.ps1',
    'injection_monitor.ps1',
    'kernel_object_monitor.ps1',
    'resource_monitor.ps1',
    'service_monitor.ps1'
)
foreach ($scriptName in $monitorScripts) {
    $scriptPath = Join-Path $monitorDir $scriptName
    if (Test-Path $scriptPath) {
        Start-Process -FilePath 'powershell.exe' `
            -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$scriptPath,'-LogDir',$logDir) `
            -WindowStyle Hidden
    }
}

$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = 'C:\'
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true
$Global:_IC_FileLog = $fileLog
Register-ObjectEvent $watcher 'Created' -MessageData $fileLog -Action {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts|created|$($Event.SourceEventArgs.FullPath)" | Out-File -Append $Event.MessageData -Encoding utf8
} | Out-Null
Register-ObjectEvent $watcher 'Changed' -MessageData $fileLog -Action {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts|modified|$($Event.SourceEventArgs.FullPath)" | Out-File -Append $Event.MessageData -Encoding utf8
} | Out-Null
Register-ObjectEvent $watcher 'Deleted' -MessageData $fileLog -Action {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts|deleted|$($Event.SourceEventArgs.FullPath)" | Out-File -Append $Event.MessageData -Encoding utf8
} | Out-Null

$allowedNames = @('powershell', 'powershell.exe', 'cmd', 'cmd.exe')
$allowedRoots = @('Z:\', ($env:SystemRoot + '\System32\'), ($env:SystemRoot + '\SysWOW64\'))
function Test-AllowedCommand($cmdValue) {
    if ([string]::IsNullOrEmpty($cmdValue)) { return $false }
    $lower = $cmdValue.ToLower()
    if ($allowedNames -contains $lower) { return $true }
    if (-not $lower.EndsWith('.exe')) { return $false }
    foreach ($root in $allowedRoots) {
        if ($lower.StartsWith($root.ToLower())) { return $true }
    }
    return $false
}

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), 4445)
$listener.Start()

function Send-Message($stream, $data) {
    $json = ConvertTo-Json $data -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json + "`n")
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
}

$knownProcs = @{}
$prevConnKeys = @{}
$prevConnKeyCap = 8192

while ($true) {
    if ($listener.Pending()) {
        $client = $listener.AcceptTcpClient()
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        while ($client.Connected) {
            try {
                $line = $reader.ReadLine()
                if ($null -eq $line) { break }
                $request = ConvertFrom-Json $line
                if ($request.type -eq 'execute') {
                    $cmd = [string]$request.command
                    $cmdArgs = @()
                    if ($request.args) { $cmdArgs = @($request.args) }
                    $output = ''
                    $errorOutput = ''
                    $exitCode = 0
                    if (-not (Test-AllowedCommand $cmd)) {
                        $errorOutput = "command not in allowlist: $cmd"
                        $exitCode = -1
                    } else {
                        try {
                            $output = & $cmd @cmdArgs 2>&1 | Out-String
                            $exitCode = $LASTEXITCODE
                            if ($null -eq $exitCode) { $exitCode = 0 }
                        } catch {
                            $errorOutput = $_.Exception.Message
                            $exitCode = 1
                        }
                    }
                    Send-Message $stream @{
                        type = 'result'
                        data = @{
                            exit_code = $exitCode
                            stdout = $output
                            stderr = $errorOutput
                        }
                    }
                }
            } catch {
                break
            }
        }
        $client.Close()
    }

    $currentProcs = Get-Process | Select-Object Id, Name, Path
    foreach ($proc in $currentProcs) {
        if (-not $knownProcs.ContainsKey($proc.Id)) {
            $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            "$ts|created|$($proc.Id)|$($proc.Name)|$($proc.Path)" | Out-File -Append $procLog -Encoding utf8
            $knownProcs[$proc.Id] = $proc.Name
        }
    }
    $currentIds = $currentProcs | ForEach-Object { $_.Id }
    $terminated = $knownProcs.Keys | Where-Object { $_ -notin $currentIds }
    foreach ($id in $terminated) {
        $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        "$ts|terminated|$id|$($knownProcs[$id])" | Out-File -Append $procLog -Encoding utf8
        $knownProcs.Remove($id)
    }

    $procNameByPid = @{}
    foreach ($p in $currentProcs) { $procNameByPid[$p.Id] = $p.Name }

    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $tcpConns = Get-NetTCPConnection -ErrorAction SilentlyContinue
    foreach ($conn in $tcpConns) {
        $state = [string]$conn.State
        $owner = $conn.OwningProcess
        $pname = ''
        if ($owner -and $procNameByPid.ContainsKey($owner)) { $pname = $procNameByPid[$owner] }
        $key = "tcp|$($conn.LocalAddress):$($conn.LocalPort)|$($conn.RemoteAddress):$($conn.RemotePort)|$state"
        if (-not $prevConnKeys.ContainsKey($key)) {
            $prevConnKeys[$key] = $true
            "$ts|connection|$($conn.LocalAddress):$($conn.LocalPort)|$($conn.RemoteAddress):$($conn.RemotePort)|$state|tcp|0|0|$owner|$pname" | Out-File -Append $netLog -Encoding utf8
        }
    }

    $udpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
    foreach ($ep in $udpEndpoints) {
        $owner = $ep.OwningProcess
        $pname = ''
        if ($owner -and $procNameByPid.ContainsKey($owner)) { $pname = $procNameByPid[$owner] }
        $key = "udp|$($ep.LocalAddress):$($ep.LocalPort)"
        if (-not $prevConnKeys.ContainsKey($key)) {
            $prevConnKeys[$key] = $true
            "$ts|bind|$($ep.LocalAddress):$($ep.LocalPort)|0.0.0.0:0|Listen|udp|0|0|$owner|$pname" | Out-File -Append $netLog -Encoding utf8
        }
    }

    if ($prevConnKeys.Count -gt $prevConnKeyCap) {
        $prevConnKeys.Clear()
    }

    Start-Sleep -Seconds 1
}
"""

    @staticmethod
    def _bundled_scripts_dir() -> Path:
        """Return the on-disk directory that contains bundled monitor PS1 scripts.

        Returns:
            Path: Absolute path to the bundled ``scripts`` directory. The
            path is resolved from this module's location and is therefore
            safe to compute synchronously even from async callers.
        """
        return Path(__file__).resolve().parent / "scripts"

    async def _create_guest_agent_script(self) -> None:
        r"""Create guest agent scripts and stage bundled monitor scripts.

        On Windows, writes ``agent.ps1`` and ``start_agent.cmd`` into the
        host-side shared folder's ``monitor`` subdirectory. The Windows
        agent maps ``Z:`` on first tick, copies the seven bundled PS1
        monitor scripts into ``Z:\monitor\``, and launches each with
        ``-LogDir Z:\logs``. On Linux, writes the existing Python agent
        and its startup shell script.

        Raises:
            ValueError: If an unsupported guest OS is configured.
        """
        if self._shared_folder is None:
            return

        monitor_dir = self._shared_folder / "monitor"

        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            agent_script = monitor_dir / "agent.ps1"
            agent_content = self._windows_agent_script_content()
            await asyncio.to_thread(agent_script.write_text, agent_content, encoding="utf-8")

            scripts_src = await asyncio.to_thread(self._bundled_scripts_dir)
            for script_name in _MONITOR_SCRIPT_NAMES:
                src = scripts_src / script_name
                dst = monitor_dir / script_name
                if await asyncio.to_thread(src.exists):
                    await asyncio.to_thread(shutil.copy2, src, dst)
                else:
                    _logger.warning("monitor_script_missing", script=script_name, path=str(src))

            startup_script = monitor_dir / "start_agent.cmd"
            startup_content = (
                '@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "Z:\\monitor\\agent.ps1"\r\n'
            )
        elif self._qemu_config.guest_os == GuestOS.LINUX:
            agent_script = monitor_dir / "agent.py"
            agent_content = '''#!/usr/bin/env python3
"""QEMU Guest Agent for Intellicrack sandbox monitoring.

This agent runs inside the QEMU guest VM to:
- Monitor process creation and termination
- Track file system changes (if inotify available)
- Execute commands from the host and return results
"""
from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

LOG_DIR: Path = Path("/mnt/shared/logs")
PORT: int = 4445
RECV_BUFFER_SIZE: int = 65536
DEFAULT_COMMAND_TIMEOUT: int = 30
MONITOR_POLL_INTERVAL: float = 1.0

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "agent.log"),
        logging.StreamHandler(sys.stderr),
    ],
)
_logger: logging.Logger = logging.getLogger("sandbox.qemu.agent")


def file_monitor() -> None:
    """Monitor file system changes using inotify.

    Logs all file operations (create, modify, delete, etc.) to the
    file_changes.log file in the shared log directory.
    """
    try:
        import inotify.adapters
    except ImportError:
        _logger.warning("inotify_module_unavailable", extra={"reason": "import failed"})
        return

    try:
        inotify_tree = inotify.adapters.InotifyTree("/")
        _logger.info("file_monitoring_started", extra={"watch_root": "/"})
        for event in inotify_tree.event_gen(yield_nones=False):
            event_header, type_names, watch_path, filename = event
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            operation = type_names[0].lower() if type_names else "unknown"
            try:
                log_path = LOG_DIR / "file_changes.log"
                with log_path.open("a", encoding="utf-8") as log_file:
                    log_file.write(f"{timestamp}|{operation}|{watch_path}/{filename}\\n")
            except OSError as write_err:
                _logger.debug("file_change_log_write_failed", extra={"error": str(write_err)})
    except OSError as inotify_err:
        _logger.error("inotify_init_failed", extra={"error": str(inotify_err)})


def process_monitor() -> None:
    """Monitor process creation and termination via /proc.

    Polls /proc directory to detect new and terminated processes,
    logging activity to the process_activity.log file.
    """
    known_pids: set[int] = set()
    _logger.info("process_monitoring_started", extra={"poll_interval": MONITOR_POLL_INTERVAL})

    while True:
        current_pids: set[int] = set()
        try:
            proc_entries = os.listdir("/proc")
        except OSError as list_err:
            _logger.debug("proc_list_failed", extra={"error": str(list_err)})
            time.sleep(MONITOR_POLL_INTERVAL)
            continue

        for pid_str in proc_entries:
            if not pid_str.isdigit():
                continue

            pid = int(pid_str)
            current_pids.add(pid)

            if pid not in known_pids:
                process_name = _get_process_name(pid)
                if process_name is not None:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    _log_process_activity(timestamp, "created", pid, process_name)

        terminated_pids = known_pids - current_pids
        for pid in terminated_pids:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            _log_process_activity(timestamp, "terminated", pid, None)

        known_pids = current_pids
        time.sleep(MONITOR_POLL_INTERVAL)


def _get_process_name(pid: int) -> str | None:
    """Read process name from /proc/<pid>/comm.

    Args:
        pid: Process ID to look up.

    Returns:
        Process name string or None if not accessible.
    """
    try:
        comm_path = Path(f"/proc/{pid}/comm")
        with comm_path.open("r", encoding="utf-8") as comm_file:
            return comm_file.read().strip()
    except (OSError, PermissionError, FileNotFoundError):
        _logger.debug("process_name_lookup_failed", exc_info=True)
        return None


def _log_process_activity(
    timestamp: str, operation: str, pid: int, name: str | None
) -> None:
    """Write process activity to the log file.

    Args:
        timestamp: Formatted timestamp string.
        operation: Either 'created' or 'terminated'.
        pid: Process ID.
        name: Process name (may be None for terminated processes).
    """
    try:
        log_path = LOG_DIR / "process_activity.log"
        with log_path.open("a", encoding="utf-8") as log_file:
            if name is not None:
                log_file.write(f"{timestamp}|{operation}|{pid}|{name}\\n")
            else:
                log_file.write(f"{timestamp}|{operation}|{pid}\\n")
    except OSError as write_err:
        _logger.debug("process_activity_log_write_failed", extra={"error": str(write_err)})


def handle_client(conn: socket.socket) -> None:
    """Handle a client connection from the host.

    Receives JSON commands and executes them, returning results.

    Args:
        conn: Connected client socket.
    """
    client_addr = "unknown"
    try:
        client_addr = str(conn.getpeername())
    except OSError:
        _logger.debug("client_peername_unavailable", exc_info=True)

    _logger.debug("client_connected", extra={"client_addr": client_addr})

    try:
        while True:
            data = conn.recv(RECV_BUFFER_SIZE)
            if not data:
                break

            try:
                request: dict[str, Any] = json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as parse_err:
                _logger.warning("invalid_client_request", extra={"client_addr": client_addr, "error": str(parse_err)})
                continue

            if request.get("type") == "execute":
                response = _execute_command(request)
                response_bytes = (json.dumps(response) + "\\n").encode("utf-8")
                conn.send(response_bytes)

    except ConnectionResetError:
        _logger.debug("client_disconnected", extra={"client_addr": client_addr})
    except OSError as sock_err:
        _logger.debug("client_socket_error", extra={"client_addr": client_addr, "error": str(sock_err)})
    finally:
        try:
            conn.close()
        except OSError:
            _logger.debug("client_close_failed", exc_info=True)
        _logger.debug("client_connection_closed", extra={"client_addr": client_addr})


def _execute_command(request: dict[str, Any]) -> dict[str, Any]:
    """Execute a command from a client request.

    Args:
        request: JSON request with 'command', 'args', and optional 'timeout'.

    Returns:
        Response dict with 'type' and 'data' containing execution results.
    """
    cmd = request.get("command", "")
    args: list[str] = request.get("args", [])
    timeout = request.get("timeout", DEFAULT_COMMAND_TIMEOUT)

    if not cmd:
        return {
            "type": "result",
            "data": {"exit_code": -1, "stdout": "", "stderr": "No command specified"},
        }

    try:
        result = subprocess.run(
            [cmd] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "type": "result",
            "data": {
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
        }
    except subprocess.TimeoutExpired:
        _logger.debug("command_execution_timeout", extra={"command": cmd, "timeout": timeout})
        return {
            "type": "result",
            "data": {"exit_code": -1, "stdout": "", "stderr": f"Command timed out after {timeout}s"},
        }
    except FileNotFoundError:
        _logger.debug("command_not_found", extra={"command": cmd})
        return {
            "type": "result",
            "data": {"exit_code": -1, "stdout": "", "stderr": f"Command not found: {cmd}"},
        }
    except PermissionError:
        _logger.debug("command_permission_denied", extra={"command": cmd})
        return {
            "type": "result",
            "data": {"exit_code": -1, "stdout": "", "stderr": f"Permission denied: {cmd}"},
        }
    except OSError as os_err:
        _logger.debug("command_os_error", extra={"command": cmd, "error": str(os_err)})
        return {
            "type": "result",
            "data": {"exit_code": -1, "stdout": "", "stderr": str(os_err)},
        }


def main() -> None:
    """Main entry point for the guest agent."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    _logger.info("guest_agent_starting", extra={"port": PORT})

    process_thread = threading.Thread(target=process_monitor, daemon=True)
    process_thread.start()

    file_thread = threading.Thread(target=file_monitor, daemon=True)
    file_thread.start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(("0.0.0.0", PORT))
        server.listen(5)
        _logger.info("agent_listening", extra={"host": "0.0.0.0", "port": PORT})

        while True:
            try:
                conn, addr = server.accept()
                client_thread = threading.Thread(
                    target=handle_client, args=(conn,), daemon=True
                )
                client_thread.start()
            except OSError as accept_err:
                _logger.error("accept_failed", extra={"error": str(accept_err)})
                break
    except OSError as bind_err:
        _logger.error("port_bind_failed", extra={"port": PORT, "error": str(bind_err)})
    finally:
        server.close()


if __name__ == "__main__":
    main()
'''
            await asyncio.to_thread(agent_script.write_text, agent_content, encoding="utf-8")

            startup_script = monitor_dir / "start_agent.sh"
            startup_content = """#!/bin/bash
python3 /mnt/shared/monitor/agent.py &
"""
        else:
            raise ValueError(_ERR_UNSUPPORTED_GUEST_OS)
        await asyncio.to_thread(startup_script.write_text, startup_content, encoding="utf-8")

        _logger.debug("guest_agent_scripts_created", extra={"path": str(monitor_dir)})

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
            tuple[int, str, str]: Tuple of (exit_code, stdout, stderr).

        Raises:
            SandboxError: If execution fails.
        """
        if self.state.status != "running":
            raise SandboxError(_ERR_NOT_RUNNING)

        effective_timeout = time_limit or self._config.timeout_seconds

        if self._agent is not None and self._agent.is_connected:
            if working_directory:
                command = f"cd {working_directory} && {command}"
            return await self._agent.send_command(command, time_limit=effective_timeout)

        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        script_id = secrets.token_hex(8)
        result_name = f"result_{script_id}.txt"
        script_name, script_content = self._generate_execution_script(
            command=command,
            working_directory=working_directory,
            script_id=script_id,
            result_name=result_name,
        )

        script_path = self._shared_folder / "input" / script_name
        result_path = self._shared_folder / "output" / result_name
        await asyncio.to_thread(script_path.write_text, script_content, encoding="utf-8")

        return await self._poll_for_result(result_path=result_path, time_limit=effective_timeout)

    def _generate_execution_script(
        self,
        *,
        command: str,
        working_directory: str | None,
        script_id: str,
        result_name: str,
    ) -> tuple[str, str]:
        """Generate an OS-specific execution script for the sandbox guest.

        Args:
            command: Command to execute in the guest.
            working_directory: Optional working directory for the command.
            script_id: Unique identifier for the script file.
            result_name: Name of the result file.

        Returns:
            tuple[str, str]: Tuple of (script_filename, script_content).

        Raises:
            ValueError: If an unsupported guest OS is configured.
        """
        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            script_name = f"exec_{script_id}.cmd"
            script_content = f"""@echo off
{f'cd /d "{working_directory}"' if working_directory else ""}
{command}
echo %ERRORLEVEL% > "{self.GUEST_SHARED_PATH_WINDOWS}output\\{result_name}"
"""
        elif self._qemu_config.guest_os == GuestOS.LINUX:
            script_name = f"exec_{script_id}.sh"
            script_content = f"""#!/bin/bash
{f'cd "{working_directory}"' if working_directory else ""}
{command}
echo $? > "{self.GUEST_SHARED_PATH_LINUX}/output/{result_name}"
"""
        else:
            _logger.error(
                "execution_script_unsupported_guest_os",
                guest_os=str(self._qemu_config.guest_os),
                script_id=script_id,
            )
            raise ValueError(_ERR_UNSUPPORTED_GUEST_OS)
        return script_name, script_content

    @staticmethod
    async def _poll_for_result(
        *,
        result_path: Path,
        time_limit: int,
    ) -> tuple[int, str, str]:
        """Poll the shared folder for command execution results.

        Args:
            result_path: Path to the expected result file.
            time_limit: Maximum time in seconds to wait.

        Returns:
            tuple[int, str, str]: Tuple of (exit_code, stdout, stderr).

        Raises:
            SandboxTimeoutError: If the command times out.
        """
        start_time = time.time()
        while time.time() - start_time < time_limit:
            await asyncio.sleep(1)
            if await asyncio.to_thread(result_path.exists):
                try:
                    result_text = await asyncio.to_thread(
                        result_path.read_text,
                        encoding="utf-8",
                    )
                    result_text = result_text.strip()
                    exit_code = int(result_text) if result_text.isdigit() else -1
                except (OSError, ValueError) as e:
                    _logger.debug("result_read_failed", extra={"error": str(e)})
                else:
                    return (exit_code, "", "")

        _logger.warning("command_timed_out", extra={"timeout_seconds": time_limit})
        raise SandboxTimeoutError(_ERR_CMD_TIMEOUT, timeout_seconds=time_limit)

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
            ExecutionReport: ExecutionReport with results and activity.

        Raises:
            SandboxError: If execution fails.
            ValueError: If the guest OS type is unsupported.
        """
        if self.state.status != "running":
            raise SandboxError(_ERR_NOT_RUNNING)

        if not await asyncio.to_thread(binary_path.exists):
            _logger.warning("binary_not_found", extra={"path": str(binary_path)})
            raise SandboxError(_ERR_BINARY_NOT_FOUND)

        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        effective_timeout = time_limit or self._config.timeout_seconds
        start_time = time.time()

        await self.copy_to_sandbox(binary_path, f"input/{binary_path.name}")

        if monitor:
            logs_folder = self._shared_folder / "logs"
            log_files = await asyncio.to_thread(lambda: list(logs_folder.glob("*.log")))
            for log_file in log_files:
                await asyncio.to_thread(log_file.unlink)

        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            binary_sandbox_path = f"{self.GUEST_SHARED_PATH_WINDOWS}input\\{binary_path.name}"
        elif self._qemu_config.guest_os == GuestOS.LINUX:
            binary_sandbox_path = f"{self.GUEST_SHARED_PATH_LINUX}/input/{binary_path.name}"
        else:
            raise ValueError(_ERR_UNSUPPORTED_GUEST_OS)

        command = f'"{binary_sandbox_path}" {" ".join(f"{chr(34)}{a}{chr(34)}" for a in (args or []))}'

        result: ExecutionResult
        try:
            exit_code, stdout, stderr = await self.run_command(
                command,
                time_limit=effective_timeout,
            )
            result = "success" if exit_code == 0 else "error"
        except SandboxTimeoutError as e:
            _logger.warning("sandbox_execution_timeout", extra={"binary": binary_path.name, "timeout": effective_timeout})
            result = "timeout"
            stderr = str(e)
            stdout = ""
            exit_code = -1
        except SandboxError as e:
            _logger.warning("sandbox_execution_error", extra={"binary": binary_path.name, "error": str(e)})
            result = "error"
            stderr = str(e)
            stdout = ""
            exit_code = -1
        duration = time.time() - start_time

        logs = _MonitoringLogs()
        if monitor:
            await self._wait_for_logs_stable()
            logs = await self._collect_monitoring_logs()

        return ExecutionReport(
            result=result,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            file_changes=logs.file_changes,
            registry_changes=logs.registry_changes,
            network_activity=logs.network_activity,
            process_activity=logs.process_activity,
            api_calls=logs.api_calls,
            service_changes=logs.service_changes,
            kernel_objects=logs.kernel_objects,
            dll_loads=logs.dll_loads,
            injection_events=logs.injection_events,
            resource_samples=logs.resource_samples,
            clipboard_events=logs.clipboard_events,
        )

    async def _collect_monitoring_logs(self) -> _MonitoringLogs:
        """Parse every monitor log file into a :class:`_MonitoringLogs` aggregate.

        Returns:
            _MonitoringLogs: All monitor-log parse results collected from
            the shared ``logs`` folder. Each field is populated from the
            corresponding parser in :mod:`intellicrack.sandbox._log_parsers`
            and defaults to an empty list when the matching log file is
            absent.
        """
        shared = self._shared_folder
        return _MonitoringLogs(
            file_changes=await parse_file_log(shared, "file_changes.log"),
            registry_changes=await parse_registry_log(shared, "registry_changes.log"),
            network_activity=await parse_network_log(shared, "network_activity.log"),
            process_activity=await parse_process_log(shared, "process_activity.log"),
            api_calls=await parse_api_trace_log(shared, "api_trace.log"),
            service_changes=await parse_service_log(shared, "service_monitor.log"),
            kernel_objects=await parse_kernel_object_log(shared, "kernel_object_monitor.log"),
            dll_loads=await parse_dll_log(shared, "dll_monitor.log"),
            injection_events=await parse_injection_log(shared, "injection_monitor.log"),
            resource_samples=await parse_resource_log(shared, "resource_monitor.log"),
            clipboard_events=await parse_clipboard_log(shared, "clipboard_monitor.log"),
        )

    async def _wait_for_logs_stable(
        self,
        *,
        poll_delay: float = _LOGS_STABLE_POLL_DELAY_S,
        stable_polls: int = _LOGS_STABLE_REQUIRED_POLLS,
        max_wait: float = _LOGS_STABLE_MAX_WAIT_S,
    ) -> None:
        """Wait until all monitoring log files have stopped growing.

        Polls every log file under ``self._shared_folder / "logs"`` and treats
        the set as stable when each file's size has been unchanged for
        ``stable_polls`` consecutive polls. Caps total wait at ``max_wait``
        seconds. The tracked file set is :data:`_MONITORING_LOG_NAMES`; files
        that do not yet exist are treated as having size ``0`` so that
        long-quiescent monitors do not block the readiness check.

        File ``stat`` calls are dispatched via :func:`asyncio.to_thread` so
        the event loop is not blocked. Elapsed time is measured with
        :func:`time.monotonic`.

        Args:
            poll_delay: Seconds to sleep between polls. Must be positive.
            stable_polls: Number of consecutive unchanged polls required to
                consider a log file stable. Must be at least one.
            max_wait: Maximum total seconds to wait before returning even if
                stability has not been reached.

        Raises:
            ValueError: If ``poll_delay`` is not positive, ``stable_polls``
                is less than one, or ``max_wait`` is negative.
            SandboxError: If the shared folder has not been initialized.
        """
        if poll_delay <= 0:
            raise ValueError(_ERR_LOGS_STABLE_POLL_DELAY)
        if stable_polls < 1:
            raise ValueError(_ERR_LOGS_STABLE_STABLE_POLLS)
        if max_wait < 0:
            raise ValueError(_ERR_LOGS_STABLE_MAX_WAIT)
        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        logs_folder = self._shared_folder / "logs"
        log_paths: tuple[Path, ...] = tuple(logs_folder / name for name in _MONITORING_LOG_NAMES)

        previous_sizes: dict[Path, int] = dict.fromkeys(log_paths, -1)
        unchanged_counts: dict[Path, int] = dict.fromkeys(log_paths, 0)

        def _stat_size(path: Path) -> int:
            """Return ``path.stat().st_size``, or ``0`` if the file is absent.

            Args:
                path: File whose size to read.

            Returns:
                int: File size in bytes, or ``0`` if the file does not exist.
            """
            try:
                return path.stat().st_size
            except FileNotFoundError:
                return 0

        start = time.monotonic()
        while True:
            for path in log_paths:
                current_size = await asyncio.to_thread(_stat_size, path)
                if current_size == previous_sizes[path]:
                    unchanged_counts[path] += 1
                else:
                    unchanged_counts[path] = 1
                    previous_sizes[path] = current_size

            if all(count >= stable_polls for count in unchanged_counts.values()):
                _logger.debug(
                    "logs_stable_reached",
                    extra={
                        "elapsed_seconds": time.monotonic() - start,
                        "stable_polls": stable_polls,
                    },
                )
                return

            if time.monotonic() - start >= max_wait:
                _logger.warning(
                    "logs_stable_max_wait_elapsed",
                    extra={
                        "max_wait_seconds": max_wait,
                        "stable_polls": stable_polls,
                    },
                )
                return

            await asyncio.sleep(poll_delay)

    async def copy_to_sandbox(self, source: Path, dest: str) -> None:
        """Copy a file into the sandbox.

        Args:
            source: Local source path.
            dest: Destination path relative to shared folder.

        Raises:
            SandboxError: If copy fails.
        """
        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        if not await asyncio.to_thread(source.exists):
            _logger.warning("source_file_not_found", extra={"path": str(source)})
            raise SandboxError(_ERR_SOURCE_NOT_FOUND)

        dest_path = self._shared_folder / dest
        await asyncio.to_thread(dest_path.parent.mkdir, parents=True, exist_ok=True)

        try:
            await asyncio.to_thread(shutil.copy2, source, dest_path)
            _logger.debug("file_copied_to_sandbox", extra={"source": str(source), "dest": dest})
        except OSError as e:
            _logger.warning("copy_to_sandbox_failed", error=str(e), source=str(source), dest=dest)
            raise SandboxError(_ERR_COPY_TO_SANDBOX) from e

    async def copy_from_sandbox(self, source: str, dest: Path) -> None:
        """Copy a file from the sandbox.

        Args:
            source: Source path relative to shared folder.
            dest: Local destination path.

        Raises:
            SandboxError: If copy fails.
        """
        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        source_path = self._shared_folder / source

        if not await asyncio.to_thread(source_path.exists):
            _logger.warning("sandbox_source_file_not_found", extra={"path": source})
            raise SandboxError(_ERR_SOURCE_NOT_FOUND)

        await asyncio.to_thread(dest.parent.mkdir, parents=True, exist_ok=True)

        try:
            await asyncio.to_thread(shutil.copy2, source_path, dest)
            _logger.debug("file_copied_from_sandbox", extra={"source": source, "dest": str(dest)})
        except OSError as e:
            _logger.warning("copy_from_sandbox_failed", error=str(e), source=source, dest=str(dest))
            raise SandboxError(_ERR_COPY_FROM_SANDBOX) from e

    async def take_snapshot(self, name: str) -> str:
        """Take a snapshot of the VM state.

        Args:
            name: Snapshot name.

        Returns:
            str: Snapshot identifier.

        Raises:
            SandboxError: If snapshot fails.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        result = await self._qmp.savevm(name)
        if not result.success:
            _logger.warning("snapshot_create_failed", extra={"error": result.error})
            raise SandboxError(_ERR_SNAPSHOT_CREATE)

        _logger.info("snapshot_created", extra={"snapshot_name": name})
        return name

    async def restore_snapshot(self, snapshot_id: str) -> None:
        """Restore a VM snapshot.

        Args:
            snapshot_id: Snapshot name to restore.

        Raises:
            SandboxError: If restore fails.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        result = await self._qmp.loadvm(snapshot_id)
        if not result.success:
            _logger.warning("snapshot_restore_failed", extra={"error": result.error})
            raise SandboxError(_ERR_SNAPSHOT_RESTORE)

        _logger.info("snapshot_restored", extra={"snapshot_id": snapshot_id})

    async def list_snapshots(self) -> list[str]:
        """List available snapshots.

        Returns:
            list[str]: List of snapshot names.
        """
        if self._qmp is None:
            return []

        result = await self._qmp.info_snapshots()
        if not result.success or result.data is None:
            return []

        output = str(result.data)
        snapshots: list[str] = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= _SNAPSHOT_LINE_MIN_PARTS and parts[0].isdigit():
                snapshots.append(parts[1])

        return snapshots

    async def delete_snapshot(self, name: str) -> None:
        """Delete a snapshot.

        Args:
            name: Snapshot name to delete.

        Raises:
            SandboxError: If deletion fails.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        result = await self._qmp.delvm(name)
        if not result.success:
            _logger.warning("snapshot_delete_failed", extra={"error": result.error})
            raise SandboxError(_ERR_SNAPSHOT_DELETE)

        _logger.info("snapshot_deleted", extra={"snapshot_name": name})

    async def start_pcap_capture(self) -> str:
        """Start packet capture on the sandbox network.

        Returns:
            str: Capture identifier for stopping later.

        Raises:
            SandboxError: If capture cannot be started.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        capture_id = f"pcap_{secrets.token_hex(8)}"
        pcap_path = self._shared_folder / "output" / f"{capture_id}.pcap"

        result = await self._qmp.execute_command({
            "execute": "object-add",
            "arguments": {
                "qom-type": "filter-dump",
                "id": capture_id,
                "netdev": "net0",
                "filename": str(pcap_path),
            },
        })

        if not result.success:
            _logger.warning("pcap_start_failed", error=result.error, capture_id=capture_id)
            raise SandboxError(_ERR_PCAP_START_FAILED)

        self._active_captures[capture_id] = pcap_path
        _logger.info("pcap_capture_started", capture_id=capture_id, path=str(pcap_path))
        return capture_id

    async def stop_pcap_capture(self, capture_id: str, output_path: Path | None = None) -> Path:
        """Stop packet capture and retrieve the PCAP file.

        Args:
            capture_id: Capture identifier from start_pcap_capture.
            output_path: Optional path to save the PCAP file.

        Returns:
            Path: Path to the saved PCAP file.

        Raises:
            SandboxError: If capture cannot be stopped.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        if capture_id not in self._active_captures:
            raise SandboxError(_ERR_PCAP_NOT_ACTIVE)

        result = await self._qmp.execute_command({
            "execute": "object-del",
            "arguments": {"id": capture_id},
        })

        if not result.success:
            _logger.warning("pcap_stop_failed", error=result.error, capture_id=capture_id)
            raise SandboxError(_ERR_PCAP_STOP_FAILED)

        pcap_path = self._active_captures.pop(capture_id)

        if output_path is not None:
            await asyncio.to_thread(output_path.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(shutil.copy2, pcap_path, output_path)
            _logger.info("pcap_saved", capture_id=capture_id, path=str(output_path))
            return output_path

        _logger.info("pcap_capture_stopped", capture_id=capture_id, path=str(pcap_path))
        return pcap_path

    @staticmethod
    async def _wait_for_ppm_stable(ppm_path: Path) -> None:
        """Wait until a PPM file size stops changing between polls.

        Polls ``ppm_path.stat().st_size`` twice per iteration with a short
        delay between reads. The file is considered stable when two
        consecutive size reads are equal and non-zero.

        Args:
            ppm_path: Path to the PPM file produced by QEMU ``screendump``.

        Raises:
            SandboxError: If the PPM file never stabilizes before the poll
                budget is exhausted.
        """
        await asyncio.sleep(_SCREENSHOT_INITIAL_DELAY_S)
        previous_size = -1
        for _ in range(_SCREENSHOT_STABILITY_MAX_POLLS):
            try:
                current_size = await asyncio.to_thread(lambda: ppm_path.stat().st_size)
            except FileNotFoundError:
                await asyncio.sleep(_SCREENSHOT_STABILITY_POLL_DELAY_S)
                continue
            if current_size > 0 and current_size == previous_size:
                return
            previous_size = current_size
            await asyncio.sleep(_SCREENSHOT_STABILITY_POLL_DELAY_S)
        raise SandboxError(_ERR_SCREENSHOT_NOT_STABLE)

    async def capture_screenshot(self, output_path: Path | None = None) -> Path:
        """Capture a screenshot of the sandbox display.

        Performs a QMP ``screendump`` to a PPM file in the shared folder,
        polls the file size for stability (two consecutive ``stat`` reads
        equal with at least :data:`_SCREENSHOT_STABILITY_POLL_DELAY_S`
        delay between them), then converts to PNG. A conversion failure is
        reported as :class:`SandboxError` rather than silently returning a
        partial PPM.

        Args:
            output_path: Optional path to save the screenshot.

        Returns:
            Path: Path to the saved screenshot file.

        Raises:
            SandboxError: If the screenshot cannot be captured, stabilized,
                or converted.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        screenshot_id = secrets.token_hex(8)
        ppm_path = self._shared_folder / "output" / f"screenshot_{screenshot_id}.ppm"

        result = await self._qmp.execute_command({
            "execute": "screendump",
            "arguments": {"filename": str(ppm_path)},
        })

        if not result.success:
            _logger.warning("screenshot_failed", error=result.error)
            raise SandboxError(_ERR_SCREENSHOT_FAILED)

        await self._wait_for_ppm_stable(ppm_path)

        png_path = ppm_path.with_suffix(".png")
        try:
            await asyncio.to_thread(_ppm_p6_to_png, ppm_path, png_path)
        except (OSError, ValueError) as exc:
            _logger.warning("ppm_to_png_conversion_failed", error=str(exc))
            raise SandboxError(_ERR_SCREENSHOT_CONVERSION_FAILED) from exc

        await asyncio.to_thread(ppm_path.unlink, missing_ok=True)
        final_path: Path = png_path

        if output_path is not None:
            await asyncio.to_thread(output_path.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(shutil.copy2, final_path, output_path)
            _logger.info("screenshot_saved", path=str(output_path))
            return output_path

        _logger.info("screenshot_captured", path=str(final_path))
        return final_path

    async def apply_anti_evasion(self, profile: str = "default") -> dict[str, Any]:
        """Apply guest-side anti-evasion registry patches.

        SMBIOS and CPUID masking are applied at VM launch through
        :meth:`_build_qemu_command`; only guest-side registry patches that
        require the guest agent can be applied post-launch. The launch-time
        techniques reported in the result are sourced from
        :attr:`QEMUConfig.anti_evasion_profile`, which is fixed at the time
        :meth:`start` was called.

        The ``profile`` argument must therefore match the profile the sandbox
        was launched with. If the caller passes a different profile, this
        method raises :class:`SandboxError` rather than silently returning a
        success result whose launch-time techniques do not correspond to the
        requested profile. To use a different profile, set
        :attr:`QEMUConfig.anti_evasion_profile` before invoking
        :meth:`start`.

        Args:
            profile: Anti-evasion profile the caller intends to apply. Must
                equal :attr:`QEMUConfig.anti_evasion_profile` of the running
                sandbox.

        Returns:
            dict[str, Any]: Dictionary describing applied techniques. Contains
            ``profile`` (the active launch-time profile), ``techniques``
            (list of technique identifiers actually in effect), and
            ``count`` (length of ``techniques``).

        Raises:
            SandboxError: If the sandbox is not running, QMP is disconnected,
                or ``profile`` does not match the launch-time profile.
        """
        if self.state.status != "running":
            _logger.error("anti_evasion_skipped_sandbox_not_running", state=self.state.status, profile=profile)
            raise SandboxError(_ERR_NOT_RUNNING)

        if self._qmp is None:
            _logger.error("anti_evasion_skipped_qmp_not_connected", profile=profile)
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        current_profile: str = self._qemu_config.anti_evasion_profile
        if profile != current_profile:
            _logger.error(
                "anti_evasion_profile_mismatch",
                requested_profile=profile,
                current_profile=current_profile,
            )
            raise SandboxError(
                _ERR_ANTI_EVASION_PROFILE_MISMATCH.format(
                    requested=profile,
                    current=current_profile,
                ),
            )

        applied: dict[str, Any] = {"profile": current_profile, "techniques": []}
        techniques: list[str] = []

        techniques.extend(f"smbios_type_{entry['type']}_launch_arg" for entry in self._anti_evasion_smbios_entries(current_profile))
        techniques.append("cpuid_hypervisor_mask_launch_arg")

        if self._agent is not None and self._agent.is_connected and self._qemu_config.guest_os == GuestOS.WINDOWS:
            product_id = secrets.token_hex(8).upper()
            sep = "\\"
            bios_key = sep.join(["HKLM", "HARDWARE", "DESCRIPTION", "System", "BIOS"])
            current_version_key = sep.join(["HKLM", "SOFTWARE", "Microsoft", "Windows", "CurrentVersion"])
            disk_enum_key = sep.join(["HKLM", "SYSTEM", "CurrentControlSet", "Services", "Disk", "Enum"])
            registry_commands: list[tuple[str, list[str]]] = [
                (
                    "reg.exe",
                    [
                        "add",
                        bios_key,
                        "/v",
                        "SystemManufacturer",
                        "/t",
                        "REG_SZ",
                        "/d",
                        "HP",
                        "/f",
                    ],
                ),
                (
                    "reg.exe",
                    [
                        "add",
                        bios_key,
                        "/v",
                        "SystemProductName",
                        "/t",
                        "REG_SZ",
                        "/d",
                        "HP EliteDesk 800 G6",
                        "/f",
                    ],
                ),
                (
                    "reg.exe",
                    [
                        "add",
                        current_version_key,
                        "/v",
                        "ProductId",
                        "/t",
                        "REG_SZ",
                        "/d",
                        product_id,
                        "/f",
                    ],
                ),
                (
                    "reg.exe",
                    [
                        "add",
                        disk_enum_key,
                        "/v",
                        "0",
                        "/t",
                        "REG_SZ",
                        "/d",
                        "WDC WD10EZEX-00BBHA0",
                        "/f",
                    ],
                ),
            ]
            for cmd_name, cmd_args in registry_commands:
                exit_code, _, _ = await self._agent.send_command(cmd_name, cmd_args)
                if exit_code == 0:
                    techniques.append("registry_patch")

            mac_octets = [f"{secrets.randbelow(256):02X}" for _ in range(5)]
            mac_literal = "00-" + "-".join(mac_octets)
            mac_ps_command = f"Set-NetAdapter -Name Ethernet -MacAddress '{mac_literal}' -Confirm:$false"
            mac_exit_code, _, _ = await self._agent.send_command(
                "powershell.exe",
                [
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    mac_ps_command,
                ],
            )
            if mac_exit_code == 0:
                techniques.append("mac_address_randomize")

        applied["techniques"] = techniques
        applied["count"] = len(techniques)
        _logger.info("anti_evasion_applied", profile=current_profile, technique_count=len(techniques))
        return applied

    async def dump_memory(self, output_path: Path | None = None) -> Path:
        """Dump guest memory to a file.

        Args:
            output_path: Optional path to save the memory dump.

        Returns:
            Path: Path to the saved memory dump file.

        Raises:
            SandboxError: If memory dump fails.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        dump_id = secrets.token_hex(8)
        dump_path = self._shared_folder / "output" / f"memdump_{dump_id}.raw"

        result = await self._qmp.execute_command({
            "execute": "dump-guest-memory",
            "arguments": {
                "paging": False,
                "protocol": f"file:{dump_path}",
            },
        })

        if not result.success:
            _logger.warning("memory_dump_failed", error=result.error)
            raise SandboxError(_ERR_MEMORY_DUMP_FAILED)

        _logger.info("memory_dump_created", path=str(dump_path))

        if output_path is not None:
            await asyncio.to_thread(output_path.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(shutil.copy2, dump_path, output_path)
            _logger.info("memory_dump_saved", path=str(output_path))
            return output_path

        return dump_path

    async def extract_dropped_files(self, output_path: Path | None = None) -> Path:
        """Extract files created by the binary during execution.

        Args:
            output_path: Optional path to save the ZIP archive.

        Returns:
            Path: Path to ZIP archive of extracted files.

        Raises:
            SandboxError: If extraction fails.
        """
        if self.state.status != "running":
            _logger.error("dropped_files_extraction_skipped_not_running", state=self.state.status)
            raise SandboxError(_ERR_NOT_RUNNING)

        if self._shared_folder is None:
            _logger.error("dropped_files_extraction_shared_folder_not_initialized")
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        extract_id = secrets.token_hex(8)
        staging_dir = self._shared_folder / "output" / f"dropped_{extract_id}"
        await asyncio.to_thread(staging_dir.mkdir, parents=True, exist_ok=True)

        guest_dirs: list[str]
        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            guest_dirs = [
                r"C:\Users\Public\Downloads",
                r"C:\Windows\Temp",
                r"C:\Users\Default\AppData\Local\Temp",
            ]
            shared_base = self.GUEST_SHARED_PATH_WINDOWS
        else:
            guest_dirs = [
                "/tmp",  # noqa: S108  # nosec B108  # guest VM filesystem path, not host
                "/var/tmp",  # noqa: S108  # nosec B108  # guest VM filesystem path, not host
                "/home",
            ]
            shared_base = self.GUEST_SHARED_PATH_LINUX

        if self._agent is not None and self._agent.is_connected:
            for guest_dir in guest_dirs:
                if self._qemu_config.guest_os == GuestOS.WINDOWS:
                    copy_cmd = f'xcopy /S /E /Y /I "{guest_dir}" "{shared_base}output\\dropped_{extract_id}\\{Path(guest_dir).name}"'
                else:
                    dir_name = Path(guest_dir).name
                    copy_cmd = f'cp -r "{guest_dir}" "{shared_base}/output/dropped_{extract_id}/{dir_name}" 2>/dev/null'
                await self._agent.send_command(copy_cmd, time_limit=30.0)

        zip_filename = f"dropped_files_{extract_id}.zip"
        zip_path = self._shared_folder / "output" / zip_filename

        def _create_zip() -> None:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                if staging_dir.exists():
                    for file_path in staging_dir.rglob("*"):
                        if file_path.is_file():
                            arcname = file_path.relative_to(staging_dir)
                            zf.write(file_path, arcname)

        await asyncio.to_thread(_create_zip)

        try:
            await asyncio.to_thread(shutil.rmtree, staging_dir, ignore_errors=True)
        except OSError as e:
            _logger.warning("staging_dir_cleanup_failed", error=str(e), staging_dir=str(staging_dir))

        _logger.info("dropped_files_extracted", zip_path=str(zip_path))

        if output_path is not None:
            await asyncio.to_thread(output_path.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(shutil.copy2, zip_path, output_path)
            return output_path

        return zip_path

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
            list[dict[str, Any]]: List of YARA match dictionaries.

        Raises:
            SandboxError: If scan fails.
        """
        try:
            import yara  # noqa: PLC0415
        except ImportError as exc:
            raise SandboxError(_ERR_YARA_NOT_AVAILABLE) from exc

        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        yara_compile: Any = getattr(yara, "compile")  # noqa: B009
        compiled_rules: Any
        if rules_path is not None:
            compiled_rules = await asyncio.to_thread(yara_compile, filepath=rules_path)
        else:
            default_rules = """
rule SuspiciousStrings {
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
        $s3 = "CreateRemoteThread"
        $s4 = "VirtualAllocEx"
        $s5 = "WriteProcessMemory"
        $s6 = "NtUnmapViewOfSection"
        $s7 = "WScript.Shell"
        $s8 = /HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run/
    condition:
        any of them
}

rule PackedBinary {
    strings:
        $upx = "UPX!"
        $aspack = ".aspack"
        $themida = ".themida"
    condition:
        any of them
}
"""
            compiled_rules = await asyncio.to_thread(yara_compile, source=default_rules)

        matches: list[dict[str, Any]] = []
        output_dir = self._shared_folder / "output"

        if scan_target == "memory":
            dump_files = await asyncio.to_thread(lambda: list(output_dir.glob("memdump_*.raw")))
            for dump_file in dump_files:
                file_matches: list[Any] = await asyncio.to_thread(compiled_rules.match, filepath=str(dump_file))
                matches.extend(_format_yara_match(ym, str(dump_file), "memory") for ym in file_matches)
        else:
            scan_files: list[Path] = []
            zip_files = await asyncio.to_thread(lambda: list(output_dir.glob("dropped_files_*.zip")))
            if zip_files:
                extract_dir = output_dir / f"yara_scan_{secrets.token_hex(4)}"
                await asyncio.to_thread(extract_dir.mkdir, parents=True, exist_ok=True)

                def _extract_zips() -> list[Path]:
                    extracted: list[Path] = []
                    for zf_path in zip_files:
                        with zipfile.ZipFile(zf_path, "r") as zf:
                            zf.extractall(extract_dir)
                    extracted.extend(fp for fp in extract_dir.rglob("*") if fp.is_file())
                    return extracted

                scan_files = await asyncio.to_thread(_extract_zips)
            else:
                scan_files = []

            for scan_file in scan_files:
                try:
                    file_matches = await asyncio.to_thread(compiled_rules.match, filepath=str(scan_file))
                    matches.extend(_format_yara_match(ym, str(scan_file), "files") for ym in file_matches)
                except (OSError, RuntimeError) as e:
                    _logger.warning("yara_file_scan_error", file=str(scan_file), error=str(e))

        _logger.info("yara_scan_complete", match_count=len(matches), scan_target=scan_target)
        return matches
