"""QEMU sandbox implementation for isolated binary analysis.

This module provides cross-platform sandbox functionality using QEMU
virtualization for safe execution and behavioral monitoring of binaries.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import secrets
import shutil
import socket
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal

import psutil

from ..core.logging import get_logger, log_sandbox_operation
from ..core.process_manager import ProcessManager, ProcessType
from .base import (
    ExecutionReport,
    ExecutionResult,
    FileChange,
    NetworkActivity,
    ProcessActivity,
    RegistryChange,
    SandboxBase,
    SandboxConfig,
    SandboxError,
    validate_file_operation,
    validate_process_operation,
    validate_registry_operation,
)


if TYPE_CHECKING:
    from collections.abc import Sequence

_logger = get_logger("sandbox.qemu")

_QMP_READ_TIMEOUT = 5.0
_QMP_CONNECT_TIMEOUT = 60.0
_AGENT_POLL_TIMEOUT = 1.0
_ACCEL_DETECT_TIMEOUT = 10
_ACCEL_TEST_TIMEOUT = 5
_PROCESS_COMMUNICATE_TIMEOUT = 30
_SNAPSHOT_LINE_MIN_PARTS = 2
_FILE_LOG_MIN_PARTS = 3
_NETWORK_LOG_MIN_PARTS = 4
_PROCESS_LOG_MIN_PARTS = 4
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
_PROCESS_LOG_NAME_INDEX = 3
_PROCESS_LOG_PATH_INDEX = 4
_PIDFILE_MAX_RETRIES = 3
_PIDFILE_RETRY_DELAY = 2.0


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
        message_type: Type of message.
        timestamp: When the event occurred.
        data: Message payload.
    """

    message_type: str
    timestamp: datetime
    data: dict[str, object] = field(default_factory=dict)


class QMPClient:
    """QEMU Machine Protocol client for VM control.

    Provides asynchronous communication with QEMU via QMP for
    VM control, snapshot management, and status queries.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 4444) -> None:
        """Initialize QMP client.

        Args:
            host: QMP server host.
            port: QMP server port.
        """
        self._host = host
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._lock = asyncio.Lock()

    async def connect(self, timeout: float = 30.0) -> bool:
        """Connect to QMP server.

        Args:
            timeout: Connection timeout in seconds.

        Returns:
            True if connected successfully.
        """
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port),
                timeout=timeout,
            )

            greeting = await asyncio.wait_for(
                self._reader.readline(),
                timeout=_QMP_READ_TIMEOUT,
            )
            _logger.debug("qmp_greeting_received", extra={"greeting": greeting.decode().strip()})

            await self._send_command({"execute": "qmp_capabilities"})
            self._connected = True
            _logger.info("qmp_connected", extra={"host": self._host, "port": self._port})

        except Exception as e:
            _logger.warning("qmp_connection_failed", extra={"error": str(e)})
            return False
        else:
            return True

    async def disconnect(self) -> None:
        """Disconnect from QMP server."""
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception as e:
                _logger.debug("qmp_disconnect_error", extra={"error": str(e)})
        self._reader = None
        self._writer = None
        self._connected = False

    async def _send_command(
        self,
        command: dict[str, object],
        timeout: float = 10.0,
    ) -> QMPResponse:
        """Send a QMP command and get response.

        Args:
            command: QMP command dictionary.
            timeout: Response timeout.

        Returns:
            QMP response.
        """
        if self._reader is None or self._writer is None:
            return QMPResponse(success=False, error="Not connected")

        async with self._lock:
            try:
                cmd_json = json.dumps(command) + "\n"
                self._writer.write(cmd_json.encode())
                await self._writer.drain()

                response_line = await asyncio.wait_for(
                    self._reader.readline(),
                    timeout=timeout,
                )

                response = json.loads(response_line.decode())

                if "error" in response:
                    return QMPResponse(
                        success=False,
                        error=response["error"].get("desc", "Unknown error"),
                    )

                return QMPResponse(success=True, data=response.get("return"))

            except TimeoutError:
                return QMPResponse(success=False, error="Command timed out")
            except Exception as e:
                return QMPResponse(success=False, error=str(e))

    async def query_status(self) -> QMPResponse:
        """Query VM status.

        Returns:
            VM status response.
        """
        return await self._send_command({"execute": "query-status"})

    async def stop(self) -> QMPResponse:
        """Pause the VM.

        Returns:
            Command response.
        """
        return await self._send_command({"execute": "stop"})

    async def cont(self) -> QMPResponse:
        """Resume the VM.

        Returns:
            Command response.
        """
        return await self._send_command({"execute": "cont"})

    async def quit(self) -> QMPResponse:
        """Quit QEMU.

        Returns:
            Command response.
        """
        return await self._send_command({"execute": "quit"})

    async def savevm(self, name: str) -> QMPResponse:
        """Save a VM snapshot.

        Args:
            name: Snapshot name.

        Returns:
            Command response.
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
            Command response.
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
            Command response.
        """
        return await self._send_command({
            "execute": "human-monitor-command",
            "arguments": {"command-line": f"delvm {name}"},
        })

    async def info_snapshots(self) -> QMPResponse:
        """Get list of snapshots.

        Returns:
            Snapshot list response.
        """
        return await self._send_command({
            "execute": "human-monitor-command",
            "arguments": {"command-line": "info snapshots"},
        })


class GuestAgentClient:
    """Client for communicating with the QEMU guest agent.

    Provides bidirectional communication with the guest OS for
    command execution, file transfer, and behavioral monitoring.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 4445) -> None:
        """Initialize guest agent client.

        Args:
            host: Agent server host.
            port: Agent server port.
        """
        self._host = host
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._lock = asyncio.Lock()
        self._message_queue: asyncio.Queue[GuestAgentMessage] = asyncio.Queue()
        self._reader_task: asyncio.Task[None] | None = None

    @property
    def is_connected(self) -> bool:
        """Whether the client is currently connected.

        Returns:
            True if the guest agent connection is active.
        """
        return self._connected

    async def connect(self, timeout: float = 60.0, retry_interval: float = 2.0) -> bool:
        """Connect to guest agent with retry.

        Args:
            timeout: Total timeout for connection attempts.
            retry_interval: Interval between retries.

        Returns:
            True if connected successfully.
        """
        start_time = time.time()

        connected = False
        while time.time() - start_time < timeout:
            try:
                self._reader, self._writer = await asyncio.wait_for(
                    asyncio.open_connection(self._host, self._port),
                    timeout=retry_interval,
                )
                self._connected = True

                self._reader_task = asyncio.create_task(self._read_messages())

                _logger.info("guest_agent_connected", extra={"host": self._host, "port": self._port})
                connected = True
                break

            except (TimeoutError, OSError):
                await asyncio.sleep(retry_interval)

        if not connected:
            _logger.warning("guest_agent_connection_failed", extra={"timeout_seconds": timeout})
        return connected

    async def disconnect(self) -> None:
        """Disconnect from guest agent."""
        if self._reader_task is not None:
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reader_task
            self._reader_task = None

        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception as e:
                _logger.debug("agent_disconnect_error", extra={"error": str(e)})

        self._reader = None
        self._writer = None
        self._connected = False

    async def _read_messages(self) -> None:
        """Background task to read messages from agent."""
        if self._reader is None:
            return

        while self._connected:
            try:
                line = await self._reader.readline()
                if not line:
                    break

                try:
                    data = json.loads(line.decode())
                    msg = GuestAgentMessage(
                        message_type=data.get("type", "unknown"),
                        timestamp=datetime.now(),
                        data=data.get("data", {}),
                    )
                    await self._message_queue.put(msg)
                except json.JSONDecodeError:
                    _logger.debug("agent_invalid_json", extra={"line": line.decode(errors="replace")})

            except asyncio.CancelledError:
                break
            except Exception as e:
                _logger.debug("agent_read_error", extra={"error": str(e)})
                break

    async def send_command(
        self,
        command: str,
        args: Sequence[str] | None = None,
        timeout: float = 30.0,
    ) -> tuple[int, str, str]:
        """Send a command to execute in the guest.

        Args:
            command: Command to execute.
            args: Command arguments.
            timeout: Execution timeout.

        Returns:
            Tuple of (exit_code, stdout, stderr).
        """
        if self._writer is None or not self._connected:
            return (-1, "", "Not connected to guest agent")

        request = {
            "type": "execute",
            "command": command,
            "args": list(args) if args else [],
            "timeout": timeout,
        }

        async with self._lock:
            result: tuple[int, str, str] = (-1, "", "Command timed out")
            try:
                self._writer.write((json.dumps(request) + "\n").encode())
                await self._writer.drain()

                start_time = time.time()
                while time.time() - start_time < timeout:
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
                        continue

            except Exception as e:
                result = (-1, "", str(e))

            return result

    async def get_pending_messages(self) -> list[GuestAgentMessage]:
        """Get all pending messages from the agent.

        Returns:
            List of pending messages.
        """
        messages: list[GuestAgentMessage] = []
        while not self._message_queue.empty():
            try:
                msg = self._message_queue.get_nowait()
                messages.append(msg)
            except asyncio.QueueEmpty:
                break
        return messages


class QEMUSandbox(SandboxBase):
    """QEMU-based sandbox for cross-platform binary analysis.

    Uses QEMU virtualization with hardware acceleration (WHPX on Windows,
    KVM on Linux) or software emulation (TCG) for isolated binary execution.

    Attributes:
        QEMU_EXE: QEMU executable name.
        TOOLS_PATH: Default path to QEMU installation.
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
        """Initialize QEMU sandbox.

        Args:
            config: General sandbox configuration.
            qemu_config: QEMU-specific configuration.
        """
        super().__init__(config)
        self._qemu_config = qemu_config or QEMUConfig()
        self._process: asyncio.subprocess.Process | None = None
        self._qmp: QMPClient | None = None
        self._agent: GuestAgentClient | None = None
        self._temp_dir: Path | None = None
        self._shared_folder: Path | None = None
        self._accelerator: AcceleratorType = AcceleratorType.TCG
        self._qemu_path: Path | None = None
        self._pidfile_path: Path | None = None
        self._qemu_pid: int | None = None

    @property
    def qemu_config(self) -> QEMUConfig:
        """Get QEMU configuration.

        Returns:
            Current QEMU configuration.
        """
        return self._qemu_config

    async def is_available(self) -> bool:
        """Check if QEMU is available.

        Checks for QEMU executable and determines available acceleration.

        Returns:
            True if QEMU can be used.
        """
        qemu_path = await self._find_qemu()
        if qemu_path is None:
            _logger.debug("qemu_executable_not_found")
            return False

        self._qemu_path = qemu_path
        self._accelerator = await self._detect_accelerator()

        _logger.info(
            "qemu_available",
            extra={"path": str(qemu_path), "accelerator": self._accelerator.value},
        )
        return True

    async def _find_qemu(self) -> Path | None:
        """Find QEMU executable.

        Returns:
            Path to QEMU executable or None if not found.
        """
        search_paths: list[Path] = []

        if self.TOOLS_PATH.exists():
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

        return next(
            (path for path in search_paths if path.exists() and path.is_file()),
            None,
        )

    async def _detect_accelerator(self) -> AcceleratorType:
        """Detect available hardware acceleration.

        Returns:
            Best available accelerator type.
        """
        if self._qemu_path is None:
            return AcceleratorType.TCG

        process_manager = ProcessManager.get_instance()

        try:
            result = await process_manager.run_tracked_async(
                [str(self._qemu_path), "-accel", "help"],
                name="qemu-accel-help",
                timeout=_ACCEL_DETECT_TIMEOUT,
            )
            output = result.stdout + result.stderr

            if "whpx" in output.lower():
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
                    timeout=_ACCEL_TEST_TIMEOUT,
                )
                stderr_bytes = whpx_test.stderr if isinstance(whpx_test.stderr, bytes) else whpx_test.stderr.encode()
                if whpx_test.returncode == _RETURNCODE_SUCCESS or b"whpx" not in stderr_bytes.lower():
                    _logger.info("whpx_acceleration_available")
                    return AcceleratorType.WHPX

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
                    timeout=_ACCEL_TEST_TIMEOUT,
                )
                if kvm_test.returncode == _RETURNCODE_SUCCESS:
                    _logger.info("kvm_acceleration_available")
                    return AcceleratorType.KVM

        except Exception as e:
            _logger.debug("acceleration_detection_failed", extra={"error": str(e)})

        _logger.info("using_tcg_software_emulation")
        return AcceleratorType.TCG

    @staticmethod
    def _get_free_port(start: int = 10000, end: int = 60000) -> int:
        """Find an available port.

        Args:
            start: Start of port range.
            end: End of port range.

        Returns:
            Available port number.

        Raises:
            SandboxError: If no free ports are available after 100 attempts.
        """
        for _ in range(100):
            port = secrets.randbelow(end - start) + start
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                if sock.connect_ex(("127.0.0.1", port)) != 0:
                    return port
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
            _logger.error("qemu_start_failed", extra={"error": error_msg})
            raise SandboxError(_ERR_QEMU_START)

    async def _connect_and_verify_qmp(self) -> None:
        """Connect to QMP and verify VM status.

        Raises:
            SandboxError: If connection or status check fails.
        """
        self._qmp = QMPClient(port=self._qemu_config.monitor_port)
        if not await self._qmp.connect(timeout=_QMP_CONNECT_TIMEOUT):
            raise SandboxError(_ERR_QMP_CONNECT)

        status = await self._qmp.query_status()
        if not status.success:
            _logger.error("vm_status_query_failed", extra={"error": status.error})
            raise SandboxError(_ERR_VM_STATUS)

    async def _build_qemu_command(self) -> list[str]:
        """Build QEMU command line.

        Returns:
            QEMU command as list of arguments.

        Raises:
            SandboxError: If configuration is invalid.
        """
        if self._qemu_path is None:
            raise SandboxError(_ERR_QEMU_PATH)

        if self._qemu_config.image_path is None or not self._qemu_config.image_path.exists():
            raise SandboxError(_ERR_NO_IMAGE)

        cmd: list[str] = [
            str(self._qemu_path),
            *["-machine", "q35,accel=" + self._accelerator.value],
            "-cpu",
            "max",
            *["-smp", f"cores={self._qemu_config.cpu_cores}"],
            *["-m", str(self._qemu_config.memory_mb)],
            *[
                "-drive",
                f"file={self._qemu_config.image_path},format=qcow2,if=virtio",
            ],
        ]

        if self._qemu_config.display == "none":
            cmd.extend(["-display", "none"])
        elif self._qemu_config.display == "vnc":
            vnc_port = self._get_free_port(5900, 5999) - 5900
            cmd.extend(["-vnc", f":{vnc_port}"])
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
                netdev += f",smb={self._shared_folder}"
            else:
                cmd.extend([
                    "-fsdev",
                    f"local,id=fsdev0,path={self._shared_folder},security_model=mapped-xattr",
                    "-device",
                    "virtio-9p-pci,fsdev=fsdev0,mount_tag=shared",
                ])

        cmd.extend(["-netdev", netdev, "-device", "virtio-net-pci,netdev=net0"])
        cmd.extend(["-qmp", f"tcp:127.0.0.1:{monitor_port},server,nowait"])

        cmd.extend([
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
        )

        return cmd

    async def start(self) -> None:
        """Start the QEMU virtual machine.

        Raises:
            SandboxError: If VM cannot be started.
        """
        if self._state.status == "running":
            _logger.warning("qemu_sandbox_already_running")
            return

        if not await self.is_available():
            raise SandboxError(_ERR_QEMU_NA)

        log_sandbox_operation("start", "qemu", guest_os=self._qemu_config.guest_os.value)
        self._state.status = "starting"
        self._state.last_error = None

        try:
            self._temp_dir = Path(tempfile.mkdtemp(prefix="intellicrack_qemu_"))
            self._shared_folder = self._temp_dir / "shared"
            self._shared_folder.mkdir(parents=True, exist_ok=True)

            (self._shared_folder / "input").mkdir(exist_ok=True)
            (self._shared_folder / "output").mkdir(exist_ok=True)
            (self._shared_folder / "logs").mkdir(exist_ok=True)
            (self._shared_folder / "monitor").mkdir(exist_ok=True)

            await self._create_guest_agent_script()

            cmd = await self._build_qemu_command()
            _logger.info("qemu_starting", extra={"command": " ".join(cmd)})

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
                    if self._pidfile_path.exists():
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
                                extra={"attempt": attempt + 1},
                            )

            if qemu_pid is None:
                _logger.error("qemu_pidfile_unreadable")
                await self._cleanup()
                raise SandboxError(_ERR_PIDFILE_UNREADABLE)  # noqa: TRY301

            self._qemu_pid = qemu_pid
            self._state.pid = qemu_pid
            _logger.info("qemu_started", extra={"pid": qemu_pid})

            process_manager = ProcessManager.get_instance()
            process_manager.register_external_pid(
                qemu_pid,
                name="qemu-vm",
                process_type=ProcessType.SANDBOX,
                metadata={
                    "guest_os": self._qemu_config.guest_os.value,
                    "image": str(self._qemu_config.image_path),
                },
            )

            await self._connect_and_verify_qmp()

            self._agent = GuestAgentClient(port=self._qemu_config.agent_port)

            self._state.status = "running"
            self._state.started_at = datetime.now()
            _logger.info("qemu_sandbox_started_successfully")

        except Exception as e:
            self._state.status = "error"
            self._state.last_error = str(e)
            await self._cleanup()
            _logger.exception("qemu_sandbox_start_failed")
            raise SandboxError(_ERR_SANDBOX_START) from e

    async def stop(self) -> None:
        """Stop the QEMU virtual machine.

        Raises:
            SandboxError: If VM cannot be stopped.
        """
        if self._state.status == "stopped":
            _logger.debug("qemu_sandbox_already_stopped")
            return

        self._state.status = "stopping"

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

            self._state.status = "stopped"
            self._state.pid = None
            _logger.info("qemu_sandbox_stopped")

        except Exception as e:
            self._state.status = "error"
            self._state.last_error = str(e)
            _logger.exception("qemu_sandbox_stop_failed")
            raise SandboxError(_ERR_SANDBOX_STOP) from e

    async def _cleanup(self) -> None:
        """Clean up temporary files and resources."""
        if self._temp_dir is not None:
            pid_path = self._temp_dir / "qemu.pid"
            if pid_path.exists():
                try:
                    pid_content = await asyncio.to_thread(pid_path.read_text, encoding="utf-8")
                    pid = int(pid_content.strip())
                    # Kill orphan QEMU process if it exists
                    with contextlib.suppress(psutil.NoSuchProcess):
                        ProcessManager.terminate_tree(pid, graceful_timeout=2.0, force_timeout=2.0)
                        _logger.debug("cleanup_killed_orphan_qemu_tree", extra={"pid": pid})
                except Exception as e:
                    _logger.debug("cleanup_pid_check_failed", extra={"error": str(e)})

        if self._temp_dir is not None and self._temp_dir.exists():
            try:
                await asyncio.to_thread(
                    shutil.rmtree,
                    self._temp_dir,
                    ignore_errors=True,
                )
            except Exception as e:
                _logger.warning("temp_dir_cleanup_failed", extra={"error": str(e)})

        self._temp_dir = None
        self._shared_folder = None

    async def _create_guest_agent_script(self) -> None:
        """Create guest agent monitoring scripts."""
        if self._shared_folder is None:
            return

        monitor_dir = self._shared_folder / "monitor"

        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            agent_script = monitor_dir / "agent.ps1"
            agent_content = r"""
$port = 4445
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $port)
$listener.Start()

function Send-Message($stream, $data) {
    $json = ConvertTo-Json $data -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json + "`n")
    $stream.Write($bytes, 0, $bytes.Length)
}

$logDir = "Z:\logs"
$fileLog = "$logDir\file_changes.log"
$regLog = "$logDir\registry_changes.log"
$netLog = "$logDir\network_activity.log"
$procLog = "$logDir\process_activity.log"

$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "C:\"
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true

Register-ObjectEvent $watcher "Created" -Action {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts|created|$($Event.SourceEventArgs.FullPath)" | Out-File -Append $using:fileLog
}
Register-ObjectEvent $watcher "Changed" -Action {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts|modified|$($Event.SourceEventArgs.FullPath)" | Out-File -Append $using:fileLog
}
Register-ObjectEvent $watcher "Deleted" -Action {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts|deleted|$($Event.SourceEventArgs.FullPath)" | Out-File -Append $using:fileLog
}

$knownProcs = @{}

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

                if ($request.type -eq "execute") {
                    $output = ""
                    $exitCode = 0
                    try {
                        $output = Invoke-Expression $request.command 2>&1
                        $exitCode = $LASTEXITCODE
                    } catch {
                        $output = $_.Exception.Message
                        $exitCode = 1
                    }

                    Send-Message $stream @{
                        type = "result"
                        data = @{
                            exit_code = $exitCode
                            stdout = ($output | Out-String)
                            stderr = ""
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
            $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            "$ts|created|$($proc.Id)|$($proc.Name)|$($proc.Path)" | Out-File -Append $procLog
            $knownProcs[$proc.Id] = $proc.Name
        }
    }

    $currentIds = $currentProcs | ForEach-Object { $_.Id }
    $terminated = $knownProcs.Keys | Where-Object { $_ -notin $currentIds }
    foreach ($id in $terminated) {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$ts|terminated|$id|$($knownProcs[$id])" | Out-File -Append $procLog
        $knownProcs.Remove($id)
    }

    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    foreach ($conn in $connections) {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$ts|tcp|$($conn.LocalAddress):$($conn.LocalPort)|$($conn.RemoteAddress):$($conn.RemotePort)" | Out-File -Append $netLog
    }

    Start-Sleep -Seconds 1
}
"""
            agent_script.write_text(agent_content, encoding="utf-8")

            startup_script = monitor_dir / "start_agent.cmd"
            startup_content = """@echo off
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "Z:\\monitor\\agent.ps1"
"""
        else:
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
_logger: logging.Logger = logging.getLogger("intellicrack_agent")


def file_monitor() -> None:
    """Monitor file system changes using inotify.

    Logs all file operations (create, modify, delete, etc.) to the
    file_changes.log file in the shared log directory.
    """
    try:
        import inotify.adapters
    except ImportError:
        _logger.warning("inotify module not available, file monitoring disabled")
        return

    try:
        inotify_tree = inotify.adapters.InotifyTree("/")
        _logger.info("File monitoring started")
        for event in inotify_tree.event_gen(yield_nones=False):
            event_header, type_names, watch_path, filename = event
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            operation = type_names[0].lower() if type_names else "unknown"
            try:
                log_path = LOG_DIR / "file_changes.log"
                with open(log_path, "a", encoding="utf-8") as log_file:
                    log_file.write(f"{timestamp}|{operation}|{watch_path}/{filename}\\n")
            except OSError as write_err:
                _logger.debug("Could not write file change log: %s", write_err)
    except OSError as inotify_err:
        _logger.error("inotify initialization failed: %s", inotify_err)


def process_monitor() -> None:
    """Monitor process creation and termination via /proc.

    Polls /proc directory to detect new and terminated processes,
    logging activity to the process_activity.log file.
    """
    known_pids: set[int] = set()
    _logger.info("Process monitoring started")

    while True:
        current_pids: set[int] = set()
        try:
            proc_entries = os.listdir("/proc")
        except OSError as list_err:
            _logger.debug("Could not list /proc: %s", list_err)
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
        comm_path = f"/proc/{pid}/comm"
        with open(comm_path, "r", encoding="utf-8") as comm_file:
            return comm_file.read().strip()
    except (OSError, PermissionError, FileNotFoundError):
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
        with open(log_path, "a", encoding="utf-8") as log_file:
            if name is not None:
                log_file.write(f"{timestamp}|{operation}|{pid}|{name}\\n")
            else:
                log_file.write(f"{timestamp}|{operation}|{pid}\\n")
    except OSError as write_err:
        _logger.debug("Could not write process activity log: %s", write_err)


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
        pass

    _logger.debug("Client connected: %s", client_addr)

    try:
        while True:
            data = conn.recv(RECV_BUFFER_SIZE)
            if not data:
                break

            try:
                request: dict[str, Any] = json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as parse_err:
                _logger.warning("Invalid request from %s: %s", client_addr, parse_err)
                continue

            if request.get("type") == "execute":
                response = _execute_command(request)
                response_bytes = (json.dumps(response) + "\\n").encode("utf-8")
                conn.send(response_bytes)

    except ConnectionResetError:
        _logger.debug("Client %s disconnected", client_addr)
    except OSError as sock_err:
        _logger.debug("Socket error with client %s: %s", client_addr, sock_err)
    finally:
        try:
            conn.close()
        except OSError:
            pass
        _logger.debug("Client connection closed: %s", client_addr)


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
        return {
            "type": "result",
            "data": {"exit_code": -1, "stdout": "", "stderr": f"Command timed out after {timeout}s"},
        }
    except FileNotFoundError:
        return {
            "type": "result",
            "data": {"exit_code": -1, "stdout": "", "stderr": f"Command not found: {cmd}"},
        }
    except PermissionError:
        return {
            "type": "result",
            "data": {"exit_code": -1, "stdout": "", "stderr": f"Permission denied: {cmd}"},
        }
    except OSError as os_err:
        return {
            "type": "result",
            "data": {"exit_code": -1, "stdout": "", "stderr": str(os_err)},
        }


def main() -> None:
    """Main entry point for the guest agent."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    _logger.info("Intellicrack guest agent starting on port %d", PORT)

    process_thread = threading.Thread(target=process_monitor, daemon=True)
    process_thread.start()

    file_thread = threading.Thread(target=file_monitor, daemon=True)
    file_thread.start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(("0.0.0.0", PORT))
        server.listen(5)
        _logger.info("Agent listening on 0.0.0.0:%d", PORT)

        while True:
            try:
                conn, addr = server.accept()
                client_thread = threading.Thread(
                    target=handle_client, args=(conn,), daemon=True
                )
                client_thread.start()
            except OSError as accept_err:
                _logger.error("Accept failed: %s", accept_err)
                break
    except OSError as bind_err:
        _logger.error("Could not bind to port %d: %s", PORT, bind_err)
    finally:
        server.close()


if __name__ == "__main__":
    main()
'''
            agent_script.write_text(agent_content, encoding="utf-8")

            startup_script = monitor_dir / "start_agent.sh"
            startup_content = """#!/bin/bash
python3 /mnt/shared/monitor/agent.py &
"""
        startup_script.write_text(startup_content, encoding="utf-8")

        _logger.debug("guest_agent_scripts_created", extra={"path": str(monitor_dir)})

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

        Returns:
            Tuple of (exit_code, stdout, stderr).

        Raises:
            SandboxError: If execution fails.
        """
        if self._state.status != "running":
            raise SandboxError(_ERR_NOT_RUNNING)

        effective_timeout = timeout or self._config.timeout_seconds

        if self._agent is not None and self._agent.is_connected:
            if working_directory:
                command = f"cd {working_directory} && {command}"
            return await self._agent.send_command(command, timeout=effective_timeout)

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
        script_path.write_text(script_content, encoding="utf-8")

        return await self._poll_for_result(result_path=result_path, timeout=effective_timeout)

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
            Tuple of (script_filename, script_content).
        """
        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            script_name = f"exec_{script_id}.cmd"
            script_content = f"""@echo off
{f'cd /d "{working_directory}"' if working_directory else ""}
{command}
echo %ERRORLEVEL% > "Z:\\output\\{result_name}"
"""
        else:
            script_name = f"exec_{script_id}.sh"
            script_content = f"""#!/bin/bash
{f'cd "{working_directory}"' if working_directory else ""}
{command}
echo $? > "/mnt/shared/output/{result_name}"
"""
        return script_name, script_content

    @staticmethod
    async def _poll_for_result(
        *,
        result_path: Path,
        timeout: int,
    ) -> tuple[int, str, str]:
        """Poll the shared folder for command execution results.

        Args:
            result_path: Path to the expected result file.
            timeout: Maximum time in seconds to wait.

        Returns:
            Tuple of (exit_code, stdout, stderr).

        Raises:
            SandboxError: If the command times out.
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            await asyncio.sleep(1)
            if result_path.exists():
                try:
                    result_text = result_path.read_text(encoding="utf-8").strip()
                    exit_code = int(result_text) if result_text.isdigit() else -1
                except Exception as e:
                    _logger.debug("result_read_failed", extra={"error": str(e)})
                else:
                    return (exit_code, "", "")

        _logger.error("command_timed_out", extra={"timeout_seconds": timeout})
        raise SandboxError(_ERR_CMD_TIMEOUT)

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

        Returns:
            ExecutionReport with results and activity.

        Raises:
            SandboxError: If execution fails.
        """
        if self._state.status != "running":
            raise SandboxError(_ERR_NOT_RUNNING)

        if not binary_path.exists():
            _logger.error("binary_not_found", extra={"path": str(binary_path)})
            raise SandboxError(_ERR_BINARY_NOT_FOUND)

        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        effective_timeout = timeout or self._config.timeout_seconds
        start_time = time.time()

        await self.copy_to_sandbox(binary_path, f"input/{binary_path.name}")

        if monitor:
            logs_folder = self._shared_folder / "logs"
            for log_file in logs_folder.glob("*.log"):
                log_file.unlink()

        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            binary_sandbox_path = f"Z:\\input\\{binary_path.name}"
        else:
            binary_sandbox_path = f"/mnt/shared/input/{binary_path.name}"

        args_str = " ".join(f'"{a}"' for a in (args or []))
        command = f'"{binary_sandbox_path}" {args_str}'

        result: ExecutionResult
        try:
            exit_code, stdout, stderr = await self.run_command(
                command,
                timeout=effective_timeout,
            )
            result = "success"
        except SandboxError as e:
            result = "timeout" if "timed out" in str(e) else "error"
            stderr = str(e)
            stdout = ""
            exit_code = -1
        duration = time.time() - start_time

        file_changes: list[FileChange] = []
        registry_changes: list[RegistryChange] = []
        network_activity: list[NetworkActivity] = []
        process_activity: list[ProcessActivity] = []

        if monitor:
            await asyncio.sleep(2)
            file_changes = await self._parse_file_log()
            registry_changes = await self._parse_registry_log()
            network_activity = await self._parse_network_log()
            process_activity = await self._parse_process_log()

        return ExecutionReport(
            result=result,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            file_changes=file_changes,
            registry_changes=registry_changes,
            network_activity=network_activity,
            process_activity=process_activity,
        )

    async def _parse_file_log(self) -> list[FileChange]:
        """Parse file monitoring log.

        Returns:
            List of file changes detected during execution.
        """
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "file_changes.log"
        if not log_path.exists():
            return []

        changes: list[FileChange] = []
        try:
            for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split("|")
                if len(parts) >= _FILE_LOG_MIN_PARTS:
                    changes.append(
                        FileChange(
                            path=parts[2],
                            operation=validate_file_operation(parts[1]),
                            old_path=None,
                            timestamp=parts[0],
                            size=None,
                        )
                    )
        except Exception as e:
            _logger.warning("file_log_parse_failed", extra={"error": str(e)})

        return changes

    async def _parse_registry_log(self) -> list[RegistryChange]:
        """Parse registry monitoring log.

        Returns:
            List of registry changes detected during execution.
        """
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "registry_changes.log"
        if not log_path.exists():
            return []

        changes: list[RegistryChange] = []
        try:
            for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split("|")
                if len(parts) >= _FILE_LOG_MIN_PARTS:
                    changes.append(
                        RegistryChange(
                            key=parts[2],
                            value_name=None,
                            operation=validate_registry_operation(parts[1]),
                            value_type=None,
                            value_data=None,
                            timestamp=parts[0],
                        )
                    )
        except Exception as e:
            _logger.warning("registry_log_parse_failed", extra={"error": str(e)})

        return changes

    async def _parse_network_log(self) -> list[NetworkActivity]:
        """Parse network monitoring log.

        Returns:
            List of network activity detected during execution.
        """
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "network_activity.log"
        if not log_path.exists():
            return []

        activities: list[NetworkActivity] = []
        try:
            for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split("|")
                if len(parts) >= _NETWORK_LOG_MIN_PARTS:
                    local_parts = parts[2].rsplit(":", 1)
                    remote_parts = parts[3].rsplit(":", 1)

                    activities.append(
                        NetworkActivity(
                            protocol="tcp",
                            direction="outbound",
                            local_address=local_parts[0] if local_parts else "",
                            local_port=int(local_parts[1]) if len(local_parts) > 1 and local_parts[1].isdigit() else 0,
                            remote_address=remote_parts[0] if remote_parts else "",
                            remote_port=int(remote_parts[1]) if len(remote_parts) > 1 and remote_parts[1].isdigit() else 0,
                            timestamp=parts[0],
                            bytes_sent=0,
                            bytes_received=0,
                        )
                    )
        except Exception as e:
            _logger.warning("network_log_parse_failed", extra={"error": str(e)})

        return activities

    async def _parse_process_log(self) -> list[ProcessActivity]:
        """Parse process monitoring log.

        Returns:
            List of process activity detected during execution.
        """
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "process_activity.log"
        if not log_path.exists():
            return []

        activities: list[ProcessActivity] = []
        try:
            for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split("|")
                if len(parts) >= _PROCESS_LOG_MIN_PARTS:
                    activities.append(
                        ProcessActivity(
                            pid=int(parts[2]) if parts[2].isdigit() else 0,
                            name=parts[_PROCESS_LOG_NAME_INDEX] if len(parts) > _PROCESS_LOG_NAME_INDEX else "",
                            path=parts[_PROCESS_LOG_PATH_INDEX] if len(parts) > _PROCESS_LOG_PATH_INDEX else None,
                            command_line=None,
                            parent_pid=None,
                            operation=validate_process_operation(parts[1]),
                            exit_code=None,
                            timestamp=parts[0],
                        )
                    )
        except Exception as e:
            _logger.warning("process_log_parse_failed", extra={"error": str(e)})

        return activities

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

        if not source.exists():
            _logger.error("source_file_not_found", extra={"path": str(source)})
            raise SandboxError(_ERR_SOURCE_NOT_FOUND)

        dest_path = self._shared_folder / dest
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            await asyncio.to_thread(shutil.copy2, source, dest_path)
            _logger.debug("file_copied_to_sandbox", extra={"source": str(source), "dest": dest})
        except Exception as e:
            _logger.exception("copy_to_sandbox_failed")
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

        if not source_path.exists():
            _logger.error("sandbox_source_file_not_found", extra={"path": source})
            raise SandboxError(_ERR_SOURCE_NOT_FOUND)

        dest.parent.mkdir(parents=True, exist_ok=True)

        try:
            await asyncio.to_thread(shutil.copy2, source_path, dest)
            _logger.debug("file_copied_from_sandbox", extra={"source": source, "dest": str(dest)})
        except Exception as e:
            _logger.exception("copy_from_sandbox_failed")
            raise SandboxError(_ERR_COPY_FROM_SANDBOX) from e

    async def take_snapshot(self, name: str) -> str:
        """Take a snapshot of the VM state.

        Args:
            name: Snapshot name.

        Returns:
            Snapshot identifier.

        Raises:
            SandboxError: If snapshot fails.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        result = await self._qmp.savevm(name)
        if not result.success:
            _logger.error("snapshot_create_failed", extra={"error": result.error})
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
            _logger.error("snapshot_restore_failed", extra={"error": result.error})
            raise SandboxError(_ERR_SNAPSHOT_RESTORE)

        _logger.info("snapshot_restored", extra={"snapshot_id": snapshot_id})

    async def list_snapshots(self) -> list[str]:
        """List available snapshots.

        Returns:
            List of snapshot names.
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
            _logger.error("snapshot_delete_failed", extra={"error": result.error})
            raise SandboxError(_ERR_SNAPSHOT_DELETE)

        _logger.info("snapshot_deleted", extra={"snapshot_name": name})
