# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Second-pass coverage for the QEMU sandbox: real qemu-img overlays, host probes and launch outcomes.

The overlay tests run the real ``qemu-img`` found in ``QEMU_INSTALL_DIR`` and read the result back with
``qemu-img info``. The WHPX and hypervisor probes are driven through the real ``subprocess`` machinery by
putting small batch files named like the host tools on a confined ``PATH``, so the product reads genuine
process output. Launch outcomes are driven by batch files standing in for the emulator, because the real
``qemu-system-x86_64`` cannot load in the container. Channel, recorder and monitor paths use real asyncio
streams, the real loopback protocol servers, and real child processes.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import json
import os
import stat
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final, Protocol, cast, override

import psutil
import pytest
import structlog.testing

from intellicrack.core.process_manager import ProcessManager
from intellicrack.core.subprocess_compat import run as run_process
from intellicrack.sandbox import qemu as qemu_module
from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import (
    AcceleratorType,
    GuestAgentClient,
    GuestOS,
    QEMUConfig,
    QemuGuestAgentClient,
    QemuOutputRecorder,
    QEMUSandbox,
    QemuTermination,
    QMPClient,
)
from tests._helpers.polling import wait_until
from tests.sandbox.qemu.guest_agent_server import (
    GuestAgentProtocolServer,
    IntellicrackAgentServer,
    QmpProtocolServer,
    command_not_found,
)


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator, Mapping, Sequence
    from subprocess import CompletedProcess

_STEP_TIMEOUT: Final[float] = 30.0
_POLL_INTERVAL_S: Final[float] = 0.05
_QEMU_DIR_VARIABLE: Final[str] = "QEMU_INSTALL_DIR"
_QEMU_EXE_NAME: Final[str] = "qemu-system-x86_64.exe"
_QEMU_IMG_NAME: Final[str] = "qemu-img.exe"
_BASE_IMAGE_SIZE: Final[int] = 1024 * 1024
_STATUS_POLL_PID: Final[int] = 4242
_GENERIC_READ: Final[int] = 0x80000000
_OPEN_EXISTING: Final[int] = 3
_BENIGN_ARTIFACT: Final[bytes] = b"MZ\x90\x00" + b"\x00" * 64 + b"nothing the rules look for\x00"
_PACKED_ARTIFACT: Final[bytes] = b"MZ\x90\x00" + b"\x00" * 64 + b"UPX!" + b"\x00" * 32

_GUEST_COMMAND_POLL_INTERVAL = cast("float", getattr(qemu_module, "_GUEST_COMMAND_POLL_INTERVAL"))
_CONFIGURED_SHARE_DIR_NAME = cast("str", getattr(qemu_module, "_CONFIGURED_SHARE_DIR_NAME"))


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


class _NoAttemptAgent(GuestAgentClient):
    """An agent client whose dispatch budget allows no attempt at all."""

    MAX_DISPATCH_ATTEMPTS: ClassVar[int] = 0

    async def run_with_recovery(self, request: dict[str, object], time_limit: float) -> tuple[int, str, str]:
        """Forward to ``_run_with_channel_recovery``.

        Args:
            request: Request payload.
            time_limit: Reply deadline in seconds.

        Returns:
            tuple[int, str, str]: ``(exit_code, stdout, stderr)``.
        """
        return await self._run_with_channel_recovery(request, time_limit)


class _Recorder(QemuOutputRecorder):
    """The output recorder with its background task made observable."""

    def current_task(self) -> asyncio.Task[None] | None:
        """Return the draining task.

        Returns:
            asyncio.Task[None] | None: The task, or None when none is running.
        """
        return self._task


class _RefusingStatusMonitor(QmpProtocolServer):
    """A monitor server that accepts the handshake but refuses ``query-status``."""

    @override
    def _result_for(self, name: str) -> dict[str, Any]:
        """Refuse ``query-status`` and answer everything else as the base server does.

        Args:
            name: The ``execute`` member of the request.

        Returns:
            dict[str, Any]: Reply body without the correlation id.
        """
        if name == "query-status":
            return command_not_found(name)
        return super()._result_for(name)


class _R1Sandbox(QEMUSandbox):
    """The QEMU sandbox with its private state and helpers made callable."""

    def set_qemu_path(self, path: Path | None) -> None:
        """Record where the QEMU binary is.

        Args:
            path: The binary's path, or None.
        """
        self._qemu_path = path

    def set_temp_dir(self, path: Path | None) -> None:
        """Record the instance's temporary directory.

        Args:
            path: The directory, or None.
        """
        self._temp_dir = path

    def set_shared_folder(self, path: Path | None) -> None:
        """Record the host-side shared folder.

        Args:
            path: The folder, or None.
        """
        self._shared_folder = path

    def set_qga(self, client: QemuGuestAgentClient | None) -> None:
        """Install the guest-agent channel client.

        Args:
            client: The client, or None to clear it.
        """
        self._qga = client

    def peek_qmp(self) -> QMPClient | None:
        """Return the monitor client.

        Returns:
            QMPClient | None: The client, or None.
        """
        return self._qmp

    def recorder(self) -> QemuOutputRecorder | None:
        """Return the output recorder.

        Returns:
            QemuOutputRecorder | None: The recorder, or None.
        """
        return self._output_recorder

    async def create_disk_overlay(self, image_path: Path) -> Path:
        """Forward to ``_create_disk_overlay``.

        Args:
            image_path: Backing image.

        Returns:
            Path: The overlay.
        """
        return await self._create_disk_overlay(image_path)

    async def connect_and_verify_qmp(self) -> None:
        """Forward to ``_connect_and_verify_qmp``."""
        await self._connect_and_verify_qmp()

    async def try_whpx(self, process_manager: ProcessManager, output_lower: str) -> AcceleratorType | None:
        """Forward to ``_try_whpx_accelerator``.

        Args:
            process_manager: Process manager used for probes.
            output_lower: Lower-cased ``-accel help`` output.

        Returns:
            AcceleratorType | None: The accelerator when usable.
        """
        return await self._try_whpx_accelerator(process_manager, output_lower)

    async def detect_accelerator(self) -> AcceleratorType:
        """Forward to ``_detect_accelerator``.

        Returns:
            AcceleratorType: The best accelerator found.
        """
        return await self._detect_accelerator()

    async def await_bootstrap_death(self, guest_pid: int) -> str:
        """Forward to ``_await_bootstrap_death``.

        Args:
            guest_pid: Guest pid of the launcher.

        Returns:
            str: Description of how the launcher exited.
        """
        return await self._await_bootstrap_death(guest_pid)

    async def stage_configured_shares(self) -> list[Path]:
        """Forward to ``_stage_configured_shares``.

        Returns:
            list[Path]: Host paths of the staged entries.
        """
        return await self._stage_configured_shares()

    async def spawn(self) -> None:
        """Forward to ``_spawn_qemu_process``."""
        await self._spawn_qemu_process()

    async def cleanup(self) -> None:
        """Forward to ``_cleanup``."""
        await self._cleanup()

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


def _events(captured: list[Any], name: str) -> list[Any]:
    """Select the captured log records carrying one event name.

    Args:
        captured: Records collected by ``structlog.testing.capture_logs``.
        name: Event name to select.

    Returns:
        list[Any]: The matching records, in emission order.
    """
    return [record for record in captured if record.get("event") == name]


def _write_batch(path: Path, lines: Sequence[str]) -> Path:
    """Write a batch file that stands in for an external tool.

    Args:
        path: Where to write the file.
        lines: Batch statements, one per line.

    Returns:
        Path: The written file.
    """
    path.write_text("\n".join(["@echo off", *lines, ""]), encoding="ascii")
    return path


def _install_tools(directory: Path, tools: Mapping[str, str]) -> None:
    """Install stand-in host tools in a directory.

    A ``.cmd`` name becomes a batch file that prints the given text; any other name becomes an empty file,
    which the operating system refuses to start.

    Args:
        directory: Directory to install into.
        tools: File name to the text the tool prints, or to an ignored empty string for an unlaunchable file.
    """
    for name, output in tools.items():
        if name.endswith(".cmd"):
            _write_batch(directory / name, [f"echo {output}"])
        else:
            (directory / name).write_bytes(b"")


def _confine_path(monkeypatch: pytest.MonkeyPatch, directory: Path) -> None:
    """Make a directory the only place host tools are looked for.

    Args:
        monkeypatch: Used to set the environment and working directory.
        directory: Directory that becomes the whole ``PATH``.
    """
    monkeypatch.setenv("PATH", str(directory))
    monkeypatch.setenv("PATHEXT", ".EXE;.CMD")
    monkeypatch.chdir(directory)


def _qemu_directory() -> Path:
    """Return the directory holding the real QEMU tools.

    Returns:
        Path: The directory named by ``QEMU_INSTALL_DIR``.
    """
    return Path(os.environ[_QEMU_DIR_VARIABLE])


def _run_qemu_img(arguments: Sequence[str]) -> CompletedProcess[str]:
    """Run the real ``qemu-img`` and require it to succeed.

    Args:
        arguments: Arguments after the executable.

    Returns:
        CompletedProcess[str]: The finished process.
    """
    completed = run_process(
        [str(_qemu_directory() / _QEMU_IMG_NAME), *arguments],
        capture_output=True,
        text=True,
        timeout=_STEP_TIMEOUT,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return completed


@contextlib.contextmanager
def _exclusively_open(path: Path) -> Generator[None]:
    """Hold a file open with no sharing, so nothing else can open it.

    Args:
        path: File to hold.

    Yields:
        None: While the file is held.

    Raises:
        OSError: If the file cannot be opened exclusively.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = cast("int | None", kernel32.CreateFileW(str(path), _GENERIC_READ, 0, None, _OPEN_EXISTING, 0, None))
    if handle is None or handle == ctypes.c_void_p(-1).value:
        message = "CreateFileW failed"
        raise OSError(ctypes.get_last_error(), message)
    try:
        yield
    finally:
        kernel32.CloseHandle(handle)


def _kill_tree(pid: int) -> None:
    """End a process and everything it started.

    Args:
        pid: Root process id.
    """
    with contextlib.suppress(psutil.NoSuchProcess):
        root = psutil.Process(pid)
        for child in root.children(recursive=True):
            with contextlib.suppress(psutil.NoSuchProcess):
                child.kill()
        root.kill()


def _launchable(tmp_path: Path, launcher: Path) -> _R1Sandbox:
    """Build a sandbox primed to launch a stand-in emulator without a disk overlay.

    Args:
        tmp_path: Directory to hold the image.
        launcher: Path of the stand-in emulator.

    Returns:
        _R1Sandbox: The primed sandbox.
    """
    image = tmp_path / "guest.qcow2"
    image.write_bytes(b"QFI\xfb" + (3).to_bytes(4, "big") + bytes(64))
    sandbox = _R1Sandbox(
        SandboxConfig(),
        QEMUConfig(guest_os=GuestOS.WINDOWS, image_path=image, disk_overlay=False),
    )
    sandbox.set_qemu_path(launcher)
    return sandbox


@pytest.mark.asyncio
async def test_a_dispatch_budget_of_zero_sends_nothing_and_reports_the_exhausted_budget() -> None:
    """With no attempts allowed the request never reaches the guest and the reply names the empty budget."""
    async with _serving(IntellicrackAgentServer()) as server:
        client = _NoAttemptAgent(port=server.port)
        try:
            assert await client.connect(time_limit=_STEP_TIMEOUT, retry_interval=_STEP_TIMEOUT)

            exit_code, stdout, stderr = await client.run_with_recovery(
                {"type": "execute", "command": "whoami", "args": [], "timeout": _STEP_TIMEOUT},
                _STEP_TIMEOUT,
            )
        finally:
            await client.disconnect()

    assert exit_code == -1
    assert not stdout
    assert "all 0 dispatch attempts" in stderr
    assert server.requests == []


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_recorder_survives_a_stream_that_fails_and_keeps_draining_the_other() -> None:
    """A read error on one pipe ends that pipe's drain, is logged, and leaves the other pipe's output retained."""
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "import sys; sys.stderr.write('parting note\\n')",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    recorder = _Recorder(process)
    try:
        stream = process.stdout
        assert stream is not None
        stream.set_exception(OSError("pipe broke"))
        recorder.expect_exit()
        with structlog.testing.capture_logs() as captured:
            recorder.start()
            task = recorder.current_task()
            assert task is not None
            await asyncio.wait_for(task, timeout=_STEP_TIMEOUT)
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()
        await recorder.aclose()

    assert recorder.termination == QemuTermination(returncode=0, output_tail=("stderr: parting note",))
    failed = _events(captured, "qemu_output_read_failed")
    assert len(failed) == 1
    assert failed[0]["channel"] == "stdout"
    assert failed[0]["error"] == "pipe broke"


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_closing_a_recorder_whose_task_failed_reports_instead_of_raising() -> None:
    """A drain that ended in an error is logged when the recorder is closed, and closing does not raise."""
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "pass",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    recorder = _Recorder(process)
    try:
        stream = process.stdout
        assert stream is not None
        stream.set_exception(ValueError("reader broke"))
        recorder.start()
        task = recorder.current_task()
        assert task is not None
        await asyncio.wait({task}, timeout=_STEP_TIMEOUT)
        assert task.done()
        with structlog.testing.capture_logs() as captured:
            await recorder.aclose()
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()

    failed = _events(captured, "qemu_output_recorder_failed")
    assert len(failed) == 1
    assert failed[0]["error"] == "reader broke"
    assert recorder.current_task() is None
    assert recorder.termination is None


@pytest.mark.asyncio
async def test_monitor_that_refuses_the_status_query_fails_the_start() -> None:
    """A monitor that connects but will not report the machine status is reported as a failed status check."""
    async with _serving(_RefusingStatusMonitor()) as server:
        sandbox = _R1Sandbox(SandboxConfig(), QEMUConfig(monitor_port=server.port))
        try:
            with (
                structlog.testing.capture_logs() as captured,
                pytest.raises(SandboxError, match="VM status query failed"),
            ):
                await sandbox.connect_and_verify_qmp()
        finally:
            monitor = sandbox.peek_qmp()
            if monitor is not None:
                await monitor.disconnect()

    failed = _events(captured, "vm_status_query_failed")
    assert [record["error"] for record in failed] == ["The command query-status has not been found"]
    assert server.commands == ["qmp_capabilities", "query-status"]


@pytest.mark.asyncio
async def test_bootstrap_watch_keeps_polling_until_a_guest_channel_exists() -> None:
    """With no channel yet the watch asks nothing, and it reports the launcher's exit once a channel appears."""
    async with _serving(GuestAgentProtocolServer()) as server:
        client = QemuGuestAgentClient(port=server.port)
        sandbox = _R1Sandbox(SandboxConfig(), QEMUConfig(guest_os=GuestOS.WINDOWS))
        watcher: asyncio.Task[str] | None = None
        try:
            assert await client.connect(time_limit=_STEP_TIMEOUT)
            watcher = asyncio.ensure_future(sandbox.await_bootstrap_death(_STATUS_POLL_PID))
            await asyncio.sleep(_GUEST_COMMAND_POLL_INTERVAL * 2.5)
            polled_without_channel = list(server.exec_status_pids)
            sandbox.set_qga(client)

            description = await asyncio.wait_for(watcher, timeout=_STEP_TIMEOUT)
        finally:
            if watcher is not None and not watcher.done():
                watcher.cancel()
            await client.disconnect()

    assert polled_without_channel == []
    assert server.exec_status_pids == [_STATUS_POLL_PID]
    assert "exited 0" in description


@pytest.mark.asyncio
async def test_a_share_that_cannot_be_staged_is_skipped_and_the_next_one_is_still_staged(tmp_path: Path) -> None:
    """A configured folder whose staged copy is blocked is logged and left out; the following folder is staged.

    Args:
        tmp_path: Scratch directory.
    """
    shared = tmp_path / "work" / "shared"
    shared.mkdir(parents=True)
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "payload.txt").write_text("fresh", encoding="utf-8")
    unblocked = tmp_path / "unblocked"
    unblocked.mkdir()
    (unblocked / "data.txt").write_text("open data", encoding="utf-8")
    stale_dir = shared / _CONFIGURED_SHARE_DIR_NAME / "blocked"
    stale_dir.mkdir(parents=True)
    stale = stale_dir / "payload.txt"
    stale.write_text("stale", encoding="utf-8")
    stale.chmod(stat.S_IREAD)
    config = SandboxConfig(shared_folders=[(blocked, "/guest/a", False), (unblocked, "/guest/b", False)])
    sandbox = _R1Sandbox(config, QEMUConfig())
    sandbox.set_shared_folder(shared)
    staged_name = shared / _CONFIGURED_SHARE_DIR_NAME / "unblocked"
    try:
        with structlog.testing.capture_logs() as captured:
            staged = await sandbox.stage_configured_shares()

        assert staged == [staged_name]
        assert (staged_name / "data.txt").read_text(encoding="utf-8") == "open data"
        assert stale.read_text(encoding="utf-8") == "stale"
    finally:
        stale.chmod(stat.S_IREAD | stat.S_IWRITE)
        if staged_name.is_junction():
            staged_name.rmdir()

    skipped = _events(captured, "configured_share_not_staged")
    assert [record["shared_folder"] for record in skipped] == [str(blocked)]


def test_junction_whose_command_line_the_system_refuses_is_reported_as_not_created(tmp_path: Path) -> None:
    """When the shell command cannot even be started the helper reports failure and logs the operating-system error.

    Args:
        tmp_path: Scratch directory.
    """
    source = tmp_path / "source"
    source.mkdir()
    destination = Path("x" * 40000)

    with structlog.testing.capture_logs() as captured:
        created = _R1Sandbox.make_junction(source, destination)

    assert created is False
    failed = _events(captured, "configured_share_junction_failed")
    assert len(failed) == 1
    assert failed[0]["shared_folder"] == str(source)
    assert failed[0]["error"]
    assert "returncode" not in failed[0]


@pytest.mark.spawns_process
@pytest.mark.parametrize(
    ("printed", "expected"),
    [("False", False), ("True", True)],
    ids=["false", "true"],
)
def test_hypervisor_probe_reads_the_printed_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    printed: str,
    *,
    expected: bool,
) -> None:
    """Whatever boolean the query prints is the answer, including a hypervisor that is not running.

    Args:
        tmp_path: Directory holding the stand-in ``pwsh``.
        monkeypatch: Used to confine ``PATH``.
        printed: What the stand-in query prints.
        expected: The probe's answer.
    """
    _install_tools(tmp_path, {"pwsh.cmd": printed})
    _confine_path(monkeypatch, tmp_path)

    assert _R1Sandbox.hypervisor_present_unelevated() is expected


@pytest.mark.spawns_process
def test_hypervisor_probe_that_prints_no_boolean_cannot_answer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Output that is neither ``true`` nor ``false`` leaves the question unanswered and is logged.

    Args:
        tmp_path: Directory holding the stand-in ``pwsh``.
        monkeypatch: Used to confine ``PATH``.
    """
    _install_tools(tmp_path, {"pwsh.cmd": "Not A Boolean"})
    _confine_path(monkeypatch, tmp_path)

    with structlog.testing.capture_logs() as captured:
        answer = _R1Sandbox.hypervisor_present_unelevated()

    assert answer is None
    assert [record["output"] for record in _events(captured, "whpx_hypervisor_present_unparsable")] == ["not a boolean"]


@pytest.mark.spawns_process
def test_hypervisor_probe_with_an_unlaunchable_shell_cannot_answer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A PowerShell the operating system refuses to start leaves the question unanswered and is logged.

    Args:
        tmp_path: Directory holding the unlaunchable ``pwsh``.
        monkeypatch: Used to confine ``PATH``.
    """
    _install_tools(tmp_path, {"pwsh.exe": ""})
    _confine_path(monkeypatch, tmp_path)

    with structlog.testing.capture_logs() as captured:
        answer = _R1Sandbox.hypervisor_present_unelevated()

    assert answer is None
    assert len(_events(captured, "whpx_hypervisor_present_probe_failed")) == 1


@pytest.mark.spawns_process
@pytest.mark.parametrize(
    ("tools", "expected", "event"),
    [
        ({"pwsh.cmd": "False"}, False, "whpx_hypervisor_not_running"),
        ({"pwsh.cmd": "Disabled"}, False, "whpx_hypervisor_platform_not_enabled"),
        ({"pwsh.exe": ""}, False, "whpx_feature_probe_failed"),
        ({"pwsh.cmd": "Enabled"}, False, "whpx_probe_no_bcdedit"),
        (
            {"pwsh.cmd": "Enabled", "bcdedit.cmd": "hypervisorlaunchtype    Off"},
            False,
            "whpx_bcdedit_hypervisorlaunchtype_not_auto",
        ),
        ({"pwsh.cmd": "Enabled", "bcdedit.exe": ""}, False, "whpx_bcdedit_probe_failed"),
        (
            {"pwsh.cmd": "Enabled", "bcdedit.cmd": "hypervisorlaunchtype    Auto"},
            True,
            "whpx_host_prerequisites_satisfied",
        ),
    ],
    ids=[
        "hypervisor-not-running",
        "feature-disabled",
        "shell-unlaunchable",
        "no-bcdedit",
        "launch-type-off",
        "bcdedit-unlaunchable",
        "everything-satisfied",
    ],
)
def test_whpx_prerequisites_follow_the_fallback_probes_when_the_flag_is_unreadable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tools: dict[str, str],
    event: str,
    *,
    expected: bool,
) -> None:
    """Each stage of the fallback decides the verdict and logs which stage decided it.

    Args:
        tmp_path: Directory holding the stand-in host tools.
        monkeypatch: Used to confine ``PATH``.
        tools: Stand-in tools to install.
        event: The log event naming the stage that decided.
        expected: The verdict.
    """
    _install_tools(tmp_path, tools)
    _confine_path(monkeypatch, tmp_path)

    with structlog.testing.capture_logs() as captured:
        verdict = _R1Sandbox.probe_whpx_prerequisites()

    assert verdict is expected
    assert len(_events(captured, event)) == 1


@pytest.mark.spawns_process
@pytest.mark.parametrize(
    ("printed", "expected"),
    [
        ("hypervisorlaunchtype    Auto", True),
        ("hypervisorlaunchtype  Auto", True),
        ("hypervisorlaunchtype    Off", False),
    ],
    ids=["four-spaces-auto", "two-spaces-auto", "off"],
)
def test_bcdedit_launch_type_is_auto_only_when_it_says_auto(tmp_path: Path, printed: str, *, expected: bool) -> None:
    """The launch-type check accepts the two column layouts of ``auto`` and rejects any other value.

    Args:
        tmp_path: Directory holding the stand-in ``bcdedit``.
        printed: What the stand-in prints.
        expected: The verdict.
    """
    bcdedit = _write_batch(tmp_path / "bcdedit.cmd", [f"echo {printed}"])

    assert _R1Sandbox.bcdedit_reports_auto(str(bcdedit)) is expected


@pytest.mark.asyncio
@pytest.mark.spawns_process
@pytest.mark.parametrize(
    ("emulator_lines", "expected"),
    [
        (["exit /b 0"], AcceleratorType.WHPX),
        (["echo qemu: whpx: failed to initialize 1>&2", "exit /b 1"], None),
    ],
    ids=["smoke-test-passes", "smoke-test-names-whpx-in-its-failure"],
)
async def test_whpx_smoke_test_decides_whether_the_accelerator_is_usable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    emulator_lines: list[str],
    expected: AcceleratorType | None,
) -> None:
    """With the host prerequisites met, a clean smoke test accepts WHPX and one that blames WHPX rejects it.

    Args:
        tmp_path: Directory holding the stand-in tools.
        monkeypatch: Used to confine ``PATH``.
        emulator_lines: Batch statements of the stand-in emulator.
        expected: The probe's answer.
    """
    _install_tools(tmp_path, {"pwsh.cmd": "True"})
    emulator = _write_batch(tmp_path / "qemu-system-x86_64.cmd", emulator_lines)
    _confine_path(monkeypatch, tmp_path)
    sandbox = _R1Sandbox(SandboxConfig(), QEMUConfig())
    sandbox.set_qemu_path(emulator)

    assert await sandbox.try_whpx(ProcessManager.get_instance(), "accelerators: whpx") == expected


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_detection_returns_whpx_as_soon_as_it_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An emulator that advertises WHPX and passes its smoke test on a capable host is detected as WHPX.

    Args:
        tmp_path: Directory holding the stand-in tools.
        monkeypatch: Used to confine ``PATH``.
    """
    _install_tools(tmp_path, {"pwsh.cmd": "True"})
    emulator = _write_batch(tmp_path / "qemu-system-x86_64.cmd", ["echo accelerators: whpx", "exit /b 0"])
    _confine_path(monkeypatch, tmp_path)
    sandbox = _R1Sandbox(SandboxConfig(), QEMUConfig())
    sandbox.set_qemu_path(emulator)

    assert await sandbox.detect_accelerator() == AcceleratorType.WHPX


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_overlay_is_a_real_qcow2_backed_by_the_untouched_base_image(tmp_path: Path) -> None:
    """The overlay qemu-img builds reports the base image as its backing file and the base is not modified.

    Args:
        tmp_path: Scratch directory.
    """
    base = tmp_path / "base.qcow2"
    _run_qemu_img(["create", "-f", "qcow2", str(base), str(_BASE_IMAGE_SIZE)])
    base_before = base.read_bytes()
    work = tmp_path / "work"
    work.mkdir()
    sandbox = _R1Sandbox(SandboxConfig(), QEMUConfig(guest_os=GuestOS.WINDOWS))
    sandbox.set_qemu_path(_qemu_directory() / _QEMU_EXE_NAME)
    sandbox.set_temp_dir(work)

    with structlog.testing.capture_logs() as captured:
        overlay = await sandbox.create_disk_overlay(base)

    assert overlay == work / "disk-overlay.qcow2"
    assert overlay.is_file()
    info = json.loads(_run_qemu_img(["info", "--output=json", str(overlay)]).stdout)
    assert info["format"] == "qcow2"
    assert info["backing-filename-format"] == "qcow2"
    assert Path(info["backing-filename"]) == base.resolve()
    assert info["virtual-size"] == _BASE_IMAGE_SIZE
    assert base.read_bytes() == base_before
    created = _events(captured, "disk_overlay_created")
    assert [(record["backing_image"], record["overlay"]) for record in created] == [(str(base), str(overlay))]


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_overlay_over_a_missing_base_image_is_refused_with_qemu_imgs_complaint(tmp_path: Path) -> None:
    """When qemu-img cannot build the overlay the error carries its own explanation and no overlay is left.

    Args:
        tmp_path: Scratch directory.
    """
    prefix = "could not create the per-instance disk overlay"
    work = tmp_path / "work"
    work.mkdir()
    sandbox = _R1Sandbox(SandboxConfig(), QEMUConfig(guest_os=GuestOS.WINDOWS))
    sandbox.set_qemu_path(_qemu_directory() / _QEMU_EXE_NAME)
    sandbox.set_temp_dir(work)

    with (
        structlog.testing.capture_logs() as captured,
        pytest.raises(SandboxError) as excinfo,
    ):
        await sandbox.create_disk_overlay(tmp_path / "absent.qcow2")

    message = str(excinfo.value)
    assert message.startswith(f"{prefix}: ")
    detail = message.removeprefix(f"{prefix}: ")
    assert detail
    assert detail != "no output"
    assert not (work / "disk-overlay.qcow2").exists()
    assert [record["error"] for record in _events(captured, "disk_overlay_create_failed")] == [detail]


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_launcher_that_exits_cleanly_at_once_is_still_a_failed_launch(tmp_path: Path) -> None:
    """A foreground emulator that exits with status zero straight away did not leave a running guest.

    Args:
        tmp_path: Scratch directory.
    """
    launcher = _write_batch(tmp_path / "qemu-exits.cmd", ["exit /b 0"])
    sandbox = _launchable(tmp_path, launcher)
    try:
        with (
            structlog.testing.capture_logs() as captured,
            pytest.raises(SandboxError, match="QEMU exited immediately after launch"),
        ):
            await sandbox.spawn()
    finally:
        await sandbox.cleanup()

    assert sandbox.process is None
    exited = _events(captured, "qemu_exited_immediately")
    assert [record["returncode"] for record in exited] == [0]


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_launcher_that_stays_up_is_kept_as_the_running_guest_and_its_exit_is_recorded(tmp_path: Path) -> None:
    """An emulator still running after the launch grace period is retained and watched by a recorder.

    Args:
        tmp_path: Scratch directory.
    """
    launcher = _write_batch(tmp_path / "qemu-stays.cmd", ["ping -n 120 127.0.0.1 >nul"])
    sandbox = _launchable(tmp_path, launcher)
    try:
        with structlog.testing.capture_logs() as captured:
            await sandbox.spawn()
        process = sandbox.process
        recorder = sandbox.recorder()
        assert process is not None
        assert recorder is not None
        assert process.returncode is None
        assert [record["pid"] for record in _events(captured, "qemu_running_foreground")] == [process.pid]

        _kill_tree(process.pid)
        await asyncio.wait_for(process.wait(), timeout=_STEP_TIMEOUT)
        await wait_until(lambda: recorder.termination is not None, budget=_STEP_TIMEOUT, interval=_POLL_INTERVAL_S)
        termination = recorder.termination
    finally:
        live = sandbox.process
        if live is not None:
            if live.returncode is None:
                _kill_tree(live.pid)
            await live.wait()
        retained = sandbox.recorder()
        if retained is not None:
            await retained.aclose()
        await sandbox.cleanup()

    assert termination is not None
    assert termination.returncode == process.returncode


@pytest.mark.asyncio
async def test_an_unreadable_artifact_is_skipped_and_the_readable_one_is_still_scanned(tmp_path: Path) -> None:
    """A file held open with no sharing is skipped and logged; the other artifact's match is still reported.

    Args:
        tmp_path: Scratch directory.
    """
    shared = tmp_path / "share"
    output_dir = shared / "output"
    output_dir.mkdir(parents=True)
    readable = output_dir / "readable.bin"
    readable.write_bytes(_PACKED_ARTIFACT)
    locked = output_dir / "locked.bin"
    locked.write_bytes(_BENIGN_ARTIFACT)
    sandbox = _R1Sandbox(SandboxConfig(), QEMUConfig(guest_os=GuestOS.WINDOWS))
    sandbox.set_shared_folder(shared)

    with _exclusively_open(locked):
        with pytest.raises(PermissionError):
            locked.read_bytes()
        matches = await sandbox.yara_scan()

    assert {match["rule"] for match in matches} == {"PackedBinary"}
    assert {match["source"] for match in matches} == {str(readable)}
