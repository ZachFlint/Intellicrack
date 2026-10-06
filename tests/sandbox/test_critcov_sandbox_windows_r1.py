# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Second-pass coverage for the Windows Sandbox backend.

Windows Sandbox never starts here. The launcher, session host and Hyper-V worker the backend looks for are
stand-in processes: copies of the host ``cmd.exe`` placed under the file names the backend searches for, so
the backend's real process lookups, launches and teardown run against real operating-system processes. The
guest command channel is the production dispatcher script run under the real ``powershell.exe``; the guest's
own tools (``pktmon``, ``xcopy``, ``powershell``) are batch files on the guest ``PATH``, standing in for the
programs a real sandbox provides. Nothing in the backend itself is replaced.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import os
import re
import shutil
import sys
import tempfile
import time
import zipfile
from typing import TYPE_CHECKING, Any, Final, cast

import pytest
from structlog.testing import capture_logs

import intellicrack.sandbox.windows as windows_module
from intellicrack.core.process_manager import ProcessManager
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen, TimeoutExpired
from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.windows import WindowsSandbox, find_sandbox_session_pid
from tests._helpers.polling import wait_until


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterator, Mapping, Sequence
    from pathlib import Path


pytestmark = [pytest.mark.spawns_process]

_LAUNCHER_EXE: Final[str] = "WindowsSandbox.exe"
_SESSION_EXE: Final[str] = "WindowsSandboxRemoteSession.exe"
_WORKER_EXE: Final[str] = "vmwp.exe"
_CONFIG_NAME: Final[str] = "intellicrack.wsb"
_COMMAND_BUDGET_S: Final[int] = 90
_READY_BUDGET_S: Final[float] = 90.0
_POLL_S: Final[float] = 0.05
_WAIT_BUDGET_S: Final[float] = 120.0
_REAP_BUDGET_S: Final[float] = 30.0
_QUIESCENCE_CEILING_S: Final[float] = 60.0
_NONEXISTENT_PID: Final[int] = 0xFFFFFFFC
_GENERIC_READ: Final[int] = 0x80000000
_OPEN_EXISTING: Final[int] = 3
_PCAP_ID_PATTERN: Final[str] = r"pcap_[0-9a-f]{16}"
_SHOT_PATTERN: Final[str] = r"screenshot_[0-9a-f]{16}\.png"
_ETL_CONTENT: Final[bytes] = b"ETLDATA\r\n"
_PCAP_CONTENT: Final[bytes] = b"PCAPDATA\r\n"
_VERIFY_FAILED: Final[str] = "WMI hijack verification did not return spoofed values"
_GUEST_DIRS: Final[tuple[str, ...]] = (
    r"C:\Users\WDAGUtilityAccount\Downloads",
    r"C:\Users\WDAGUtilityAccount\AppData\Local\Temp",
    r"C:\Windows\Temp",
    r"C:\Users\Public\Downloads",
)

_PKTMON_TEMPLATE: Final[str] = """@echo off
echo %*>>"@LOG@"
if /I "%~1"=="start" goto start
if /I "%~1"=="stop" goto stop
if /I "%~1"=="etl2pcap" goto convert
exit /b 99
:start
echo ETLDATA>"%~4"
exit /b 0
:stop
if exist "@CTRL@\\stop_fails" exit /b 1
exit /b 0
:convert
if exist "@CTRL@\\convert_fails" exit /b 1
echo PCAPDATA>"%~4"
exit /b 0
"""

_XCOPY_TEMPLATE: Final[str] = """@echo off
echo %~6>>"@LOG@"
if /I "%~6"=="C:\\Users\\WDAGUtilityAccount\\Downloads" exit /b 5
if /I "%~6"=="C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Temp" exit /b 2
if /I "%~6"=="C:\\Windows\\Temp" exit /b 1
exit /b 0
"""

_SCREENSHOT_TEMPLATE: Final[str] = """@echo off
:wait
if not exist "@SENTINEL@" goto wait
exit /b 0
"""

_PRINT_TEMPLATE: Final[str] = """@echo off
echo @BODY@
exit /b 0
"""

_minidump_via_dbghelp = cast(
    "Callable[[int, Path], tuple[bool, str]]",
    getattr(windows_module, "_minidump_via_dbghelp"),
)


class _Exposed(WindowsSandbox):
    """WindowsSandbox with its private state and steps reachable from tests."""

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Create the backend with a bounded command budget.

        Args:
            config: Optional configuration; a bounded command timeout is used when omitted.
        """
        super().__init__(config or SandboxConfig(timeout_seconds=_COMMAND_BUDGET_S))

    def bind(self, shared: Path, *, running: bool) -> None:
        """Point the backend at a host directory standing in for the guest's shared folder.

        Args:
            shared: Directory the guest dispatcher watches.
            running: Whether the backend should report ``running``.
        """
        self.SANDBOX_SHARED_PATH = str(shared)
        self._shared_folder = shared
        self.state.status = "running" if running else "stopped"

    def use_wsb_path(self, path: Path | None) -> None:
        """Record the ``.wsb`` configuration path.

        Args:
            path: Configuration path, or None.
        """
        self._wsb_path = path

    def wsb_path(self) -> Path | None:
        """Return the ``.wsb`` configuration path.

        Returns:
            Path | None: The recorded configuration path.
        """
        return self._wsb_path

    def session_pid(self) -> int | None:
        """Return the bound session host.

        Returns:
            int | None: The session process id.
        """
        return self._session_pid

    def use_session_pid(self, pid: int | None) -> None:
        """Record a session host.

        Args:
            pid: Session process id, or None.
        """
        self._session_pid = pid

    def worker_pid(self) -> int | None:
        """Return the tracked worker.

        Returns:
            int | None: The worker process id.
        """
        return self._worker_pid

    def shared_folder(self) -> Path:
        """Return the bound shared folder.

        Returns:
            Path: The shared folder.
        """
        assert self._shared_folder is not None
        return self._shared_folder

    def dispatcher_source(self) -> str:
        """Return the dispatcher script the backend would stage.

        Returns:
            str: The generated PowerShell source.
        """
        return self._dispatcher_ps1_source()

    def ready_flag_path(self) -> Path:
        """Return the flag the dispatcher writes when it comes up.

        Returns:
            Path: Host path of the readiness flag.
        """
        return self.shared_folder() / "flags" / self.DISPATCHER_READY_MARKER

    async def prepare_shared_folders(self) -> None:
        """Forward to :meth:`WindowsSandbox._prepare_shared_folders`."""
        await self._prepare_shared_folders()

    async def launch_sandbox_process(self) -> None:
        """Forward to :meth:`WindowsSandbox._launch_sandbox_process`."""
        await self._launch_sandbox_process()

    async def bind_sandbox_session(self) -> None:
        """Forward to :meth:`WindowsSandbox._bind_sandbox_session`."""
        await self._bind_sandbox_session()

    async def resolve_worker_pid(self) -> int | None:
        """Forward to :meth:`WindowsSandbox._resolve_worker_pid`.

        Returns:
            int | None: The worker process id, or None.
        """
        return await self._resolve_worker_pid()

    async def abort_client(self) -> None:
        """Forward to :meth:`WindowsSandbox._abort_client`."""
        await self._abort_client()

    async def terminate_client(self) -> None:
        """Forward to :meth:`WindowsSandbox._terminate_sandbox_client`."""
        await self._terminate_sandbox_client(ProcessManager.get_instance())

    async def run_cleanup(self) -> None:
        """Forward to :meth:`WindowsSandbox._cleanup`."""
        await self._cleanup()

    async def apply_telemetry_blocking(self) -> None:
        """Forward to :meth:`WindowsSandbox._apply_telemetry_blocking`."""
        await self._apply_telemetry_blocking()

    async def wait_for_monitor_quiescence(self) -> None:
        """Forward to :meth:`WindowsSandbox._wait_for_monitor_quiescence`."""
        await self._wait_for_monitor_quiescence()

    async def query_wmi_identity(self) -> dict[str, str]:
        """Forward to :meth:`WindowsSandbox._query_wmi_identity`.

        Returns:
            dict[str, str]: The identity the guest reported.
        """
        return await self._query_wmi_identity()

    async def minidump_via_procdump(self, pid: int, dump_path: Path) -> bool:
        """Forward to :meth:`WindowsSandbox._minidump_via_procdump`.

        Args:
            pid: Process to dump.
            dump_path: Destination dump path.

        Returns:
            bool: Whether a dump file was produced.
        """
        return await self._minidump_via_procdump(pid, dump_path)


@pytest.fixture
def children() -> Iterator[list[Popen[bytes]]]:
    """Kill and reap every process a test started, however it ended.

    Yields:
        list[Popen[bytes]]: Registry of processes to reap on teardown.
    """
    started: list[Popen[bytes]] = []
    try:
        yield started
    finally:
        for process in started:
            if process.poll() is None:
                process.kill()
            process.wait()
            if process.stdin is not None:
                process.stdin.close()


@pytest.fixture
def temp_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the standard-library temporary directory at a folder under ``tmp_path``.

    Args:
        tmp_path: Pytest scratch directory.
        monkeypatch: Restores the setting afterwards.

    Returns:
        Path: The directory ``tempfile.mkdtemp`` now creates its directories in.
    """
    root = tmp_path / "temp_root"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


def _cmd_exe() -> str:
    """Locate the host ``cmd.exe``.

    Returns:
        str: Path of ``cmd.exe``.
    """
    found = shutil.which("cmd.exe")
    assert found is not None, "cmd.exe is required to build the stand-in processes"
    return found


def _install_exe(directory: Path, name: str) -> Path:
    """Place a copy of the host ``cmd.exe`` in ``directory`` under ``name``.

    Args:
        directory: Destination directory.
        name: File name to give the copy.

    Returns:
        Path: Path of the copy.
    """
    target = directory / name
    shutil.copy2(_cmd_exe(), target)
    return target


def _prepend_path(monkeypatch: pytest.MonkeyPatch, directory: Path) -> None:
    """Put ``directory`` first on ``PATH``.

    Args:
        monkeypatch: Restores ``PATH`` afterwards.
        directory: Directory to search first.
    """
    monkeypatch.setenv("PATH", f"{directory}{os.pathsep}{os.environ['PATH']}")


def _start_blocker(exe: Path, tag: str, children: list[Popen[bytes]]) -> Popen[bytes]:
    """Start a copy of ``cmd.exe`` that waits on stdin with ``tag`` in its command line.

    Args:
        exe: The copy to run.
        tag: Text that appears in the process command line.
        children: Registry that reaps the process on teardown.

    Returns:
        Popen[bytes]: The running process.
    """
    process = Popen([str(exe), "/c", "set", "/p", f"IC={tag}"], stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL)
    children.append(process)
    return process


def _start_python(code: str, children: list[Popen[bytes]]) -> Popen[bytes]:
    """Start a real Python child running ``code`` with a pipe for stdin.

    Args:
        code: Source passed to ``python -c``.
        children: Registry that reaps the process on teardown.

    Returns:
        Popen[bytes]: The started child.
    """
    process = Popen([sys.executable, "-c", code], stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL)
    children.append(process)
    return process


def _events(captured: Sequence[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    """Select the captured log records with a given event name.

    Args:
        captured: Records collected by ``capture_logs``.
        name: Event name to select.

    Returns:
        list[Mapping[str, Any]]: Matching records in order.
    """
    return [entry for entry in captured if entry.get("event") == name]


def _plant_unrunnable_taskkill(directory: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make a program started as ``taskkill`` fail to start, by shadowing it in the working directory.

    The working directory is searched before the system directory when a program is started by name, and a
    file that is not an executable image makes the start fail with an operating-system error.

    Args:
        directory: Directory to become the working directory.
        monkeypatch: Restores the working directory afterwards.
    """
    (directory / "taskkill.exe").write_text("not a program", encoding="ascii")
    monkeypatch.chdir(directory)


@contextlib.contextmanager
def _guest(root: Path, tools: Mapping[str, str] | None = None) -> Generator[_Exposed]:
    """Run the production dispatcher script as the guest of a sandbox bound to ``root``.

    The guest ``PATH`` holds only a copy of ``cmd.exe`` and the batch files given in ``tools``.

    Args:
        root: Scratch directory for the share, the guest ``PATH`` directory and the dispatcher script.
        tools: Guest tool file names mapped to their batch source.

    Yields:
        _Exposed: A running sandbox whose dispatcher is polling.
    """
    powershell = shutil.which("powershell.exe")
    assert powershell is not None, "this test needs the real powershell.exe to run the dispatcher"
    share = root / "IntellicrackShared"
    share.mkdir()
    guest_bin = root / "guest_bin"
    guest_bin.mkdir()
    shutil.copy2(_cmd_exe(), guest_bin / "cmd.exe")
    for name, body in (tools or {}).items():
        (guest_bin / name).write_text(body, encoding="ascii", newline="\r\n")
    sandbox = _Exposed()
    sandbox.bind(share, running=True)
    environment = dict(os.environ)
    environment["PATH"] = str(guest_bin)
    script = root / "dispatcher.ps1"
    script.write_text(sandbox.dispatcher_source(), encoding="utf-8")
    process = Popen(
        [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        stdin=DEVNULL,
        stdout=DEVNULL,
        stderr=DEVNULL,
        env=environment,
    )
    try:
        deadline = time.monotonic() + _READY_BUDGET_S
        while time.monotonic() < deadline and not sandbox.ready_flag_path().is_file():
            if process.poll() is not None:
                pytest.fail("the dispatcher exited before signalling ready")
            time.sleep(0.25)
        assert sandbox.ready_flag_path().is_file(), "the real dispatcher never signalled ready"
        yield sandbox
    finally:
        process.terminate()
        try:
            process.wait(timeout=_READY_BUDGET_S)
        except TimeoutExpired:
            process.kill()
            process.wait(timeout=_READY_BUDGET_S)


def _trigger_text(shared: Path) -> str:
    """Read every command ticket currently staged under a shared folder.

    Args:
        shared: Host-side shared folder.

    Returns:
        str: The tickets' text joined together; empty when there are none or they cannot be read yet.
    """
    parts: list[str] = []
    for ticket in (shared / "input" / "trigger").glob("*.cmd"):
        with contextlib.suppress(OSError):
            parts.append(ticket.read_text(encoding="utf-8"))
    return "\n".join(parts)


async def _supply_screenshot(shared: Path, sentinel: Path, payload: bytes) -> str:
    """Create the image the guest screenshot command is asked to write, then release the guest tool.

    Args:
        shared: Host-side shared folder.
        sentinel: File the guest tool waits for before it exits.
        payload: Bytes to put in the image file.

    Returns:
        str: File name of the image the staged command names.
    """
    await wait_until(lambda: re.search(_SHOT_PATTERN, _trigger_text(shared)) is not None, budget=_READY_BUDGET_S, interval=0.01)
    return _publish_screenshot(shared, sentinel, payload)


def _publish_screenshot(shared: Path, sentinel: Path, payload: bytes) -> str:
    """Write the staged command's image file, then the sentinel that releases the guest tool.

    Args:
        shared: Host-side shared folder.
        sentinel: File the guest tool waits for before it exits.
        payload: Bytes to put in the image file.

    Returns:
        str: File name of the image the staged command names.
    """
    found = re.search(_SHOT_PATTERN, _trigger_text(shared))
    assert found is not None, "the screenshot command was never staged"
    (shared / "output" / found.group(0)).write_bytes(payload)
    sentinel.write_text("go", encoding="ascii")
    return found.group(0)


def _flags_dirs(temp_root: Path) -> list[Path]:
    """List the flag folders of every sandbox temporary tree under ``temp_root``.

    Args:
        temp_root: Directory the backend's temporary directory is created in.

    Returns:
        list[Path]: The ``flags`` folders that exist.
    """
    return list(temp_root.glob("intellicrack_sandbox_*/IntellicrackShared/flags"))


def _entry_names(directory: Path) -> list[str]:
    """List the names inside a directory.

    Args:
        directory: Directory to list.

    Returns:
        list[str]: Sorted entry names.
    """
    return sorted(entry.name for entry in directory.iterdir())


def _remove_staging_dirs(output_dir: Path) -> None:
    """Delete every extraction staging directory under ``output_dir``.

    Args:
        output_dir: The shared folder's ``output`` directory.
    """
    for staging in output_dir.glob("dropped_*"):
        if staging.is_dir():
            shutil.rmtree(staging)


async def _write_ready_flag_once_prepared(temp_root: Path) -> None:
    """Write the dispatcher readiness flag as soon as the backend has created its folders.

    Args:
        temp_root: Directory the backend's temporary directory is created in.
    """
    await wait_until(lambda: bool(_flags_dirs(temp_root)), budget=_READY_BUDGET_S, interval=_POLL_S)
    _write_ready_marker(_flags_dirs(temp_root)[0])


def _write_ready_marker(flags: Path) -> None:
    """Write the dispatcher readiness marker into a flags folder.

    Args:
        flags: The sandbox's ``flags`` folder.
    """
    (flags / WindowsSandbox.DISPATCHER_READY_MARKER).write_text("ready", encoding="ascii")


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
        raise OSError(ctypes.get_last_error(), "CreateFileW failed")
    try:
        yield
    finally:
        kernel32.CloseHandle(handle)


def test_session_lookup_finds_a_running_session_by_its_config_name(
    tmp_path: Path,
    children: list[Popen[bytes]],
) -> None:
    """A process named like the session host whose command line holds the config name is the session.

    Args:
        tmp_path: Pytest scratch directory.
        children: Fixture that reaps the stand-in session.
    """
    config_name = "intellicrack_critcov_second_pass_lookup.wsb"
    session = _start_blocker(_install_exe(tmp_path, _SESSION_EXE), config_name, children)

    assert find_sandbox_session_pid(config_name) == session.pid


@pytest.mark.asyncio
async def test_bind_registers_the_session_process_found_for_the_config(
    tmp_path: Path,
    children: list[Popen[bytes]],
) -> None:
    """The bind step stores the session pid it found and registers that pid for cleanup tracking.

    Args:
        tmp_path: Pytest scratch directory.
        children: Fixture that reaps the stand-in session.
    """
    config_name = "intellicrack_critcov_second_pass_bind.wsb"
    session = _start_blocker(_install_exe(tmp_path, _SESSION_EXE), config_name, children)
    sandbox = _Exposed()
    sandbox.use_wsb_path(tmp_path / config_name)
    manager = ProcessManager.get_instance()
    try:
        await sandbox.bind_sandbox_session()

        assert sandbox.session_pid() == session.pid
        assert manager.unregister_external_pid(session.pid) is True
    finally:
        manager.unregister_external_pid(session.pid)


@pytest.mark.asyncio
async def test_launch_starts_the_resolved_launcher_and_binds_the_session(
    tmp_path: Path,
    children: list[Popen[bytes]],
    temp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With a launcher on ``PATH`` and a session for the config, the launch runs the launcher and binds.

    Args:
        tmp_path: Pytest scratch directory.
        children: Fixture that reaps the stand-in session.
        temp_root: Fixture redirecting temporary directories under ``tmp_path``.
        monkeypatch: Used to put the stand-in launcher on ``PATH``.
    """
    fake_bin = tmp_path / "fake_bin"
    fake_bin.mkdir()
    _install_exe(fake_bin, _LAUNCHER_EXE)
    session = _start_blocker(_install_exe(fake_bin, _SESSION_EXE), _CONFIG_NAME, children)
    _prepend_path(monkeypatch, fake_bin)
    sandbox = _Exposed()
    manager = ProcessManager.get_instance()
    try:
        await sandbox.prepare_shared_folders()
        await sandbox.launch_sandbox_process()

        launcher = sandbox.process
        assert launcher is not None
        wsb_path = sandbox.wsb_path()
        assert wsb_path is not None
        assert cast("list[str]", launcher.args) == [_LAUNCHER_EXE, str(wsb_path)]
        assert wsb_path.is_file()
        assert sandbox.session_pid() == session.pid
    finally:
        if sandbox.process is not None:
            sandbox.process.kill()
            sandbox.process.wait()
            manager.unregister(sandbox.process.pid)
        manager.unregister_external_pid(session.pid)
        await sandbox.run_cleanup()
    assert _entry_names(temp_root) == []


@pytest.mark.slow
@pytest.mark.asyncio
async def test_a_full_start_attaches_the_worker_and_a_stop_ends_the_session(
    tmp_path: Path,
    children: list[Popen[bytes]],
    temp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A start with stand-in launcher, session and worker reaches running; a stop removes it all.

    Args:
        tmp_path: Pytest scratch directory.
        children: Fixture that reaps the stand-in processes.
        temp_root: Fixture redirecting temporary directories under ``tmp_path``.
        monkeypatch: Used to put the stand-in launcher on ``PATH``.
    """
    fake_bin = tmp_path / "fake_bin"
    fake_bin.mkdir()
    _install_exe(fake_bin, _LAUNCHER_EXE)
    session = _start_blocker(_install_exe(fake_bin, _SESSION_EXE), _CONFIG_NAME, children)
    worker = _start_blocker(_install_exe(fake_bin, _WORKER_EXE), "worker", children)
    _prepend_path(monkeypatch, fake_bin)
    sandbox = _Exposed(SandboxConfig(timeout_seconds=_COMMAND_BUDGET_S, block_telemetry=False))
    manager = ProcessManager.get_instance()
    try:
        await asyncio.gather(sandbox.start(), _write_ready_flag_once_prepared(temp_root))

        assert sandbox.state.status == "running"
        assert sandbox.state.pid == session.pid
        assert sandbox.session_pid() == session.pid
        assert sandbox.worker_pid() == worker.pid
        assert manager.unregister_external_pid(worker.pid) is True
        worker.kill()
        worker.wait()

        await sandbox.stop()

        assert sandbox.state.status == "stopped"
        assert sandbox.process is None
        assert session.wait(timeout=_REAP_BUDGET_S) is not None
    finally:
        manager.unregister_external_pid(session.pid)
        manager.unregister_external_pid(worker.pid)
        if sandbox.state.status != "stopped":
            await sandbox.stop()
    assert _entry_names(temp_root) == []


@pytest.mark.slow
@pytest.mark.asyncio
async def test_the_worker_lookup_keeps_polling_after_its_query_cannot_start(
    tmp_path: Path,
    children: list[Popen[bytes]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A PowerShell that cannot be started is logged and retried, and the worker is found once it can.

    Args:
        tmp_path: Pytest scratch directory.
        children: Fixture that reaps the stand-in worker.
        monkeypatch: Used to empty ``PATH`` and then restore it.
    """
    fake_bin = tmp_path / "fake_bin"
    fake_bin.mkdir()
    worker = _start_blocker(_install_exe(fake_bin, _WORKER_EXE), "worker", children)
    original_path = os.environ["PATH"]
    empty = tmp_path / "empty_path"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    with capture_logs() as captured:
        lookup = asyncio.create_task(_Exposed().resolve_worker_pid())
        try:
            await wait_until(lambda: bool(_events(captured, "vmwp_lookup_error")), budget=_READY_BUDGET_S, interval=_POLL_S)
            monkeypatch.setenv("PATH", original_path)
            found = await asyncio.wait_for(lookup, timeout=_WAIT_BUDGET_S)
        finally:
            if not lookup.done():
                lookup.cancel()
                await asyncio.gather(lookup, return_exceptions=True)

    assert _events(captured, "vmwp_lookup_error"), "the failed PowerShell start was not logged"
    assert found == worker.pid


@pytest.mark.asyncio
async def test_abort_client_force_kills_after_a_wait_timeout_when_taskkill_cannot_run(
    tmp_path: Path,
    children: list[Popen[bytes]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When neither taskkill call can start, the client survives the wait and is killed directly.

    Args:
        tmp_path: Pytest scratch directory.
        children: Fixture that reaps the client.
        monkeypatch: Used to shadow ``taskkill`` in the working directory.
    """
    client = _start_python("import sys\nsys.stdin.read()\n", children)
    _plant_unrunnable_taskkill(tmp_path, monkeypatch)
    sandbox = _Exposed()
    sandbox.process = client

    with capture_logs() as captured:
        await asyncio.wait_for(sandbox.abort_client(), timeout=_WAIT_BUDGET_S)

    assert len(_events(captured, "client_taskkill_failed_trying_image_name")) == 1
    assert len(_events(captured, "client_taskkill_fallback_failed")) == 1
    timeouts = _events(captured, "sandbox_client_abort_wait_timeout")
    assert [entry.get("pid") for entry in timeouts] == [client.pid]
    assert sandbox.process is None
    assert client.poll() is not None


@pytest.mark.asyncio
async def test_terminate_client_force_kills_after_a_wait_timeout_when_taskkill_cannot_run(
    tmp_path: Path,
    children: list[Popen[bytes]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A client that outlives both a failed graceful close and a failed taskkill is killed directly.

    Args:
        tmp_path: Pytest scratch directory.
        children: Fixture that reaps the client.
        monkeypatch: Used to shadow ``taskkill`` in the working directory.
    """
    client = _start_python("import sys\nsys.stdin.read()\n", children)
    _plant_unrunnable_taskkill(tmp_path, monkeypatch)
    sandbox = _Exposed()
    sandbox.process = client

    with capture_logs() as captured:
        await asyncio.wait_for(sandbox.terminate_client(), timeout=_WAIT_BUDGET_S)

    timeouts = _events(captured, "sandbox_process_terminate_timeout")
    assert [entry.get("pid") for entry in timeouts] == [client.pid]
    assert sandbox.process is None
    assert client.poll() is not None


@pytest.mark.asyncio
async def test_telemetry_blocking_that_the_guest_cannot_run_is_reported_as_incomplete(tmp_path: Path) -> None:
    """A guest without PowerShell exits non-zero, and the pass is logged as incomplete, not applied.

    Args:
        tmp_path: Pytest scratch directory.
    """
    with _guest(tmp_path) as sandbox, capture_logs() as captured:
        await sandbox.apply_telemetry_blocking()

    incomplete = _events(captured, "telemetry_blocking_incomplete")
    assert len(incomplete) == 1
    assert incomplete[0].get("log_level") == "warning"
    assert incomplete[0].get("exit_code") != 0
    assert not _events(captured, "telemetry_blocking_applied")


@pytest.mark.slow
@pytest.mark.asyncio
async def test_quiescence_reports_the_ceiling_when_collectors_keep_arriving_but_one_never_does(tmp_path: Path) -> None:
    """Arrivals spaced inside the settle window keep the wait going until the ceiling, naming the silent one.

    Args:
        tmp_path: Pytest scratch directory.
    """
    logs = tmp_path / "logs"
    logs.mkdir()
    stems = ["alpha", "bravo", "charlie", "delta", "echo"]
    (logs / "monitors.pids").write_text("\n".join(f"{100 + index} {stem}.ps1" for index, stem in enumerate(stems)), encoding="utf-8")
    sandbox = _Exposed()
    sandbox.bind(tmp_path, running=False)

    async def arrive() -> None:
        """Create the survivors' logs 10, 25, 40 and 55 seconds in; ``delta`` never reports."""
        for delay, stem in ((10, "alpha"), (15, "bravo"), (15, "charlie"), (15, "echo")):
            await asyncio.sleep(delay)
            (logs / f"{stem}.log").write_text("record", encoding="utf-8")

    with capture_logs() as captured:
        started = time.monotonic()
        await asyncio.gather(sandbox.wait_for_monitor_quiescence(), arrive())
        elapsed = time.monotonic() - started

    reached = _events(captured, "monitor_quiescence_ceiling_reached")
    assert len(reached) == 1
    assert reached[0].get("silent") == ["delta"]
    assert reached[0].get("waited") == _QUIESCENCE_CEILING_S
    assert elapsed >= _QUIESCENCE_CEILING_S - 1.0
    assert not _events(captured, "monitor_quiescence_settled_with_silent_collectors")


@pytest.mark.asyncio
async def test_pcap_capture_starts_and_stops_with_a_converted_file(tmp_path: Path) -> None:
    """Start and stop run the guest packet-capture commands and return the converted file.

    The first capture is saved to a requested path, the second is returned from the shared folder.

    Args:
        tmp_path: Pytest scratch directory.
    """
    log = tmp_path / "pktmon.log"
    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    tool = _PKTMON_TEMPLATE.replace("@LOG@", str(log)).replace("@CTRL@", str(ctrl))
    saved = tmp_path / "saved" / "trace.pcap"
    root = tmp_path / "guest"
    root.mkdir()
    with _guest(root, {"pktmon.cmd": tool}) as sandbox:
        shared = sandbox.shared_folder()
        first = await sandbox.start_pcap_capture()
        assert re.fullmatch(_PCAP_ID_PATTERN, first)
        assert (shared / "output" / f"{first}.etl").read_bytes() == _ETL_CONTENT
        returned = await sandbox.stop_pcap_capture(first, saved)
        second = await sandbox.start_pcap_capture()
        unsaved = await sandbox.stop_pcap_capture(second)

    assert second != first
    assert returned == saved
    assert saved.read_bytes() == _PCAP_CONTENT
    assert unsaved == shared / "output" / f"{second}.pcap"
    assert unsaved.read_bytes() == _PCAP_CONTENT
    lines = log.read_text(encoding="ascii", errors="replace").splitlines()
    etl = f"{shared}\\output\\{first}.etl"
    pcap = f"{shared}\\output\\{first}.pcap"
    assert lines[0] == f'start --capture --file-name "{etl}" --log-mode real-time'
    assert lines[1] == "stop"
    assert lines[2] == f'etl2pcap "{etl}" --out "{pcap}"'


@pytest.mark.asyncio
async def test_pcap_stop_falls_back_to_the_etl_when_conversion_fails_and_fails_when_the_stop_fails(tmp_path: Path) -> None:
    """A failed conversion returns the raw trace; a failed stop is an error and leaves the capture active.

    Args:
        tmp_path: Pytest scratch directory.
    """
    log = tmp_path / "pktmon.log"
    ctrl = tmp_path / "ctrl"
    ctrl.mkdir()
    tool = _PKTMON_TEMPLATE.replace("@LOG@", str(log)).replace("@CTRL@", str(ctrl))
    root = tmp_path / "guest"
    root.mkdir()
    with _guest(root, {"pktmon.cmd": tool}) as sandbox, capture_logs() as captured:
        shared = sandbox.shared_folder()
        capture = await sandbox.start_pcap_capture()
        (ctrl / "convert_fails").write_text("x", encoding="ascii")
        fallback = await sandbox.stop_pcap_capture(capture)
        (ctrl / "convert_fails").unlink()
        (ctrl / "stop_fails").write_text("x", encoding="ascii")
        second = await sandbox.start_pcap_capture()
        with pytest.raises(SandboxError) as stop_failure:
            await sandbox.stop_pcap_capture(second)
        (ctrl / "stop_fails").unlink()
        recovered = await sandbox.stop_pcap_capture(second)

    assert fallback == shared / "output" / f"{capture}.etl"
    assert fallback.read_bytes() == _ETL_CONTENT
    assert len(_events(captured, "pcap_etl2pcap_failed_returning_etl")) == 1
    assert str(stop_failure.value) == "Packet capture stop failed"
    assert len(_events(captured, "pcap_stop_failed")) == 1
    assert recovered == shared / "output" / f"{second}.pcap"


@pytest.mark.asyncio
async def test_pcap_start_fails_when_the_guest_has_no_pktmon(tmp_path: Path) -> None:
    """A guest that cannot run the capture tool makes the start fail with the start error.

    Args:
        tmp_path: Pytest scratch directory.
    """
    with _guest(tmp_path) as sandbox, capture_logs() as captured:
        with pytest.raises(SandboxError) as excinfo:
            await sandbox.start_pcap_capture()
        output = sandbox.shared_folder() / "output"

        assert not list(output.glob("pcap_*"))

    assert str(excinfo.value) == "Packet capture start failed"
    assert len(_events(captured, "pcap_start_failed")) == 1


@pytest.mark.asyncio
async def test_screenshot_returns_the_guest_image_and_copies_it_when_asked(tmp_path: Path) -> None:
    """After the guest command succeeds the image path is returned, or the image is copied to the target.

    Args:
        tmp_path: Pytest scratch directory.
    """
    sentinel = tmp_path / "release.flag"
    tool = _SCREENSHOT_TEMPLATE.replace("@SENTINEL@", str(sentinel))
    payload = b"\x89PNG\r\n\x1a\n" + bytes(range(32))
    target = tmp_path / "saved" / "shot.png"
    root = tmp_path / "guest"
    root.mkdir()
    with _guest(root, {"powershell.cmd": tool}) as sandbox:
        shared = sandbox.shared_folder()
        returned, name = await asyncio.gather(
            sandbox.capture_screenshot(target),
            _supply_screenshot(shared, sentinel, payload),
        )
        in_shared = await sandbox.capture_screenshot()

    assert returned == target
    assert target.read_bytes() == payload
    assert name != in_shared.name
    assert in_shared.parent == shared / "output"
    assert re.fullmatch(_SHOT_PATTERN, in_shared.name)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body", "cause"),
    [("this is not json", ValueError), ("[1, 2]", None)],
    ids=["not-json", "not-an-object"],
)
async def test_the_wmi_identity_query_rejects_output_that_is_not_a_json_object(
    tmp_path: Path,
    body: str,
    cause: type[BaseException] | None,
) -> None:
    """Guest output that is not a JSON object fails verification, with the parse error kept when there is one.

    Args:
        tmp_path: Pytest scratch directory.
        body: What the guest query prints and exits 0 with.
        cause: Exception type expected as the cause, or None when the output parsed.
    """
    tool = _PRINT_TEMPLATE.replace("@BODY@", body)
    root = tmp_path / "guest"
    root.mkdir()
    with _guest(root, {"powershell.cmd": tool}) as sandbox, capture_logs() as captured, pytest.raises(SandboxError) as excinfo:
        await sandbox.query_wmi_identity()

    assert str(excinfo.value) == _VERIFY_FAILED
    if cause is None:
        assert excinfo.value.__cause__ is None
        assert len(_events(captured, "wmi_hijack_verification_unexpected_payload")) == 1
    else:
        assert isinstance(excinfo.value.__cause__, cause)
        assert len(_events(captured, "wmi_hijack_verification_parse_failed")) == 1


def _xcopy_tool(log: Path) -> str:
    """Build the guest ``xcopy`` batch file that answers by source directory.

    Args:
        log: File the tool appends each source directory to.

    Returns:
        str: The batch source.
    """
    return _XCOPY_TEMPLATE.replace("@LOG@", str(log))


@pytest.mark.asyncio
async def test_extraction_continues_through_every_guest_directory_whatever_xcopy_exits_with(tmp_path: Path) -> None:
    """Exit codes 5, 2, 1 and 0 from the copy tool never stop the extraction or end it with an error.

    The log lines each exit code produces are deliberately not asserted here; the red test below holds
    the labeling of those codes.

    Args:
        tmp_path: Pytest scratch directory.
    """
    log = tmp_path / "xcopy.log"
    root = tmp_path / "guest"
    root.mkdir()
    with _guest(root, {"xcopy.cmd": _xcopy_tool(log)}) as sandbox, capture_logs() as captured:
        archive = await sandbox.extract_dropped_files()

    assert log.read_text(encoding="ascii", errors="replace").split() == list(_GUEST_DIRS)
    assert not _events(captured, "xcopy_initialisation_error")
    with zipfile.ZipFile(archive) as opened:
        assert opened.namelist() == []


@pytest.mark.asyncio
async def test_xcopy_exit_codes_are_labeled_by_their_documented_meaning(tmp_path: Path) -> None:
    """Exit 1 means no files were found, and 2 (Ctrl+C) and 5 (disk write error) are unexpected outcomes.

    The documented ``xcopy`` exit codes are 0 success, 1 no files found, 2 terminated by the user, 4
    initialization error and 5 disk write error. The backend treats 1 as silent success, calls 2 "no files
    found" and calls 5 "access denied".

    Args:
        tmp_path: Pytest scratch directory.
    """
    log = tmp_path / "xcopy.log"
    root = tmp_path / "guest"
    root.mkdir()
    with _guest(root, {"xcopy.cmd": _xcopy_tool(log)}) as sandbox, capture_logs() as captured:
        await sandbox.extract_dropped_files()

    no_files = [entry.get("guest_dir") for entry in _events(captured, "xcopy_no_files_found")]
    unexpected = {entry.get("exit_code"): entry.get("guest_dir") for entry in _events(captured, "xcopy_unexpected_exit_code")}
    assert no_files == [r"C:\Windows\Temp"]
    assert unexpected == {2: _GUEST_DIRS[1], 5: _GUEST_DIRS[0]}
    assert not _events(captured, "xcopy_access_denied")


@pytest.mark.asyncio
async def test_extraction_archives_nothing_when_the_staging_directory_vanishes(tmp_path: Path) -> None:
    """A staging directory removed while the guest commands run leaves an empty archive, not an error.

    Args:
        tmp_path: Pytest scratch directory.
    """

    async def remove_staging(output_dir: Path) -> None:
        """Delete the extraction staging directory as soon as it appears.

        Args:
            output_dir: The shared folder's ``output`` directory.
        """
        await wait_until(lambda: any(output_dir.glob("dropped_*")), budget=_READY_BUDGET_S, interval=0.01)
        _remove_staging_dirs(output_dir)

    with _guest(tmp_path) as sandbox:
        output_dir = sandbox.shared_folder() / "output"
        archive, _ = await asyncio.gather(sandbox.extract_dropped_files(), remove_staging(output_dir))

    with zipfile.ZipFile(archive) as opened:
        assert opened.namelist() == []
    assert not [entry for entry in output_dir.glob("dropped_*") if entry.is_dir()]


@pytest.mark.asyncio
async def test_copy_to_sandbox_reports_a_destination_folder_that_cannot_be_created(tmp_path: Path) -> None:
    """A destination folder that cannot be created is a failed copy, like any other copy failure.

    Args:
        tmp_path: Pytest scratch directory.
    """
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "input").write_text("a file where a folder belongs", encoding="utf-8")
    source = tmp_path / "payload.bin"
    source.write_bytes(b"data")
    sandbox = _Exposed()
    sandbox.bind(shared, running=False)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.copy_to_sandbox(source, "input\\payload.bin")

    assert str(excinfo.value) == "Failed to copy file to sandbox"


@pytest.mark.asyncio
async def test_copy_from_sandbox_reports_a_destination_folder_that_cannot_be_created(tmp_path: Path) -> None:
    """A local destination folder that cannot be created is a failed copy, like any other copy failure.

    Args:
        tmp_path: Pytest scratch directory.
    """
    shared = tmp_path / "shared"
    (shared / "output").mkdir(parents=True)
    (shared / "output" / "result.bin").write_bytes(b"data")
    blocker = tmp_path / "blocker"
    blocker.write_text("a file where a folder belongs", encoding="utf-8")
    sandbox = _Exposed()
    sandbox.bind(shared, running=False)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.copy_from_sandbox("output\\result.bin", blocker / "result.bin")

    assert str(excinfo.value) == "Failed to copy file from sandbox"


@pytest.mark.asyncio
async def test_a_yara_scan_skips_an_artifact_it_cannot_open_and_scans_the_rest(tmp_path: Path) -> None:
    """One artifact nothing can open does not abort the scan of the readable ones.

    Args:
        tmp_path: Pytest scratch directory.
    """
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    locked = output_dir / "locked.bin"
    locked.write_bytes(b"CreateRemoteThread")
    readable = output_dir / "readable.bin"
    readable.write_bytes(b"CreateRemoteThread")
    sandbox = _Exposed()
    sandbox.bind(tmp_path, running=False)

    with _exclusively_open(locked), capture_logs() as captured:
        matches = await sandbox.yara_scan()

    assert {match["source"] for match in matches} == {str(readable)}
    assert [entry.get("file") for entry in _events(captured, "yara_file_scan_error")] == [str(locked)]


def test_a_dump_of_an_exited_process_is_reported_as_a_failed_dump(tmp_path: Path, children: list[Popen[bytes]]) -> None:
    """The process can be opened while its handle is held, but writing its dump fails with a Win32 error.

    Args:
        tmp_path: Pytest scratch directory.
        children: Fixture that reaps the child and holds its handle until teardown.
    """
    finished = _start_python("raise SystemExit(0)", children)
    assert finished.wait(timeout=_REAP_BUDGET_S) == 0
    dump = tmp_path / "dumps" / "gone.dmp"

    produced, reason = _minidump_via_dbghelp(finished.pid, dump)

    kind, _, code = reason.partition(":")
    assert produced is False
    assert kind in {"access_denied", "minidump_failed"}
    assert code.isdigit()
    assert dump.is_file()


@pytest.mark.asyncio
async def test_the_procdump_fallback_reports_a_dump_that_was_not_produced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the in-process dump fails and procdump runs but leaves no dump file, the result is False.

    The stand-in procdump is a copy of the host ``hostname.exe``, which ignores the procdump arguments.

    Args:
        tmp_path: Pytest scratch directory.
        monkeypatch: Used to put the stand-in procdump on ``PATH``.
    """
    fake_bin = tmp_path / "fake_bin"
    fake_bin.mkdir()
    hostname = shutil.which("hostname.exe")
    assert hostname is not None
    shutil.copy2(hostname, fake_bin / "procdump64.exe")
    _prepend_path(monkeypatch, fake_bin)
    dump = tmp_path / "never.dmp"

    with capture_logs() as captured:
        produced = await _Exposed().minidump_via_procdump(_NONEXISTENT_PID, dump)

    assert produced is False
    assert not dump.exists()
    failed = _events(captured, "procdump_failed")
    assert [entry.get("pid") for entry in failed] == [_NONEXISTENT_PID]


@pytest.mark.asyncio
async def test_the_procdump_fallback_reports_a_procdump_that_cannot_be_started(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A procdump that is not an executable image is an invocation failure, not a crash.

    Args:
        tmp_path: Pytest scratch directory.
        monkeypatch: Used to put the broken procdump on ``PATH``.
    """
    fake_bin = tmp_path / "fake_bin"
    fake_bin.mkdir()
    (fake_bin / "procdump64.exe").write_text("not a program", encoding="ascii")
    _prepend_path(monkeypatch, fake_bin)
    dump = tmp_path / "never.dmp"

    with capture_logs() as captured:
        produced = await _Exposed().minidump_via_procdump(_NONEXISTENT_PID, dump)

    assert produced is False
    assert [entry.get("pid") for entry in _events(captured, "procdump_invocation_failed")] == [_NONEXISTENT_PID]
