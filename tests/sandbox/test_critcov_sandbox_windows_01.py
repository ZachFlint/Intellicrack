# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the Windows Sandbox backend paths that never need a running sandbox.

Windows Sandbox cannot start inside the test container, so nothing here launches it. What is
exercised instead is everything the backend does around a launch: resolving the launcher and
probing the feature, looking for a session process, judging liveness from real processes,
building the shared-folder tree and the ``.wsb`` document, detecting a native failure dialog
against real Win32 dialog windows, and the start and stop sequences when no sandbox exists to
start or stop.
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import sys
import tempfile
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, cast

import pytest
from structlog.testing import capture_logs

import intellicrack.sandbox.windows as win_mod
from intellicrack.core.process_manager import ProcessManager
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen, run
from intellicrack.sandbox.base import SandboxError
from intellicrack.sandbox.windows import WindowsSandbox, find_sandbox_session_pid


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_FEATURE_NAME: Final[str] = "Containers-DisposableClientVM"
_FEATURE_ENABLED_STATE: Final[str] = "1"
_TERMINATED_MESSAGE: Final[str] = "Windows Sandbox terminated unexpectedly"
_START_FAILED_MESSAGE: Final[str] = "Failed to start Windows Sandbox"
_NO_SESSION_PREFIX: Final[str] = "The Windows Sandbox launcher exited successfully but no sandbox session process appeared."
_BOOTSTRAP_GUEST_PATH: Final[str] = r"C:\Users\WDAGUtilityAccount\Desktop\Shared\monitor\sandbox_bootstrap.cmd"
_BLOCK_ON_STDIN: Final[str] = "import sys\nsys.stdin.read()\n"
_PROCESS_WAIT_TIMEOUT: Final[int] = cast("int", getattr(win_mod, "_PROCESS_WAIT_TIMEOUT"))
_KILL_BUDGET_S: Final[float] = _PROCESS_WAIT_TIMEOUT - 1.0
_REAP_BUDGET_S: Final[float] = 30.0

_WC_DIALOG: Final[int] = 0x8002
_WS_CHILD: Final[int] = 0x40000000
_DIALOG_CLASS_NAME: Final[str] = "#32770"
_CLASS_NAME_BUFFER: Final[int] = 256
_UNOWNED_PID: Final[int] = 1
_FAILURE_BODY: Final[str] = "The connection to the sandbox could not be initialized. Error 0x800706d9."
_UNRELATED_FAILURE_BODY: Final[str] = "Unexpected failure 0x80004005 occurred."
_PROGRESS_BODY: Final[str] = "Please wait while the sandbox prepares."


class _ExposedSandbox(WindowsSandbox):
    """WindowsSandbox with its private state and start/stop steps reachable from tests."""

    def use_launcher(self, name: str | None) -> None:
        """Record which launcher executable this instance has resolved.

        Args:
            name: Launcher file name, or None for "not resolved yet".
        """
        self._launcher_exe = name

    def launcher(self) -> str | None:
        """Return the launcher this instance has resolved.

        Returns:
            str | None: The remembered launcher name.
        """
        return self._launcher_exe

    def use_session_pid(self, pid: int | None) -> None:
        """Record the session host this instance is bound to.

        Args:
            pid: Session host process id, or None for "no session bound".
        """
        self._session_pid = pid

    def session_pid(self) -> int | None:
        """Return the session host this instance is bound to.

        Returns:
            int | None: The bound session process id.
        """
        return self._session_pid

    def worker_pid(self) -> int | None:
        """Return the worker process this instance tracks.

        Returns:
            int | None: The tracked worker process id.
        """
        return self._worker_pid

    def use_wsb_path(self, path: Path | None) -> None:
        """Record the ``.wsb`` configuration path of this instance.

        Args:
            path: Configuration file path, or None for "not generated yet".
        """
        self._wsb_path = path

    def wsb_path(self) -> Path | None:
        """Return the ``.wsb`` configuration path of this instance.

        Returns:
            Path | None: The configuration file path.
        """
        return self._wsb_path

    def use_folders(self, *, shared: Path | None, monitor: Path | None) -> None:
        """Record the shared and monitor folders without creating a temp directory.

        Args:
            shared: Host-side shared folder.
            monitor: Host-side monitor folder inside the shared folder.
        """
        self._shared_folder = shared
        self._monitor_folder = monitor

    def temp_dir(self) -> Path | None:
        """Return the temporary directory this instance owns.

        Returns:
            Path | None: The temporary directory.
        """
        return self._temp_dir

    def shared_folder(self) -> Path | None:
        """Return the shared folder this instance owns.

        Returns:
            Path | None: The shared folder.
        """
        return self._shared_folder

    def monitor_folder(self) -> Path | None:
        """Return the monitor folder this instance owns.

        Returns:
            Path | None: The monitor folder.
        """
        return self._monitor_folder

    async def resolve_launcher(self) -> str | None:
        """Forward to :meth:`WindowsSandbox._resolve_launcher_exe`.

        Returns:
            str | None: The resolved launcher name.
        """
        return await self._resolve_launcher_exe()

    async def probe_availability(self) -> bool:
        """Forward to :meth:`WindowsSandbox._probe_sandbox_availability`.

        Returns:
            bool: Whether the probe judged Windows Sandbox available.
        """
        return await self._probe_sandbox_availability()

    def check_alive(self) -> None:
        """Forward to :meth:`WindowsSandbox._check_sandbox_alive`."""
        self._check_sandbox_alive()

    async def prepare_shared_folders(self) -> None:
        """Forward to :meth:`WindowsSandbox._prepare_shared_folders`."""
        await self._prepare_shared_folders()

    async def find_session_pid(self) -> int | None:
        """Forward to :meth:`WindowsSandbox._find_session_pid`.

        Returns:
            int | None: The session process id, if one was found.
        """
        return await self._find_session_pid()

    async def launch_sandbox_process(self) -> None:
        """Forward to :meth:`WindowsSandbox._launch_sandbox_process`."""
        await self._launch_sandbox_process()

    async def bind_sandbox_session(self) -> None:
        """Forward to :meth:`WindowsSandbox._bind_sandbox_session`."""
        await self._bind_sandbox_session()

    async def attach_sandbox_worker(self) -> None:
        """Forward to :meth:`WindowsSandbox._attach_sandbox_worker`."""
        await self._attach_sandbox_worker()

    async def apply_telemetry_blocking(self) -> None:
        """Forward to :meth:`WindowsSandbox._apply_telemetry_blocking`."""
        await self._apply_telemetry_blocking()

    async def abort_client(self) -> None:
        """Forward to :meth:`WindowsSandbox._abort_client`."""
        await self._abort_client()

    async def terminate_client(self) -> None:
        """Forward to :meth:`WindowsSandbox._terminate_sandbox_client`."""
        await self._terminate_sandbox_client(ProcessManager.get_instance())

    async def terminate_session(self) -> None:
        """Forward to :meth:`WindowsSandbox._terminate_sandbox_session`."""
        await self._terminate_sandbox_session(ProcessManager.get_instance())


class _DesktopWindows:
    """Real native windows created on the calling thread's desktop, destroyed on request."""

    def __init__(self) -> None:
        """Bind user32 and kernel32 with the prototypes the helpers rely on."""
        self._user32 = ctypes.WinDLL("user32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._created: list[int] = []
        self._user32.CreateWindowExW.restype = ctypes.c_void_p
        self._user32.CreateWindowExW.argtypes = [
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self._user32.DestroyWindow.restype = ctypes.c_int
        self._user32.DestroyWindow.argtypes = [ctypes.c_void_p]
        self._user32.GetClassNameW.restype = ctypes.c_int
        self._user32.GetClassNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
        self._user32.GetWindowTextLengthW.restype = ctypes.c_int
        self._user32.GetWindowTextLengthW.argtypes = [ctypes.c_void_p]
        self._user32.GetWindowTextW.restype = ctypes.c_int
        self._user32.GetWindowTextW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
        self._kernel32.GetModuleHandleW.restype = ctypes.c_void_p
        self._kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]

    def _create(self, window_class: int | str, title: str, style: int, parent: int | None) -> int:
        """Create one window and return its handle.

        Args:
            window_class: Class name, or a class atom for a system class.
            title: Window text.
            style: Window style flags.
            parent: Parent window handle, or None for a top-level window.

        Returns:
            int: Handle of the new window.

        Raises:
            OSError: If Windows refuses to create the window.
        """
        instance = cast("int | None", self._kernel32.GetModuleHandleW(None))
        handle = cast(
            "int | None",
            self._user32.CreateWindowExW(0, window_class, title, style, 0, 0, 1, 1, parent, None, instance, None),
        )
        if not handle:
            raise OSError(ctypes.get_last_error(), "CreateWindowExW failed")
        return handle

    def top_level(self, window_class: int | str, title: str) -> int:
        """Create a hidden top-level window owned by this process.

        Args:
            window_class: Class name, or a class atom for a system class.
            title: Window text.

        Returns:
            int: Handle of the new window.
        """
        handle = self._create(window_class, title, 0, None)
        self._created.append(handle)
        return handle

    def dialog(self, title: str, *child_texts: str) -> int:
        """Create a hidden dialog-class window holding one static child per text.

        Args:
            title: Dialog caption.
            *child_texts: Text of each static child control; an empty string makes a child with no text.

        Returns:
            int: Handle of the dialog window.
        """
        handle = self.top_level(_WC_DIALOG, title)
        for text in child_texts:
            self._create("STATIC", text, _WS_CHILD, handle)
        return handle

    def class_name_of(self, handle: int) -> str:
        """Read a window's class name straight from user32.

        Args:
            handle: Window handle.

        Returns:
            str: The window's class name.
        """
        buffer = ctypes.create_unicode_buffer(_CLASS_NAME_BUFFER)
        self._user32.GetClassNameW(handle, buffer, _CLASS_NAME_BUFFER)
        return buffer.value

    def text_of(self, handle: int) -> str:
        """Read a window's caption straight from user32.

        Args:
            handle: Window handle.

        Returns:
            str: The window's caption text.
        """
        length = cast("int", self._user32.GetWindowTextLengthW(handle))
        buffer = ctypes.create_unicode_buffer(length + 1)
        self._user32.GetWindowTextW(handle, buffer, length + 1)
        return buffer.value

    def destroy_all(self) -> None:
        """Destroy every top-level window this helper created, newest first."""
        for handle in reversed(self._created):
            self._user32.DestroyWindow(handle)
        self._created.clear()


@pytest.fixture
def desktop() -> Iterator[_DesktopWindows]:
    """Provide native window creation and destroy whatever a test left behind.

    Yields:
        _DesktopWindows: Helper bound to the test thread's desktop.
    """
    windows = _DesktopWindows()
    try:
        yield windows
    finally:
        windows.destroy_all()


@pytest.fixture
def reaped() -> Iterator[list[Popen[bytes]]]:
    """Kill and reap every process a test started, however the test ended.

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
        tmp_path: Pytest scratch directory for this test.
        monkeypatch: Restores the temporary-directory setting afterwards.

    Returns:
        Path: The directory ``tempfile.mkdtemp`` now creates its directories in.
    """
    root = tmp_path / "temp_root"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


@pytest.fixture
def empty_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Make ``PATH`` name one empty directory, so no program resolves by bare name.

    Args:
        tmp_path: Pytest scratch directory for this test.
        monkeypatch: Restores ``PATH`` afterwards.

    Returns:
        Path: The empty directory ``PATH`` now consists of.
    """
    directory = tmp_path / "empty_path"
    directory.mkdir()
    monkeypatch.setenv("PATH", str(directory))
    return directory


def _start_process(reaped: list[Popen[bytes]], code: str) -> Popen[bytes]:
    """Start a real Python child running ``code`` with a pipe for stdin.

    Args:
        reaped: Registry that kills the child on teardown.
        code: Source passed to ``python -c``.

    Returns:
        Popen[bytes]: The started child.
    """
    process = Popen([sys.executable, "-c", code], stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL)
    reaped.append(process)
    return process


def _exited_process(reaped: list[Popen[bytes]], exit_code: int) -> Popen[bytes]:
    """Start a real Python child that exits with ``exit_code`` and wait for it.

    Args:
        reaped: Registry that reaps the child on teardown.
        exit_code: Status the child exits with.

    Returns:
        Popen[bytes]: The finished child, whose handle is still held so its pid cannot be reused.
    """
    process = _start_process(reaped, f"raise SystemExit({exit_code})")
    process.wait(timeout=_REAP_BUDGET_S)
    return process


def _entry_names(directory: Path) -> list[str]:
    """List the names inside a directory.

    Args:
        directory: Directory to list.

    Returns:
        list[str]: Sorted names of its entries.
    """
    return sorted(entry.name for entry in directory.iterdir())


@pytest.mark.spawns_process
def test_session_lookup_finds_nothing_when_no_session_references_the_config() -> None:
    """No process is a Windows Sandbox session for a config nobody launched."""
    assert find_sandbox_session_pid("intellicrack_critcov_no_such_session.wsb") is None


@pytest.mark.spawns_process
@pytest.mark.usefixtures("empty_path")
def test_session_lookup_gives_up_quietly_when_powershell_cannot_be_started() -> None:
    """A host with no PowerShell reachable yields no session instead of an exception."""
    with capture_logs() as captured:
        found = find_sandbox_session_pid("intellicrack_critcov_no_such_session.wsb")

    assert found is None
    lookup_errors = [entry for entry in captured if entry.get("event") == "sandbox_session_lookup_error"]
    assert lookup_errors, f"the failed PowerShell start must be logged as a lookup error; got {captured!r}"
    assert lookup_errors[0].get("log_level") == "warning"


@pytest.mark.asyncio
async def test_resolve_launcher_returns_the_remembered_launcher() -> None:
    """A launcher resolved earlier is returned as is, with no new ``PATH`` search."""
    sandbox = _ExposedSandbox()
    sandbox.use_launcher("not-a-real-launcher-anywhere.exe")

    assert await sandbox.resolve_launcher() == "not-a-real-launcher-anywhere.exe"


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_probe_reports_the_feature_state_the_os_reports() -> None:
    """The probe says available exactly when ``Win32_OptionalFeature`` reports install state 1."""
    query = f"(Get-CimInstance -ClassName Win32_OptionalFeature -Filter \"Name='{_FEATURE_NAME}'\").InstallState"
    reported = run(
        ["powershell", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", query],
        capture_output=True,
        text=True,
        timeout=_REAP_BUDGET_S * 4,
        check=False,
    )
    sandbox = _ExposedSandbox()
    sandbox.use_launcher("WindowsSandbox.exe")

    available = await sandbox.probe_availability()

    assert available is (reported.stdout.strip() == _FEATURE_ENABLED_STATE)


@pytest.mark.asyncio
@pytest.mark.spawns_process
@pytest.mark.usefixtures("empty_path")
async def test_is_available_is_false_when_the_feature_query_cannot_run() -> None:
    """A failure to start the feature query reads as "not available", not as an exception."""
    sandbox = _ExposedSandbox()
    sandbox.use_launcher("WindowsSandbox.exe")

    with capture_logs() as captured:
        available = await sandbox.is_available()

    assert available is False
    failures = [entry for entry in captured if entry.get("event") == "windows_sandbox_availability_check_failed"]
    assert failures, f"the failed feature query must be logged; got {captured!r}"
    assert failures[0].get("log_level") == "warning"


@pytest.mark.spawns_process
def test_check_alive_raises_when_the_bound_session_process_is_gone(reaped: list[Popen[bytes]]) -> None:
    """A session host that has exited ends the sandbox's liveness.

    Args:
        reaped: Fixture that reaps the child on teardown.
    """
    finished = _exited_process(reaped, 0)
    sandbox = _ExposedSandbox()
    sandbox.use_session_pid(finished.pid)

    with pytest.raises(SandboxError) as excinfo:
        sandbox.check_alive()

    assert str(excinfo.value) == _TERMINATED_MESSAGE


@pytest.mark.spawns_process
def test_check_alive_judges_a_bound_session_not_the_launcher(reaped: list[Popen[bytes]]) -> None:
    """Once a session is bound, a launcher that failed and exited no longer matters.

    The launcher is a fire-and-forget process; the session host is what owns the VM.

    Args:
        reaped: Fixture that reaps the child on teardown.
    """
    failed_launcher = _exited_process(reaped, 3)
    sandbox = _ExposedSandbox()
    sandbox.process = failed_launcher
    sandbox.use_session_pid(os.getpid())

    sandbox.check_alive()

    assert sandbox.state.status == "stopped"


@pytest.mark.spawns_process
def test_check_alive_raises_when_the_launcher_failed_before_any_session_was_bound(reaped: list[Popen[bytes]]) -> None:
    """With no session bound yet, a launcher that exited non-zero is a dead sandbox.

    Args:
        reaped: Fixture that reaps the child on teardown.
    """
    failed_launcher = _exited_process(reaped, 3)
    sandbox = _ExposedSandbox()
    sandbox.process = failed_launcher

    with pytest.raises(SandboxError) as excinfo:
        sandbox.check_alive()

    assert str(excinfo.value) == _TERMINATED_MESSAGE


@pytest.mark.spawns_process
def test_check_alive_accepts_a_launcher_that_exited_cleanly(reaped: list[Popen[bytes]]) -> None:
    """A launcher exiting 0 is the normal hand-off, not a failure.

    Args:
        reaped: Fixture that reaps the child on teardown.
    """
    handed_off = _exited_process(reaped, 0)
    sandbox = _ExposedSandbox()
    sandbox.process = handed_off

    sandbox.check_alive()

    assert sandbox.process is handed_off
    assert sandbox.state.status == "stopped"


def test_failure_dialog_owned_by_the_client_is_reported_with_title_and_body(desktop: _DesktopWindows) -> None:
    """A real dialog window with a failure body is returned as its title and text.

    Args:
        desktop: Fixture creating real native windows.
    """
    dialog = desktop.dialog("Windows Sandbox", "", _FAILURE_BODY)
    assert desktop.class_name_of(dialog) == _DIALOG_CLASS_NAME
    assert desktop.text_of(dialog) == "Windows Sandbox"

    detail = WindowsSandbox.detect_failure_dialog(os.getpid())

    assert detail == f"Windows Sandbox\n{_FAILURE_BODY}"


def test_failure_dialog_owned_by_the_client_is_reported_whatever_its_title(desktop: _DesktopWindows) -> None:
    """Ownership by the client alone is enough, without the sandbox title.

    Args:
        desktop: Fixture creating real native windows.
    """
    dialog = desktop.dialog("Launcher Error", _FAILURE_BODY)
    assert desktop.text_of(dialog) == "Launcher Error"

    detail = WindowsSandbox.detect_failure_dialog(os.getpid())

    assert detail == f"Launcher Error\n{_FAILURE_BODY}"


def test_failure_dialog_titled_windows_sandbox_is_reported_whatever_its_owner(desktop: _DesktopWindows) -> None:
    """A dialog titled Windows Sandbox counts even when another process was named as the client.

    Args:
        desktop: Fixture creating real native windows.
    """
    desktop.dialog("Windows Sandbox", _FAILURE_BODY)

    detail = WindowsSandbox.detect_failure_dialog(_UNOWNED_PID)

    assert detail == f"Windows Sandbox\n{_FAILURE_BODY}"


def test_failure_text_in_an_unrelated_dialog_is_ignored(desktop: _DesktopWindows) -> None:
    """A dialog neither owned by the client nor titled Windows Sandbox is not the sandbox's.

    Args:
        desktop: Fixture creating real native windows.
    """
    desktop.dialog("Other Application", _UNRELATED_FAILURE_BODY)

    assert WindowsSandbox.detect_failure_dialog(_UNOWNED_PID) is None


def test_a_window_that_is_not_a_dialog_is_ignored(desktop: _DesktopWindows) -> None:
    """Only dialog-class windows are read, even when the title and owner both match.

    Args:
        desktop: Fixture creating real native windows.
    """
    window = desktop.top_level("STATIC", "Windows Sandbox failed to start")
    assert desktop.class_name_of(window) != _DIALOG_CLASS_NAME
    assert desktop.text_of(window) == "Windows Sandbox failed to start"

    assert WindowsSandbox.detect_failure_dialog(os.getpid()) is None


def test_the_startup_progress_dialog_is_not_a_failure(desktop: _DesktopWindows) -> None:
    """The transient progress dialog carries no error marker and is not reported.

    Args:
        desktop: Fixture creating real native windows.
    """
    desktop.dialog("Starting Windows Sandbox", _PROGRESS_BODY)

    assert WindowsSandbox.detect_failure_dialog(os.getpid()) is None


def test_a_second_failure_dialog_does_not_change_the_report(desktop: _DesktopWindows) -> None:
    """Two identical failure dialogs yield one report with the text of a single dialog.

    Args:
        desktop: Fixture creating real native windows.
    """
    desktop.dialog("Windows Sandbox", _FAILURE_BODY)
    desktop.dialog("Windows Sandbox", _FAILURE_BODY)

    detail = WindowsSandbox.detect_failure_dialog(os.getpid())

    assert detail == f"Windows Sandbox\n{_FAILURE_BODY}"


def test_progress_dialog_text_never_leaks_into_a_failure_report(desktop: _DesktopWindows) -> None:
    """The report holds the failure dialog's own title and text, whichever dialog is read first.

    Args:
        desktop: Fixture creating real native windows.
    """
    desktop.dialog("Starting Windows Sandbox", _PROGRESS_BODY)
    desktop.dialog("Windows Sandbox", _FAILURE_BODY)

    detail = WindowsSandbox.detect_failure_dialog(os.getpid())

    assert detail == f"Windows Sandbox\n{_FAILURE_BODY}"


@pytest.mark.asyncio
async def test_prepare_shared_folders_builds_the_guest_visible_tree(temp_root: Path) -> None:
    """The temp directory holds the shared folder with every subfolder the dispatcher uses.

    Args:
        temp_root: Fixture redirecting temporary directories under ``tmp_path``.
    """
    sandbox = _ExposedSandbox()

    await sandbox.prepare_shared_folders()

    temp_dir = sandbox.temp_dir()
    assert temp_dir is not None
    assert temp_dir.parent == temp_root
    assert temp_dir.name.startswith("intellicrack_sandbox_")
    shared = temp_dir / "IntellicrackShared"
    assert sandbox.shared_folder() == shared
    assert sandbox.monitor_folder() == shared / "monitor"
    for relative in ("monitor", "input", "output", "logs", "flags", "input/trigger"):
        assert (shared / relative).is_dir(), f"{relative} was not created under the shared folder"


@pytest.mark.asyncio
async def test_find_session_pid_is_none_before_a_config_exists() -> None:
    """With no ``.wsb`` generated there is nothing to match a session against."""
    sandbox = _ExposedSandbox()

    assert await sandbox.find_session_pid() is None


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_find_session_pid_is_none_when_no_session_runs_for_the_config(tmp_path: Path) -> None:
    """A generated config that no session process was started from has no session.

    Args:
        tmp_path: Pytest scratch directory for this test.
    """
    sandbox = _ExposedSandbox()
    sandbox.use_wsb_path(tmp_path / "intellicrack_critcov_unlaunched.wsb")

    assert await sandbox.find_session_pid() is None


@pytest.mark.asyncio
async def test_launch_without_a_temp_dir_is_refused_after_the_scripts_are_staged(tmp_path: Path) -> None:
    """A launch with no temporary directory fails with the start error before any config is written.

    Args:
        tmp_path: Pytest scratch directory for this test.
    """
    shared = tmp_path / "shared"
    monitor = shared / "monitor"
    monitor.mkdir(parents=True)
    sandbox = _ExposedSandbox()
    sandbox.use_folders(shared=shared, monitor=monitor)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.launch_sandbox_process()

    assert str(excinfo.value) == _START_FAILED_MESSAGE
    assert (monitor / "sandbox_bootstrap.cmd").is_file()
    assert (shared / "dispatcher" / "sandbox_dispatcher.ps1").is_file()
    assert sandbox.wsb_path() is None
    assert sandbox.process is None


@pytest.mark.asyncio
@pytest.mark.usefixtures("temp_root", "empty_path")
async def test_launch_writes_the_wsb_config_then_fails_when_no_launcher_exists() -> None:
    """With neither launcher on ``PATH`` the config is written and the start fails without launching."""
    sandbox = _ExposedSandbox()
    await sandbox.prepare_shared_folders()

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.launch_sandbox_process()

    assert str(excinfo.value) == _START_FAILED_MESSAGE
    temp_dir = sandbox.temp_dir()
    assert temp_dir is not None
    wsb_path = temp_dir / "intellicrack.wsb"
    assert sandbox.wsb_path() == wsb_path
    document = wsb_path.read_bytes().decode("utf-8")
    assert f"<HostFolder>{temp_dir / 'IntellicrackShared'}</HostFolder>" in document
    assert _BOOTSTRAP_GUEST_PATH in document
    assert sandbox.launcher() is None
    assert sandbox.process is None


@pytest.mark.asyncio
@pytest.mark.usefixtures("empty_path")
async def test_start_without_a_launcher_reports_error_state_and_removes_its_files(temp_root: Path) -> None:
    """A start that cannot find a launcher ends in the error state with the temp tree removed.

    Args:
        temp_root: Fixture redirecting temporary directories under ``tmp_path``.
    """
    sandbox = _ExposedSandbox()

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.start()

    assert str(excinfo.value) == _START_FAILED_MESSAGE
    assert sandbox.state.status == "error"
    assert sandbox.state.last_error == _START_FAILED_MESSAGE
    assert sandbox.process is None
    assert sandbox.temp_dir() is None
    assert _entry_names(temp_root) == []


@pytest.mark.asyncio
async def test_start_does_nothing_when_the_sandbox_is_already_running(temp_root: Path) -> None:
    """Starting a running sandbox only logs a warning and leaves everything as it was.

    Args:
        temp_root: Fixture redirecting temporary directories under ``tmp_path``.
    """
    sandbox = _ExposedSandbox()
    sandbox.state.status = "running"

    with capture_logs() as captured:
        await sandbox.start()

    assert sandbox.state.status == "running"
    assert sandbox.temp_dir() is None
    assert _entry_names(temp_root) == []
    warnings = [entry for entry in captured if entry.get("event") == "sandbox_already_running"]
    assert warnings, f"a second start must be logged as already running; got {captured!r}"
    assert warnings[0].get("log_level") == "warning"


@pytest.mark.asyncio
async def test_stop_does_nothing_when_the_sandbox_is_already_stopped() -> None:
    """Stopping a stopped sandbox leaves its state untouched."""
    sandbox = _ExposedSandbox()
    sandbox.state.pid = 4242

    await sandbox.stop()

    assert sandbox.state.status == "stopped"
    assert sandbox.state.pid == 4242


@pytest.mark.asyncio
async def test_stop_of_a_sandbox_with_nothing_live_removes_its_files_and_resets_state(temp_root: Path) -> None:
    """Stopping a sandbox that owns only a temp tree deletes the tree and reports stopped.

    Args:
        temp_root: Fixture redirecting temporary directories under ``tmp_path``.
    """
    sandbox = _ExposedSandbox()
    await sandbox.prepare_shared_folders()
    temp_dir = sandbox.temp_dir()
    assert temp_dir is not None
    assert temp_dir.is_dir()
    sandbox.state.status = "running"
    sandbox.state.pid = 4242

    await sandbox.stop()

    assert sandbox.state.status == "stopped"
    assert sandbox.state.pid is None
    assert not temp_dir.exists()
    assert sandbox.temp_dir() is None
    assert sandbox.shared_folder() is None
    assert sandbox.worker_pid() is None
    assert _entry_names(temp_root) == []


@pytest.mark.asyncio
async def test_telemetry_blocking_failure_is_logged_and_does_not_abort_the_start() -> None:
    """When the in-guest command cannot run, blocking is skipped with a warning and no exception."""
    sandbox = _ExposedSandbox()

    with capture_logs() as captured:
        await sandbox.apply_telemetry_blocking()

    failures = [entry for entry in captured if entry.get("event") == "telemetry_blocking_failed"]
    assert failures, f"the refused command must be logged as a blocking failure; got {captured!r}"
    assert failures[0].get("log_level") == "warning"
    assert failures[0].get("error") == "Sandbox is not running"
    assert sandbox.state.status == "stopped"


@pytest.mark.asyncio
@pytest.mark.usefixtures("temp_root")
async def test_attach_requires_a_launcher_process_once_the_dispatcher_is_ready() -> None:
    """A ready dispatcher with no launcher process behind it is reported as a dead sandbox."""
    sandbox = _ExposedSandbox()
    await sandbox.prepare_shared_folders()
    shared = sandbox.shared_folder()
    assert shared is not None
    (shared / "flags" / WindowsSandbox.DISPATCHER_READY_MARKER).write_text("ready", encoding="ascii")

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.attach_sandbox_worker()

    assert str(excinfo.value) == _TERMINATED_MESSAGE
    assert sandbox.state.status == "stopped"


@pytest.mark.slow
@pytest.mark.asyncio
@pytest.mark.spawns_process
@pytest.mark.usefixtures("temp_root")
async def test_attach_marks_the_sandbox_running_even_when_no_worker_is_found(reaped: list[Popen[bytes]]) -> None:
    """With a live launcher and no vmwp worker anywhere, the sandbox still becomes running.

    The worker search runs its full 90 second poll before giving up.

    Args:
        reaped: Fixture that reaps the launcher stand-in on teardown.
    """
    launcher = _start_process(reaped, _BLOCK_ON_STDIN)
    sandbox = _ExposedSandbox()
    sandbox.process = launcher
    await sandbox.prepare_shared_folders()
    shared = sandbox.shared_folder()
    assert shared is not None
    (shared / "flags" / WindowsSandbox.DISPATCHER_READY_MARKER).write_text("ready", encoding="ascii")
    before = datetime.now(UTC)

    await sandbox.attach_sandbox_worker()

    after = datetime.now(UTC)
    assert sandbox.state.status == "running"
    assert sandbox.state.pid == launcher.pid
    assert sandbox.state.started_at is not None
    assert before <= sandbox.state.started_at <= after
    assert sandbox.worker_pid() is None


@pytest.mark.slow
@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_bind_without_any_session_process_reports_the_sandbox_did_not_start(tmp_path: Path) -> None:
    """When no session process ever appears for the config, the bind fails with the not-started error.

    The session search runs its full 60 second poll before giving up.

    Args:
        tmp_path: Pytest scratch directory for this test.
    """
    sandbox = _ExposedSandbox()
    sandbox.use_wsb_path(tmp_path / "intellicrack_critcov_unlaunched.wsb")

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.bind_sandbox_session()

    assert str(excinfo.value).startswith(_NO_SESSION_PREFIX)
    assert sandbox.session_pid() is None


@pytest.mark.asyncio
async def test_abort_client_with_nothing_to_abort_returns() -> None:
    """Aborting a sandbox that never launched anything is a no-op."""
    sandbox = _ExposedSandbox()

    await sandbox.abort_client()

    assert sandbox.process is None
    assert sandbox.session_pid() is None


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_abort_client_kills_a_running_client(reaped: list[Popen[bytes]]) -> None:
    """A client still running after a failed start is force-killed and forgotten.

    Args:
        reaped: Fixture that reaps the client on teardown.
    """
    client = _start_process(reaped, _BLOCK_ON_STDIN)
    sandbox = _ExposedSandbox()
    sandbox.process = client

    await asyncio.wait_for(sandbox.abort_client(), timeout=_KILL_BUDGET_S)

    assert sandbox.process is None
    assert client.poll() is not None


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_abort_client_forgets_a_client_that_already_exited(reaped: list[Popen[bytes]]) -> None:
    """A client that exited on its own is not killed again, only forgotten.

    Args:
        reaped: Fixture that reaps the client on teardown.
    """
    client = _exited_process(reaped, 0)
    sandbox = _ExposedSandbox()
    sandbox.process = client

    await asyncio.wait_for(sandbox.abort_client(), timeout=_KILL_BUDGET_S)

    assert sandbox.process is None
    assert client.returncode == 0


@pytest.mark.asyncio
async def test_terminate_client_with_no_client_returns() -> None:
    """Terminating a sandbox with no client process is a no-op."""
    sandbox = _ExposedSandbox()

    await sandbox.terminate_client()

    assert sandbox.process is None


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_terminate_client_force_kills_a_client_that_has_no_window_to_close(reaped: list[Popen[bytes]]) -> None:
    """A client with no window to ask politely is force-killed within the wait budget.

    Args:
        reaped: Fixture that reaps the client on teardown.
    """
    client = _start_process(reaped, _BLOCK_ON_STDIN)
    sandbox = _ExposedSandbox()
    sandbox.process = client

    await asyncio.wait_for(sandbox.terminate_client(), timeout=_KILL_BUDGET_S)

    assert sandbox.process is None
    assert client.poll() is not None


@pytest.mark.asyncio
async def test_terminate_session_with_no_session_returns() -> None:
    """Terminating a sandbox with no bound session is a no-op."""
    sandbox = _ExposedSandbox()

    await sandbox.terminate_session()

    assert sandbox.session_pid() is None


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_terminate_session_force_kills_a_session_that_has_no_window_to_close(reaped: list[Popen[bytes]]) -> None:
    """A session host with no window to close is force-killed and unbound.

    Args:
        reaped: Fixture that reaps the session stand-in on teardown.
    """
    session = _start_process(reaped, _BLOCK_ON_STDIN)
    sandbox = _ExposedSandbox()
    sandbox.use_session_pid(session.pid)

    await sandbox.terminate_session()

    assert sandbox.session_pid() is None
    assert session.wait(timeout=_REAP_BUDGET_S) is not None
