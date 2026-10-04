# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Coverage for the Windows Sandbox backend paths that need no running sandbox.

Windows Sandbox cannot start inside the test container and is never launched here. What can be reached
honestly is reached with real objects: the guard clauses that refuse work while the sandbox is down, the
shared-folder file operations against a directory under ``tmp_path``, the monitor-log bookkeeping, the
teardown helpers against real child processes, and the polling loop that waits for a dispatcher result
that never arrives. A guard clause is tested by arming the real backend with exactly the state that
trips it, through a subclass that exposes the protected attributes.
"""

from __future__ import annotations

import asyncio
import ctypes
import sys
import time
from ctypes import wintypes
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.subprocess_compat import DEVNULL, Popen
from intellicrack.sandbox.base import SandboxConfig, SandboxError, SandboxTimeoutError
from intellicrack.sandbox.windows import WindowsSandbox
from tests._helpers.polling import wait_until


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_SELF_EXIT_CODE: Final[int] = 42
_LONG_LIVED_SCRIPT: Final[str] = "import sys, time; time.sleep(120); sys.exit(42)"
_SHORT_LIVED_SCRIPT: Final[str] = "import sys, time; time.sleep(1); sys.exit(42)"
_DEAD_LAUNCHER_SCRIPT: Final[str] = "import sys; sys.exit(3)"
_EXIT_WAIT_BUDGET_S: Final[float] = 60.0
_IMPATIENT_BUDGET_S: Final[float] = 1.0
_KILL_WAIT_S: Final[float] = 30.0
_WATCH_BUDGET_S: Final[float] = 15.0
_WATCH_INTERVAL_S: Final[float] = 0.01
_COMMAND_LIMIT_S: Final[int] = 1
_PLANTED_LIMIT_S: Final[int] = 2
_LARGEST_MEASURED_ARRIVAL_GAP_S: Final[float] = 16.0
_WORKER_LOOKUP_CEILING_S: Final[float] = 300.0
_HIDDEN_WINDOW_TITLE: Final[str] = "IntellicrackCritcovSandboxHiddenWindow"
_STALE_FILE_LOG_LINE: Final[str] = "2026-01-01T00:00:00|created|C:\\stale\\artifact.txt||12\n"
_ERR_NOT_RUNNING: Final[str] = "Sandbox is not running"
_ERR_NO_SHARED: Final[str] = "Shared folder not initialized"
_ERR_NO_PATHS: Final[str] = "Sandbox paths not initialized"


class _Probe(WindowsSandbox):
    """Windows Sandbox backend whose protected state and helpers are reachable from tests.

    Nothing here replaces behavior. Each method forwards to the production member of the same name, and
    :meth:`arm` sets the plain data attributes a started sandbox would hold, so a guard clause can be
    driven with exactly the state that trips it.
    """

    def arm(
        self,
        *,
        temp_dir: Path | None = None,
        shared_folder: Path | None = None,
        monitor_folder: Path | None = None,
        wsb_path: Path | None = None,
        running: bool = False,
    ) -> None:
        """Set the data attributes a started sandbox holds.

        Args:
            temp_dir: Temporary directory the sandbox owns.
            shared_folder: Host-side shared folder.
            monitor_folder: Host-side monitor folder.
            wsb_path: Path of the generated ``.wsb`` configuration.
            running: Whether the sandbox state reads ``running``.
        """
        self._temp_dir = temp_dir
        self._shared_folder = shared_folder
        self._monitor_folder = monitor_folder
        self._wsb_path = wsb_path
        if running:
            self.state.status = "running"

    def held_paths(self) -> tuple[Path | None, Path | None, Path | None, Path | None]:
        """Return the paths the sandbox still considers its own.

        Returns:
            tuple[Path | None, Path | None, Path | None, Path | None]: Temporary directory, shared
            folder, monitor folder and ``.wsb`` path, in that order.
        """
        return (self._temp_dir, self._shared_folder, self._monitor_folder, self._wsb_path)

    def use_process(self, process: Popen[bytes] | None) -> None:
        """Stand a real process in for the launcher this instance spawned.

        Args:
            process: Process to treat as the launcher, or None.
        """
        self.process = process

    async def run_cleanup(self) -> None:
        """Forward to :meth:`WindowsSandbox._cleanup`."""
        await self._cleanup()

    def progress_markers(self) -> tuple[bool, bool]:
        """Forward to :meth:`WindowsSandbox._dispatcher_progress_markers`.

        Returns:
            tuple[bool, bool]: Whether the logon ran and whether any monitor reported.
        """
        return self._dispatcher_progress_markers()

    async def wait_for_dispatcher_ready(self) -> None:
        """Forward to :meth:`WindowsSandbox._wait_for_dispatcher_ready`."""
        await self._wait_for_dispatcher_ready()

    async def generate_wsb_config(self) -> None:
        """Forward to :meth:`WindowsSandbox._generate_wsb_config`."""
        await self._generate_wsb_config()

    async def create_dispatcher_scripts(self) -> None:
        """Forward to :meth:`WindowsSandbox._create_dispatcher_scripts`."""
        await self._create_dispatcher_scripts()

    def bootstrap_source(self) -> str:
        """Forward to :meth:`WindowsSandbox._bootstrap_cmd_source`.

        Returns:
            str: The guest bootstrap batch script.
        """
        return self._bootstrap_cmd_source()

    async def create_monitor_scripts(self) -> None:
        """Forward to :meth:`WindowsSandbox._create_monitor_scripts`."""
        await self._create_monitor_scripts()

    async def emit_inline_monitors(self) -> None:
        """Forward to :meth:`WindowsSandbox._emit_inline_monitors`."""
        await self._emit_inline_monitors()

    async def reset_monitor_logs(self) -> None:
        """Forward to :meth:`WindowsSandbox._reset_monitor_logs`."""
        await self._reset_monitor_logs()

    def surviving_collectors(self) -> set[str]:
        """Forward to :meth:`WindowsSandbox._surviving_collectors`.

        Returns:
            set[str]: Script stems the launcher recorded as survivors.
        """
        return self._surviving_collectors()

    def collectors_reporting(self, expected: set[str]) -> set[str]:
        """Forward to :meth:`WindowsSandbox._collectors_reporting`.

        Args:
            expected: Script stems expected to report.

        Returns:
            set[str]: The expected stems whose log exists.
        """
        return self._collectors_reporting(expected)

    async def wait_for_monitor_quiescence(self) -> None:
        """Forward to :meth:`WindowsSandbox._wait_for_monitor_quiescence`."""
        await self._wait_for_monitor_quiescence()

    async def try_graceful_close(self, pid: int) -> bool:
        """Forward to :meth:`WindowsSandbox._try_graceful_close`.

        Args:
            pid: Process whose window should be closed.

        Returns:
            bool: Whether the process closed gracefully.
        """
        return await self._try_graceful_close(pid)

    async def await_pid_exit(self, pid: int, budget_seconds: float) -> bool:
        """Forward to :meth:`WindowsSandbox._await_pid_exit`.

        Args:
            pid: Process to watch.
            budget_seconds: Seconds to wait for it.

        Returns:
            bool: Whether that process left within the window.
        """
        return await self._await_pid_exit(pid, budget_seconds)

    async def force_kill(self, pid: int) -> None:
        """Forward to :meth:`WindowsSandbox._force_kill_sandbox`.

        Args:
            pid: Process to terminate.
        """
        await self._force_kill_sandbox(pid)

    async def resolve_worker_pid(self) -> int | None:
        """Forward to :meth:`WindowsSandbox._resolve_worker_pid`.

        Returns:
            int | None: The vmwp worker pid, or None when none was found.
        """
        return await self._resolve_worker_pid()


@pytest.fixture
def children() -> Iterator[list[Popen[bytes]]]:
    """Reap every child process a test leaves running, however it failed.

    Yields:
        list[Popen[bytes]]: Registry the test appends its children to.
    """
    started: list[Popen[bytes]] = []
    try:
        yield started
    finally:
        for process in started:
            if process.poll() is None:
                process.kill()
            process.wait()


def _spawn(script: str, children: list[Popen[bytes]]) -> Popen[bytes]:
    """Start a real Python child running ``script`` and register it for reaping.

    Args:
        script: Source the child interpreter runs.
        children: Registry the child is appended to.

    Returns:
        Popen[bytes]: The running child.
    """
    process = Popen([sys.executable, "-c", script], stdout=DEVNULL, stderr=DEVNULL, stdin=DEVNULL)
    children.append(process)
    return process


def _create_hidden_window() -> int:
    """Create a top-level window that is not visible, owned by this process.

    Returns:
        int: Native window handle, or 0 when the desktop refuses to create one.
    """
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.CreateWindowExW.argtypes = [
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.LPVOID,
    ]
    handle = user32.CreateWindowExW(0, "STATIC", _HIDDEN_WINDOW_TITLE, 0, 0, 0, 1, 1, None, None, None, None)
    return int(handle) if handle else 0


def _destroy_window(hwnd: int) -> None:
    """Destroy a window created by :func:`_create_hidden_window`.

    Args:
        hwnd: Native window handle.
    """
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.DestroyWindow.restype = wintypes.BOOL
    user32.DestroyWindow.argtypes = [wintypes.HWND]
    user32.DestroyWindow(hwnd)


def _entries(directory: Path) -> list[str]:
    """List the names directly under a directory.

    Args:
        directory: Directory to list.

    Returns:
        list[str]: Sorted entry names.
    """
    return sorted(entry.name for entry in directory.iterdir())


def _triggers(shared: Path) -> list[str]:
    """List the trigger files currently staged under a shared folder.

    Args:
        shared: Host-side shared folder.

    Returns:
        list[str]: Sorted trigger file names.
    """
    return sorted(trigger.name for trigger in (shared / "input" / "trigger").glob("*.cmd"))


async def _plant_unreadable_result(shared: Path) -> Path:
    """Put a directory where the dispatcher result file of the next ticket belongs.

    The in-guest dispatcher names a ticket's result ``<ticket>.result.txt`` under ``output``. A directory
    at that path exists but cannot be read as a file, which is how a result that is present yet unreadable
    looks to the host.

    Args:
        shared: Host-side shared folder the sandbox polls.

    Returns:
        Path: The directory planted at the result path.
    """
    trigger_dir = shared / "input" / "trigger"
    await wait_until(lambda: any(trigger_dir.glob("*.cmd")), budget=_WATCH_BUDGET_S, interval=_WATCH_INTERVAL_S)
    trigger = next(iter(trigger_dir.glob("*.cmd")))
    planted = shared / "output" / f"{trigger.stem}.result.txt"
    planted.mkdir()
    return planted


@pytest.mark.asyncio
async def test_cleanup_removes_the_tree_and_forgets_every_path(tmp_path: Path) -> None:
    """A finished sandbox leaves no temporary tree behind and holds no path to it.

    Args:
        tmp_path: Workspace standing in for the sandbox temporary directory.
    """
    temp_dir = tmp_path / "intellicrack_sandbox_probe"
    shared = temp_dir / "IntellicrackShared"
    monitor = shared / "monitor"
    monitor.mkdir(parents=True)
    (monitor / "file_monitor.ps1").write_text("payload", encoding="utf-8")
    (shared / "logs").mkdir()
    (shared / "logs" / "file_monitor.log").write_text("record", encoding="utf-8")
    wsb = temp_dir / "intellicrack.wsb"
    wsb.write_text("<Configuration />", encoding="utf-8")
    sandbox = _Probe()
    sandbox.arm(temp_dir=temp_dir, shared_folder=shared, monitor_folder=monitor, wsb_path=wsb)

    await sandbox.run_cleanup()

    assert not temp_dir.exists(), f"the temporary tree survived cleanup: {sorted(p.name for p in temp_dir.rglob('*'))}"
    assert sandbox.held_paths() == (None, None, None, None)


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_name", [None, "never_created"], ids=["no-temp-dir", "temp-dir-not-on-disk"])
async def test_cleanup_without_a_directory_still_forgets_every_path(tmp_path: Path, missing_name: str | None) -> None:
    """Cleanup of a sandbox with no directory on disk touches nothing and still resets its paths.

    Args:
        tmp_path: Workspace holding a neighbor file that must survive.
        missing_name: Name of a temporary directory that was never created, or None for no directory at all.
    """
    neighbor = tmp_path / "neighbor.txt"
    neighbor.write_text("keep", encoding="utf-8")
    temp_dir = None if missing_name is None else tmp_path / missing_name
    sandbox = _Probe()
    sandbox.arm(temp_dir=temp_dir, shared_folder=tmp_path / "s", monitor_folder=tmp_path / "m", wsb_path=tmp_path / "x.wsb")

    await sandbox.run_cleanup()

    assert neighbor.read_text(encoding="utf-8") == "keep"
    assert sandbox.held_paths() == (None, None, None, None)


@pytest.mark.asyncio
async def test_cleanup_continues_past_an_entry_it_cannot_delete(tmp_path: Path) -> None:
    """One undeletable file does not stop the rest of the tree from being removed.

    A file held open without delete sharing cannot be unlinked on Windows. Cleanup has to report that entry
    and keep going, not abort at the first refusal and leave the whole tree.

    Args:
        tmp_path: Workspace standing in for the sandbox temporary directory.
    """
    temp_dir = tmp_path / "intellicrack_sandbox_locked"
    (temp_dir / "c_dir").mkdir(parents=True)
    locked = temp_dir / "a_locked.bin"
    locked.write_bytes(b"held")
    (temp_dir / "b_free.txt").write_text("free", encoding="utf-8")
    (temp_dir / "c_dir" / "d_free.txt").write_text("free", encoding="utf-8")
    sandbox = _Probe()
    sandbox.arm(temp_dir=temp_dir, shared_folder=temp_dir / "s")

    with locked.open("r+b"):
        with pytest.raises(PermissionError):
            locked.unlink()
        await sandbox.run_cleanup()

        assert locked.exists(), "the file held open was reported deleted"
        assert not (temp_dir / "b_free.txt").exists(), "a deletable sibling was left behind"
        assert not (temp_dir / "c_dir").exists(), "a deletable subtree was left behind"
        assert sandbox.held_paths() == (None, None, None, None)


@pytest.mark.asyncio
async def test_run_command_refuses_when_the_sandbox_is_not_running(tmp_path: Path) -> None:
    """A command is rejected before anything is staged when the sandbox is down.

    Args:
        tmp_path: Workspace standing in for the shared folder.
    """
    sandbox = _Probe()
    sandbox.arm(shared_folder=tmp_path)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.run_command("echo hi")

    assert str(excinfo.value) == _ERR_NOT_RUNNING
    assert not isinstance(excinfo.value, SandboxTimeoutError)
    assert _entries(tmp_path) == [], "a command was staged for a sandbox that is not running"


@pytest.mark.asyncio
async def test_run_command_needs_an_initialized_shared_folder() -> None:
    """A running sandbox with no shared folder cannot take a command."""
    sandbox = _Probe()
    sandbox.arm(running=True)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.run_command("echo hi")

    assert str(excinfo.value) == _ERR_NO_SHARED


@pytest.mark.asyncio
async def test_run_command_times_out_and_removes_its_trigger_file(tmp_path: Path) -> None:
    """With no dispatcher answering, the command times out and leaves no trigger behind.

    Args:
        tmp_path: Workspace standing in for the shared folder.
    """
    sandbox = _Probe()
    sandbox.arm(shared_folder=tmp_path, running=True)

    with pytest.raises(SandboxTimeoutError) as excinfo:
        await sandbox.run_command("echo hi", time_limit=_COMMAND_LIMIT_S)

    assert str(excinfo.value) == "Command timed out"
    assert _triggers(tmp_path) == [], "the unanswered trigger file was left for the next run"


@pytest.mark.asyncio
async def test_an_unreadable_result_is_polled_past_and_an_undeletable_ticket_does_not_mask_the_timeout(tmp_path: Path) -> None:
    """A result that cannot be read keeps the wait going, and a ticket that cannot be removed is only logged.

    The planted directory exists at the result path, so the poll sees a result and fails to read it, then
    keeps polling until the deadline. When the run ends, the cleanup cannot unlink that path either. The
    caller must still receive the timeout, not the cleanup failure.

    Args:
        tmp_path: Workspace standing in for the shared folder.
    """
    sandbox = _Probe()
    sandbox.arm(shared_folder=tmp_path, running=True)
    watcher = asyncio.create_task(_plant_unreadable_result(tmp_path))
    try:
        with pytest.raises(SandboxTimeoutError) as excinfo:
            await sandbox.run_command("echo hi", time_limit=_PLANTED_LIMIT_S)
        planted = await asyncio.wait_for(watcher, timeout=_WATCH_BUDGET_S)
    finally:
        if not watcher.done():
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)

    assert str(excinfo.value) == "Command timed out"
    assert planted.is_dir(), "the unreadable result path was removed, so the failing cleanup branch was not reached"
    assert _triggers(tmp_path) == []
    planted.rmdir()


@pytest.mark.asyncio
async def test_run_binary_refuses_when_the_sandbox_is_not_running(tmp_path: Path) -> None:
    """A binary is rejected before anything is staged when the sandbox is down.

    Args:
        tmp_path: Workspace holding the binary and the shared folder.
    """
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    shared = tmp_path / "shared"
    sandbox = _Probe()
    sandbox.arm(shared_folder=shared)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.run_binary(binary, monitor=False)

    assert str(excinfo.value) == _ERR_NOT_RUNNING
    assert not shared.exists(), "the binary was staged for a sandbox that is not running"


@pytest.mark.asyncio
async def test_run_binary_rejects_a_binary_that_does_not_exist(tmp_path: Path) -> None:
    """A path with no file behind it is reported as such, not run.

    Args:
        tmp_path: Workspace standing in for the shared folder.
    """
    sandbox = _Probe()
    sandbox.arm(shared_folder=tmp_path, running=True)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.run_binary(tmp_path / "absent.exe", monitor=False)

    assert str(excinfo.value) == "Binary not found"
    assert _entries(tmp_path) == []


@pytest.mark.asyncio
async def test_run_binary_needs_an_initialized_shared_folder(tmp_path: Path) -> None:
    """A running sandbox with no shared folder cannot take a binary.

    Args:
        tmp_path: Workspace holding the binary.
    """
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    sandbox = _Probe()
    sandbox.arm(running=True)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.run_binary(binary, monitor=False)

    assert str(excinfo.value) == _ERR_NO_SHARED


@pytest.mark.asyncio
async def test_run_binary_reports_a_timeout_and_leaves_monitor_logs_alone_when_unmonitored(tmp_path: Path) -> None:
    """A run nothing answers is reported as a timeout, and an unmonitored run keeps the existing logs.

    Args:
        tmp_path: Workspace holding the binary and the shared folder.
    """
    payload = b"MZ" + bytes(range(16))
    binary = tmp_path / "sample.exe"
    binary.write_bytes(payload)
    shared = tmp_path / "shared"
    (shared / "logs").mkdir(parents=True)
    existing_log = shared / "logs" / "file_monitor.log"
    existing_log.write_text(_STALE_FILE_LOG_LINE, encoding="utf-8")
    sandbox = _Probe()
    sandbox.arm(shared_folder=shared, running=True)

    report = await sandbox.run_binary(binary, args=["--flag", "value"], time_limit=_COMMAND_LIMIT_S, monitor=False)

    assert report.result == "timeout"
    assert report.exit_code == -1
    assert not report.stdout
    assert report.stderr == "Command timed out"
    assert (shared / "input" / "sample.exe").read_bytes() == payload
    assert existing_log.read_text(encoding="utf-8") == _STALE_FILE_LOG_LINE, "an unmonitored run cleared the monitor logs"


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_run_binary_reports_an_error_when_the_launcher_died(tmp_path: Path, children: list[Popen[bytes]]) -> None:
    """A launcher that exited non-zero fails the run with that reason, not a timeout.

    Args:
        tmp_path: Workspace holding the binary and the shared folder.
        children: Registry that reaps the stand-in launcher.
    """
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    shared = tmp_path / "shared"
    shared.mkdir()
    launcher = _spawn(_DEAD_LAUNCHER_SCRIPT, children)
    assert launcher.wait(timeout=_KILL_WAIT_S) == 3
    sandbox = _Probe()
    sandbox.arm(shared_folder=shared, running=True)
    sandbox.use_process(launcher)

    report = await sandbox.run_binary(binary, time_limit=_COMMAND_LIMIT_S, monitor=False)

    assert report.result == "error"
    assert report.exit_code == -1
    assert not report.stdout
    assert report.stderr == "Windows Sandbox terminated unexpectedly"


@pytest.mark.asyncio
async def test_a_monitored_run_clears_old_logs_waits_for_the_fleet_and_collects(tmp_path: Path) -> None:
    """A monitored run discards the previous run's logs and gives the collectors time before reading.

    With no ``monitors.pids`` record there is no fleet to wait for by name, so the wait has to cover the
    longest gap between two collectors' first records, which was measured at sixteen seconds. The stale
    file-monitor log must not reach the report.

    Args:
        tmp_path: Workspace holding the binary and the shared folder.
    """
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    shared = tmp_path / "shared"
    logs = shared / "logs"
    logs.mkdir(parents=True)
    stale = logs / "file_monitor.log"
    stale.write_text(_STALE_FILE_LOG_LINE, encoding="utf-8")
    note = logs / "readme.txt"
    note.write_text("not a log", encoding="utf-8")
    sandbox = _Probe()
    sandbox.arm(shared_folder=shared, running=True)

    started = time.monotonic()
    report = await sandbox.run_binary(binary, time_limit=_COMMAND_LIMIT_S)
    elapsed = time.monotonic() - started

    assert report.result == "timeout"
    assert report.file_changes == [], f"the previous run's file log reached the report: {report.file_changes}"
    assert not stale.exists()
    assert note.read_text(encoding="utf-8") == "not a log"
    assert elapsed > _LARGEST_MEASURED_ARRIVAL_GAP_S, f"the collector wait returned after {elapsed:.1f}s, inside the measured arrival gap"


@pytest.mark.asyncio
async def test_resetting_logs_without_a_shared_folder_or_logs_folder_does_nothing(tmp_path: Path) -> None:
    """Resetting the monitor logs is a no-op when there is nowhere they could be.

    Args:
        tmp_path: Workspace standing in for a shared folder with no ``logs`` directory.
    """
    unarmed = _Probe()
    await unarmed.reset_monitor_logs()

    sandbox = _Probe()
    sandbox.arm(shared_folder=tmp_path)
    await sandbox.reset_monitor_logs()

    assert _entries(tmp_path) == []


@pytest.mark.asyncio
async def test_resetting_logs_removes_only_the_top_level_log_files(tmp_path: Path) -> None:
    """Only ``*.log`` files directly under ``logs`` are cleared; everything else is kept.

    Args:
        tmp_path: Workspace standing in for the shared folder.
    """
    logs = tmp_path / "logs"
    (logs / "nested").mkdir(parents=True)
    (logs / "file_monitor.log").write_text("a", encoding="utf-8")
    (logs / "network_monitor.log").write_text("b", encoding="utf-8")
    (logs / "monitors.pids").write_text("1 file_monitor.ps1", encoding="utf-8")
    (logs / "nested" / "deep.log").write_text("c", encoding="utf-8")
    sandbox = _Probe()
    sandbox.arm(shared_folder=tmp_path)

    await sandbox.reset_monitor_logs()

    assert _entries(logs) == ["monitors.pids", "nested"]
    assert (logs / "nested" / "deep.log").exists()


@pytest.mark.asyncio
async def test_resetting_logs_skips_a_log_it_cannot_delete_and_clears_the_rest(tmp_path: Path) -> None:
    """A log held open elsewhere is left in place and does not stop the others being cleared.

    Args:
        tmp_path: Workspace standing in for the shared folder.
    """
    logs = tmp_path / "logs"
    logs.mkdir()
    held = logs / "a_held.log"
    held.write_text("busy", encoding="utf-8")
    free = logs / "b_free.log"
    free.write_text("idle", encoding="utf-8")
    sandbox = _Probe()
    sandbox.arm(shared_folder=tmp_path)

    with held.open("r+b"):
        with pytest.raises(PermissionError):
            held.unlink()
        await sandbox.reset_monitor_logs()

        assert held.exists()
        assert not free.exists(), "a deletable log was left behind because an earlier one was held"


def test_survivors_are_empty_without_a_shared_folder_or_a_pid_file(tmp_path: Path) -> None:
    """With no launcher record to read there are no named survivors.

    Args:
        tmp_path: Workspace standing in for a shared folder with no ``logs`` directory.
    """
    assert _Probe().surviving_collectors() == set()

    sandbox = _Probe()
    sandbox.arm(shared_folder=tmp_path)
    assert sandbox.surviving_collectors() == set()


def test_survivors_are_the_script_stems_of_well_formed_records(tmp_path: Path) -> None:
    """Each ``<pid> <script>`` line names one survivor by script stem; malformed lines name none.

    Args:
        tmp_path: Workspace standing in for the shared folder.
    """
    logs = tmp_path / "logs"
    logs.mkdir()
    records = [
        "101 file_monitor.ps1",
        "102",
        "103 .",
        "104 C:\\Scripts\\network_monitor.ps1",
        "105 my monitor.ps1",
        "",
    ]
    (logs / "monitors.pids").write_text("\n".join(records), encoding="utf-8")
    sandbox = _Probe()
    sandbox.arm(shared_folder=tmp_path)

    assert sandbox.surviving_collectors() == {"file_monitor", "network_monitor", "my monitor"}


def test_no_collector_reports_without_a_shared_folder() -> None:
    """Without a shared folder no expected collector can have a log."""
    assert _Probe().collectors_reporting({"file_monitor"}) == set()


@pytest.mark.asyncio
async def test_waiting_for_the_fleet_without_a_shared_folder_returns_at_once() -> None:
    """With no shared folder there is nothing to wait on, so the wait ends without sleeping."""
    started = time.monotonic()
    await _Probe().wait_for_monitor_quiescence()

    assert time.monotonic() - started < _LARGEST_MEASURED_ARRIVAL_GAP_S


@pytest.mark.asyncio
async def test_waiting_for_the_dispatcher_needs_a_shared_folder() -> None:
    """The readiness wait refuses to start when it has no folder to watch."""
    with pytest.raises(SandboxError) as excinfo:
        await _Probe().wait_for_dispatcher_ready()

    assert str(excinfo.value) == _ERR_NO_SHARED


def test_startup_progress_is_unknown_without_a_shared_folder() -> None:
    """Without a shared folder neither the logon nor any monitor can have left evidence."""
    assert _Probe().progress_markers() == (False, False)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("with_wsb", "with_shared"),
    [(False, False), (True, False), (False, True)],
    ids=["neither", "wsb-only", "shared-only"],
)
async def test_the_wsb_config_needs_both_the_wsb_path_and_the_shared_folder(tmp_path: Path, *, with_wsb: bool, with_shared: bool) -> None:
    """The configuration is not written unless both of its paths are known.

    Args:
        tmp_path: Workspace for the paths that are set.
        with_wsb: Whether the ``.wsb`` path is set.
        with_shared: Whether the shared folder is set.
    """
    wsb = tmp_path / "intellicrack.wsb"
    sandbox = _Probe()
    sandbox.arm(wsb_path=wsb if with_wsb else None, shared_folder=tmp_path / "shared" if with_shared else None)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.generate_wsb_config()

    assert str(excinfo.value) == _ERR_NO_PATHS
    assert not wsb.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("with_monitor", "with_shared"),
    [(False, False), (True, False), (False, True)],
    ids=["neither", "monitor-only", "shared-only"],
)
async def test_dispatcher_scripts_need_both_the_monitor_and_shared_folders(
    tmp_path: Path,
    *,
    with_monitor: bool,
    with_shared: bool,
) -> None:
    """The dispatcher and bootstrap are not staged unless both folders are known.

    Args:
        tmp_path: Workspace for the folders that are set.
        with_monitor: Whether the monitor folder is set.
        with_shared: Whether the shared folder is set.
    """
    monitor = tmp_path / "monitor"
    shared = tmp_path / "shared"
    monitor.mkdir()
    shared.mkdir()
    sandbox = _Probe()
    sandbox.arm(monitor_folder=monitor if with_monitor else None, shared_folder=shared if with_shared else None)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.create_dispatcher_scripts()

    assert str(excinfo.value) == _ERR_NO_PATHS
    assert _entries(monitor) == []
    assert _entries(shared) == []


@pytest.mark.asyncio
async def test_monitor_scripts_need_the_monitor_folder(tmp_path: Path) -> None:
    """Monitor staging refuses to run without a destination.

    Args:
        tmp_path: Workspace that must stay empty.
    """
    sandbox = _Probe()
    sandbox.arm(shared_folder=tmp_path)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.create_monitor_scripts()

    assert str(excinfo.value) == _ERR_NO_PATHS
    assert _entries(tmp_path) == []


@pytest.mark.asyncio
async def test_inline_monitors_are_not_written_without_a_monitor_folder(tmp_path: Path) -> None:
    """Writing the baseline monitors is skipped, not attempted, when there is no destination.

    Args:
        tmp_path: Workspace that must stay empty.
    """
    sandbox = _Probe()
    sandbox.arm(shared_folder=tmp_path)

    await sandbox.emit_inline_monitors()

    assert _entries(tmp_path) == []
    assert sandbox.held_paths()[2] is None


def test_the_bootstrap_sets_configured_variables_before_it_starts_the_dispatcher() -> None:
    """Each configured variable is set for the guest, ahead of the dispatcher that must inherit it."""
    config = SandboxConfig(environment_variables={"IC_ALPHA": "one", "IC_QUOTED": 'say "hi"'})
    lines = _Probe(config).bootstrap_source().split("\r\n")

    logon = next(i for i, line in enumerate(lines) if line.startswith("echo logon_started"))
    dispatcher = next(i for i, line in enumerate(lines) if line.startswith('start "" /B powershell.exe'))
    persistent_alpha = lines.index('setx IC_ALPHA "one" >nul 2>&1')
    current_alpha = lines.index('set "IC_ALPHA=one"')
    persistent_quoted = lines.index('setx IC_QUOTED "say ""hi""" >nul 2>&1')

    assert logon < persistent_alpha < current_alpha < dispatcher
    assert logon < persistent_quoted < dispatcher


def test_the_bootstrap_sets_no_variables_when_none_are_configured() -> None:
    """With no configured variables the bootstrap persists and sets nothing."""
    source = _Probe().bootstrap_source()

    assert "setx" not in source
    assert 'set "' not in source


@pytest.mark.asyncio
async def test_copy_to_sandbox_needs_an_initialized_shared_folder(tmp_path: Path) -> None:
    """Copying in is refused when there is no shared folder to copy into.

    Args:
        tmp_path: Workspace holding the source file.
    """
    source = tmp_path / "payload.bin"
    source.write_bytes(b"data")

    with pytest.raises(SandboxError) as excinfo:
        await _Probe().copy_to_sandbox(source, "input\\payload.bin")

    assert str(excinfo.value) == _ERR_NO_SHARED


@pytest.mark.asyncio
async def test_copy_to_sandbox_rejects_a_missing_source(tmp_path: Path) -> None:
    """Copying in a file that does not exist fails with a clear reason and writes nothing.

    Args:
        tmp_path: Workspace standing in for the shared folder.
    """
    sandbox = _Probe()
    sandbox.arm(shared_folder=tmp_path)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.copy_to_sandbox(tmp_path / "absent.bin", "input\\absent.bin")

    assert str(excinfo.value) == "Source file not found"
    assert _entries(tmp_path) == []


@pytest.mark.asyncio
async def test_copy_to_sandbox_reports_a_source_that_cannot_be_copied(tmp_path: Path) -> None:
    """A source that exists but is not a copyable file is reported as a failed copy, with the cause kept.

    Args:
        tmp_path: Workspace holding a directory used as the source.
    """
    shared = tmp_path / "shared"
    shared.mkdir()
    source = tmp_path / "a_directory"
    source.mkdir()
    sandbox = _Probe()
    sandbox.arm(shared_folder=shared)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.copy_to_sandbox(source, "input\\a_directory")

    assert str(excinfo.value) == "Failed to copy file to sandbox"
    assert isinstance(excinfo.value.__cause__, OSError)


@pytest.mark.asyncio
async def test_copy_from_sandbox_needs_an_initialized_shared_folder(tmp_path: Path) -> None:
    """Copying out is refused when there is no shared folder to copy from.

    Args:
        tmp_path: Workspace for the destination that must not be created.
    """
    destination = tmp_path / "out" / "result.bin"

    with pytest.raises(SandboxError) as excinfo:
        await _Probe().copy_from_sandbox("output\\result.bin", destination)

    assert str(excinfo.value) == _ERR_NO_SHARED
    assert not destination.parent.exists()


@pytest.mark.asyncio
async def test_copy_from_sandbox_rejects_a_missing_source(tmp_path: Path) -> None:
    """Copying out a file the sandbox does not have fails with a clear reason and writes nothing.

    Args:
        tmp_path: Workspace standing in for the shared folder and the destination.
    """
    shared = tmp_path / "shared"
    shared.mkdir()
    destination = tmp_path / "out" / "result.bin"
    sandbox = _Probe()
    sandbox.arm(shared_folder=shared)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.copy_from_sandbox("output\\absent.bin", destination)

    assert str(excinfo.value) == "Source file not found in sandbox"
    assert not destination.parent.exists()


@pytest.mark.asyncio
async def test_copy_from_sandbox_copies_the_file_and_creates_the_destination_folders(tmp_path: Path) -> None:
    """A file in the shared folder arrives byte for byte, in destination folders created on demand.

    Args:
        tmp_path: Workspace standing in for the shared folder and the destination.
    """
    shared = tmp_path / "shared"
    (shared / "output").mkdir(parents=True)
    payload = bytes(range(256))
    (shared / "output" / "result.bin").write_bytes(payload)
    destination = tmp_path / "out" / "nested" / "result.bin"
    sandbox = _Probe()
    sandbox.arm(shared_folder=shared)

    await sandbox.copy_from_sandbox("output\\result.bin", destination)

    assert destination.read_bytes() == payload


@pytest.mark.asyncio
async def test_copy_from_sandbox_reports_a_source_that_cannot_be_copied(tmp_path: Path) -> None:
    """A guest path that is a directory is reported as a failed copy, with the cause kept.

    Args:
        tmp_path: Workspace standing in for the shared folder and the destination.
    """
    shared = tmp_path / "shared"
    (shared / "output" / "a_directory").mkdir(parents=True)
    sandbox = _Probe()
    sandbox.arm(shared_folder=shared)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.copy_from_sandbox("output\\a_directory", tmp_path / "out" / "copied")

    assert str(excinfo.value) == "Failed to copy file from sandbox"
    assert isinstance(excinfo.value.__cause__, OSError)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("running", "with_shared", "message"),
    [(False, True, _ERR_NOT_RUNNING), (True, False, _ERR_NO_SHARED)],
    ids=["not-running", "no-shared-folder"],
)
async def test_start_pcap_capture_refuses_until_the_sandbox_is_ready(
    tmp_path: Path,
    *,
    running: bool,
    with_shared: bool,
    message: str,
) -> None:
    """A capture cannot be started on a stopped sandbox or one with no shared folder.

    Args:
        tmp_path: Workspace standing in for the shared folder.
        running: Whether the sandbox state reads ``running``.
        with_shared: Whether the shared folder is set.
        message: Error text expected for this state.
    """
    sandbox = _Probe()
    sandbox.arm(shared_folder=tmp_path if with_shared else None, running=running)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.start_pcap_capture()

    assert str(excinfo.value) == message
    assert _entries(tmp_path) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("running", "with_shared", "message"),
    [
        (False, True, _ERR_NOT_RUNNING),
        (True, False, _ERR_NO_SHARED),
        (True, True, "No active packet capture with this ID"),
    ],
    ids=["not-running", "no-shared-folder", "unknown-capture"],
)
async def test_stop_pcap_capture_refuses_until_there_is_a_capture_to_stop(
    tmp_path: Path,
    *,
    running: bool,
    with_shared: bool,
    message: str,
) -> None:
    """A capture cannot be stopped on a stopped sandbox, with no shared folder, or under an unknown id.

    Args:
        tmp_path: Workspace standing in for the shared folder.
        running: Whether the sandbox state reads ``running``.
        with_shared: Whether the shared folder is set.
        message: Error text expected for this state.
    """
    sandbox = _Probe()
    sandbox.arm(shared_folder=tmp_path if with_shared else None, running=running)

    with pytest.raises(SandboxError) as excinfo:
        await sandbox.stop_pcap_capture("pcap_0000000000000000")

    assert str(excinfo.value) == message
    assert _entries(tmp_path) == [], "stopping an unknown capture staged a command"


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_waiting_on_the_launcher_returns_when_it_exits_on_its_own(children: list[Popen[bytes]]) -> None:
    """The launcher's own exit within the budget reads as gone, and its exit code shows nobody killed it.

    Args:
        children: Registry that reaps the stand-in launcher.
    """
    launcher = _spawn(_SHORT_LIVED_SCRIPT, children)
    sandbox = _Probe()
    sandbox.use_process(launcher)

    exited = await sandbox.await_pid_exit(launcher.pid, _EXIT_WAIT_BUDGET_S)

    assert exited
    assert launcher.returncode == _SELF_EXIT_CODE


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_waiting_on_the_launcher_gives_up_when_it_outlives_the_budget(children: list[Popen[bytes]]) -> None:
    """A launcher still running when the budget ends does not read as gone.

    Args:
        children: Registry that reaps the stand-in launcher.
    """
    launcher = _spawn(_LONG_LIVED_SCRIPT, children)
    sandbox = _Probe()
    sandbox.use_process(launcher)
    try:
        exited = await sandbox.await_pid_exit(launcher.pid, _IMPATIENT_BUDGET_S)
        still_running = launcher.poll() is None
    finally:
        launcher.kill()
        launcher.wait()

    assert not exited
    assert still_running, "the launcher exited on its own, so this run cannot show that the wait gave up"


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_force_kill_terminates_the_process_it_is_given(children: list[Popen[bytes]]) -> None:
    """The forced kill ends the named process, and its exit code is not the one it would exit with.

    Args:
        children: Registry that reaps the process if the kill fails.
    """
    victim = _spawn(_LONG_LIVED_SCRIPT, children)

    await _Probe().force_kill(victim.pid)

    assert victim.wait(timeout=_KILL_WAIT_S) != _SELF_EXIT_CODE
    assert victim.returncode is not None


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_a_process_with_no_visible_window_is_not_closed_gracefully(children: list[Popen[bytes]]) -> None:
    """With no window to post a close to, the graceful close reports failure and leaves the process alone.

    Args:
        children: Registry that reaps the child.
    """
    child = _spawn(_LONG_LIVED_SCRIPT, children)

    closed = await _Probe().try_graceful_close(child.pid)

    assert closed is False
    assert child.poll() is None, "the graceful close ended a process that owns no window"


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_hidden_windows_elsewhere_do_not_make_a_windowless_process_closable(children: list[Popen[bytes]]) -> None:
    """A hidden window on the desktop, owned by another process, is not a close target for this one.

    Args:
        children: Registry that reaps the child.
    """
    child = _spawn(_LONG_LIVED_SCRIPT, children)
    hwnd = _create_hidden_window()
    try:
        closed = await _Probe().try_graceful_close(child.pid)
    finally:
        if hwnd:
            _destroy_window(hwnd)

    assert closed is False
    assert child.poll() is None


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_no_vmwp_worker_means_no_worker_pid() -> None:
    """With no Hyper-V worker process on the machine, the lookup gives up and reports none."""
    worker = await asyncio.wait_for(_Probe().resolve_worker_pid(), timeout=_WORKER_LOOKUP_CEILING_S)

    assert worker is None
