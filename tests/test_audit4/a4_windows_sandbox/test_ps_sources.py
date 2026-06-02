# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Runtime gates for the inline PowerShell monitor and dispatcher sources.

The :class:`~intellicrack.sandbox.windows.WindowsSandbox` emits inline
PowerShell scripts for the file, process, registry, and network monitors and
the in-guest command dispatcher. Audit-4 (F-0008, F-0017, F-0018, F-0019)
recorded defective patterns in these scripts. Rather than string-matching the
generated source, these tests execute the real generated scripts with ``pwsh``
against real operating-system events (a self-created file under a watched root,
a self-spawned process, a real loopback TCP listener, a real typed registry
value, and a real dispatched command) and assert the exact telemetry the
scripts produce. A regression in any covered pattern (``$using:`` scope binding,
shadowing the ``$pid`` automatic variable, hardcoded ``REG_SZ`` typing, or a
silent dispatcher catch block) makes the corresponding script stop producing
the asserted output, turning the test red.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import socket
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from collections.abc import Callable, Generator


_PWSH: str | None = shutil.which("pwsh")
_CMD_EXE: str = shutil.which("cmd") or r"C:\Windows\System32\cmd.exe"

pytestmark = pytest.mark.skipif(
    _PWSH is None,
    reason="PowerShell 7 (pwsh) is required to execute the generated monitor scripts",
)

_WATCHED_ROOT = Path(r"C:\Users\Public")
_POLL_INTERVAL_S = 0.1
_EVENT_SETTLE_S = 4.0
_MONITOR_DEADLINE_S = 25.0


def _pwsh_path() -> str:
    """Return the resolved path to the ``pwsh`` executable.

    Returns:
        str: Absolute path to PowerShell 7.

    Raises:
        RuntimeError: If ``pwsh`` could not be located (should be guarded by skip).
    """
    if _PWSH is None:
        msg = "pwsh executable not available"
        raise RuntimeError(msg)
    return _PWSH


def _monitor_source(method_name: str) -> str:
    """Return the PowerShell source produced by a ``WindowsSandbox`` static builder.

    The inline monitor source builders are non-public; resolving them via
    ``getattr`` exercises the real implementation without binding to a protected
    attribute at the type level.

    Args:
        method_name: Name of the static source method (for example
            ``"_process_monitor_source"``).

    Returns:
        str: The PowerShell script source text.
    """
    builder: Callable[[], str] = getattr(WindowsSandbox, method_name)
    return builder()


def _dispatcher_source(sandbox: WindowsSandbox) -> str:
    """Return the in-guest dispatcher source for a sandbox instance.

    Args:
        sandbox: The :class:`WindowsSandbox` whose dispatcher source is built.

    Returns:
        str: The PowerShell dispatcher script source text.
    """
    method_name = "_dispatcher_ps1_source"
    builder: Callable[[], str] = getattr(sandbox, method_name)
    return builder()


def _run_pwsh_script(script_path: Path, log_dir: Path) -> subprocess.Popen[bytes]:
    """Launch a monitor script as a detached ``pwsh`` process.

    Args:
        script_path: Path to the ``.ps1`` script to run.
        log_dir: Directory passed as the ``-LogDir`` argument.

    Returns:
        subprocess.Popen[bytes]: The running PowerShell process.
    """
    return subprocess.Popen(
        [
            _pwsh_path(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
            "-LogDir",
            str(log_dir),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _terminate(proc: subprocess.Popen[bytes]) -> None:
    """Terminate a child process and wait for it to exit.

    Args:
        proc: The process to stop.
    """
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


@contextlib.contextmanager
def _running_monitor(script_path: Path, log_dir: Path) -> Generator[subprocess.Popen[bytes]]:
    """Run a monitor script for the duration of the context, terminating on exit.

    Args:
        script_path: Path to the ``.ps1`` monitor script.
        log_dir: Directory passed as the ``-LogDir`` argument.

    Yields:
        Generator[subprocess.Popen[bytes]]: The running PowerShell process.
    """
    proc = _run_pwsh_script(script_path, log_dir)
    try:
        yield proc
    finally:
        _terminate(proc)


@contextlib.contextmanager
def _running_child(cmd_tail: str) -> Generator[subprocess.Popen[bytes]]:
    """Spawn a real ``cmd.exe`` child for the context, killing it on exit.

    Args:
        cmd_tail: The command string passed to ``cmd.exe /c``.

    Yields:
        Generator[subprocess.Popen[bytes]]: The running child process.
    """
    child = subprocess.Popen(
        [_CMD_EXE, "/c", cmd_tail],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield child
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)


@contextlib.contextmanager
def _temp_paths(*paths: Path) -> Generator[None]:
    """Ensure the given filesystem paths are removed when the context exits.

    Args:
        *paths: Paths to delete on exit if they still exist.

    Yields:
        None: Nothing; this manager exists only for its cleanup side effect.
    """
    try:
        yield
    finally:
        for leftover in paths:
            if leftover.exists():
                leftover.unlink()


def _wait_for_log_line(log_file: Path, needle: str, deadline_s: float) -> list[str]:
    """Poll a log file until a line containing ``needle`` appears or time runs out.

    Args:
        log_file: Path to the monitor log file.
        needle: Substring that must appear in at least one log line.
        deadline_s: Maximum wall-clock time to wait, in seconds.

    Returns:
        list[str]: All log lines that contain ``needle`` (possibly empty if the
        deadline elapsed first).
    """
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        if log_file.exists():
            matched = [line for line in log_file.read_text(encoding="utf-8").splitlines() if needle in line]
            if matched:
                return matched
        time.sleep(_POLL_INTERVAL_S)
    if log_file.exists():
        return [line for line in log_file.read_text(encoding="utf-8").splitlines() if needle in line]
    return []


def _write_script(directory: Path, name: str, source: str) -> Path:
    """Write a monitor source to a ``.ps1`` file and return its path.

    Args:
        directory: Directory to write into.
        name: File name for the script.
        source: PowerShell source text.

    Returns:
        Path: Path to the written script.
    """
    script_path = directory / name
    script_path.write_text(source, encoding="utf-8")
    return script_path


@pytest.fixture
def monitor_workspace(tmp_path: Path) -> tuple[Path, Path]:
    """Provide a script directory and a fresh log directory for a monitor run.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        tuple[Path, Path]: ``(script_dir, log_dir)`` for the test.
    """
    script_dir = tmp_path / "scripts"
    log_dir = tmp_path / "logs"
    script_dir.mkdir()
    log_dir.mkdir()
    return script_dir, log_dir


class TestFileMonitorRuntime:
    """Runtime gates for F-0008: file monitor MessageData log routing."""

    def test_self_created_file_event_is_logged_with_exact_path(self, monitor_workspace: tuple[Path, Path]) -> None:
        """Verify a self-created file under a watched root is logged with its exact path.

        Drives a real ``Created`` filesystem event by writing a uniquely named
        file under the public-profile root the monitor watches. The action
        block reaches the log only because the log path is delivered through
        ``-MessageData`` and read via ``$Event.MessageData``; if it instead
        relied on the broken ``$using:`` scope, the action would fail in the
        event runspace and no line would be written.

        Args:
            monitor_workspace: ``(script_dir, log_dir)`` fixture.
        """
        script_dir, log_dir = monitor_workspace
        script = _write_script(script_dir, "file_monitor.ps1", _monitor_source("_file_monitor_source"))
        marker = "ICFILE" + uuid.uuid4().hex
        target = _WATCHED_ROOT / f"{marker}.txt"
        with _running_monitor(script, log_dir), _temp_paths(target):
            time.sleep(_EVENT_SETTLE_S)
            target.write_text("payload-data", encoding="utf-8")
            matched = _wait_for_log_line(log_dir / "file_monitor.log", marker, _MONITOR_DEADLINE_S)
        assert matched, "file monitor produced no log line for the self-created event"
        fields = matched[0].split("|")
        assert fields[1] in {"Created", "Changed"}
        assert fields[2] == str(target)

    def test_renamed_file_event_records_old_and_new_path(self, monitor_workspace: tuple[Path, Path]) -> None:
        """Verify a rename event records both the old and new file paths.

        Args:
            monitor_workspace: ``(script_dir, log_dir)`` fixture.
        """
        script_dir, log_dir = monitor_workspace
        script = _write_script(script_dir, "file_monitor.ps1", _monitor_source("_file_monitor_source"))
        marker = "ICREN" + uuid.uuid4().hex
        src = _WATCHED_ROOT / f"{marker}_old.txt"
        dst = _WATCHED_ROOT / f"{marker}_new.txt"
        with _running_monitor(script, log_dir), _temp_paths(src, dst):
            time.sleep(_EVENT_SETTLE_S)
            src.write_text("data", encoding="utf-8")
            time.sleep(1.0)
            src.rename(dst)
            matched = _wait_for_log_line(log_dir / "file_monitor.log", f"{marker}_new.txt", _MONITOR_DEADLINE_S)
        renamed = [line for line in matched if line.split("|")[1] == "Renamed"]
        assert renamed, "no Renamed entry captured for the rename event"
        fields = renamed[0].split("|")
        assert fields[2] == str(dst)
        assert fields[3] == str(src)


class TestProcessMonitorRuntime:
    """Runtime gates for F-0018: process monitor must not shadow $pid."""

    def test_spawned_process_lifecycle_is_logged(self, monitor_workspace: tuple[Path, Path]) -> None:
        """Verify a self-spawned process is logged with exact PID, command, and lifecycle.

        Spawns a real, uniquely identifiable ``cmd.exe`` process and asserts the
        monitor records a ``created`` then ``terminated`` entry keyed on that
        exact PID. The process-enumeration loop only works because it iterates
        with ``$procId``; using ``$pid`` would raise "Cannot overwrite variable
        PID" and the loop would never capture an arbitrary spawned process.

        Args:
            monitor_workspace: ``(script_dir, log_dir)`` fixture.
        """
        script_dir, log_dir = monitor_workspace
        script = _write_script(script_dir, "process_monitor.ps1", _monitor_source("_process_monitor_source"))
        marker = "ICPROC" + uuid.uuid4().hex
        log_file = log_dir / "process_monitor.log"
        created, terminated, child_pid = self._observe_process_lifecycle(script, log_dir, log_file, marker)
        assert created, "process monitor did not log the spawned process creation"
        created_fields = created[0].split("|")
        assert created_fields[1] == "created"
        assert created_fields[2] == str(child_pid)
        assert created_fields[3] == "cmd.exe"
        assert marker in created_fields[5]
        assert terminated, "process monitor did not log the spawned process termination"
        assert terminated[0].split("|")[1] == "terminated"

    @staticmethod
    def _observe_process_lifecycle(
        script: Path,
        log_dir: Path,
        log_file: Path,
        marker: str,
    ) -> tuple[list[str], list[str], int]:
        """Run the monitor, spawn a marked child, and collect its lifecycle log lines.

        Args:
            script: Path to the staged process-monitor script.
            log_dir: Directory passed to the monitor as ``-LogDir``.
            log_file: Path to the monitor's log file.
            marker: Unique token embedded in the child's command line.

        Returns:
            tuple[list[str], list[str], int]: ``(created_lines, terminated_lines, child_pid)``.
        """
        with _running_monitor(script, log_dir):
            time.sleep(_EVENT_SETTLE_S)
            with _running_child(f"title {marker} & ping -n 5 127.0.0.1 >nul") as child:
                child_pid = child.pid
                created = _wait_for_log_line(log_file, f"|created|{child_pid}|", _MONITOR_DEADLINE_S)
                child.wait(timeout=20)
            terminated = _wait_for_log_line(log_file, f"|terminated|{child_pid}|", _MONITOR_DEADLINE_S)
        return created, terminated, child_pid

    def test_pid_automatic_variable_is_not_shadowed(self, monitor_workspace: tuple[Path, Path]) -> None:
        """Verify the monitor body never assigns to the read-only $pid automatic variable.

        Re-runs the exact process-monitor body once (loop unrolled to a single
        pass) under ``Set-StrictMode`` with terminating errors. If the source
        assigned to ``$pid``, PowerShell raises "Cannot overwrite variable PID
        because it is read-only or constant" and the harness exits non-zero with
        that message. A clean exit proves the automatic variable is untouched.

        Args:
            monitor_workspace: ``(script_dir, log_dir)`` fixture.
        """
        script_dir, log_dir = monitor_workspace
        source = _monitor_source("_process_monitor_source")
        single_pass = source.replace("while ($true) {", "for ($__once = 0; $__once -lt 1; $__once++) {")
        single_pass = single_pass.replace("Start-Sleep -Seconds 1\n}", "}\n")
        param_line, body = single_pass.split("\n", 1)
        probe_setup = "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n$__initialPid = $PID\n"
        harness = param_line + "\n" + probe_setup + body
        harness += '\nif ($PID -ne $__initialPid) { throw "PID automatic variable was mutated" }\n'
        harness += '"OK_PID_INTACT"\n'
        script = _write_script(script_dir, "pid_probe.ps1", harness)
        completed = subprocess.run(
            [
                _pwsh_path(),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
                "-LogDir",
                str(log_dir),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert "Cannot overwrite variable PID" not in completed.stderr
        assert "PID automatic variable was mutated" not in completed.stderr
        assert completed.returncode == 0, f"process-monitor body errored: {completed.stderr.strip()}"
        assert "OK_PID_INTACT" in completed.stdout


class TestNetworkMonitorRuntime:
    """Runtime gates for the network monitor: owning-PID attribution via $ownerPid."""

    def test_real_tcp_listener_is_logged_with_owner_pid(self, monitor_workspace: tuple[Path, Path]) -> None:
        """Verify a real loopback TCP listener is attributed to the owning process.

        Opens a real listening socket on an ephemeral loopback port and asserts
        the monitor logs a ``listen`` entry for that exact port carrying the
        owning PID. The connection enumeration uses ``$ownerPid`` rather than the
        read-only ``$pid`` automatic variable; shadowing ``$pid`` would error the
        enumeration loop and the listener would never be recorded.

        Args:
            monitor_workspace: ``(script_dir, log_dir)`` fixture.
        """
        script_dir, log_dir = monitor_workspace
        script = _write_script(script_dir, "network_monitor.ps1", _monitor_source("_network_monitor_source"))
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        with _running_monitor(script, log_dir), contextlib.closing(listener):
            matched = _wait_for_log_line(log_dir / "network_monitor.log", f":{port}|", _MONITOR_DEADLINE_S)
        listen_lines = [line for line in matched if line.split("|")[1] == "listen" and f"127.0.0.1:{port}" in line]
        assert listen_lines, f"network monitor did not record the loopback listener on port {port}"
        fields = listen_lines[0].split("|")
        assert fields[2] == f"127.0.0.1:{port}"
        assert fields[5] == "tcp"
        assert int(fields[8]) == os.getpid()


class TestRegistryMonitorRuntime:
    """Runtime gates for F-0019: registry monitor records the real value type."""

    def test_get_reg_value_type_reports_real_value_kinds(self, monitor_workspace: tuple[Path, Path]) -> None:
        """Verify the Get-RegValueType helper reports the true RegistryValueKind per value.

        Creates real registry values of four distinct kinds and runs the exact
        ``Get-RegValueType`` function extracted from the production source. The
        independent oracle is the ``PropertyType`` each value was created with.
        The F-0019 fix replaced a hardcoded ``REG_SZ`` with this dynamic lookup;
        a regression to a constant type would mismatch the DWord, Binary, and
        MultiString cases.

        Args:
            monitor_workspace: ``(script_dir, log_dir)`` fixture.
        """
        script_dir, _log_dir = monitor_workspace
        source = _monitor_source("_registry_monitor_source")
        start = source.index("function Get-RegValueType")
        end = source.index("function Snapshot-Values")
        func = source[start:end]

        base = r"HKCU:\SOFTWARE\ICRegTypeTest_" + uuid.uuid4().hex
        setup = (
            f"New-Item -Path '{base}' -Force | Out-Null\n"
            f"New-ItemProperty -Path '{base}' -Name 'DwVal' -Value 7 -PropertyType DWord -Force | Out-Null\n"
            f"New-ItemProperty -Path '{base}' -Name 'SzVal' -Value 'hi' -PropertyType String -Force | Out-Null\n"
            f"New-ItemProperty -Path '{base}' -Name 'BinVal' -Value ([byte[]](1,2,3)) -PropertyType Binary -Force | Out-Null\n"
            f"New-ItemProperty -Path '{base}' -Name 'MultiVal' -Value @('a','b') -PropertyType MultiString -Force | Out-Null\n"
        )
        calls = (
            f"Get-RegValueType -RegPath '{base}' -ValueName 'DwVal'\n"
            f"Get-RegValueType -RegPath '{base}' -ValueName 'SzVal'\n"
            f"Get-RegValueType -RegPath '{base}' -ValueName 'BinVal'\n"
            f"Get-RegValueType -RegPath '{base}' -ValueName 'MultiVal'\n"
            f"Get-RegValueType -RegPath '{base}' -ValueName 'NoSuchValue'\n"
        )
        cleanup = f"[Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree('{base[6:]}')\n"
        script = _write_script(script_dir, "reg_type_probe.ps1", setup + func + "\n" + calls + cleanup)
        completed = subprocess.run(
            [_pwsh_path(), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert completed.returncode == 0, f"registry type probe failed: {completed.stderr.strip()}"
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        assert lines == ["DWord", "String", "Binary", "MultiString", "Unknown"]


class TestDispatcherRuntime:
    """Runtime gates for F-0017: dispatcher executes commands and surfaces errors."""

    def _staged_dispatcher(self, root: Path) -> str:
        """Return dispatcher source with the guest shared path retargeted to ``root``.

        Args:
            root: Host directory to use as the shared dispatcher root.

        Returns:
            str: PowerShell dispatcher source bound to the host directory.
        """
        sandbox = WindowsSandbox(SandboxConfig(timeout_seconds=30))
        return _dispatcher_source(sandbox).replace(WindowsSandbox.SANDBOX_SHARED_PATH, str(root))

    def _wait_for(self, predicate_path: Path, deadline_s: float) -> bool:
        """Wait until a non-empty file exists at ``predicate_path``.

        Args:
            predicate_path: File whose non-empty existence is awaited.
            deadline_s: Maximum wall-clock time to wait, in seconds.

        Returns:
            bool: ``True`` if the file became non-empty before the deadline.
        """
        deadline = time.monotonic() + deadline_s
        while time.monotonic() < deadline:
            if predicate_path.exists() and predicate_path.read_text(encoding="utf-8").strip():
                return True
            time.sleep(_POLL_INTERVAL_S)
        return False

    def test_dispatcher_runs_command_and_records_output_and_exit_code(self, tmp_path: Path) -> None:
        """Verify the dispatcher executes a real command and writes stdout and exit code.

        Stages the real dispatcher against a host temp directory, drops a real
        ``.cmd`` trigger that prints a marker and exits with code 7, and asserts
        the captured stdout and the recorded exit code exactly match.

        Args:
            tmp_path: Pytest temporary directory.
        """
        root = tmp_path / "shared"
        root.mkdir()
        script = _write_script(tmp_path, "dispatcher.ps1", self._staged_dispatcher(root))
        ticket = "tkt" + uuid.uuid4().hex
        result_file = root / "output" / f"{ticket}.result.txt"
        out_file = root / "output" / f"{ticket}.out.txt"
        with _running_dispatcher(script):
            assert self._wait_for(root / "flags" / WindowsSandbox.DISPATCHER_READY_MARKER, 20.0), "dispatcher never signalled ready"
            self._drop_trigger(root, ticket, "@echo off\r\necho HELLO_FROM_DISPATCHER_123\r\nexit /b 7\r\n")
            assert self._wait_for(result_file, 25.0), "dispatcher produced no result file"
        assert result_file.read_text(encoding="utf-8").strip() == "7"
        assert out_file.read_text(encoding="utf-8").strip() == "HELLO_FROM_DISPATCHER_123"

    @staticmethod
    def _drop_trigger(root: Path, ticket: str, body: str) -> None:
        """Write a dispatcher trigger ``.cmd`` file for ``ticket``.

        Args:
            root: The shared dispatcher root directory.
            ticket: Unique ticket identifier.
            body: Batch script body for the trigger.
        """
        (root / "input" / "trigger" / f"{ticket}.cmd").write_text(body, encoding="utf-8")

    def test_dispatcher_catch_block_logs_error(self, tmp_path: Path) -> None:
        """Verify the dispatcher catch block records errors instead of swallowing them.

        Forces a real failure inside the dispatcher ``try`` block by pre-creating
        the per-ticket ``.out.txt`` as a read-only file, so ``Set-Content`` raises
        an access-denied error. The F-0017 fix routes the caught exception
        message to ``dispatcher_errors.log``; a silent catch would leave no log.

        Args:
            tmp_path: Pytest temporary directory.
        """
        root = tmp_path / "shared"
        root.mkdir()
        script = _write_script(tmp_path, "dispatcher.ps1", self._staged_dispatcher(root))
        ticket = "tkt" + uuid.uuid4().hex
        out_file = root / "output" / f"{ticket}.out.txt"
        error_log = root / "output" / "dispatcher_errors.log"
        log_text = self._capture_dispatcher_error(script, root, ticket, out_file, error_log)
        line = next(entry for entry in log_text.splitlines() if entry.strip())
        fields = line.split("|")
        assert fields[1] == "dispatcher_error"
        assert "denied" in fields[2].lower()

    def _capture_dispatcher_error(self, script: Path, root: Path, ticket: str, out_file: Path, error_log: Path) -> str:
        """Run the dispatcher, force a write error, and return the error-log text.

        Args:
            script: Path to the staged dispatcher script.
            root: The shared dispatcher root directory.
            ticket: Unique ticket identifier.
            out_file: Per-ticket stdout file to make read-only.
            error_log: Path to the dispatcher error log.

        Returns:
            str: The contents of the dispatcher error log.
        """
        with _running_dispatcher(script):
            assert self._wait_for(root / "flags" / WindowsSandbox.DISPATCHER_READY_MARKER, 20.0), "dispatcher never signalled ready"
            out_file.write_text("locked", encoding="utf-8")
            out_file.chmod(stat.S_IREAD)
            try:
                self._drop_trigger(root, ticket, "@echo off\r\necho hi\r\n")
                assert self._wait_for(error_log, 25.0), "dispatcher catch block wrote no error log"
                return error_log.read_text(encoding="utf-8")
            finally:
                out_file.chmod(stat.S_IWRITE)


@contextlib.contextmanager
def _running_dispatcher(script_path: Path) -> Generator[subprocess.Popen[bytes]]:
    """Run the dispatcher script for the duration of the context, terminating on exit.

    Args:
        script_path: Path to the dispatcher ``.ps1`` script.

    Yields:
        Generator[subprocess.Popen[bytes]]: The running PowerShell process.
    """
    proc = subprocess.Popen(
        [
            _pwsh_path(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield proc
    finally:
        _terminate(proc)
