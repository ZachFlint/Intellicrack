# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Gate for S17-D80: the Test Sandbox path does not leave a sandbox running.

Pressing Test Sandbox launches a real Windows Sandbox to prove sandboxing
works. The teardown then terminated ``self._process`` - the **launcher** - but
the launcher is fire-and-forget and has normally already exited by then, so
``_terminate_sandbox_process`` returned at its own liveness guard and reaped
nothing. The session host, a separate process that outlives the launcher and
owns the Host Compute Service session, was left running.

Measured live on 2026-08-09: the worker reported ``success=True`` in 0.7 s and
deleted its ``.wsb``, and ``WindowsSandboxRemoteSession.exe`` was still running
afterwards with no owner. The run log carried neither
``sandbox_test_graceful_close_ok`` nor ``sandbox_test_process_terminated``,
which is the guard returning early. Windows Sandbox permits one session at a
time and shares HCS with the QEMU backend and the Docker engine, so a leaked
session denies the machine to every later sandbox operation.

These gates drive the **real** :class:`SandboxTestWorker` against a **real
Windows Sandbox** and judge the outcome with ``Win32_Process``, an oracle
outside the worker entirely: the session is matched by the exact ``.wsb``
filename on its command line, so nothing else on the host can be mistaken for
it. The control proves the environment is one where a session genuinely starts
- otherwise "no session survives" would pass on a host that can create no
sandbox at all, which is the tautology this defect hid behind.

Windows Sandbox needs a working Host Compute Service and cannot exist in the
test container, so these run in the host-native pass and skip where a session
cannot be created.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, cast

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.core.process_manager import pid_is_running
from intellicrack.ui.sandbox_config import SandboxTestWorker


if TYPE_CHECKING:
    from collections.abc import Iterator


_SESSION_EXE: Final[str] = "WindowsSandboxRemoteSession.exe"
_MEMORY_LIMIT_MB: Final[int] = 2048
_WORKER_TIMEOUT_S: Final[float] = 240.0
_REAP_GRACE_S: Final[float] = 30.0
_POLL_S: Final[float] = 0.5
_PS_TIMEOUT_S: Final[float] = 60.0
_SUCCESS: Final[int] = 0


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows Sandbox exists only on Windows",
)


def _powershell() -> str:
    """Locate a PowerShell interpreter for the out-of-band process oracle.

    Returns:
        str: Absolute path to ``pwsh`` or to Windows PowerShell.
    """
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("no PowerShell interpreter is available to query sandbox sessions")
    return shell


def _session_pids_for(wsb_name: str) -> list[int]:
    """List sandbox session PIDs whose command line names ``wsb_name``.

    This does not go through the worker or through
    :func:`find_sandbox_session_pid`, so it cannot agree with a broken
    implementation by sharing its mistake.

    Args:
        wsb_name: Filename of the ``.wsb`` the session was launched from.

    Returns:
        list[int]: PIDs of matching live session processes.
    """
    escaped = wsb_name.replace("'", "''")
    script = (
        "$ErrorActionPreference='Stop';"
        f"@(Get-CimInstance Win32_Process -Filter \"Name='{_SESSION_EXE}'\" |"
        f" Where-Object {{ $_.CommandLine -and $_.CommandLine.Contains('{escaped}') }} |"
        " ForEach-Object { [int]$_.ProcessId }) | ConvertTo-Json -Compress -AsArray"
    )
    completed = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        check=False,
        timeout=_PS_TIMEOUT_S,
    )
    raw = (completed.stdout or "").strip()
    if completed.returncode != _SUCCESS or not raw:
        return []
    parsed: object = json.loads(raw)
    if not isinstance(parsed, list):
        return []
    entries = cast("list[object]", parsed)
    return [entry for entry in entries if isinstance(entry, int)]


class _ObservedTestWorker(SandboxTestWorker):
    """The real worker, with the session it observed exposed to the gate.

    Only reads are added. Every decision under test - locating the session,
    judging success, tearing down - stays the production implementation.

    Attributes:
        captured_session_pid: The session PID production had recorded at the
            moment teardown began, kept because teardown clears it.
    """

    captured_session_pid: int | None

    def __init__(self, *, network_enabled: bool = False, memory_limit_mb: int = _MEMORY_LIMIT_MB) -> None:
        """Build the real worker and add somewhere to keep the observed PID.

        Args:
            network_enabled: Whether networking is enabled in the sandbox.
            memory_limit_mb: Memory limit in MB for the sandbox.
        """
        super().__init__(network_enabled=network_enabled, memory_limit_mb=memory_limit_mb)
        self.captured_session_pid = None

    def observed_wsb_name(self) -> str | None:
        """Return the filename of the ``.wsb`` this run wrote.

        Returns:
            str | None: The configuration filename, or None if none was written.
        """
        return None if self._wsb_file is None else self._wsb_file.name

    def _verify_sandbox_session(self) -> bool:
        """Run the real verification, then record the session it found.

        The capture sits here, immediately after verification and before any
        teardown, for two reasons: the production teardown clears
        ``_session_pid`` and a run can finish in under a second, so sampling
        from outside races it; and anchoring the capture to verification keeps
        it independent of the teardown this gate is testing, so the control
        still reports whether a session started even when the teardown is
        broken. The verification decision itself is untouched.

        Returns:
            bool: Whatever the production implementation decided - True when
            it emitted ``finished`` itself, False when a session was confirmed.
        """
        handled = super()._verify_sandbox_session()
        self.captured_session_pid = self._session_pid
        return handled


@dataclass(frozen=True)
class _WorkerRun:
    """One completed run of the real worker and what it left behind.

    Attributes:
        success: The verdict the worker emitted.
        message: The message the worker emitted.
        wsb_name: Filename of the configuration it launched from.
        session_pid: The session PID it observed while verifying.
    """

    success: bool
    message: str
    wsb_name: str | None
    session_pid: int | None


def _kill_sessions(pids: list[int]) -> None:
    """Force-stop leftover session processes so a run cannot poison the next.

    Args:
        pids: Session PIDs to stop.
    """
    taskkill = shutil.which("taskkill")
    if taskkill is None:
        return
    for pid in pids:
        subprocess.run([taskkill, "/PID", str(pid), "/T", "/F"], capture_output=True, check=False, timeout=_PS_TIMEOUT_S)


@pytest.fixture
def worker_run() -> Iterator[_WorkerRun]:
    """Run the real Test Sandbox worker once and clean up whatever survives.

    The cleanup is the fixture's own, not the worker's: it exists so a failing
    run - which by definition leaks - cannot leave a sandbox holding HCS for
    the rest of the session.

    Yields:
        _WorkerRun: The verdict and the session the worker started.
    """
    app = QApplication.instance() or QApplication([])
    assert app is not None, "a Qt application is required to run the worker thread"

    worker = _ObservedTestWorker(network_enabled=False, memory_limit_mb=_MEMORY_LIMIT_MB)
    verdict: list[tuple[bool, str]] = []

    def record(success: object, message: object) -> None:
        verdict.append((bool(success), str(message)))

    worker.finished.connect(record)

    worker.start()
    deadline = time.monotonic() + _WORKER_TIMEOUT_S
    while worker.isRunning() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(_POLL_S)
    worker.wait(int(_REAP_GRACE_S * 1000))
    app.processEvents()

    assert verdict, "the real Test Sandbox worker never reported a verdict"
    success, message = verdict[0]
    wsb_name = worker.observed_wsb_name()
    observed = worker.captured_session_pid

    try:
        yield _WorkerRun(success=success, message=message, wsb_name=wsb_name, session_pid=observed)
    finally:
        if wsb_name is not None:
            _kill_sessions(_session_pids_for(wsb_name))


class TestTheTestSandboxPathLeavesNoSessionRunning:
    """Test Sandbox must reap the sandbox it started."""

    def test_a_session_really_started(self, worker_run: _WorkerRun) -> None:
        """The control: this host genuinely creates a sandbox session.

        Without this, the leak assertion below would pass on a host where no
        sandbox can be created at all - nothing started, so nothing survives -
        which proves nothing about the teardown.

        Args:
            worker_run: The completed worker run.
        """
        if not worker_run.success:
            pytest.skip(f"this host cannot create a Windows Sandbox session: {worker_run.message}")
        assert worker_run.session_pid is not None, "the worker reported success without ever observing a session"

    def test_no_sandbox_session_survives_the_test(self, worker_run: _WorkerRun) -> None:
        """The Verify: once the test finishes, its sandbox is gone.

        Args:
            worker_run: The completed worker run.
        """
        if not worker_run.success:
            pytest.skip(f"this host cannot create a Windows Sandbox session: {worker_run.message}")
        assert worker_run.wsb_name is not None, "the run wrote no configuration, so nothing is under test"

        deadline = time.monotonic() + _REAP_GRACE_S
        survivors = _session_pids_for(worker_run.wsb_name)
        while survivors and time.monotonic() < deadline:
            time.sleep(_POLL_S)
            survivors = _session_pids_for(worker_run.wsb_name)

        assert not survivors, f"Test Sandbox left a sandbox session running: {survivors}"
        assert worker_run.session_pid is not None
        assert not pid_is_running(worker_run.session_pid), f"the observed session {worker_run.session_pid} is still alive"
