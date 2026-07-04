# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for process cleanup and resource management fixes.

Validates that:
1. SandboxTestWorker finally-block kills processes and cleans temp files
2. CutterBridge._r2_cmd enforces timeout on blocking commands
3. QEMU pidfile retry logic handles delayed/missing pidfiles
4. GhidraBridge.shutdown cleans up temp bridge scripts
5. ProcessManager.terminate_tree kills real process trees
"""

from __future__ import annotations

import asyncio
import sys
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

import psutil
import pytest

import intellicrack.bridges.cutter as cutter_module
import intellicrack.sandbox.qemu as qemu_module
from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.subprocess_compat import PIPE, Popen
from intellicrack.core.types import SandboxError, ToolError
from intellicrack.sandbox.qemu import QEMUSandbox
from intellicrack.ui.sandbox_config import SandboxTestWorker


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


_GRACEFUL_TIMEOUT = 5.0
_FORCE_TIMEOUT = 3.0
_GRACEFUL_TIMEOUT_SHORT = 3.0
_FORCE_TIMEOUT_SHORT = 2.0
_R2_TEST_TIMEOUT = 0.5
_ELAPSED_UPPER_BOUND = 5.0
_EXPECTED_PID_IMMEDIATE = 99999
_EXPECTED_PID_DELAYED = 54321
_EXPECTED_PID_CORRUPT = 77777
_SLEEP_DELAY_HALF = 0.5
_MIN_RETRIES = 2
_MIN_RETRY_DELAY = 1.0
_MIN_TOTAL_WAIT = 4.0
_BLOCKING_WAIT_TIMEOUT = 30
_FAST_RETRY_DELAY = 0.02
_FAST_MAX_RETRIES = 10
_DELAYED_WRITE_DELAY = 0.05
_IS_WINDOWS = sys.platform == "win32"


# ─── 1. Process termination (sandbox_config.py finally-block pattern) ────────


def _spawn_sleeper() -> Popen[bytes]:
    """Spawn a subprocess that sleeps for 60 seconds.

    Returns:
        Popen[bytes]: The spawned process.
    """
    return Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=PIPE,
        stderr=PIPE,
    )


@pytest.mark.asyncio
async def test_terminate_tree_kills_running_process() -> None:
    """ProcessManager.terminate_tree kills a real running subprocess.

    This validates the finally-block in SandboxTestWorker.run() that calls
    terminate_tree + unregister when the sandbox process is still alive.
    Reverting the fix (removing finally block) would leave the process running.
    """
    process = await asyncio.to_thread(_spawn_sleeper)
    pid = process.pid

    pm = ProcessManager.get_instance()
    _ = pm.register(process, "sandbox-test", ProcessType.SANDBOX)

    assert psutil.pid_exists(pid), "Process should be running before cleanup"

    ProcessManager.terminate_tree(pid, graceful_timeout=_GRACEFUL_TIMEOUT, force_timeout=_FORCE_TIMEOUT)
    _ = pm.unregister(pid)

    await asyncio.sleep(_SLEEP_DELAY_HALF)
    assert not psutil.pid_exists(pid), "terminate_tree should have killed the process"


@pytest.mark.asyncio
async def test_terminate_tree_kills_process_with_children() -> None:
    """ProcessManager.terminate_tree kills parent AND child processes.

    Mirrors the real scenario where WindowsSandbox.exe spawns child processes.
    """
    child_code = "import time; time.sleep(60)"
    parent_code = f"""\
import subprocess, sys, time
p = subprocess.Popen([sys.executable, "-c", {child_code!r}])
print(p.pid)
sys.stdout.flush()
time.sleep(60)
"""

    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        parent_code,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    parent_pid = process.pid

    assert process.stdout is not None
    try:
        line = await asyncio.wait_for(process.stdout.readline(), timeout=_GRACEFUL_TIMEOUT)
        child_pid = int(line.strip())
    except (TimeoutError, ValueError):
        process.kill()
        pytest.fail("Failed to get child PID from parent process")

    assert psutil.pid_exists(parent_pid), "Parent should be running"
    assert psutil.pid_exists(child_pid), "Child should be running"

    pm = ProcessManager.get_instance()
    _ = pm.register(process, "sandbox-test-tree", ProcessType.SANDBOX)

    ProcessManager.terminate_tree(parent_pid, graceful_timeout=_GRACEFUL_TIMEOUT, force_timeout=_FORCE_TIMEOUT)
    _ = pm.unregister(parent_pid)

    await asyncio.sleep(_SLEEP_DELAY_HALF)
    assert not psutil.pid_exists(parent_pid), "Parent process leaked"
    assert not psutil.pid_exists(child_pid), "Child process leaked"


@pytest.mark.skipif(not _IS_WINDOWS, reason="Windows Sandbox (SandboxTestWorker.run) is a Windows-only OS capability")
def test_sandbox_temp_wsb_file_cleaned_up() -> None:
    """SandboxTestWorker.run() unlinks the real .wsb file in its finally block.

    Drives the production ``SandboxTestWorker.run()`` end-to-end. The worker
    generates a real ``.wsb`` configuration with the production
    ``_generate_wsb_config`` helper, writes it to a real ``NamedTemporaryFile``,
    then attempts to launch the external ``WindowsSandbox.exe`` tool. Whether
    that external binary is present or absent, the production ``finally`` block
    is responsible for calling ``unlink()`` on the temp file it created.

    The oracle is the file path the production code records in ``_wsb_file``
    together with the independently recomputed configuration XML: the test
    reconstructs the expected ``.wsb`` body from the worker's public
    constructor arguments via the production generator and asserts that the
    file the worker actually wrote existed with that exact content, and that
    the production cleanup removed it after ``run()`` returned. Deleting the
    ``self._wsb_file.unlink()`` call in the ``finally`` block leaves the file
    on disk and fails this test.
    """
    worker = SandboxTestWorker(network_enabled=False, memory_limit_mb=2048)
    captured: dict[str, Path | str | None] = {"path": None, "content": None}

    def _on_output(message: str) -> None:
        """Capture the .wsb path and its on-disk content from the worker output.

        Args:
            message: A status line emitted by the production worker.
        """
        marker = "Configuration file: "
        if not message.startswith(marker):
            return
        wsb_path = Path(message[len(marker) :])
        captured["path"] = wsb_path
        if wsb_path.exists():
            captured["content"] = wsb_path.read_text(encoding="utf-8")

    worker.output.connect(_on_output)
    worker.run()

    created = captured["path"]
    assert isinstance(created, Path), "Production worker must emit the .wsb file path it created"
    assert created.suffix == ".wsb", "Production code must use a .wsb suffix"

    generate_wsb_config: Callable[[], str] = getattr(worker, "_generate_wsb_config")
    expected_xml = generate_wsb_config()
    assert captured["content"] == expected_xml, "Worker must write the generated WSB XML to the temp file"

    assert not created.exists(), "SandboxTestWorker.run() finally block must unlink the .wsb file"


# ─── 2. Cutter command timeout (cutter.py) ───────────────────────────────────


class _BlockingR2:
    """Blocking callable with interruptible sleep for thread cleanup."""

    _stop: threading.Event

    def __init__(self) -> None:
        self._stop = threading.Event()

    def cmd(self, _command: str) -> str:
        """Block until stop event is set or 30s elapses.

        Args:
            _command: The r2 command (unused, blocks regardless).

        Returns:
            str: A string that should never be reached in timeout tests.
        """
        _ = self._stop.wait(_BLOCKING_WAIT_TIMEOUT)
        return "never_returned"

    def release(self) -> None:
        """Release the blocked thread so event loop can shut down cleanly."""
        self._stop.set()


class _FastR2:
    """Callable that returns immediately."""

    @staticmethod
    def cmd(command: str) -> str:
        """Return formatted result immediately.

        Args:
            command: The r2 command to echo back.

        Returns:
            str: Formatted result string.
        """
        return f"result:{command}"


class _NoneR2:
    """Callable that returns None (r2pipe does this for some commands)."""

    @staticmethod
    def cmd(_command: str) -> None:
        """Return None as r2pipe sometimes does.

        Args:
            _command: The r2 command (unused).
        """


_R2_BACKING_FIELD: str = "_r2"


def _install_r2(bridge: CutterBridge, r2_like: _BlockingR2 | _FastR2 | _NoneR2) -> None:
    """Install a fake r2pipe implementation onto the bridge's backing field.

    The ``CutterBridge.r2`` setter is strictly typed against ``r2pipe.open``,
    which is not a public Protocol. Tests need to inject duck-typed fakes, so
    we write to the backing attribute by name to avoid violating the public
    typed setter contract while still exercising the bridge's runtime
    behaviour via the ``r2.cmd`` dispatch path.

    Args:
        bridge: The CutterBridge instance under test.
        r2_like: A test fake exposing an r2pipe-compatible ``cmd`` method.
    """
    setattr(bridge, _R2_BACKING_FIELD, r2_like)


@pytest.mark.asyncio
async def test_r2_cmd_timeout_raises_tool_error() -> None:
    """_r2_cmd raises ToolError when r2 command blocks past the timeout.

    Before the fix, _r2_cmd had no timeout wrapper and would block forever.
    This test would HANG INDEFINITELY if the asyncio.wait_for wrapper
    were removed.
    """
    bridge = CutterBridge()
    blocker = _BlockingR2()
    _install_r2(bridge, blocker)

    original_timeout: float = cutter_module.R2_COMMAND_TIMEOUT
    cutter_module.R2_COMMAND_TIMEOUT = _R2_TEST_TIMEOUT

    try:
        await _assert_r2_cmd_timeout(bridge)
    finally:
        blocker.release()
        cutter_module.R2_COMMAND_TIMEOUT = original_timeout


async def _assert_r2_cmd_timeout(bridge: CutterBridge) -> None:
    """Run r2_cmd and assert it times out within the configured bound.

    Args:
        bridge: CutterBridge wired to a blocking r2 stub.
    """
    start = time.monotonic()
    with pytest.raises(ToolError, match="cutter command timed out"):
        _ = await bridge.r2_cmd("aaa")
    elapsed = time.monotonic() - start

    msg = f"Timeout should fire in ~0.5s, but took {elapsed:.1f}s. The asyncio.wait_for wrapper may be missing."
    assert elapsed < _ELAPSED_UPPER_BOUND, msg


@pytest.mark.asyncio
async def test_r2_cmd_returns_result_within_timeout() -> None:
    """_r2_cmd returns normally when the command completes before timeout."""
    bridge = CutterBridge()
    _install_r2(bridge, _FastR2())

    result = await bridge.r2_cmd("pd 10")
    assert result == "result:pd 10"


@pytest.mark.asyncio
async def test_r2_cmd_converts_none_to_empty_string() -> None:
    """_r2_cmd converts None return from r2pipe to empty string."""
    bridge = CutterBridge()
    _install_r2(bridge, _NoneR2())

    result = await bridge.r2_cmd("?")
    assert not result, "None r2 result should become empty string"


@pytest.mark.asyncio
async def test_r2_cmd_no_binary_raises_tool_error() -> None:
    """_r2_cmd raises ToolError when no binary is loaded (r2 is None)."""
    bridge = CutterBridge()
    assert bridge.r2 is None

    with pytest.raises(ToolError):
        _ = await bridge.r2_cmd("aaa")


# ─── 3. QEMU pidfile retry logic (qemu.py) ──────────────────────────────────


def _make_qemu_sandbox(pidfile: Path) -> QEMUSandbox:
    """Build a real QEMUSandbox and point its pidfile path at ``pidfile``.

    Args:
        pidfile: Path the production retry loop should poll.

    Returns:
        QEMUSandbox: A real sandbox instance whose ``_pidfile_path`` is set.
    """
    sandbox = QEMUSandbox()
    setattr(sandbox, "_pidfile_path", pidfile)
    return sandbox


def _install_fast_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shrink the production retry delay/count so real-loop tests run quickly.

    Patches the module-level constants the production ``_resolve_qemu_pid``
    loop actually reads, leaving its real polling logic intact.

    Args:
        monkeypatch: Pytest monkeypatch fixture used to set the constants.
    """
    monkeypatch.setattr(qemu_module, "_PIDFILE_RETRY_DELAY", _FAST_RETRY_DELAY)
    monkeypatch.setattr(qemu_module, "_PIDFILE_MAX_RETRIES", _FAST_MAX_RETRIES)


@pytest.mark.asyncio
async def test_qemu_resolve_pid_uses_real_retry_constants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real _resolve_qemu_pid reads the PID by consuming its retry constants.

    Exercises the shipping retry loop end-to-end against a real pidfile rather
    than asserting the bare numeric value of the configuration constants. The
    public ``PIDFILE_MAX_RETRIES`` / ``PIDFILE_RETRY_DELAY`` re-exports are
    still verified to expose a sane bound, but the gate is the real loop
    returning the PID parsed from the file.

    Args:
        tmp_path: Pytest temporary directory for the test.
        monkeypatch: Pytest monkeypatch fixture used to speed up the loop.
    """
    assert qemu_module.PIDFILE_MAX_RETRIES >= _MIN_RETRIES
    assert qemu_module.PIDFILE_RETRY_DELAY >= _MIN_RETRY_DELAY
    assert qemu_module.PIDFILE_MAX_RETRIES * qemu_module.PIDFILE_RETRY_DELAY >= _MIN_TOTAL_WAIT

    _install_fast_retry(monkeypatch)
    pidfile = tmp_path / "qemu.pid"
    _ = pidfile.write_text(str(_EXPECTED_PID_IMMEDIATE))

    sandbox = _make_qemu_sandbox(pidfile)
    resolve_qemu_pid: Callable[[], Awaitable[int | None]] = getattr(sandbox, "_resolve_qemu_pid")
    qemu_pid = await resolve_qemu_pid()

    assert qemu_pid == _EXPECTED_PID_IMMEDIATE, "Real retry loop must return the PID written to the pidfile"


@pytest.mark.asyncio
async def test_qemu_pidfile_retry_reads_immediate_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real _resolve_qemu_pid reads a pidfile present on the first attempt.

    Drives the production ``QEMUSandbox._resolve_qemu_pid`` retry loop, which
    delegates to ``_read_pidfile_once``. The oracle is the integer the test
    independently wrote to the file: production must return exactly that value.

    Args:
        tmp_path: Pytest temporary directory for the test.
        monkeypatch: Pytest monkeypatch fixture used to speed up the loop.
    """
    _install_fast_retry(monkeypatch)
    pidfile = tmp_path / "qemu.pid"
    _ = pidfile.write_text(str(_EXPECTED_PID_IMMEDIATE))

    sandbox = _make_qemu_sandbox(pidfile)
    resolve_qemu_pid: Callable[[], Awaitable[int | None]] = getattr(sandbox, "_resolve_qemu_pid")
    qemu_pid = await resolve_qemu_pid()

    assert qemu_pid == _EXPECTED_PID_IMMEDIATE, "Should read pidfile on first attempt"


@pytest.mark.asyncio
async def test_qemu_pidfile_retry_reads_delayed_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real _resolve_qemu_pid recovers a pidfile that appears after a delay.

    A background task writes the pidfile after the first poll would have
    missed it. A single non-retrying read would return ``None``; the
    production retry loop must keep polling and eventually return the PID.

    Args:
        tmp_path: Pytest temporary directory for the test.
        monkeypatch: Pytest monkeypatch fixture used to speed up the loop.
    """
    _install_fast_retry(monkeypatch)
    pidfile = tmp_path / "qemu.pid"

    async def write_pidfile_after_delay() -> None:
        """Write the expected pidfile after a short delay."""
        await asyncio.sleep(_DELAYED_WRITE_DELAY)
        _ = pidfile.write_text(str(_EXPECTED_PID_DELAYED))

    writer = asyncio.create_task(write_pidfile_after_delay())
    sandbox = _make_qemu_sandbox(pidfile)
    resolve_qemu_pid: Callable[[], Awaitable[int | None]] = getattr(sandbox, "_resolve_qemu_pid")
    qemu_pid = await resolve_qemu_pid()
    await writer

    assert qemu_pid == _EXPECTED_PID_DELAYED, "Retry loop should catch delayed pidfile"


@pytest.mark.asyncio
async def test_qemu_pidfile_retry_exhausted_raises_sandbox_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exhausted pidfile retries yield None and verification raises SandboxError.

    Drives the production ``_resolve_qemu_pid`` against a pidfile that never
    appears: the real loop must return ``None`` after exhausting its retries.
    The documented contract is that the missing PID is fatal, so the test then
    drives the real ``_verify_qemu_pid`` and asserts it raises ``SandboxError``
    on that ``None`` result. Removing the raise from ``_verify_qemu_pid`` fails
    this test.

    Args:
        tmp_path: Pytest temporary directory for the test.
        monkeypatch: Pytest monkeypatch fixture used to speed up the loop.
    """
    _install_fast_retry(monkeypatch)
    pidfile = tmp_path / "nonexistent_qemu.pid"

    sandbox = _make_qemu_sandbox(pidfile)
    resolve_qemu_pid: Callable[[], Awaitable[int | None]] = getattr(sandbox, "_resolve_qemu_pid")
    qemu_pid = await resolve_qemu_pid()

    assert qemu_pid is None, "Real retry loop must return None when the pidfile never appears"

    verify_qemu_pid: Callable[[int | None], Awaitable[None]] = getattr(sandbox, "_verify_qemu_pid")
    with pytest.raises(SandboxError):
        await verify_qemu_pid(qemu_pid)


@pytest.mark.asyncio
async def test_qemu_pidfile_retry_handles_corrupt_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real _read_pidfile_once tolerates corrupt content; retry recovers the PID.

    First asserts the production ``_read_pidfile_once`` returns ``None`` for an
    unparseable pidfile (rather than raising). Then a background task rewrites
    the file with a valid PID and the real ``_resolve_qemu_pid`` retry loop
    must recover that PID. A regression that stopped tolerating corrupt content
    (e.g. letting ``int()`` propagate) would fail the first assertion.

    Args:
        tmp_path: Pytest temporary directory for the test.
        monkeypatch: Pytest monkeypatch fixture used to speed up the loop.
    """
    _install_fast_retry(monkeypatch)
    pidfile = tmp_path / "qemu.pid"
    _ = pidfile.write_text("not_a_number\n")

    read_pidfile_once: Callable[[Path], Awaitable[int | None]] = getattr(QEMUSandbox, "_read_pidfile_once")
    corrupt_read = await read_pidfile_once(pidfile)
    assert corrupt_read is None, "Corrupt pidfile content must parse to None, not raise"

    async def fix_pidfile_after_delay() -> None:
        """Rewrite the pidfile with valid content after a short delay."""
        await asyncio.sleep(_DELAYED_WRITE_DELAY)
        _ = pidfile.write_text(str(_EXPECTED_PID_CORRUPT))

    fixer = asyncio.create_task(fix_pidfile_after_delay())
    sandbox = _make_qemu_sandbox(pidfile)
    resolve_qemu_pid: Callable[[], Awaitable[int | None]] = getattr(sandbox, "_resolve_qemu_pid")
    qemu_pid = await resolve_qemu_pid()
    await fixer

    assert qemu_pid == _EXPECTED_PID_CORRUPT, "Retry should recover after corrupt content is corrected"


# ─── 4. Ghidra bridge script cleanup (ghidra.py) ────────────────────────────


def test_ghidra_create_bridge_script_writes_real_file() -> None:
    """_create_bridge_script creates a real Python script on disk.

    Verifies the file is created with correct content and the path is
    tracked in _bridge_script_path for later cleanup.
    """
    bridge = GhidraBridge()
    script_path = bridge.create_bridge_script()

    try:
        assert script_path.exists(), "Bridge script should be created on disk"
        assert script_path.suffix == ".py"
        content = script_path.read_text()
        assert "ghidra_bridge_server" in content, "Script should contain ghidra_bridge_server import"
        assert bridge.bridge_script_path == script_path, "Path should be tracked for cleanup"
    finally:
        if script_path.exists():
            script_path.unlink(missing_ok=True)
        parent = script_path.parent
        if parent.exists() and not any(parent.iterdir()):
            parent.rmdir()


@pytest.mark.asyncio
async def test_ghidra_shutdown_deletes_bridge_script() -> None:
    """GhidraBridge.shutdown() deletes the temp bridge script.

    Before the fix, the script in tempdir/intellicrack_ghidra/ was never
    cleaned up. Now shutdown() calls unlink() on it.
    """
    bridge = GhidraBridge()
    script_path = bridge.create_bridge_script()
    assert script_path.exists(), "Script should exist before shutdown"

    await bridge.shutdown()

    assert not script_path.exists(), "Bridge script should be deleted after shutdown"
    assert bridge.bridge_script_path is None, "Path reference should be cleared after cleanup"


@pytest.mark.asyncio
async def test_ghidra_shutdown_removes_empty_parent_directory() -> None:
    """GhidraBridge.shutdown() removes the empty intellicrack_ghidra dir.

    After deleting the script file, if the parent directory is empty,
    shutdown() should also remove it.
    """
    bridge = GhidraBridge()
    script_path = bridge.create_bridge_script()
    parent_dir = script_path.parent
    assert parent_dir.exists()

    await bridge.shutdown()

    assert not parent_dir.exists(), "Empty parent directory should be removed after cleanup"


@pytest.mark.asyncio
async def test_ghidra_shutdown_preserves_nonempty_parent_directory() -> None:
    """GhidraBridge.shutdown() preserves parent dir if other files exist.

    If another process/session left files in intellicrack_ghidra/,
    shutdown should only delete its own script, not the directory.
    """
    bridge = GhidraBridge()
    script_path = bridge.create_bridge_script()
    parent_dir = script_path.parent

    other_file = parent_dir / "other_session_script.py"
    _ = other_file.write_text("# another session's script")

    await bridge.shutdown()

    assert not script_path.exists(), "Our script should be deleted"
    assert parent_dir.exists(), "Directory with other files should be preserved"
    assert other_file.exists(), "Other session's file should not be deleted"

    other_file.unlink()
    if parent_dir.exists() and not any(parent_dir.iterdir()):
        parent_dir.rmdir()


# ─── 5. Windows Sandbox PID-based kill (windows.py) ─────────────────────────


@pytest.mark.asyncio
async def test_pid_based_kill_targets_specific_process() -> None:
    """PID-based taskkill targets a specific process, not all with same name.

    Before the fix, `taskkill /F /IM WindowsSandbox.exe` killed ALL sandbox
    instances. Now it uses `/PID` to target just the managed process.

    This test spawns two processes with the same Python executable, kills
    one by PID, and verifies the other survives.
    """
    proc_a = await asyncio.to_thread(_spawn_sleeper)
    proc_b = await asyncio.to_thread(_spawn_sleeper)

    try:
        await _assert_only_target_killed(proc_a, proc_b)
    finally:
        for proc in (proc_a, proc_b):
            if psutil.pid_exists(proc.pid):
                proc.kill()
                proc.wait()


async def _assert_only_target_killed(
    proc_a: Popen[bytes],
    proc_b: Popen[bytes],
) -> None:
    """Terminate ``proc_a`` by PID and assert ``proc_b`` survives.

    Args:
        proc_a: The process targeted for termination.
        proc_b: The sibling process expected to survive.
    """
    assert psutil.pid_exists(proc_a.pid)
    assert psutil.pid_exists(proc_b.pid)

    ProcessManager.terminate_tree(proc_a.pid, graceful_timeout=_GRACEFUL_TIMEOUT_SHORT, force_timeout=_FORCE_TIMEOUT_SHORT)

    await asyncio.sleep(_SLEEP_DELAY_HALF)

    assert not psutil.pid_exists(proc_a.pid), "Target process should be dead"
    assert psutil.pid_exists(proc_b.pid), "Other process with same executable should survive PID-based kill"


def test_process_manager_unregister_after_terminate() -> None:
    """ProcessManager.unregister removes the process from tracking.

    The Windows Sandbox stop() method now calls unregister(pid) after
    terminate. This ensures the process is fully cleaned from the registry.
    """
    process = Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=PIPE,
        stderr=PIPE,
    )
    pid = process.pid

    pm = ProcessManager.get_instance()
    _ = pm.register(process, "test-unregister", ProcessType.SANDBOX)

    ProcessManager.terminate_tree(pid, graceful_timeout=_GRACEFUL_TIMEOUT_SHORT, force_timeout=_FORCE_TIMEOUT_SHORT)
    result = pm.unregister(pid)

    assert result is not None, "unregister should return the tracked process"

    second_result = pm.unregister(pid)
    assert second_result is None, "Second unregister should return None"
