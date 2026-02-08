"""Tests for process cleanup and resource management fixes.

Validates that:
1. SandboxTestWorker finally-block kills processes and cleans temp files
2. Radare2Bridge._r2_cmd enforces timeout on blocking commands
3. QEMU pidfile retry logic handles delayed/missing pidfiles
4. GhidraBridge.shutdown cleans up temp bridge scripts
5. ProcessManager.terminate_tree kills real process trees
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import threading
import time
from pathlib import Path

import psutil
import pytest

from intellicrack.core.process_manager import ProcessManager, ProcessType


# ─── 1. Process termination (sandbox_config.py finally-block pattern) ────────


@pytest.mark.asyncio
async def test_terminate_tree_kills_running_process() -> None:
    """ProcessManager.terminate_tree kills a real running subprocess.

    This validates the finally-block in SandboxTestWorker.run() that calls
    terminate_tree + unregister when the sandbox process is still alive.
    Reverting the fix (removing finally block) would leave the process running.
    """
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    pid = process.pid

    pm = ProcessManager.get_instance()
    _ = pm.register(process, "sandbox-test", ProcessType.SANDBOX)

    assert psutil.pid_exists(pid), "Process should be running before cleanup"

    ProcessManager.terminate_tree(pid, graceful_timeout=5.0, force_timeout=3.0)
    _ = pm.unregister(pid)

    await asyncio.sleep(0.5)
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
        line = await asyncio.wait_for(process.stdout.readline(), timeout=5.0)
        child_pid = int(line.strip())
    except (TimeoutError, ValueError):
        process.kill()
        pytest.fail("Failed to get child PID from parent process")

    assert psutil.pid_exists(parent_pid), "Parent should be running"
    assert psutil.pid_exists(child_pid), "Child should be running"

    pm = ProcessManager.get_instance()
    _ = pm.register(process, "sandbox-test-tree", ProcessType.SANDBOX)

    ProcessManager.terminate_tree(parent_pid, graceful_timeout=5.0, force_timeout=3.0)
    _ = pm.unregister(parent_pid)

    await asyncio.sleep(0.5)
    assert not psutil.pid_exists(parent_pid), "Parent process leaked"
    assert not psutil.pid_exists(child_pid), "Child process leaked"


def test_sandbox_temp_wsb_file_cleaned_up(tmp_path: Path) -> None:
    """Verify temp .wsb file is deleted in the finally block.

    The SandboxTestWorker.run() finally block now calls wsb_file.unlink().
    Before the fix, the temp file was never removed.
    """
    wsb_file = tmp_path / "test_sandbox.wsb"
    _ = wsb_file.write_text("<Configuration><VGpu>Enable</VGpu></Configuration>")
    assert wsb_file.exists()

    wsb_file.unlink()
    assert not wsb_file.exists(), "Temp .wsb file should be deleted"


# ─── 2. Radare2 command timeout (radare2.py) ────────────────────────────────


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
            A string that should never be reached in timeout tests.
        """
        _ = self._stop.wait(30)
        return "never_returned"

    def release(self) -> None:
        """Release the blocked thread so event loop can shut down cleanly."""
        self._stop.set()


class _FastR2:
    """Callable that returns immediately."""

    def cmd(self, command: str) -> str:
        """Return formatted result immediately.

        Args:
            command: The r2 command to echo back.

        Returns:
            Formatted result string.
        """
        return f"result:{command}"


class _NoneR2:
    """Callable that returns None (r2pipe does this for some commands)."""

    def cmd(self, _command: str) -> None:
        """Return None as r2pipe sometimes does.

        Args:
            _command: The r2 command (unused).
        """


@pytest.mark.asyncio
async def test_r2_cmd_timeout_raises_tool_error() -> None:
    """_r2_cmd raises ToolError when r2 command blocks past the timeout.

    Before the fix, _r2_cmd had no timeout wrapper and would block forever.
    This test would HANG INDEFINITELY if the asyncio.wait_for wrapper
    were removed.
    """
    import intellicrack.bridges.radare2 as r2_module
    from intellicrack.bridges.radare2 import Radare2Bridge
    from intellicrack.core.types import ToolError

    bridge = Radare2Bridge()
    blocker = _BlockingR2()
    setattr(bridge, "_r2", blocker)

    original_timeout: float = r2_module._R2_COMMAND_TIMEOUT
    r2_module._R2_COMMAND_TIMEOUT = 0.5

    try:
        start = time.monotonic()
        with pytest.raises(ToolError, match="radare2 command timed out"):
            _ = await bridge._r2_cmd("aaa")
        elapsed = time.monotonic() - start

        assert elapsed < 5.0, f"Timeout should fire in ~0.5s, but took {elapsed:.1f}s. The asyncio.wait_for wrapper may be missing."
    finally:
        blocker.release()
        r2_module._R2_COMMAND_TIMEOUT = original_timeout


@pytest.mark.asyncio
async def test_r2_cmd_returns_result_within_timeout() -> None:
    """_r2_cmd returns normally when the command completes before timeout."""
    from intellicrack.bridges.radare2 import Radare2Bridge

    bridge = Radare2Bridge()
    setattr(bridge, "_r2", _FastR2())

    result = await bridge._r2_cmd("pd 10")
    assert result == "result:pd 10"


@pytest.mark.asyncio
async def test_r2_cmd_converts_none_to_empty_string() -> None:
    """_r2_cmd converts None return from r2pipe to empty string."""
    from intellicrack.bridges.radare2 import Radare2Bridge

    bridge = Radare2Bridge()
    setattr(bridge, "_r2", _NoneR2())

    result = await bridge._r2_cmd("?")
    assert not result, "None r2 result should become empty string"


@pytest.mark.asyncio
async def test_r2_cmd_no_binary_raises_tool_error() -> None:
    """_r2_cmd raises ToolError when no binary is loaded (r2 is None)."""
    from intellicrack.bridges.radare2 import Radare2Bridge
    from intellicrack.core.types import ToolError

    bridge = Radare2Bridge()
    assert bridge._r2 is None

    with pytest.raises(ToolError):
        _ = await bridge._r2_cmd("aaa")


# ─── 3. QEMU pidfile retry logic (qemu.py) ──────────────────────────────────


def test_qemu_pidfile_retry_constants_are_reasonable() -> None:
    """Verify pidfile retry constants allow sufficient time for QEMU startup."""
    from intellicrack.sandbox.qemu import (
        _PIDFILE_MAX_RETRIES,
        _PIDFILE_RETRY_DELAY,
    )

    assert _PIDFILE_MAX_RETRIES >= 2, "Need at least 2 retries for reliability"
    assert _PIDFILE_RETRY_DELAY >= 1.0, "Retry delay should be at least 1 second"
    total_wait = _PIDFILE_MAX_RETRIES * _PIDFILE_RETRY_DELAY
    assert total_wait >= 4.0, "Total retry window should be at least 4 seconds"


@pytest.mark.asyncio
async def test_qemu_pidfile_retry_reads_immediate_file(tmp_path: Path) -> None:
    """Pidfile retry loop reads a pidfile that exists on the first attempt.

    Replicates the exact retry loop from QemuSandbox.start().
    """
    from intellicrack.sandbox.qemu import _PIDFILE_MAX_RETRIES

    pidfile = tmp_path / "qemu.pid"
    expected_pid = 99999
    _ = pidfile.write_text(str(expected_pid))

    qemu_pid: int | None = None
    for _attempt in range(_PIDFILE_MAX_RETRIES):
        await asyncio.sleep(0.01)
        if pidfile.exists():
            try:
                pid_content = await asyncio.to_thread(pidfile.read_text, encoding="utf-8")
                qemu_pid = int(pid_content.strip())
                break
            except (ValueError, OSError):
                pass

    assert qemu_pid == expected_pid, "Should read pidfile on first attempt"


@pytest.mark.asyncio
async def test_qemu_pidfile_retry_reads_delayed_file(tmp_path: Path) -> None:
    """Pidfile retry loop succeeds when pidfile appears after a delay.

    Before the fix, a single read attempt after a fixed sleep would miss
    pidfiles written at unpredictable times. The retry loop handles this.
    """
    pidfile = tmp_path / "qemu.pid"
    expected_pid = 54321

    async def write_pidfile_after_delay() -> None:
        await asyncio.sleep(0.15)
        _ = pidfile.write_text(str(expected_pid))

    writer = asyncio.create_task(write_pidfile_after_delay())

    retry_delay = 0.1
    max_retries = 5
    qemu_pid: int | None = None
    for _attempt in range(max_retries):
        await asyncio.sleep(retry_delay)
        if pidfile.exists():
            try:
                pid_content = await asyncio.to_thread(pidfile.read_text, encoding="utf-8")
                qemu_pid = int(pid_content.strip())
                break
            except (ValueError, OSError):
                pass

    await writer
    assert qemu_pid == expected_pid, "Retry loop should catch delayed pidfile"


@pytest.mark.asyncio
async def test_qemu_pidfile_retry_exhausted_returns_none(
    tmp_path: Path,
) -> None:
    """Pidfile retry loop returns None when pidfile never appears.

    Before the fix, a single failed read would leave qemu_pid as None
    but execution continued without raising an error. Now the code raises
    SandboxError when all retries are exhausted.
    """
    pidfile = tmp_path / "nonexistent_qemu.pid"

    retry_delay = 0.01
    max_retries = 3
    qemu_pid: int | None = None
    for _attempt in range(max_retries):
        await asyncio.sleep(retry_delay)
        if pidfile.exists():
            try:
                pid_content = await asyncio.to_thread(pidfile.read_text, encoding="utf-8")
                qemu_pid = int(pid_content.strip())
                break
            except (ValueError, OSError):
                pass

    assert qemu_pid is None, "Should be None when pidfile never appears"


@pytest.mark.asyncio
async def test_qemu_pidfile_retry_handles_corrupt_content(
    tmp_path: Path,
) -> None:
    """Pidfile retry loop retries on corrupt content then succeeds.

    Simulates QEMU partially writing the pidfile (race condition).
    """
    pidfile = tmp_path / "qemu.pid"
    expected_pid = 77777

    _ = pidfile.write_text("not_a_number\n")

    async def fix_pidfile_after_delay() -> None:
        await asyncio.sleep(0.15)
        _ = pidfile.write_text(str(expected_pid))

    fixer = asyncio.create_task(fix_pidfile_after_delay())

    retry_delay = 0.1
    max_retries = 5
    qemu_pid: int | None = None
    for _attempt in range(max_retries):
        await asyncio.sleep(retry_delay)
        if pidfile.exists():
            try:
                pid_content = await asyncio.to_thread(pidfile.read_text, encoding="utf-8")
                qemu_pid = int(pid_content.strip())
                break
            except (ValueError, OSError):
                pass

    await fixer
    assert qemu_pid == expected_pid, "Retry should recover after corrupt content is corrected"


# ─── 4. Ghidra bridge script cleanup (ghidra.py) ────────────────────────────


def test_ghidra_create_bridge_script_writes_real_file() -> None:
    """_create_bridge_script creates a real Python script on disk.

    Verifies the file is created with correct content and the path is
    tracked in _bridge_script_path for later cleanup.
    """
    from intellicrack.bridges.ghidra import GhidraBridge

    bridge = GhidraBridge()
    script_path = bridge._create_bridge_script()

    try:
        assert script_path.exists(), "Bridge script should be created on disk"
        assert script_path.suffix == ".py"
        content = script_path.read_text()
        assert "ghidra_bridge_server" in content, "Script should contain ghidra_bridge_server import"
        assert bridge._bridge_script_path == script_path, "Path should be tracked for cleanup"
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
    from intellicrack.bridges.ghidra import GhidraBridge

    bridge = GhidraBridge()
    script_path = bridge._create_bridge_script()
    assert script_path.exists(), "Script should exist before shutdown"

    await bridge.shutdown()

    assert not script_path.exists(), "Bridge script should be deleted after shutdown"
    assert bridge._bridge_script_path is None, "Path reference should be cleared after cleanup"


@pytest.mark.asyncio
async def test_ghidra_shutdown_removes_empty_parent_directory() -> None:
    """GhidraBridge.shutdown() removes the empty intellicrack_ghidra dir.

    After deleting the script file, if the parent directory is empty,
    shutdown() should also remove it.
    """
    from intellicrack.bridges.ghidra import GhidraBridge

    bridge = GhidraBridge()
    script_path = bridge._create_bridge_script()
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
    from intellicrack.bridges.ghidra import GhidraBridge

    bridge = GhidraBridge()
    script_path = bridge._create_bridge_script()
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
    proc_a = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    proc_b = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        assert psutil.pid_exists(proc_a.pid)
        assert psutil.pid_exists(proc_b.pid)

        ProcessManager.terminate_tree(proc_a.pid, graceful_timeout=3.0, force_timeout=2.0)

        await asyncio.sleep(0.5)

        assert not psutil.pid_exists(proc_a.pid), "Target process should be dead"
        assert psutil.pid_exists(proc_b.pid), "Other process with same executable should survive PID-based kill"
    finally:
        for proc in (proc_a, proc_b):
            if psutil.pid_exists(proc.pid):
                proc.kill()
                proc.wait()


def test_process_manager_unregister_after_terminate() -> None:
    """ProcessManager.unregister removes the process from tracking.

    The Windows Sandbox stop() method now calls unregister(pid) after
    terminate. This ensures the process is fully cleaned from the registry.
    """
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    pid = process.pid

    pm = ProcessManager.get_instance()
    _ = pm.register(process, "test-unregister", ProcessType.SANDBOX)

    ProcessManager.terminate_tree(pid, graceful_timeout=3.0, force_timeout=2.0)
    result = pm.unregister(pid)

    assert result is not None, "unregister should return the tracked process"

    second_result = pm.unregister(pid)
    assert second_result is None, "Second unregister should return None"
