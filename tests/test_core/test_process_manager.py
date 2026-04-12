# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for ProcessManager process tracking and cleanup.

Tests validate:
- Subprocess tracking with run_tracked and run_tracked_async
- External PID registration and termination
- Process cleanup during application shutdown
- Singleton behavior and thread safety
- Windows-specific process termination
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, TypedDict, cast

import pytest

from intellicrack.core.process_manager import (
    ProcessManager,
    ProcessType,
    TrackedProcess,
)


if TYPE_CHECKING:
    from collections.abc import Generator
    from datetime import datetime
    from pathlib import Path


class _ExternalPidEntry(TypedDict):
    """Shape of internal external PID tracking entries.

    Matches ``intellicrack.core.process_manager._ExternalPidInfo`` so tests can
    inspect the registry without relying on implementation-private symbols.
    """

    name: str
    process_type: ProcessType
    metadata: dict[str, str]
    registered_at: datetime


def _external_pids(pm: ProcessManager) -> dict[int, _ExternalPidEntry]:
    """Return the ProcessManager's external PID registry via ``getattr``.

    Args:
        pm: The ProcessManager instance to inspect.

    Returns:
        dict[int, _ExternalPidEntry]: Mapping of PID to registration info.
    """
    return cast(dict[int, _ExternalPidEntry], getattr(pm, "_external_pids"))


def _sync_cleanup(pm: ProcessManager) -> None:
    """Invoke the ProcessManager's synchronous cleanup routine.

    Args:
        pm: The ProcessManager instance to clean up.
    """
    cleanup = cast(Callable[[], None], getattr(pm, "_sync_cleanup"))
    cleanup()


EXPECTED_EXIT_CODE_FAILURE = 1
EXPECTED_EXIT_CODE_42 = 42
EXPECTED_CONCURRENT_RESULTS = 2
CONCURRENT_MAX_ELAPSED = 1.5
TEST_PID_EXTERNAL = 99999
TEST_PID_UNREGISTER = 99998
TEST_PID_UNKNOWN = 12345
TEST_PID_DUPLICATE = 99997
NONEXISTENT_PID = 999999999
ASYNC_CLEANUP_EXTERNAL_PID = 99996
PROCESS_WAIT_TIMEOUT = 5
CLEANUP_WAIT_TIMEOUT = 10
EXPECTED_TRACKED_COUNT_TWO = 2
EXPECTED_TRACKED_COUNT_ONE = 1
EXPECTED_TRACKED_COUNT_ZERO = 0
EXPECTED_RUNNING_COUNT_ONE = 1
EXPECTED_KEY_WITH_CHECKSUM_LENGTH = 40
PROCESS_STARTUP_DELAY = 0.2
PROCESS_TIMEOUT = 0.5
EXPECTED_DASHED_GROUPS = 4


@pytest.fixture
def process_manager() -> Generator[ProcessManager]:
    """Provide a fresh ProcessManager instance for each test.

    Yields:
        Generator[ProcessManager]: A fresh ProcessManager instance.
    """
    ProcessManager.reset_instance()
    pm = ProcessManager.get_instance()
    yield pm
    pm.uninstall_handlers()
    ProcessManager.reset_instance()


class TestProcessManagerSingleton:
    """Test ProcessManager singleton pattern."""

    @staticmethod
    def test_singleton_returns_same_instance() -> None:
        """Verify ProcessManager always returns the same instance."""
        ProcessManager.reset_instance()
        pm1 = ProcessManager.get_instance()
        pm2 = ProcessManager.get_instance()
        pm3 = ProcessManager()

        assert pm1 is pm2
        assert pm1 is pm3

        ProcessManager.reset_instance()

    @staticmethod
    def test_reset_instance_clears_singleton() -> None:
        """Verify reset_instance creates a new instance."""
        ProcessManager.reset_instance()
        pm1 = ProcessManager.get_instance()
        ProcessManager.reset_instance()
        pm2 = ProcessManager.get_instance()

        assert pm1 is not pm2

        ProcessManager.reset_instance()


class TestRunTracked:
    """Test run_tracked subprocess execution with tracking."""

    @staticmethod
    def test_run_tracked_captures_stdout(
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked captures stdout from subprocess."""
        result = process_manager.run_tracked(
            [sys.executable, "-c", "print('hello world')"],
            name="test-stdout",
        )

        assert result.returncode == 0
        assert "hello world" in result.stdout

    @staticmethod
    def test_run_tracked_captures_stderr(
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked captures stderr from subprocess."""
        result = process_manager.run_tracked(
            [sys.executable, "-c", "import sys; sys.stderr.write('error msg')"],
            name="test-stderr",
        )

        assert "error msg" in result.stderr

    @staticmethod
    def test_run_tracked_returns_nonzero_exit_code(
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked returns correct exit code for failing process."""
        result = process_manager.run_tracked(
            [sys.executable, "-c", "import sys; sys.exit(42)"],
            name="test-exit-code",
        )

        assert result.returncode == EXPECTED_EXIT_CODE_42

    @staticmethod
    def test_run_tracked_check_raises_on_failure(
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked raises CalledProcessError when check=True."""
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            process_manager.run_tracked(
                [sys.executable, "-c", "import sys; sys.exit(1)"],
                name="test-check-fail",
                check=True,
            )

        assert exc_info.value.returncode == EXPECTED_EXIT_CODE_FAILURE

    @staticmethod
    def test_run_tracked_timeout_terminates_process(
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked terminates process on timeout."""
        with pytest.raises(subprocess.TimeoutExpired):
            process_manager.run_tracked(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                name="test-timeout",
                timeout=PROCESS_TIMEOUT,
            )

    @staticmethod
    def test_run_tracked_unregisters_after_completion(
        process_manager: ProcessManager,
    ) -> None:
        """Verify process is unregistered after successful completion."""
        initial_count = process_manager.process_count

        process_manager.run_tracked(
            [sys.executable, "-c", "print('done')"],
            name="test-unregister",
        )

        assert process_manager.process_count == initial_count

    @staticmethod
    def test_run_tracked_with_cwd(
        process_manager: ProcessManager,
        tmp_path: Path,
    ) -> None:
        """Verify run_tracked respects cwd parameter."""
        result = process_manager.run_tracked(
            [sys.executable, "-c", "import os; print(os.getcwd())"],
            name="test-cwd",
            cwd=str(tmp_path),
        )

        assert (
            str(tmp_path)
            in result.stdout.replace("\\", "/").replace(
                str(tmp_path).replace("\\", "/"),
                str(tmp_path),
            )
            or tmp_path.name in result.stdout
        )

    @staticmethod
    def test_run_tracked_with_env(
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked passes environment variables."""
        custom_env = os.environ.copy()
        custom_env["INTELLICRACK_TEST_VAR"] = "test_value_12345"

        result = process_manager.run_tracked(
            [
                sys.executable,
                "-c",
                "import os; print(os.environ.get('INTELLICRACK_TEST_VAR', ''))",
            ],
            name="test-env",
            env=custom_env,
        )

        assert "test_value_12345" in result.stdout

    @staticmethod
    def test_run_tracked_text_false_returns_bytes(
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked returns bytes when text=False."""
        result = process_manager.run_tracked(
            [sys.executable, "-c", "print('bytes test')"],
            name="test-bytes",
            text=False,
        )

        assert isinstance(result.stdout, bytes)
        assert b"bytes test" in result.stdout


class TestRunTrackedAsync:
    """Test run_tracked_async asynchronous subprocess execution."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_run_tracked_async_captures_output(
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked_async captures stdout asynchronously."""
        result = await process_manager.run_tracked_async(
            [sys.executable, "-c", "print('async hello')"],
            name="test-async-stdout",
        )

        assert result.returncode == 0
        assert "async hello" in result.stdout

    @staticmethod
    @pytest.mark.asyncio
    async def test_run_tracked_async_timeout(
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked_async handles timeout correctly."""
        with pytest.raises(subprocess.TimeoutExpired):
            await process_manager.run_tracked_async(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                name="test-async-timeout",
                process_timeout=PROCESS_TIMEOUT,
            )

    @staticmethod
    @pytest.mark.asyncio
    async def test_run_tracked_async_check_raises(
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked_async raises on failure with check=True."""
        with pytest.raises(subprocess.CalledProcessError):
            await process_manager.run_tracked_async(
                [sys.executable, "-c", "import sys; sys.exit(1)"],
                name="test-async-check",
                check=True,
            )

    @staticmethod
    @pytest.mark.asyncio
    async def test_run_tracked_async_concurrent_execution(
        process_manager: ProcessManager,
    ) -> None:
        """Verify multiple async processes can run concurrently."""
        start_time = time.time()

        results = await asyncio.gather(
            process_manager.run_tracked_async(
                [sys.executable, "-c", "import time; time.sleep(0.5); print('a')"],
                name="test-concurrent-a",
            ),
            process_manager.run_tracked_async(
                [sys.executable, "-c", "import time; time.sleep(0.5); print('b')"],
                name="test-concurrent-b",
            ),
        )

        elapsed = time.time() - start_time

        assert len(results) == EXPECTED_CONCURRENT_RESULTS
        assert all(r.returncode == 0 for r in results)
        assert elapsed < CONCURRENT_MAX_ELAPSED


class TestExternalPidRegistration:
    """Test external PID registration and management."""

    @staticmethod
    def test_register_external_pid_stores_info(
        process_manager: ProcessManager,
    ) -> None:
        """Verify register_external_pid stores process information."""
        process_manager.register_external_pid(
            TEST_PID_EXTERNAL,
            name="test-external",
            process_type=ProcessType.SANDBOX,
            metadata={"test_key": "test_value"},
        )

        pids = _external_pids(process_manager)
        assert TEST_PID_EXTERNAL in pids
        assert pids[TEST_PID_EXTERNAL]["name"] == "test-external"
        assert pids[TEST_PID_EXTERNAL]["process_type"] == ProcessType.SANDBOX
        assert pids[TEST_PID_EXTERNAL]["metadata"]["test_key"] == "test_value"

    @staticmethod
    def test_unregister_external_pid_removes_entry(
        process_manager: ProcessManager,
    ) -> None:
        """Verify unregister_external_pid removes the registered PID."""
        process_manager.register_external_pid(TEST_PID_UNREGISTER, name="test-unregister")

        assert TEST_PID_UNREGISTER in _external_pids(process_manager)

        result = process_manager.unregister_external_pid(TEST_PID_UNREGISTER)

        assert result is True
        assert TEST_PID_UNREGISTER not in _external_pids(process_manager)

    @staticmethod
    def test_unregister_external_pid_returns_false_for_unknown(
        process_manager: ProcessManager,
    ) -> None:
        """Verify unregister_external_pid returns False for unknown PID."""
        result = process_manager.unregister_external_pid(TEST_PID_UNKNOWN)

        assert result is False

    @staticmethod
    def test_register_external_pid_skips_duplicate(
        process_manager: ProcessManager,
    ) -> None:
        """Verify register_external_pid does not overwrite existing entry."""
        process_manager.register_external_pid(TEST_PID_DUPLICATE, name="original-name")
        process_manager.register_external_pid(TEST_PID_DUPLICATE, name="new-name")

        assert _external_pids(process_manager)[TEST_PID_DUPLICATE]["name"] == "original-name"


class TestTerminateExternalPid:
    """Test external PID termination functionality."""

    @staticmethod
    def test_terminate_external_pid_handles_nonexistent_process(
        process_manager: ProcessManager,
    ) -> None:
        """Verify terminate_external_pid handles non-existent PID gracefully."""
        process_manager.register_external_pid(NONEXISTENT_PID, name="nonexistent")

        result = process_manager.terminate_external_pid(NONEXISTENT_PID)

        assert result is False
        assert NONEXISTENT_PID not in _external_pids(process_manager)

    @staticmethod
    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_terminate_external_pid_kills_real_process_windows(
        process_manager: ProcessManager,
    ) -> None:
        """Verify terminate_external_pid kills a real process on Windows."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        pid = proc.pid
        process_manager.register_external_pid(pid, name="test-kill-windows")

        time.sleep(PROCESS_STARTUP_DELAY)

        result = process_manager.terminate_external_pid(pid, force=True)

        assert result is True

        exit_code = proc.wait(timeout=PROCESS_WAIT_TIMEOUT)
        assert exit_code != 0

    @staticmethod
    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-specific test")
    def test_terminate_external_pid_kills_real_process_unix(
        process_manager: ProcessManager,
    ) -> None:
        """Verify terminate_external_pid kills a real process on Unix."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        pid = proc.pid
        process_manager.register_external_pid(pid, name="test-kill-unix")

        time.sleep(PROCESS_STARTUP_DELAY)

        result = process_manager.terminate_external_pid(pid, force=True)

        assert result is True

        exit_code = proc.wait(timeout=PROCESS_WAIT_TIMEOUT)
        assert exit_code != 0


class TestProcessCleanup:
    """Test process cleanup during shutdown."""

    @staticmethod
    def test_sync_cleanup_terminates_tracked_processes(
        process_manager: ProcessManager,
    ) -> None:
        """Verify _sync_cleanup terminates all tracked processes."""
        proc1 = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        proc2 = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        process_manager.register(proc1, name="cleanup-test-1")
        process_manager.register(proc2, name="cleanup-test-2")

        assert process_manager.process_count == EXPECTED_TRACKED_COUNT_TWO

        time.sleep(PROCESS_STARTUP_DELAY)

        _sync_cleanup(process_manager)

        exit1 = proc1.wait(timeout=CLEANUP_WAIT_TIMEOUT)
        exit2 = proc2.wait(timeout=CLEANUP_WAIT_TIMEOUT)

        assert exit1 is not None
        assert exit2 is not None
        assert process_manager.process_count == EXPECTED_TRACKED_COUNT_ZERO

    @staticmethod
    def test_sync_cleanup_terminates_external_pids(
        process_manager: ProcessManager,
    ) -> None:
        """Verify _sync_cleanup terminates registered external PIDs."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        process_manager.register_external_pid(proc.pid, name="external-cleanup-test")

        time.sleep(PROCESS_STARTUP_DELAY)

        _sync_cleanup(process_manager)

        exit_code = proc.wait(timeout=CLEANUP_WAIT_TIMEOUT)

        assert exit_code is not None
        assert proc.pid not in _external_pids(process_manager)

    @staticmethod
    @pytest.mark.asyncio
    async def test_async_cleanup_terminates_all_processes(
        process_manager: ProcessManager,
    ) -> None:
        """Verify cleanup_all_async terminates all tracked processes."""
        proc = await asyncio.to_thread(
            subprocess.Popen,
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        process_manager.register(proc, name="async-cleanup-test")
        process_manager.register_external_pid(ASYNC_CLEANUP_EXTERNAL_PID, name="external-async-test")

        await asyncio.to_thread(time.sleep, PROCESS_STARTUP_DELAY)

        await process_manager.cleanup_all_async()

        exit_code = proc.wait(timeout=CLEANUP_WAIT_TIMEOUT)

        assert exit_code is not None
        assert process_manager.process_count == EXPECTED_TRACKED_COUNT_ZERO
        assert ASYNC_CLEANUP_EXTERNAL_PID not in _external_pids(process_manager)


class TestTrackedProcess:
    """Test TrackedProcess dataclass functionality."""

    @staticmethod
    def test_tracked_process_is_running_for_active_process() -> None:
        """Verify is_running returns True for running process."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        tracked = TrackedProcess(
            process=proc,
            process_type=ProcessType.SUBPROCESS,
            name="test-is-running",
        )

        assert tracked.is_running is True
        assert tracked.pid == proc.pid

        proc.terminate()
        proc.wait()

    @staticmethod
    def test_tracked_process_is_running_false_after_completion() -> None:
        """Verify is_running returns False after process completes."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "print('done')"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        proc.wait()

        tracked = TrackedProcess(
            process=proc,
            process_type=ProcessType.SUBPROCESS,
            name="test-completed",
        )

        assert tracked.is_running is False


class TestHandlerInstallation:
    """Test signal handler and atexit registration."""

    @staticmethod
    def test_install_handlers_registers_atexit(
        process_manager: ProcessManager,
    ) -> None:
        """Verify install_handlers registers atexit callback."""
        assert process_manager.atexit_registered is False

        process_manager.install_handlers()

        assert process_manager.atexit_registered is True

    @staticmethod
    def test_install_handlers_idempotent(
        process_manager: ProcessManager,
    ) -> None:
        """Verify install_handlers can be called multiple times safely."""
        process_manager.install_handlers()
        process_manager.install_handlers()
        process_manager.install_handlers()

        assert process_manager.atexit_registered is True

    @staticmethod
    def test_uninstall_handlers_clears_registration(
        process_manager: ProcessManager,
    ) -> None:
        """Verify uninstall_handlers clears atexit registration."""
        process_manager.install_handlers()
        assert process_manager.atexit_registered is True

        process_manager.uninstall_handlers()

        assert process_manager.atexit_registered is False

    @staticmethod
    def test_shutdown_event_initially_clear(
        process_manager: ProcessManager,
    ) -> None:
        """Verify shutdown event is initially not set."""
        assert process_manager.is_shutdown_requested() is False

    @staticmethod
    def test_shutdown_event_can_be_set_and_cleared(
        process_manager: ProcessManager,
    ) -> None:
        """Verify shutdown event can be set and cleared."""
        process_manager.shutdown_event.set()
        assert process_manager.is_shutdown_requested() is True

        process_manager.clear_shutdown_request()
        assert process_manager.is_shutdown_requested() is False


class TestProcessManagerProperties:
    """Test ProcessManager property methods."""

    @staticmethod
    def test_process_count_reflects_registered_processes(
        process_manager: ProcessManager,
    ) -> None:
        """Verify process_count returns correct count."""
        assert process_manager.process_count == EXPECTED_TRACKED_COUNT_ZERO

        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        process_manager.register(proc, name="count-test")

        assert process_manager.process_count == EXPECTED_TRACKED_COUNT_ONE

        proc.terminate()
        proc.wait()
        process_manager.unregister(proc.pid)

    @staticmethod
    def test_running_count_reflects_active_processes(
        process_manager: ProcessManager,
    ) -> None:
        """Verify running_count returns count of active processes."""
        proc1 = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        proc2 = subprocess.Popen(
            [sys.executable, "-c", "print('done')"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        proc2.wait()

        process_manager.register(proc1, name="running-1")
        process_manager.register(proc2, name="completed-2")

        assert process_manager.process_count == EXPECTED_TRACKED_COUNT_TWO
        assert process_manager.running_count == EXPECTED_RUNNING_COUNT_ONE

        proc1.terminate()
        proc1.wait()

    @staticmethod
    def test_repr_includes_counts(
        process_manager: ProcessManager,
    ) -> None:
        """Verify __repr__ includes process counts."""
        repr_str = repr(process_manager)

        assert "ProcessManager" in repr_str
        assert "tracked=" in repr_str
        assert "running=" in repr_str

    @staticmethod
    def test_get_all_tracked_returns_list(
        process_manager: ProcessManager,
    ) -> None:
        """Verify get_all_tracked returns list of tracked processes."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        process_manager.register(proc, name="list-test")

        tracked_list = process_manager.get_all_tracked()

        assert len(tracked_list) == EXPECTED_TRACKED_COUNT_ONE
        assert tracked_list[0].name == "list-test"

        proc.terminate()
        proc.wait()

    @staticmethod
    def test_get_running_processes_filters_completed(
        process_manager: ProcessManager,
    ) -> None:
        """Verify get_running_processes excludes completed processes."""
        proc1 = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        proc2 = subprocess.Popen(
            [sys.executable, "-c", "print('done')"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        proc2.wait()

        process_manager.register(proc1, name="running")
        process_manager.register(proc2, name="completed")

        running = process_manager.get_running_processes()

        assert len(running) == EXPECTED_RUNNING_COUNT_ONE
        assert running[0].name == "running"

        proc1.terminate()
        proc1.wait()
