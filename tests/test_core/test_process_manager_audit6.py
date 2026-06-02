# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit6 CORE-D regression tests for ``intellicrack.core.process_manager``.

Exercises:
    * F-0014 - ``register_external_pid`` rejects PIDs without a live OS process.
    * F-0020 - ``_atexit_cleanup`` is deduplicated and only walks the process
      tree once.
    * F-0025 - ``_signal_handler`` does not block synchronously when no event
      loop is running.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import signal
import sys
import threading
import time
from typing import TYPE_CHECKING, TypedDict, cast

import pytest

from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.subprocess_compat import (
    PIPE,
    Popen,
)


if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from datetime import datetime


_PROCESS_STARTUP_DELAY_S = 0.2
_PROCESS_WAIT_TIMEOUT_S = 5.0
_NEVER_VALID_PID = 0

_process_manager_module = importlib.import_module("intellicrack.core.process_manager")
_pid_exists = cast(
    "Callable[[int], bool]",
    getattr(_process_manager_module, "_pid_exists"),
)


class _ExternalPidEntry(TypedDict):
    """Shape of internal external PID tracking entries."""

    name: str
    process_type: ProcessType
    metadata: dict[str, str]
    registered_at: datetime


@pytest.fixture
def process_manager() -> Generator[ProcessManager]:
    """Provide a fresh ProcessManager for each test.

    Yields:
        Generator[ProcessManager]: Fresh singleton instance with handlers uninstalled.
    """
    ProcessManager.reset_instance()
    pm = ProcessManager.get_instance()
    yield pm
    pm.uninstall_handlers()
    ProcessManager.reset_instance()


def _spawn_alive_subprocess() -> Popen[bytes]:
    """Spawn a sleeping Python subprocess used as a real, alive PID source.

    Returns:
        Popen[bytes]: Running subprocess that the caller must kill.
    """
    return Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=PIPE,
        stderr=PIPE,
    )


def _guaranteed_dead_pid() -> int:
    """Return a PID that the production ``_pid_exists`` probe confirms is dead.

    Spawns a subprocess that exits immediately, waits for the OS to reap it,
    then polls the production-side ``_pid_exists`` oracle (the same probe
    ``register_external_pid`` uses) until it reports the PID is gone. This
    guards against the brief window where the kernel still reports the exited
    child as alive. The returned PID is genuinely dead at the moment of return,
    though the OS may still recycle it afterward; callers re-verify with
    ``_pid_exists`` immediately before relying on it.

    Returns:
        int: PID of an exited child process that ``_pid_exists`` reports dead.

    Raises:
        RuntimeError: If the OS never reports the exited child's PID as dead
            within the bounded poll window (would indicate a probe defect).
    """
    proc = Popen(
        [sys.executable, "-c", ""],
        stdout=PIPE,
        stderr=PIPE,
    )
    proc.wait(timeout=_PROCESS_WAIT_TIMEOUT_S)
    pid = proc.pid
    deadline = time.perf_counter() + _PROCESS_WAIT_TIMEOUT_S
    while time.perf_counter() < deadline:
        if not _pid_exists(pid):
            return pid
        time.sleep(0.01)
    msg = f"PID {pid} still reported alive after child exit and reap"
    raise RuntimeError(msg)


def _obtain_confirmed_dead_pid(attempts: int = 8) -> int:
    """Return a PID that ``_pid_exists`` confirms dead at the moment of return.

    Repeatedly generates a freshly-exited PID and re-checks it against the
    production ``_pid_exists`` oracle, guarding against the OS recycling the
    PID into a new live process between generation and the caller's use.

    Args:
        attempts: Maximum number of generate-and-verify rounds before giving up.

    Returns:
        int: A PID that the production probe reports as not alive.

    Raises:
        RuntimeError: If no confirmed-dead PID could be obtained within
            ``attempts`` rounds (would indicate pathological PID churn).
    """
    for _ in range(attempts):
        pid = _guaranteed_dead_pid()
        if not _pid_exists(pid):
            return pid
    msg = "could not obtain a confirmed-dead PID; the OS recycled every candidate"
    raise RuntimeError(msg)


def _external_registry(pm: ProcessManager) -> dict[int, _ExternalPidEntry]:
    """Return the ProcessManager's external PID registry via ``getattr``.

    Args:
        pm: ProcessManager singleton.

    Returns:
        dict[int, _ExternalPidEntry]: Live registry mapping.
    """
    return cast(dict[int, _ExternalPidEntry], getattr(pm, "_external_pids"))


class TestF0014RegisterExternalPidVerifies:
    """``register_external_pid`` must verify the OS process exists."""

    @staticmethod
    def test_register_rejects_zero_pid(process_manager: ProcessManager) -> None:
        """PID 0 must always be rejected.

        Args:
            process_manager: Fresh ProcessManager fixture.
        """
        with pytest.raises(ValueError, match="does not exist"):
            process_manager.register_external_pid(_NEVER_VALID_PID, name="test")
        assert _NEVER_VALID_PID not in _external_registry(process_manager)

    @staticmethod
    def test_register_rejects_dead_pid(process_manager: ProcessManager) -> None:
        """An exited PID must be rejected with a "process does not exist" error.

        Obtains a genuinely dead PID, re-confirms it dead via the production
        ``_pid_exists`` oracle (the same probe the registration path uses), then
        asserts ``register_external_pid`` raises a ``ValueError`` whose message
        attributes the rejection to a non-existent process. Asserting the
        message - not just the exception type - prevents a regression where
        registration rejects for an unrelated reason (e.g. a duplicate-name
        guard or a malformed-PID check) from masquerading as a working liveness
        check.

        Determinism: the PID is re-verified dead via ``_pid_exists`` immediately
        before use; the OS-recycle window is handled by regenerating a fresh
        dead PID rather than relying on timing or sleeps.

        Args:
            process_manager: Fresh ProcessManager fixture.
        """
        dead_pid = _obtain_confirmed_dead_pid()

        with pytest.raises(ValueError, match="does not exist") as excinfo:
            process_manager.register_external_pid(dead_pid, name="dead")

        message = str(excinfo.value)
        assert str(dead_pid) in message, f"error message must name the rejected PID {dead_pid}; got {message!r}"
        assert dead_pid not in _external_registry(process_manager), "rejected dead PID must not be recorded in the external registry"

    @staticmethod
    def test_register_accepts_live_pid(process_manager: ProcessManager) -> None:
        """A real, currently-alive PID must be accepted.

        Args:
            process_manager: Fresh ProcessManager fixture.
        """
        proc = _spawn_alive_subprocess()
        try:
            process_manager.register_external_pid(proc.pid, name="live")
            assert proc.pid in _external_registry(process_manager)
        finally:
            proc.kill()
            proc.wait(timeout=_PROCESS_WAIT_TIMEOUT_S)

    @staticmethod
    def test_register_accepts_self_pid(process_manager: ProcessManager) -> None:
        """The pytest process itself is alive and must be acceptable.

        Args:
            process_manager: Fresh ProcessManager fixture.
        """
        own_pid = os.getpid()
        try:
            process_manager.register_external_pid(own_pid, name="self")
            assert own_pid in _external_registry(process_manager)
        finally:
            process_manager.unregister_external_pid(own_pid)


class TestF0020AtexitDeduplication:
    """``_atexit_cleanup`` must terminate processes only once."""

    @staticmethod
    def test_atexit_cleanup_calls_sync_cleanup_once(
        process_manager: ProcessManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``_atexit_cleanup`` must invoke ``_sync_cleanup`` exactly once.

        Args:
            process_manager: Fresh ProcessManager fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        call_counter = {"sync": 0, "terminate": 0}

        original_sync = cast(
            "Callable[[], None]",
            getattr(process_manager, "_sync_cleanup"),
        )

        def _counting_sync() -> None:
            call_counter["sync"] += 1
            original_sync()

        def _counting_terminate(_process: object) -> None:
            call_counter["terminate"] += 1

        monkeypatch.setattr(process_manager, "_sync_cleanup", _counting_sync)
        monkeypatch.setattr(
            ProcessManager,
            "_terminate_process_sync",
            staticmethod(_counting_terminate),
        )

        atexit_cleanup = cast(
            "Callable[[], None]",
            getattr(process_manager, "_atexit_cleanup"),
        )
        atexit_cleanup()

        assert call_counter["sync"] == 1
        assert call_counter["terminate"] == 0, "atexit cleanup should not duplicate per-process termination before _sync_cleanup runs"

    @staticmethod
    def test_install_handlers_registers_atexit_only_once(
        process_manager: ProcessManager,
    ) -> None:
        """Repeated install_handlers calls must not stack atexit hooks.

        Args:
            process_manager: Fresh ProcessManager fixture.
        """
        process_manager.install_handlers()
        first_state = process_manager.atexit_registered

        process_manager.install_handlers()
        process_manager.install_handlers()
        second_state = process_manager.atexit_registered

        assert first_state is True
        assert second_state is True

        pm_module = importlib.import_module("intellicrack.core.process_manager")
        global_flag = getattr(pm_module, "_atexit_registered_globally")
        assert global_flag is True


class TestF0025SignalHandlerNonBlocking:
    """``_signal_handler`` must not block when no event loop is running."""

    @staticmethod
    def test_signal_handler_returns_quickly_without_loop(
        process_manager: ProcessManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The handler must complete quickly even when cleanup is slow.

        Schedules ``_sync_cleanup`` on a daemon thread and returns to the
        caller within milliseconds; without the fix, ``_sync_cleanup`` blocks
        the OS-level signal handler for the full graceful timeout.

        Args:
            process_manager: Fresh ProcessManager fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        cleanup_started = threading.Event()
        cleanup_release = threading.Event()
        cleanup_finished = threading.Event()

        def _slow_cleanup() -> None:
            cleanup_started.set()
            cleanup_release.wait(timeout=10.0)
            cleanup_finished.set()

        monkeypatch.setattr(process_manager, "_sync_cleanup", _slow_cleanup)

        handler = cast(
            "Callable[[int, object], None]",
            getattr(process_manager, "_signal_handler"),
        )

        start = time.perf_counter()
        handler(int(signal.SIGINT), None)
        elapsed = time.perf_counter() - start

        assert cleanup_started.wait(timeout=5.0), "cleanup thread did not start"
        assert elapsed < 1.0, f"signal handler blocked for {elapsed:.3f}s; expected <1s because cleanup must run on a background thread"
        assert not cleanup_finished.is_set(), "signal handler must not block on cleanup completion"
        cleanup_release.set()

    @staticmethod
    def test_signal_handler_uses_running_loop_when_available(
        process_manager: ProcessManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The handler must schedule async cleanup when a loop is running.

        Args:
            process_manager: Fresh ProcessManager fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        scheduled = threading.Event()
        cleanup_started = threading.Event()

        async def _async_cleanup_replacement(
            _graceful: float | None = None,
            _force: float | None = None,
        ) -> None:
            cleanup_started.set()
            await asyncio.sleep(0)

        def _sync_should_not_run() -> None:
            pytest.fail("_sync_cleanup must not run when a loop is active")

        monkeypatch.setattr(process_manager, "cleanup_all_async", _async_cleanup_replacement)
        monkeypatch.setattr(process_manager, "_sync_cleanup", _sync_should_not_run)

        async def _runner() -> None:
            handler = cast(
                "Callable[[int, object], None]",
                getattr(process_manager, "_signal_handler"),
            )
            handler(int(signal.SIGINT), None)
            scheduled.set()
            for _ in range(50):
                await asyncio.sleep(0.02)
                if cleanup_started.is_set():
                    return

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_runner())
        finally:
            loop.close()

        assert scheduled.is_set()
        assert cleanup_started.is_set()
