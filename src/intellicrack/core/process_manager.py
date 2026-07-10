# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Centralized process management for Intellicrack.

This module provides a singleton ProcessManager that tracks all spawned processes and ensures proper cleanup on application exit, signal
handling, or exceptions.
"""

from __future__ import annotations

import asyncio
import atexit
import ctypes
import os
import signal
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from types import FrameType
from typing import TYPE_CHECKING, Any, Self, TypedDict, cast

import psutil

from intellicrack.core.subprocess_compat import PIPE, CalledProcessError, CompletedProcess, Popen, TimeoutExpired

from .logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Coroutine

    import structlog

_logger = get_logger(__name__)

_WIN_PROCESS_TERMINATE = 1
_SIGNAL_SIGKILL = 9
_SIGNAL_SIGTERM = 15

_WIN_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_WIN_PROCESS_QUERY_INFORMATION = 0x0400
_WIN_INVALID_PARAMETER = 87
_WIN_ACCESS_DENIED = 5

_atexit_registered_globally: list[bool] = [False]
_atexit_guard_lock: threading.Lock = threading.Lock()


def _pid_exists(pid: int) -> bool:
    """Check whether a process with the given PID exists on the host OS.

    Uses ``kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, ...)`` on
    Windows (falling back to ``PROCESS_QUERY_INFORMATION`` on older systems).
    On POSIX systems, checks for ``/proc/<pid>`` membership and falls back to
    ``os.kill(pid, 0)`` semantics. The PID ``0`` is treated as never existing
    because the OS reserves it for the idle/system process and cannot be a
    normal external process to manage.

    Args:
        pid: The process identifier to verify.

    Returns:
        bool: True when a live process is detected for ``pid``; False when the
            PID is invalid, dead, or impossible to verify.
    """
    if pid <= 0:
        return False

    if sys.platform == "win32":
        return _pid_exists_windows(pid)
    return _pid_exists_posix(pid)


def _pid_handle_alive(kernel32: ctypes.CDLL, handle: int) -> bool:
    """Check whether an opened Windows process handle refers to a live process.

    Args:
        kernel32: The ``kernel32`` ctypes wrapper exposing
            ``GetExitCodeProcess``.
        handle: A non-NULL process handle returned by ``OpenProcess``.

    Returns:
        bool: True when ``GetExitCodeProcess`` fails (treated as live to avoid
            false negatives) or the exit code is ``STILL_ACTIVE`` (259);
            False when the kernel reports the process has exited.
    """
    exit_code = ctypes.c_uint32(0)
    get_exit = kernel32.GetExitCodeProcess
    get_exit.restype = ctypes.c_int
    get_exit.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    if get_exit(handle, ctypes.byref(exit_code)) == 0:
        return True
    still_active = 259
    return exit_code.value == still_active


def _pid_exists_windows(pid: int) -> bool:
    """Verify a PID exists on Windows by attempting to open a handle.

    Args:
        pid: The Windows process identifier.

    Returns:
        bool: True when ``OpenProcess`` returns a non-NULL handle, indicating
            the process is alive; False when the kernel refuses with
            ``ERROR_INVALID_PARAMETER`` (no such PID).
    """
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return psutil.pid_exists(pid)
    kernel32 = windll.kernel32
    open_process = kernel32.OpenProcess
    open_process.restype = ctypes.c_void_p
    open_process.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]

    handle = cast("int | None", open_process(_WIN_PROCESS_QUERY_LIMITED_INFORMATION, 0, pid))
    if not handle:
        last_error = kernel32.GetLastError()
        if last_error == _WIN_ACCESS_DENIED:
            return True
        if last_error == _WIN_INVALID_PARAMETER:
            return False
        handle = cast("int | None", open_process(_WIN_PROCESS_QUERY_INFORMATION, 0, pid))
    if not handle:
        second_error = kernel32.GetLastError()
        return second_error == _WIN_ACCESS_DENIED

    try:
        return _pid_handle_alive(kernel32, handle)
    finally:
        kernel32.CloseHandle(handle)


def _pid_exists_posix(pid: int) -> bool:
    """Verify a PID exists on POSIX systems via ``/proc`` and ``os.kill``.

    Args:
        pid: The POSIX process identifier.

    Returns:
        bool: True when ``/proc/<pid>`` is present or ``os.kill(pid, 0)``
            indicates the process is alive; False when the kernel reports
            ``ESRCH``.
    """
    proc_path = Path("/proc") / str(pid)
    if proc_path.exists():
        return True

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        _logger.warning("pid_probe_no_such_process", pid=pid)
        return False
    except PermissionError:
        _logger.warning("pid_probe_permission_denied", pid=pid)
        return True
    except OSError as exc:
        _logger.warning("pid_probe_oserror", pid=pid, error=str(exc))
        return False
    return True


class ProcessStateError(RuntimeError):
    """Raised when a tracked subprocess finishes in an unexpected state.

    This error surfaces cases where a subprocess wrapped by ``ProcessManager`` leaves ``returncode`` unset after ``communicate`` returns,
    indicating the operating system failed to report the final exit status.
    """

    def __init__(self, name: str, pid: int, message: str | None = None) -> None:
        """Initialize the ProcessStateError.

        Args:
            name: Human-readable name of the subprocess.
            pid: Process ID of the subprocess.
            message: Optional additional detail describing the failure.
        """
        self.process_name = name
        self.pid = pid
        detail = message or "subprocess returned no exit status"
        super().__init__(f"{detail} (name={name!r}, pid={pid})")
        _logger.debug(
            "process_state_error_constructed",
            process_name=name,
            pid=pid,
            detail=detail,
        )


class ProcessType(Enum):
    """Type of process being tracked."""

    SUBPROCESS = "subprocess"
    ASYNC_SUBPROCESS = "async_subprocess"
    EXTERNAL_TOOL = "external_tool"
    SANDBOX = "sandbox"
    DEBUGGER = "debugger"


class _ExternalPidInfo(TypedDict):
    """Type structure for external PID tracking entries."""

    name: str
    process_type: ProcessType
    metadata: dict[str, Any]
    registered_at: datetime


@dataclass
class TrackedProcess:
    """Information about a tracked process."""

    process: Popen[bytes] | asyncio.subprocess.Process
    process_type: ProcessType
    name: str
    registered_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    metadata: dict[str, Any] = field(default_factory=dict)
    cleanup_callback: Callable[[], Coroutine[Any, Any, None]] | None = None

    @property
    def pid(self) -> int | None:
        """Get process ID if available.

        Returns:
            int | None: The process ID, or None if not available.
        """
        return self.process.pid

    @property
    def is_running(self) -> bool:
        """Check if process is still running.

        Returns:
            bool: True if the process is still running, False otherwise.
        """
        if isinstance(self.process, Popen):
            return self.process.poll() is None
        return self.process.returncode is None

    def check_running(self) -> bool:
        """Check if process is still running (non-cached version).

        This method exists to avoid mypy's type narrowing on property access.
        Use this when checking running state after an operation that may have
        changed the process state.

        Returns:
            bool: True if the process is still running, False otherwise.
        """
        if isinstance(self.process, Popen):
            return self.process.poll() is None
        return self.process.returncode is None


class ProcessManager:
    """Centralized manager for all spawned processes.

    This singleton class tracks all processes spawned by Intellicrack and ensures
    proper cleanup on application exit. It handles:
    - Normal exit via atexit handlers
    - Signal-based termination (SIGINT, SIGTERM)
    - Graceful shutdown with timeout followed by forceful termination

    Attributes:
        DEFAULT_GRACEFUL_TIMEOUT: Default graceful shutdown timeout in seconds.
        DEFAULT_FORCE_TIMEOUT: Default forced termination timeout in seconds.
    """

    _instance: ProcessManager | None = None
    _lock: threading.Lock = threading.Lock()
    _processes: dict[int, TrackedProcess]
    _external_pids: dict[int, _ExternalPidInfo]

    DEFAULT_GRACEFUL_TIMEOUT: float = 5.0
    DEFAULT_FORCE_TIMEOUT: float = 3.0

    _SignalHandler = Callable[[int, FrameType | None], Any] | int | None

    def __new__(cls) -> Self:
        """Create or return the singleton instance.

        Returns:
            Self: The singleton ProcessManager instance.
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    object.__setattr__(instance, "_initialized", False)
                    cls._instance = instance
        return cast("Self", cls._instance)

    def __init__(self) -> None:
        """Initialize the ProcessManager singleton instance."""
        if self._initialized:
            return

        self._processes = {}
        self._external_pids = {}
        self._process_lock = threading.Lock()
        self._cleanup_in_progress = False
        self._original_sigint_handler: ProcessManager._SignalHandler = None
        self._original_sigterm_handler: ProcessManager._SignalHandler = None
        self.atexit_registered = False
        self.shutdown_event = threading.Event()
        self._initialized = True
        _logger.debug("process_manager_initialized")

    @classmethod
    def get_instance(cls) -> ProcessManager:
        """Get the singleton instance.

        Returns:
            ProcessManager: The singleton ProcessManager instance.
        """
        return cls()

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (for testing)."""
        _logger.debug("process_manager_resetting")
        with cls._lock:
            inst = cls._instance
            if inst is not None:
                inst.prepare_for_teardown()
            cls._instance = None

    def prepare_for_teardown(self) -> None:
        """Reset internal state in preparation for singleton teardown."""
        self._cleanup_in_progress = False
        self._processes.clear()

    @staticmethod
    def _get_logger() -> structlog.stdlib.BoundLogger:
        """Get the module logger.

        Returns:
            structlog.stdlib.BoundLogger: The module logger instance.
        """
        return _logger

    def install_handlers(self) -> None:
        """Install signal handlers and atexit hook for cleanup.

        This should be called once during application startup, typically in ``main.py`` before any processes are spawned. The atexit hook is
        registered at most once per Python interpreter — even when :meth:`reset_instance` is invoked between calls — using a module-level
        guard so cleanup never executes twice on shutdown.
        """
        if self.atexit_registered:
            return

        with _atexit_guard_lock:
            if not _atexit_registered_globally[0]:
                atexit.register(ProcessManager._atexit_cleanup_global)
                _atexit_registered_globally[0] = True
        self.atexit_registered = True

        if sys.platform != "win32":
            self._original_sigint_handler = signal.getsignal(signal.SIGINT)
            self._original_sigterm_handler = signal.getsignal(signal.SIGTERM)
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        else:
            try:
                self._original_sigint_handler = signal.getsignal(signal.SIGINT)
                signal.signal(signal.SIGINT, self._signal_handler)
                if hasattr(signal, "SIGBREAK"):
                    signal.signal(signal.SIGBREAK, self._signal_handler)
            except (ValueError, OSError) as e:
                _logger.exception(
                    "signal_handler_install_failed",
                    error_str=str(e),
                    error_type=type(e).__name__,
                )

        ProcessManager._get_logger().info("handlers_installed")

    def uninstall_handlers(self) -> None:
        """Uninstall signal handlers (restore original handlers)."""
        if sys.platform != "win32":
            if self._original_sigint_handler is not None:
                signal.signal(signal.SIGINT, self._original_sigint_handler)
            if self._original_sigterm_handler is not None:
                signal.signal(signal.SIGTERM, self._original_sigterm_handler)
        elif self._original_sigint_handler is not None:
            try:
                signal.signal(signal.SIGINT, self._original_sigint_handler)
            except (ValueError, OSError):
                _logger.exception("signal_handler_uninstall_failed")

        if self.atexit_registered:
            self.atexit_registered = False

        ProcessManager._get_logger().info("handlers_uninstalled")

    @staticmethod
    def _atexit_cleanup_global() -> None:
        """Global atexit hook that delegates to the active singleton.

        Registered once per interpreter via :meth:`install_handlers`. If no :class:`ProcessManager` singleton exists (because callers reset
        it), this is a no-op and exit proceeds without spurious work.
        """
        instance = ProcessManager._instance
        if instance is None:
            return
        instance.run_atexit_cleanup()

    def run_atexit_cleanup(self) -> None:
        """Public entry point that runs the at-exit cleanup once.

        Delegates to :meth:`_atexit_cleanup`; provided so the global hook can invoke instance cleanup without violating member-access lint
        rules.
        """
        self._atexit_cleanup()

    def _signal_handler(self, signum: int, frame: FrameType | None) -> None:
        """Handle termination signals by triggering cleanup.

        Returns control to the interpreter immediately so the OS-level signal
        handler does not block other system activity. When an asyncio loop is
        running, the cleanup coroutine is scheduled thread-safely. Otherwise a
        background daemon thread runs :meth:`_sync_cleanup` so the original
        handler delegate fires without waiting on process termination.

        Args:
            signum: The signal number received.
            frame: The current stack frame, or None.
        """
        logger = ProcessManager._get_logger()
        logger.info("signal_received", signal=signum)

        self.shutdown_event.set()

        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(lambda: asyncio.create_task(self.cleanup_all_async()))
        except RuntimeError:
            logger.warning("no_running_event_loop_for_async_cleanup")
            cleanup_thread = threading.Thread(
                target=self._sync_cleanup,
                name="ProcessManagerSignalCleanup",
                daemon=True,
            )
            cleanup_thread.start()

        if (
            self._original_sigint_handler not in {None, signal.SIG_DFL, signal.SIG_IGN}
            and callable(self._original_sigint_handler)
            and signum == signal.SIGINT
        ):
            self._original_sigint_handler(signum, frame)

    def _atexit_cleanup(self) -> None:
        """Cleanup handler for normal program exit.

        Delegates to :meth:`_sync_cleanup`, which terminates every tracked subprocess and external PID along with their descendants in a
        single pass. The historical implementation invoked :meth:`_terminate_process_sync` for each tracked entry before calling
        :meth:`_sync_cleanup`, causing every process tree to be walked twice and adding tens of seconds of latency to interpreter shutdown.
        """
        if self._cleanup_in_progress:
            return

        ProcessManager._get_logger().info("atexit_cleanup_triggered")
        self._sync_cleanup()
        ProcessManager.reset_instance()

    def _sync_cleanup(self) -> None:
        """Clean up resources synchronously for use outside async context."""
        if self._cleanup_in_progress:
            return

        self._cleanup_in_progress = True
        logger = ProcessManager._get_logger()
        logger.info("sync_cleanup_started")

        with self._process_lock:
            processes = list(self._processes.values())
            external_pids = list(self._external_pids.keys())

        # Collect all processes including children
        all_procs_psutil: list[psutil.Process] = []
        root_pids = [p.pid for p in processes if p.pid is not None] + external_pids

        for pid in root_pids:
            try:
                proc = psutil.Process(pid)
                all_procs_psutil.append(proc)
                all_procs_psutil.extend(proc.children(recursive=True))
            except psutil.NoSuchProcess:
                _logger.exception("process_lookup_failed", pid=pid)
        # Deduplicate based on PID
        seen_pids: set[int] = set()
        unique_procs: list[psutil.Process] = []
        for p in all_procs_psutil:
            if p.pid not in seen_pids:
                seen_pids.add(p.pid)
                unique_procs.append(p)

        for p in unique_procs:
            try:
                p.terminate()
                _logger.info("signal_sent", pid=p.pid, signal=_SIGNAL_SIGTERM)
            except psutil.NoSuchProcess:
                _logger.exception("process_terminate_target_missing", pid=p.pid)

        _, alive = psutil.wait_procs(unique_procs, timeout=self.DEFAULT_GRACEFUL_TIMEOUT)

        if alive:
            logger.warning("sync_cleanup_force_kill", count=len(alive))
            for p in alive:
                try:
                    ProcessManager._force_kill_process(p)
                except psutil.NoSuchProcess:
                    _logger.exception("kill_process_target_missing", pid=p.pid)
            psutil.wait_procs(alive, timeout=self.DEFAULT_FORCE_TIMEOUT)

        with self._process_lock:
            self._processes.clear()
            self._external_pids.clear()

        self._cleanup_in_progress = False
        logger.info("sync_cleanup_complete")

    @staticmethod
    def _force_kill_process(p: psutil.Process) -> None:
        """Force-kill a single ``psutil.Process`` with platform-specific logging.

        Propagates :class:`psutil.NoSuchProcess` from ``kill()`` when the
        target process has already exited so the caller can log the missing
        target.

        Args:
            p: The ``psutil.Process`` to kill. The caller is responsible for
                catching :class:`psutil.NoSuchProcess` if the target has
                already exited.
        """
        if sys.platform == "win32":
            p.kill()
            _logger.info("win32_terminate_signal_sent", pid=p.pid, exit_code=_WIN_PROCESS_TERMINATE)
        else:
            p.kill()
            _logger.info("signal_sent", pid=p.pid, signal=_SIGNAL_SIGKILL)

    @staticmethod
    def _terminate_process_sync(
        process: Popen[bytes] | asyncio.subprocess.Process,
    ) -> None:
        """Terminate a process synchronously.

        Args:
            process: The process to terminate.
        """
        ProcessManager._terminate_tree_with_psutil(
            process.pid,
            ProcessManager.DEFAULT_GRACEFUL_TIMEOUT,
            ProcessManager.DEFAULT_FORCE_TIMEOUT,
        )

    @staticmethod
    def terminate_tree(
        pid: int,
        graceful_timeout: float = DEFAULT_GRACEFUL_TIMEOUT,
        force_timeout: float = DEFAULT_FORCE_TIMEOUT,
    ) -> None:
        """Terminate a process tree using psutil.

        Kills the root process and all its descendants. First sends
        SIGTERM and waits for graceful_timeout, then sends SIGKILL
        to any survivors and waits for force_timeout.

        Args:
            pid: Root process ID.
            graceful_timeout: Seconds to wait for SIGTERM.
            force_timeout: Seconds to wait for SIGKILL.
        """
        ProcessManager._terminate_tree_with_psutil(pid, graceful_timeout, force_timeout)

    @staticmethod
    def _terminate_tree_with_psutil(
        pid: int,
        graceful_timeout: float,
        force_timeout: float,
    ) -> None:
        """Terminate a process tree using psutil (internal).

        Args:
            pid: Root process ID.
            graceful_timeout: Seconds to wait for SIGTERM.
            force_timeout: Seconds to wait for SIGKILL.
        """
        try:
            parent = psutil.Process(pid)
        except psutil.NoSuchProcess:
            _logger.exception("terminate_tree_root_lookup_missing", pid=pid)
            return
        except psutil.AccessDenied:
            _logger.warning("terminate_tree_root_access_denied", pid=pid)
            return

        try:
            children = parent.children(recursive=True)
        except psutil.NoSuchProcess:
            _logger.exception("terminate_tree_root_lookup_exited", pid=pid)
            return
        except psutil.AccessDenied:
            _logger.warning("terminate_tree_children_access_denied", pid=pid)
            return

        all_procs = [*children, parent]

        for p in all_procs:
            try:
                p.terminate()
            except psutil.NoSuchProcess:
                _logger.exception("terminate_tree_process_target_missing", pid=p.pid)
            except psutil.AccessDenied:
                _logger.warning("terminate_tree_access_denied", pid=p.pid)

        _, alive = psutil.wait_procs(all_procs, timeout=graceful_timeout)

        if alive:
            for p in alive:
                try:
                    p.kill()
                except psutil.NoSuchProcess:
                    _logger.exception("kill_tree_process_target_missing", pid=p.pid)
                except psutil.AccessDenied:
                    _logger.warning("kill_tree_access_denied", pid=p.pid)
            psutil.wait_procs(alive, timeout=force_timeout)

    def register(
        self,
        process: Popen[bytes] | asyncio.subprocess.Process,
        name: str,
        process_type: ProcessType = ProcessType.SUBPROCESS,
        metadata: dict[str, Any] | None = None,
        cleanup_callback: Callable[[], Coroutine[Any, Any, None]] | None = None,
    ) -> int:
        """Register a process for tracking.

        Args:
            process: The process to track.
            name: Human-readable name for the process.
            process_type: Type of process being tracked.
            metadata: Optional metadata about the process.
            cleanup_callback: Optional async callback for custom cleanup.

        Returns:
            int: The process ID used as the tracking key.
        """
        pid = process.pid

        tracked = TrackedProcess(
            process=process,
            process_type=process_type,
            name=name,
            metadata=metadata or {},
            cleanup_callback=cleanup_callback,
        )

        with self._process_lock:
            self._processes[pid] = tracked

        ProcessManager._get_logger().debug(
            "process_registered",
            process_name=name,
            pid=pid,
            type=process_type.value,
        )

        return pid

    def unregister(self, pid: int) -> TrackedProcess | None:
        """Unregister a process from tracking.

        Args:
            pid: The process ID to unregister.

        Returns:
            TrackedProcess | None: The tracked process info if found, None otherwise.
        """
        with self._process_lock:
            tracked = self._processes.pop(pid, None)

        if tracked is not None:
            ProcessManager._get_logger().debug(
                "process_unregistered",
                process_name=tracked.name,
                pid=pid,
            )

        return tracked

    def get_tracked(self, pid: int) -> TrackedProcess | None:
        """Get tracked process information.

        Args:
            pid: The process ID to look up.

        Returns:
            TrackedProcess | None: The tracked process info if found, None otherwise.
        """
        with self._process_lock:
            return self._processes.get(pid)

    def get_all_tracked(self) -> list[TrackedProcess]:
        """Get all tracked processes.

        Returns:
            list[TrackedProcess]: List of all tracked processes.
        """
        with self._process_lock:
            return list(self._processes.values())

    def get_running_processes(self) -> list[TrackedProcess]:
        """Get all currently running tracked processes.

        Returns:
            list[TrackedProcess]: List of tracked processes that are still running.
        """
        with self._process_lock:
            return [p for p in self._processes.values() if p.is_running]

    async def terminate_process(
        self,
        pid: int,
        graceful_timeout: float | None = None,
        force_timeout: float | None = None,
    ) -> bool:
        """Terminate a specific process.

        Args:
            pid: The process ID to terminate.
            graceful_timeout: Timeout for graceful termination.
            force_timeout: Timeout for forceful termination.

        Returns:
            bool: True if process was terminated, False if not found or already stopped.
        """
        graceful_timeout = graceful_timeout or self.DEFAULT_GRACEFUL_TIMEOUT
        force_timeout = force_timeout or self.DEFAULT_FORCE_TIMEOUT
        logger = ProcessManager._get_logger()

        tracked = self.get_tracked(pid)
        if tracked is None:
            logger.warning("process_not_found", pid=pid)
            return False

        if not tracked.is_running:
            self.unregister(pid)
            return True

        logger.debug("process_terminating", process_name=tracked.name, pid=pid)

        if tracked.cleanup_callback is not None:
            try:
                await tracked.cleanup_callback()
                await asyncio.sleep(0.5)
                if not tracked.check_running():
                    self.unregister(pid)
                    return True
            except (OSError, RuntimeError) as e:
                logger.warning("cleanup_callback_failed", process_name=tracked.name, error=str(e))

        process = tracked.process

        if isinstance(process, Popen):
            await ProcessManager._terminate_subprocess(process, tracked.name, graceful_timeout, force_timeout)
        else:
            await ProcessManager._terminate_async_subprocess(process, tracked.name, graceful_timeout, force_timeout)

        self.unregister(pid)
        return True

    @staticmethod
    async def _terminate_subprocess(
        process: Popen[bytes],
        name: str,
        graceful_timeout: float,
        force_timeout: float,
    ) -> None:
        """Terminate a Popen process.

        Args:
            process: The subprocess to terminate.
            name: Human-readable name for the process (for logging).
            graceful_timeout: Timeout for graceful termination in seconds.
            force_timeout: Timeout for forceful termination in seconds.
        """
        logger = ProcessManager._get_logger()

        await asyncio.to_thread(
            ProcessManager._terminate_tree_with_psutil,
            process.pid,
            graceful_timeout,
            force_timeout,
        )

        # Ensure the Python object reflects the termination
        if process.poll() is None:
            try:
                await asyncio.to_thread(process.wait, timeout=0.1)
            except TimeoutExpired:
                # Should not happen if psutil worked, but as fallback
                logger.warning("process_zombie_fallback", process_name=name)
                ProcessManager._terminate_process_sync(process)
                await asyncio.to_thread(process.wait)

        logger.info("process_terminated_tree", process_name=name)

    @staticmethod
    async def _terminate_async_subprocess(
        process: asyncio.subprocess.Process,
        name: str,
        graceful_timeout: float,
        force_timeout: float,
    ) -> None:
        """Terminate an asyncio subprocess.

        Args:
            process: The async subprocess to terminate.
            name: Human-readable name for the process (for logging).
            graceful_timeout: Timeout for graceful termination in seconds.
            force_timeout: Timeout for forceful termination in seconds.
        """
        logger = ProcessManager._get_logger()

        await asyncio.to_thread(
            ProcessManager._terminate_tree_with_psutil,
            process.pid,
            graceful_timeout,
            force_timeout,
        )

        try:
            await asyncio.wait_for(process.wait(), timeout=0.1)
        except TimeoutError:
            logger.warning("async_process_zombie_fallback", process_name=name)
            ProcessManager._terminate_process_sync(process)
            try:
                await process.wait()
            except (OSError, RuntimeError) as exc:
                _logger.warning("zombie_wait_fallback_failed", error=str(exc))

        logger.info("async_process_terminated_tree", process_name=name)

    async def cleanup_all_async(
        self,
        graceful_timeout: float | None = None,
        force_timeout: float | None = None,
    ) -> None:
        """Cleanup all tracked processes asynchronously.

        Args:
            graceful_timeout: Timeout for graceful termination per process.
            force_timeout: Timeout for forceful termination per process.
        """
        if self._cleanup_in_progress:
            return

        self._cleanup_in_progress = True
        logger = ProcessManager._get_logger()
        logger.info("async_cleanup_started")

        graceful_timeout = graceful_timeout or self.DEFAULT_GRACEFUL_TIMEOUT
        force_timeout = force_timeout or self.DEFAULT_FORCE_TIMEOUT

        with self._process_lock:
            pids = list(self._processes.keys())
            external_pids = list(self._external_pids.keys())

        for pid in pids:
            try:
                await self.terminate_process(pid, graceful_timeout, force_timeout)
            except (OSError, psutil.NoSuchProcess, RuntimeError) as e:
                logger.warning("cleanup_pid_failed", pid=pid, error=str(e))

        for ext_pid in external_pids:
            try:
                logger.debug("external_pid_terminating", pid=ext_pid)
                await asyncio.to_thread(self.terminate_external_pid, ext_pid, force=True)
            except (OSError, psutil.NoSuchProcess, RuntimeError) as e:
                logger.warning("external_pid_terminate_failed", pid=ext_pid, error=str(e))

        with self._process_lock:
            self._external_pids.clear()

        self._cleanup_in_progress = False
        self.clear_shutdown_request()
        logger.info("async_cleanup_complete")

    def is_shutdown_requested(self) -> bool:
        """Check if shutdown has been requested via signal.

        Returns:
            bool: True if a shutdown signal has been received, False otherwise.
        """
        return self.shutdown_event.is_set()

    def clear_shutdown_request(self) -> None:
        """Clear the shutdown request flag."""
        self.shutdown_event.clear()

    def request_shutdown(self) -> None:
        """Request and perform an immediate shutdown of all tracked processes.

        Sets the shutdown flag observed by :meth:`is_shutdown_requested`, then
        synchronously runs :meth:`_sync_cleanup`, which walks every tracked
        subprocess and external PID (including descendant processes) and
        terminates them. This gives callers -- such as ``MainWindow.closeEvent``
        -- a guaranteed, bounded final sweep that reaps any process left behind
        by a bridge whose own ``detach``/``shutdown``/``stop`` teardown silently
        failed or timed out, rather than merely flipping a flag nothing else
        acts on.
        """
        logger = ProcessManager._get_logger()
        logger.info("shutdown_requested")
        self.shutdown_event.set()
        self._sync_cleanup()

    @property
    def process_count(self) -> int:
        """Get the number of tracked processes.

        Returns:
            int: The total count of tracked processes.
        """
        with self._process_lock:
            return len(self._processes)

    @property
    def running_count(self) -> int:
        """Get the number of running tracked processes.

        Returns:
            int: The count of currently running tracked processes.
        """
        with self._process_lock:
            return sum(bool(p.is_running) for p in self._processes.values())

    def __repr__(self) -> str:
        """Return string representation.

        Returns:
            str: A string representation of the ProcessManager state.
        """
        return f"ProcessManager(tracked={self.process_count}, running={self.running_count})"

    @staticmethod
    def _communicate_tracked(
        *,
        process: Popen[bytes],
        name: str,
        timeout: float | None,
        text: bool,
        empty_text: str | bytes,
        logger: structlog.stdlib.BoundLogger,
    ) -> tuple[str | bytes, str | bytes, int | None]:
        """Drive ``process.communicate`` and decode its output.

        Performs the blocking ``communicate`` call, decodes stdout/stderr when
        ``text`` is true, and returns the streams together with the captured
        ``returncode``. The caller is responsible for handling
        :class:`TimeoutExpired`, killing the process, and unregistering it.
        Propagates :class:`TimeoutExpired` from ``process.communicate`` when
        the process does not exit within ``timeout`` seconds.

        Args:
            process: The :class:`subprocess.Popen` instance returned by
                :meth:`run_tracked`.
            name: Human-readable process name used for log records.
            timeout: Optional ``communicate`` timeout (seconds).
            text: When true, decode bytes to ``utf-8`` with ``errors="replace"``.
            empty_text: Sentinel returned when a stream is ``None``; matches
                the ``str``/``bytes`` mode chosen by ``text``.
            logger: Bound logger used to emit the completion record.

        Returns:
            tuple[str | bytes, str | bytes, int | None]: ``(stdout, stderr,
            returncode)`` after the process exits.
        """
        communicate_result = cast(
            "tuple[bytes | None, bytes | None]",
            process.communicate(timeout=timeout),
        )
        stdout_data, stderr_data = communicate_result

        stdout_result: str | bytes
        if stdout_data is None:
            stdout_result = empty_text
        elif text:
            stdout_result = stdout_data.decode("utf-8", errors="replace")
        else:
            stdout_result = stdout_data

        stderr_result: str | bytes
        if stderr_data is None:
            stderr_result = empty_text
        elif text:
            stderr_result = stderr_data.decode("utf-8", errors="replace")
        else:
            stderr_result = stderr_data

        returncode = process.returncode
        logger.debug("subprocess_completed", process_name=name, returncode=returncode)
        return stdout_result, stderr_result, returncode

    def run_tracked(
        self,
        args: list[str],
        name: str,
        *,
        capture_output: bool = True,
        text: bool = True,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = False,
        creationflags: int = 0,
    ) -> CompletedProcess[Any]:
        """Execute a subprocess with ProcessManager tracking.

        This method wraps subprocess execution to ensure the process is tracked
        and will be terminated during application shutdown.

        Args:
            args: Command and arguments to execute.
            name: Human-readable name for the process.
            capture_output: Capture stdout and stderr.
            text: Decode output as text (returns str); False returns bytes.
            timeout: Maximum time to wait for process.
            cwd: Working directory for the process.
            env: Environment variables for the process.
            check: Raise CalledProcessError if process returns non-zero.
            creationflags: Windows process creation flags.

        Returns:
            CompletedProcess[Any]: Execution results (stdout/stderr as str if text=True).

        Raises:
            TimeoutExpired: If timeout exceeded.
            CalledProcessError: If check=True and process failed.
            ProcessStateError: If the subprocess returns without an exit status.
        """
        logger = ProcessManager._get_logger()
        stdout_pipe = PIPE if capture_output else None
        stderr_pipe = PIPE if capture_output else None

        logger.debug("subprocess_started", process_name=name, command=args[0])
        process = Popen(
            args,
            stdout=stdout_pipe,
            stderr=stderr_pipe,
            cwd=cwd,
            env=env,
            creationflags=creationflags,
        )

        pid = self.register(
            process,
            name=name,
            process_type=ProcessType.SUBPROCESS,
            metadata={"args": args, "timeout": timeout},
        )

        empty_text: str | bytes = "" if text else b""
        try:
            stdout_result, stderr_result, returncode = ProcessManager._communicate_tracked(
                process=process,
                name=name,
                timeout=timeout,
                text=text,
                empty_text=empty_text,
                logger=logger,
            )

        except TimeoutExpired:
            logger.warning("process_timeout", process_name=name, pid=pid)
            process.kill()
            process.wait()
            self.unregister(pid)
            raise

        finally:
            self.unregister(pid)

        if returncode is None:
            logger.error("subprocess_missing_returncode", process_name=name, pid=pid)
            raise ProcessStateError(name=name, pid=pid)

        result: CompletedProcess[Any] = CompletedProcess(
            args=args,
            returncode=returncode,
            stdout=stdout_result,
            stderr=stderr_result,
        )

        if check and result.returncode != 0:
            raise CalledProcessError(
                result.returncode,
                args,
                output=result.stdout,
                stderr=result.stderr,
            )

        return result

    async def run_tracked_async(
        self,
        args: list[str],
        name: str,
        *,
        capture_output: bool = True,
        text: bool = True,
        process_timeout: float | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = False,
        creationflags: int = 0,
    ) -> CompletedProcess[Any]:
        """Execute a subprocess asynchronously with ProcessManager tracking.

        This method wraps subprocess execution to ensure the process is tracked
        and will be terminated during application shutdown. It delegates to
        run_tracked via asyncio.to_thread.

        Args:
            args: Command and arguments to execute.
            name: Human-readable name for the process.
            capture_output: Capture stdout and stderr.
            text: Decode output as text.
            process_timeout: Maximum time to wait for process.
            cwd: Working directory for the process.
            env: Environment variables for the process.
            check: Raise CalledProcessError if process returns non-zero.
            creationflags: Windows process creation flags.

        Returns:
            CompletedProcess[Any]: Execution results with captured stdout/stderr.
        """
        return await asyncio.to_thread(
            self.run_tracked,
            args,
            name,
            capture_output=capture_output,
            text=text,
            timeout=process_timeout,
            cwd=cwd,
            env=env,
            check=check,
            creationflags=creationflags,
        )

    def register_external_pid(
        self,
        pid: int,
        name: str,
        process_type: ProcessType = ProcessType.EXTERNAL_TOOL,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Register an external process by PID for cleanup tracking.

        Use this for processes not directly spawned by subprocess (e.g.,
        daemonized processes) that should be terminated when the application
        exits. Verifies the PID corresponds to a live OS process via
        :func:`_pid_exists` before registering.

        Args:
            pid: The process ID to track.
            name: Human-readable name for the process.
            process_type: Type of process being tracked.
            metadata: Optional metadata about the process.

        Raises:
            ValueError: If ``pid`` does not correspond to a live process.
        """
        logger = ProcessManager._get_logger()

        if not _pid_exists(pid):
            logger.warning(
                "external_pid_register_rejected_dead_pid",
                process_name=name,
                pid=pid,
            )
            msg = f"cannot register external PID {pid}: process does not exist"
            raise ValueError(msg)

        with self._process_lock:
            if pid in self._processes or pid in self._external_pids:
                logger.debug("pid_already_registered", pid=pid)
                return

            self._external_pids[pid] = {
                "name": name,
                "process_type": process_type,
                "metadata": metadata or {},
                "registered_at": datetime.now(tz=UTC),
            }

        logger.debug(
            "external_pid_registered",
            process_name=name,
            pid=pid,
            type=process_type.value,
        )

    def unregister_external_pid(self, pid: int) -> bool:
        """Unregister an external process from tracking.

        Args:
            pid: The process ID to unregister.

        Returns:
            bool: True if the PID was registered and removed, False otherwise.
        """
        with self._process_lock:
            if pid in self._external_pids:
                del self._external_pids[pid]
                ProcessManager._get_logger().debug("external_pid_unregistered", pid=pid)
                return True
        return False

    def terminate_external_pid(self, pid: int, *, force: bool = False) -> bool:
        """Terminate an external process by PID using psutil (tree kill).

        Args:
            pid: The process ID to terminate.
            force: If True, skip graceful termination and kill immediately.

        Returns:
            bool: True if process was terminated (or already gone), False on error.
        """
        logger = ProcessManager._get_logger()

        with self._process_lock:
            info = self._external_pids.get(pid)
            name = info["name"] if info else f"PID-{pid}"

        try:
            graceful = 0.1 if force else self.DEFAULT_GRACEFUL_TIMEOUT
            force_to = self.DEFAULT_FORCE_TIMEOUT

            self._terminate_tree_with_psutil(pid, graceful, force_to)

            self.unregister_external_pid(pid)
            logger.info(
                "external_pid_terminated",
                process_name=name,
                pid=pid,
            )

        except psutil.NoSuchProcess:
            logger.warning("external_pid_already_gone", pid=pid)
            self.unregister_external_pid(pid)
            return False

        except (OSError, psutil.Error, RuntimeError) as e:
            logger.warning(
                "external_pid_terminate_error",
                pid=pid,
                error=str(e),
            )
            return False

        else:
            return True
