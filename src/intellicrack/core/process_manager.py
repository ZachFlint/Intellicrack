# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Centralized process management for Intellicrack.

This module provides a singleton ProcessManager that tracks all spawned processes
and ensures proper cleanup on application exit, signal handling, or exceptions.
"""

from __future__ import annotations

import asyncio
import atexit
import signal
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from types import FrameType
from typing import TYPE_CHECKING, Any

import psutil

from intellicrack.core._subprocess import PIPE, CalledProcessError, CompletedProcess, Popen, TimeoutExpired

from .logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Coroutine

    import structlog

_module_logger = get_logger("process_manager")

_WIN_PROCESS_TERMINATE = 1
_SIGNAL_SIGKILL = 9
_SIGNAL_SIGTERM = 15


class ProcessType(Enum):
    """Type of process being tracked."""

    SUBPROCESS = "subprocess"
    ASYNC_SUBPROCESS = "async_subprocess"
    EXTERNAL_TOOL = "external_tool"
    SANDBOX = "sandbox"
    DEBUGGER = "debugger"


@dataclass
class TrackedProcess:
    """Information about a tracked process."""

    process: Popen[bytes] | asyncio.subprocess.Process
    process_type: ProcessType
    name: str
    registered_at: datetime = field(default_factory=datetime.now)
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

    DEFAULT_GRACEFUL_TIMEOUT: float = 5.0
    DEFAULT_FORCE_TIMEOUT: float = 3.0

    _SignalHandler = Callable[[int, FrameType | None], Any] | int | None

    def __new__(cls) -> ProcessManager:
        """Create or return the singleton instance.

        Returns:
            ProcessManager: The singleton ProcessManager instance.
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialized = False
                    cls._instance = instance
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return

        self._processes = {}
        self._external_pids = {}
        self._process_lock = threading.Lock()
        self._cleanup_in_progress = False
        self._original_sigint_handler = None
        self._original_sigterm_handler = None
        self._atexit_registered = False
        self._shutdown_event = threading.Event()
        self._initialized = True
        _module_logger.debug("process_manager_initialized")

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
        _module_logger.debug("process_manager_resetting")
        with cls._lock:
            if cls._instance is not None:
                cls._instance._cleanup_in_progress = False
                cls._instance._processes.clear()
            cls._instance = None

    @staticmethod
    def _get_logger() -> structlog.stdlib.BoundLogger:
        """Get the module logger.

        Returns:
            structlog.stdlib.BoundLogger: The module logger instance.
        """
        return _module_logger

    def install_handlers(self) -> None:
        """Install signal handlers and atexit hook for cleanup.

        This should be called once during application startup, typically
        in main.py before any processes are spawned.
        """
        if self._atexit_registered:
            return

        atexit.register(self._atexit_cleanup)
        self._atexit_registered = True

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
                _module_logger.debug("signal_handler_install_failed", error=str(e))

        ProcessManager._get_logger().debug("handlers_installed")

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
                _module_logger.debug("signal_handler_uninstall_failed", exc_info=True)

        if self._atexit_registered:
            try:
                atexit.unregister(self._atexit_cleanup)
            except Exception:
                _module_logger.warning("atexit_unregister_failed", exc_info=True)
            self._atexit_registered = False

        ProcessManager._get_logger().debug("handlers_uninstalled")

    def _signal_handler(self, signum: int, frame: FrameType | None) -> None:
        """Handle termination signals by triggering cleanup.

        Args:
            signum: The signal number received.
            frame: The current stack frame, or None.
        """
        logger = ProcessManager._get_logger()
        logger.info("signal_received", signal=signum)

        self._shutdown_event.set()

        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(lambda: asyncio.create_task(self.cleanup_all_async()))
        except RuntimeError:
            logger.warning("no_running_event_loop_for_async_cleanup")
            self._sync_cleanup()

        if (
            self._original_sigint_handler not in {None, signal.SIG_DFL, signal.SIG_IGN}
            and callable(self._original_sigint_handler)
            and signum == signal.SIGINT
        ):
            self._original_sigint_handler(signum, frame)

    def _atexit_cleanup(self) -> None:
        """Cleanup handler for normal program exit."""
        if self._cleanup_in_progress:
            return

        ProcessManager._get_logger().info("atexit_cleanup_triggered")
        self._sync_cleanup()

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
                _module_logger.debug("process_already_exited", pid=pid)
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
            except psutil.NoSuchProcess:
                _module_logger.debug("terminate_process_already_exited", pid=p.pid)

        # 2. Wait for graceful termination
        _, alive = psutil.wait_procs(unique_procs, timeout=self.DEFAULT_GRACEFUL_TIMEOUT)

        if alive:
            logger.warning("sync_cleanup_force_kill", count=len(alive))
            for p in alive:
                try:
                    p.kill()
                except psutil.NoSuchProcess:
                    _module_logger.debug("kill_process_already_exited", pid=p.pid)
            psutil.wait_procs(alive, timeout=self.DEFAULT_FORCE_TIMEOUT)

        with self._process_lock:
            self._processes.clear()
            self._external_pids.clear()

        self._cleanup_in_progress = False
        logger.info("sync_cleanup_complete")

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
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)

        all_procs = [*children, parent]

        for p in all_procs:
            try:
                p.terminate()
            except psutil.NoSuchProcess:
                _module_logger.debug("terminate_tree_process_exited", pid=p.pid)

        _, alive = psutil.wait_procs(all_procs, timeout=graceful_timeout)

        if alive:
            for p in alive:
                try:
                    p.kill()
                except psutil.NoSuchProcess:
                    _module_logger.debug("kill_tree_process_exited", pid=p.pid)
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
            except Exception as e:
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
                process.kill()
                await asyncio.to_thread(process.wait)

        logger.debug("process_terminated_tree", process_name=name)

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
            process.kill()
            try:
                await process.wait()
            except Exception:
                _module_logger.warning("zombie_wait_fallback_failed", exc_info=True)

        logger.debug("async_process_terminated_tree", process_name=name)

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
            if self.is_shutdown_requested():
                logger.info("cleanup_interrupted_by_shutdown", remaining=len(pids))
                break
            try:
                await self.terminate_process(pid, graceful_timeout, force_timeout)
            except Exception as e:
                logger.warning("cleanup_pid_failed", pid=pid, error=str(e))

        for ext_pid in external_pids:
            try:
                logger.debug("external_pid_terminating", pid=ext_pid)
                await asyncio.to_thread(self.terminate_external_pid, ext_pid, True)
            except Exception as e:
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
        return self._shutdown_event.is_set()

    def clear_shutdown_request(self) -> None:
        """Clear the shutdown request flag."""
        self._shutdown_event.clear()

    def request_shutdown(self) -> None:
        """Request a graceful shutdown of all tracked processes."""
        logger = ProcessManager._get_logger()
        logger.info("shutdown_requested")
        self._shutdown_event.set()

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

        try:
            stdout_data, stderr_data = process.communicate(timeout=timeout)

            stdout_result: str | bytes
            stdout_result = stdout_data.decode("utf-8", errors="replace") if text else stdout_data

            stderr_result: str | bytes
            stderr_result = stderr_data.decode("utf-8", errors="replace") if text else stderr_data

            returncode = process.returncode
            logger.debug("subprocess_completed", process_name=name, returncode=returncode)

        except TimeoutExpired:
            logger.warning("process_timeout", process_name=name, pid=pid)
            process.kill()
            process.wait()
            self.unregister(pid)
            raise

        finally:
            self.unregister(pid)

        result: CompletedProcess[Any] = CompletedProcess(
            args=args,
            returncode=returncode if returncode is not None else -1,
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
        timeout: float | None = None,
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
            timeout: Maximum time to wait for process.
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
            timeout=timeout,
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

        Use this for processes not directly spawned by subprocess (e.g., daemonized
        processes) that should be terminated when the application exits.

        Args:
            pid: The process ID to track.
            name: Human-readable name for the process.
            process_type: Type of process being tracked.
            metadata: Optional metadata about the process.
        """
        logger = ProcessManager._get_logger()

        with self._process_lock:
            if pid in self._processes or pid in self._external_pids:
                logger.debug("pid_already_registered", pid=pid)
                return

            self._external_pids[pid] = {
                "name": name,
                "process_type": process_type,
                "metadata": metadata or {},
                "registered_at": datetime.now(),
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

    def terminate_external_pid(self, pid: int, force: bool = False) -> bool:
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
            logger.debug(
                "external_pid_terminated",
                process_name=name,
                pid=pid,
            )

        except psutil.NoSuchProcess:
            logger.warning("external_pid_already_gone", pid=pid)
            self.unregister_external_pid(pid)
            return False

        except Exception as e:
            logger.warning(
                "external_pid_terminate_error",
                pid=pid,
                error=str(e),
            )
            return False

        else:
            return True
