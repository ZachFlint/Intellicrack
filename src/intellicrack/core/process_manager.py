"""Centralized process management for Intellicrack.

This module provides a singleton ProcessManager that tracks all spawned processes
and ensures proper cleanup on application exit, signal handling, or exceptions.
"""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import ctypes
import os
import signal
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from types import FrameType
from typing import TYPE_CHECKING, Any

from .logging import get_logger


if TYPE_CHECKING:
    import logging
    from collections.abc import Coroutine

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

    process: subprocess.Popen[bytes] | asyncio.subprocess.Process
    process_type: ProcessType
    name: str
    registered_at: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)
    cleanup_callback: Callable[[], Coroutine[Any, Any, None]] | None = None

    @property
    def pid(self) -> int | None:
        """Get process ID if available.

        Returns:
            The process ID, or None if not available.
        """
        return self.process.pid

    @property
    def is_running(self) -> bool:
        """Check if process is still running.

        Returns:
            True if the process is still running, False otherwise.
        """
        if isinstance(self.process, subprocess.Popen):
            return self.process.poll() is None
        return self.process.returncode is None

    def check_running(self) -> bool:
        """Check if process is still running (non-cached version).

        This method exists to avoid mypy's type narrowing on property access.
        Use this when checking running state after an operation that may have
        changed the process state.

        Returns:
            True if the process is still running, False otherwise.
        """
        if isinstance(self.process, subprocess.Popen):
            return self.process.poll() is None
        return self.process.returncode is None


class ProcessManager:
    """Centralized manager for all spawned processes.

    This singleton class tracks all processes spawned by Intellicrack and ensures
    proper cleanup on application exit. It handles:
    - Normal exit via atexit handlers
    - Signal-based termination (SIGINT, SIGTERM)
    - Graceful shutdown with timeout followed by forceful termination
    """

    _instance: ProcessManager | None = None
    _lock: threading.Lock = threading.Lock()
    _initialized: bool
    _processes: dict[int, TrackedProcess]
    _external_pids: dict[int, dict[str, Any]]
    _process_lock: threading.Lock
    _cleanup_in_progress: bool
    _original_sigint_handler: Callable[[int, FrameType | None], Any] | int | None
    _original_sigterm_handler: Callable[[int, FrameType | None], Any] | int | None
    _atexit_registered: bool
    _shutdown_event: threading.Event

    DEFAULT_GRACEFUL_TIMEOUT: float = 5.0
    DEFAULT_FORCE_TIMEOUT: float = 3.0

    _SignalHandler = Callable[[int, FrameType | None], Any] | int | None

    def __new__(cls) -> ProcessManager:
        """Create or return the singleton instance.

        Returns:
            The singleton ProcessManager instance.
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialized = False
                    cls._instance = instance
        return cls._instance

    def __init__(self) -> None:
        """Initialize the ProcessManager."""
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

    @classmethod
    def get_instance(cls) -> ProcessManager:
        """Get the singleton instance.

        Returns:
            The singleton ProcessManager instance.
        """
        return cls()

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (for testing)."""
        with cls._lock:
            if cls._instance is not None:
                cls._instance._cleanup_in_progress = False
                cls._instance._processes.clear()
            cls._instance = None

    @staticmethod
    def _get_logger() -> logging.Logger:
        """Get the module logger.

        Returns:
            The module logger instance.
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
                _module_logger.debug("signal_handler_install_failed", extra={"error": str(e)})

        ProcessManager._get_logger().debug("handlers_installed")

    def uninstall_handlers(self) -> None:
        """Uninstall signal handlers (restore original handlers)."""
        if sys.platform != "win32":
            if self._original_sigint_handler is not None:
                signal.signal(signal.SIGINT, self._original_sigint_handler)
            if self._original_sigterm_handler is not None:
                signal.signal(signal.SIGTERM, self._original_sigterm_handler)
        elif self._original_sigint_handler is not None:
            with contextlib.suppress(ValueError, OSError):
                signal.signal(signal.SIGINT, self._original_sigint_handler)

        if self._atexit_registered:
            with contextlib.suppress(Exception):
                atexit.unregister(self._atexit_cleanup)
            self._atexit_registered = False

        ProcessManager._get_logger().debug("handlers_uninstalled")

    def _signal_handler(self, signum: int, frame: FrameType | None) -> None:
        """Handle termination signals by triggering cleanup.

        Args:
            signum: The signal number received.
            frame: The current stack frame, or None.
        """
        logger = ProcessManager._get_logger()
        logger.info("signal_received", extra={"signal": signum})

        self._shutdown_event.set()

        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(lambda: asyncio.create_task(self.cleanup_all_async()))
        except RuntimeError:
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
        """Synchronous cleanup for use outside async context."""
        if self._cleanup_in_progress:
            return

        self._cleanup_in_progress = True
        logger = ProcessManager._get_logger()

        with self._process_lock:
            processes = list(self._processes.values())
            external_pids = list(self._external_pids.keys())

        for tracked in processes:
            if not tracked.is_running:
                continue

            try:
                logger.debug("process_terminating", extra={"name": tracked.name, "pid": tracked.pid})
                self._terminate_process_sync(tracked.process)
            except Exception as e:
                logger.warning("process_terminate_failed", extra={"name": tracked.name, "error": str(e)})

        for tracked in processes:
            if not tracked.is_running:
                continue

            try:
                self._wait_or_kill_sync(tracked.process, tracked.name)
            except Exception as e:
                logger.warning("process_kill_failed", extra={"name": tracked.name, "error": str(e)})

        for ext_pid in external_pids:
            try:
                logger.debug("external_pid_terminating", extra={"pid": ext_pid})
                self.terminate_external_pid(ext_pid, force=True)
            except Exception as e:
                logger.warning("external_pid_terminate_failed", extra={"pid": ext_pid, "error": str(e)})

        with self._process_lock:
            self._processes.clear()
            self._external_pids.clear()

        self._cleanup_in_progress = False
        logger.info("sync_cleanup_complete")

    @staticmethod
    def _terminate_process_sync(
        process: subprocess.Popen[bytes] | asyncio.subprocess.Process,
    ) -> None:
        """Terminate a process synchronously.

        Args:
            process: The process to terminate.
        """
        process.terminate()

    def _wait_or_kill_sync(
        self,
        process: subprocess.Popen[bytes] | asyncio.subprocess.Process,
        name: str,
    ) -> None:
        """Wait for process to terminate, then kill if needed.

        Args:
            process: The process to wait for or kill.
            name: Human-readable name for the process (for logging).
        """
        logger = ProcessManager._get_logger()

        if isinstance(process, subprocess.Popen):
            try:
                process.wait(timeout=self.DEFAULT_GRACEFUL_TIMEOUT)
            except subprocess.TimeoutExpired:
                logger.warning("process_graceful_terminate_failed", extra={"name": name})
                process.kill()
                try:
                    process.wait(timeout=self.DEFAULT_FORCE_TIMEOUT)
                except subprocess.TimeoutExpired:
                    logger.warning("process_kill_timeout", extra={"name": name})

    def register(
        self,
        process: subprocess.Popen[bytes] | asyncio.subprocess.Process,
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
            The process ID used as the tracking key.
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
            extra={"name": name, "pid": pid, "type": process_type.value},
        )

        return pid

    def unregister(self, pid: int) -> TrackedProcess | None:
        """Unregister a process from tracking.

        Args:
            pid: The process ID to unregister.

        Returns:
            The tracked process info if found, None otherwise.
        """
        with self._process_lock:
            tracked = self._processes.pop(pid, None)

        if tracked is not None:
            ProcessManager._get_logger().debug(
                "process_unregistered",
                extra={"name": tracked.name, "pid": pid},
            )

        return tracked

    def get_tracked(self, pid: int) -> TrackedProcess | None:
        """Get tracked process information.

        Args:
            pid: The process ID to look up.

        Returns:
            The tracked process info if found, None otherwise.
        """
        with self._process_lock:
            return self._processes.get(pid)

    def get_all_tracked(self) -> list[TrackedProcess]:
        """Get all tracked processes.

        Returns:
            List of all tracked processes.
        """
        with self._process_lock:
            return list(self._processes.values())

    def get_running_processes(self) -> list[TrackedProcess]:
        """Get all currently running tracked processes.

        Returns:
            List of tracked processes that are still running.
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
            True if process was terminated, False if not found or already stopped.
        """
        graceful_timeout = graceful_timeout or self.DEFAULT_GRACEFUL_TIMEOUT
        force_timeout = force_timeout or self.DEFAULT_FORCE_TIMEOUT
        logger = ProcessManager._get_logger()

        tracked = self.get_tracked(pid)
        if tracked is None:
            logger.warning("process_not_found", extra={"pid": pid})
            return False

        if not tracked.is_running:
            self.unregister(pid)
            return True

        logger.debug("process_terminating", extra={"name": tracked.name, "pid": pid})

        if tracked.cleanup_callback is not None:
            try:
                await tracked.cleanup_callback()
                await asyncio.sleep(0.5)
                if not tracked.check_running():
                    self.unregister(pid)
                    return True
            except Exception as e:
                logger.warning("cleanup_callback_failed", extra={"name": tracked.name, "error": str(e)})

        process = tracked.process

        if isinstance(process, subprocess.Popen):
            await ProcessManager._terminate_subprocess(process, tracked.name, graceful_timeout, force_timeout)
        else:
            await ProcessManager._terminate_async_subprocess(process, tracked.name, graceful_timeout, force_timeout)

        self.unregister(pid)
        return True

    @staticmethod
    async def _terminate_subprocess(
        process: subprocess.Popen[bytes],
        name: str,
        graceful_timeout: float,
        force_timeout: float,
    ) -> None:
        """Terminate a subprocess.Popen process.

        Args:
            process: The subprocess to terminate.
            name: Human-readable name for the process (for logging).
            graceful_timeout: Timeout for graceful termination in seconds.
            force_timeout: Timeout for forceful termination in seconds.
        """
        logger = ProcessManager._get_logger()

        process.terminate()

        try:
            await asyncio.wait_for(
                asyncio.to_thread(process.wait),
                timeout=graceful_timeout,
            )
            logger.debug("process_terminated_gracefully", extra={"name": name})
        except TimeoutError:
            logger.warning("process_graceful_terminate_failed", extra={"name": name})
            process.kill()
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(process.wait),
                    timeout=force_timeout,
                )
            except TimeoutError:
                logger.warning("process_kill_timeout", extra={"name": name})

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

        process.terminate()

        try:
            await asyncio.wait_for(process.wait(), timeout=graceful_timeout)
            logger.debug("async_process_terminated_gracefully", extra={"name": name})
        except TimeoutError:
            logger.warning("async_process_graceful_terminate_failed", extra={"name": name})
            process.kill()
            try:
                await asyncio.wait_for(process.wait(), timeout=force_timeout)
            except TimeoutError:
                logger.warning("async_process_kill_timeout", extra={"name": name})

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
            except Exception as e:
                logger.warning("cleanup_pid_failed", extra={"pid": pid, "error": str(e)})

        for ext_pid in external_pids:
            try:
                logger.debug("external_pid_terminating", extra={"pid": ext_pid})
                await asyncio.to_thread(self.terminate_external_pid, ext_pid, True)
            except Exception as e:
                logger.warning("external_pid_terminate_failed", extra={"pid": ext_pid, "error": str(e)})

        with self._process_lock:
            self._external_pids.clear()

        self._cleanup_in_progress = False
        logger.info("async_cleanup_complete")

    def is_shutdown_requested(self) -> bool:
        """Check if shutdown has been requested via signal.

        Returns:
            True if a shutdown signal has been received, False otherwise.
        """
        return self._shutdown_event.is_set()

    def clear_shutdown_request(self) -> None:
        """Clear the shutdown request flag."""
        self._shutdown_event.clear()

    @property
    def process_count(self) -> int:
        """Get the number of tracked processes.

        Returns:
            The total count of tracked processes.
        """
        with self._process_lock:
            return len(self._processes)

    @property
    def running_count(self) -> int:
        """Get the number of running tracked processes.

        Returns:
            The count of currently running tracked processes.
        """
        with self._process_lock:
            return sum(1 for p in self._processes.values() if p.is_running)

    def __repr__(self) -> str:
        """Return string representation.

        Returns:
            A string representation of the ProcessManager state.
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
    ) -> subprocess.CompletedProcess[Any]:
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
            CompletedProcess with execution results (stdout/stderr as str if text=True).

        Raises:
            subprocess.TimeoutExpired: If timeout exceeded.
            CalledProcessError: If check=True and process failed.
        """
        logger = ProcessManager._get_logger()
        stdout_pipe = subprocess.PIPE if capture_output else None
        stderr_pipe = subprocess.PIPE if capture_output else None

        process = subprocess.Popen(
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
            if text:
                stdout_result = stdout_data.decode("utf-8", errors="replace")
            else:
                stdout_result = stdout_data

            stderr_result: str | bytes
            if text:
                stderr_result = stderr_data.decode("utf-8", errors="replace")
            else:
                stderr_result = stderr_data

            returncode = process.returncode

        except subprocess.TimeoutExpired:
            logger.warning("process_timeout", extra={"name": name, "pid": pid})
            process.kill()
            process.wait()
            self.unregister(pid)
            raise

        finally:
            self.unregister(pid)

        result: subprocess.CompletedProcess[Any] = subprocess.CompletedProcess(
            args=args,
            returncode=returncode if returncode is not None else -1,
            stdout=stdout_result,
            stderr=stderr_result,
        )

        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
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
    ) -> subprocess.CompletedProcess[Any]:
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
            CompletedProcess with execution results.
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
                logger.debug("pid_already_registered", extra={"pid": pid})
                return

            self._external_pids[pid] = {
                "name": name,
                "process_type": process_type,
                "metadata": metadata or {},
                "registered_at": datetime.now(),
            }

        logger.debug(
            "external_pid_registered",
            extra={"name": name, "pid": pid, "type": process_type.value},
        )

    def unregister_external_pid(self, pid: int) -> bool:
        """Unregister an external process from tracking.

        Args:
            pid: The process ID to unregister.

        Returns:
            True if the PID was registered and removed, False otherwise.
        """
        with self._process_lock:
            if pid in self._external_pids:
                del self._external_pids[pid]
                ProcessManager._get_logger().debug("external_pid_unregistered", extra={"pid": pid})
                return True
        return False

    def terminate_external_pid(self, pid: int, force: bool = False) -> bool:
        """Terminate an external process by PID using OS-level signals.

        Args:
            pid: The process ID to terminate.
            force: If True, use SIGKILL immediately; otherwise try SIGTERM first.

        Returns:
            True if process was terminated, False if not found or error.
        """
        logger = ProcessManager._get_logger()

        with self._process_lock:
            info = self._external_pids.get(pid)
            name = info["name"] if info else f"PID-{pid}"

        success = False
        try:
            if sys.platform == "win32":
                success = self._terminate_windows_process(pid, name, logger)
            else:
                sig = _SIGNAL_SIGKILL if force else _SIGNAL_SIGTERM
                os.kill(pid, sig)
                logger.debug("signal_sent", extra={"signal": sig, "name": name, "pid": pid})
                self.unregister_external_pid(pid)
                success = True
        except (ProcessLookupError, PermissionError) as e:
            logger.debug("external_pid_terminate_skipped", extra={"pid": pid, "error": str(e)})
            self.unregister_external_pid(pid)
        except Exception as e:
            logger.warning("external_pid_terminate_error", extra={"pid": pid, "error": str(e)})

        return success

    def _terminate_windows_process(self, pid: int, name: str, logger: logging.Logger) -> bool:
        """Terminate a process using Windows API.

        Args:
            pid: Process ID to terminate.
            name: Process name for logging.
            logger: Logger instance.

        Returns:
            True if terminated successfully, False otherwise.
        """
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(_WIN_PROCESS_TERMINATE, False, pid)
        if handle:
            kernel32.TerminateProcess(handle, _WIN_PROCESS_TERMINATE)
            kernel32.CloseHandle(handle)
            logger.debug("windows_process_terminated", extra={"name": name, "pid": pid})
            self.unregister_external_pid(pid)
            return True

        logger.warning("windows_process_open_failed", extra={"name": name, "pid": pid})
        self.unregister_external_pid(pid)
        return False
