# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Process-lifecycle helpers for the test suite.

Provides three primitives that together give zero tolerance for zombie
processes spawned by tests:

* :func:`is_sandboxed`: detects whether pytest is executing inside the
  Intellicrack Docker test sandbox. Tests that spawn external processes
  (notepad, ollama, target binaries, debuggee processes) should run only
  inside the sandbox; the root ``conftest.py`` uses this flag to skip those
  tests on the host unless the operator explicitly opts in.
* :class:`ManagedProcess`: a context manager that wraps :class:`Popen`
  and guarantees the spawned process tree is killed on context exit, even if
  the test fails, raises, or pytest is interrupted. Cleanup is layered:
  graceful terminate, force kill, then a psutil-backed tree kill so orphaned
  grandchildren cannot survive.
* :func:`snapshot_descendants` / :func:`kill_new_descendants`: a session-level
  safety net used by the autouse orphan killer fixture. Snapshots the current
  pytest process's descendants at session start and forcibly terminates any
  new descendants that remain at session end. This catches leaks from
  fixtures that bypass :class:`ManagedProcess`, exception paths in legacy
  tests, and any future code that spawns processes without registering them.

The helpers are deliberately conservative: cleanup never raises, descendant
enumeration tolerates :class:`psutil.NoSuchProcess` and
:class:`psutil.AccessDenied`, and every wait has a hard timeout.
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import AbstractContextManager
from typing import IO, TYPE_CHECKING, Any, Final, Self

import psutil

from intellicrack.core.subprocess_compat import (
    DEVNULL,
    Popen,
    TimeoutExpired,
)


if TYPE_CHECKING:
    from types import TracebackType


__all__ = [
    "ALLOW_HOST_PROCESS_TESTS_ENV",
    "SANDBOX_ENV_VAR",
    "ManagedProcess",
    "allow_host_process_tests",
    "is_sandboxed",
    "kill_new_descendants",
    "kill_pid_tree",
    "snapshot_descendants",
]


_logger: Final[logging.Logger] = logging.getLogger(__name__)


SANDBOX_ENV_VAR: Final[str] = "INTELLICRACK_SANDBOXED"
ALLOW_HOST_PROCESS_TESTS_ENV: Final[str] = "INTELLICRACK_ALLOW_HOST_PROCESS_TESTS"

_GRACEFUL_TERMINATE_TIMEOUT_S: Final[float] = 5.0
_FORCE_KILL_TIMEOUT_S: Final[float] = 3.0
_TREE_KILL_TIMEOUT_S: Final[float] = 3.0
_TRUTHY_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})


def _env_truthy(name: str) -> bool:
    """Return whether environment variable ``name`` is set to a truthy value.

    Args:
        name: Environment variable name to inspect.

    Returns:
        bool: ``True`` when the variable is set to ``1``, ``true``, ``yes``,
            or ``on`` (case-insensitive). ``False`` when unset or any other value.
    """
    raw = os.environ.get(name)
    return False if raw is None else raw.strip().lower() in _TRUTHY_VALUES


def is_sandboxed() -> bool:
    """Return whether pytest is running inside the Intellicrack Docker sandbox.

    The Docker test image sets :data:`SANDBOX_ENV_VAR` to ``1`` in its
    ``ENV`` block; ``scripts.sandbox.docker_sandbox`` also forwards it via
    ``--env``. When the variable is absent the test process is assumed to be
    running on the host (developer machine, CI runner, IDE test runner).

    Returns:
        bool: ``True`` when the sandbox env var is set to a truthy value.
    """
    return _env_truthy(SANDBOX_ENV_VAR)


def allow_host_process_tests() -> bool:
    """Return whether the operator explicitly allowed host-side process tests.

    When :data:`ALLOW_HOST_PROCESS_TESTS_ENV` is truthy, tests marked with
    ``@pytest.mark.spawns_process`` are not skipped on the host. Use this only
    for local debugging when an in-container run is impractical; the standard
    workflow is ``just test``.

    Returns:
        bool: ``True`` when the override env var is truthy.
    """
    return _env_truthy(ALLOW_HOST_PROCESS_TESTS_ENV)


def kill_pid_tree(pid: int, *, timeout: float = _TREE_KILL_TIMEOUT_S) -> None:
    """Forcibly terminate ``pid`` and all of its descendants.

    Sends ``terminate()`` to every descendant first, waits up to ``timeout``
    seconds for graceful exit, then ``kill()``s any survivors. The function
    never raises: psutil exceptions for processes that have already exited,
    or that we lack permission to inspect, are swallowed.

    Args:
        pid: Root PID of the process tree to kill.
        timeout: Seconds to wait between graceful terminate and force kill.
    """
    try:
        root = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return
    except psutil.Error as exc:
        _logger.debug("kill_pid_tree_lookup_failed", extra={"pid": pid, "error": str(exc)})
        return

    try:
        descendants = root.children(recursive=True)
    except psutil.Error:
        descendants = []
    targets = [*descendants, root]

    for proc in targets:
        try:
            proc.terminate()
        except psutil.NoSuchProcess:
            continue
        except psutil.Error as exc:
            _logger.debug(
                "kill_pid_tree_terminate_failed",
                extra={"pid": proc.pid, "error": str(exc)},
            )

    _gone, alive = psutil.wait_procs(targets, timeout=timeout)
    for proc in alive:
        try:
            proc.kill()
        except psutil.NoSuchProcess:
            continue
        except psutil.Error as exc:
            _logger.debug(
                "kill_pid_tree_kill_failed",
                extra={"pid": proc.pid, "error": str(exc)},
            )

    psutil.wait_procs(alive, timeout=timeout)


class ManagedProcess(AbstractContextManager["ManagedProcess"]):
    """Context manager wrapping :class:`Popen` with guaranteed cleanup.

    On context exit, regardless of whether the body returned normally, raised,
    or was interrupted, the wrapped process AND its full descendant tree are
    terminated. Exit follows a strict three-stage policy:

    1. ``Popen.terminate()`` and wait up to ``graceful_timeout`` seconds.
    2. ``Popen.kill()`` and wait up to ``force_timeout`` seconds.
    3. :func:`kill_pid_tree` to mop up any orphaned descendants.

    This is the canonical way for tests to spawn external processes; tests
    that use :class:`Popen` directly are at risk of leaking
    processes when assertions fail mid-test.

    Attributes:
        argv: The argv passed to :class:`Popen`.
        process: The underlying :class:`Popen` once entered.
    """

    argv: list[str]
    process: Popen[bytes]

    def __init__(
        self,
        argv: list[str],
        *,
        graceful_timeout: float = _GRACEFUL_TERMINATE_TIMEOUT_S,
        force_timeout: float = _FORCE_KILL_TIMEOUT_S,
        startup_delay: float = 0.0,
        stdout: int | IO[Any] | None = DEVNULL,
        stderr: int | IO[Any] | None = DEVNULL,
        stdin: int | IO[Any] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        """Initialise the manager with the argv to spawn on context entry.

        Args:
            argv: Argument vector passed to :class:`Popen`.
            graceful_timeout: Seconds to wait after ``terminate()`` before
                escalating to ``kill()``.
            force_timeout: Seconds to wait after ``kill()`` before invoking
                the psutil-backed tree kill.
            startup_delay: Optional seconds to sleep after spawn so the child
                can initialise before tests interact with it.
            stdout: ``Popen`` ``stdout`` argument.
            stderr: ``Popen`` ``stderr`` argument.
            stdin: ``Popen`` ``stdin`` argument.
            cwd: Working directory for the child, or ``None`` for inherited.
            env: Environment dict for the child, or ``None`` for inherited.
        """
        self.argv = list(argv)
        self._graceful_timeout = graceful_timeout
        self._force_timeout = force_timeout
        self._startup_delay = startup_delay
        self._stdout = stdout
        self._stderr = stderr
        self._stdin = stdin
        self._cwd = cwd
        self._env = env
        self._closed = False

    @property
    def pid(self) -> int:
        """Return the PID of the wrapped process.

        Returns:
            int: PID assigned by the operating system.

        Raises:
            RuntimeError: If accessed before context entry.
        """
        if not hasattr(self, "process"):
            message = "ManagedProcess.pid accessed before context entry"
            raise RuntimeError(message)
        return self.process.pid

    def __enter__(self) -> Self:
        """Spawn the process and optionally sleep for ``startup_delay``.

        Returns:
            Self: ``self`` so callers can access ``self.process``.
        """
        self.process = Popen(
            self.argv,
            stdout=self._stdout,
            stderr=self._stderr,
            stdin=self._stdin,
            cwd=self._cwd,
            env=self._env,
        )
        if self._startup_delay > 0:
            time.sleep(self._startup_delay)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Terminate the wrapped process and its descendants.

        The cleanup never re-raises; failures during teardown are logged at
        debug level so the original test exception (if any) propagates.

        Args:
            exc_type: Exception type raised in the body, or ``None``.
            exc: Exception instance raised in the body, or ``None``.
            tb: Traceback of the body exception, or ``None``.
        """
        del exc_type, exc, tb
        self.close()

    def close(self) -> None:
        """Idempotently terminate the wrapped process and its descendants.

        Safe to call multiple times; subsequent calls are no-ops once the
        process has been reaped.
        """
        if self._closed:
            return
        self._closed = True
        if not hasattr(self, "process"):
            return

        proc = self.process
        pid = proc.pid

        if proc.poll() is None:
            try:
                proc.terminate()
            except OSError as exc:
                _logger.debug(
                    "managed_process_terminate_failed",
                    extra={"pid": pid, "error": str(exc)},
                )

        try:
            proc.wait(timeout=self._graceful_timeout)
        except TimeoutExpired:
            try:
                proc.kill()
            except OSError as exc:
                _logger.debug(
                    "managed_process_kill_failed",
                    extra={"pid": pid, "error": str(exc)},
                )
            try:
                proc.wait(timeout=self._force_timeout)
            except TimeoutExpired:
                _logger.warning(
                    "managed_process_force_kill_timeout",
                    extra={"pid": pid, "argv": self.argv},
                )
        except OSError as exc:
            _logger.debug(
                "managed_process_wait_failed",
                extra={"pid": pid, "error": str(exc)},
            )

        kill_pid_tree(pid)


def snapshot_descendants(root_pid: int | None = None) -> set[int]:
    """Capture the PID set of ``root_pid``'s descendants right now.

    Used as the baseline for :func:`kill_new_descendants`. Failures during
    enumeration return an empty set rather than raising, since the caller is
    typically a session-level safety-net fixture and must not break test runs.

    Args:
        root_pid: PID whose descendants should be snapshotted. Defaults to
            the current process.

    Returns:
        set[int]: PIDs alive under ``root_pid`` at call time. Empty if the
            root or any descendant disappears mid-enumeration.
    """
    if root_pid is None:
        root_pid = os.getpid()
    try:
        root = psutil.Process(root_pid)
        descendants = root.children(recursive=True)
    except psutil.NoSuchProcess:
        return set()
    except psutil.Error as exc:
        _logger.debug(
            "snapshot_descendants_failed",
            extra={"root_pid": root_pid, "error": str(exc)},
        )
        return set()
    return {proc.pid for proc in descendants}


def kill_new_descendants(
    baseline: set[int],
    *,
    root_pid: int | None = None,
    timeout: float = _TREE_KILL_TIMEOUT_S,
) -> list[int]:
    """Forcibly terminate descendants spawned since ``baseline`` was captured.

    Compares the current descendant set against ``baseline`` and kills any
    PIDs that are new. Each new PID is treated as the root of a subtree and
    its full descendant chain is killed via :func:`kill_pid_tree`. Failures
    are swallowed so this can be safely called from a session-end fixture.

    Args:
        baseline: PID set returned by an earlier :func:`snapshot_descendants`
            call.
        root_pid: PID under which to scan; defaults to the current process.
        timeout: Per-tree timeout passed to :func:`kill_pid_tree`.

    Returns:
        list[int]: PIDs of new descendants that were targeted for killing.
            Useful for diagnostic logging by the caller.
    """
    if root_pid is None:
        root_pid = os.getpid()
    current = snapshot_descendants(root_pid)
    new_pids = sorted(current - baseline)
    for pid in new_pids:
        kill_pid_tree(pid, timeout=timeout)
    return new_pids
