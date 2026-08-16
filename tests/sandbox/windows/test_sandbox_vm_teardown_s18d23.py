# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S18-D23: the stop force-killed a session that had closed cleanly.

Measured live. The backend's own stop log, both lines stamped the same second:

```
graceful_close_ok                  pid=19056
windows_sandbox_session_force_kill graceful=True session_pid=19056
```

A close that succeeded was escalated to a kill anyway, and
``vmmemWindowsSandbox`` stayed resident through ``destroy`` and ``shutdown``.
Because Windows Sandbox allows one instance at a time, that leak blocks every
later run.

Two faults produced it. :meth:`WindowsSandbox._try_graceful_close` is asked to
close a pid - the session host, which owns the window - but waited on
``self.process``, the launcher, which is a different process that exits on its
own the moment it has handed the session off. So it reported success for a pid
it never watched, the caller saw that pid still alive and force-killed it. And
the vmwp worker was force-killed immediately afterwards, during the very Host
Compute Service teardown that releases the VM.

These gates use real processes only. The discriminator for "was it killed or
did it exit on its own" is the exit code: the probe exits ``42`` under its own
control, and Windows stamps ``1`` on a process it terminates, so the two
outcomes can never be confused.
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.process_manager import ProcessManager
from intellicrack.core.subprocess_compat import DEVNULL, Popen
from intellicrack.sandbox.windows import WindowsSandbox

from .backend_constants import production_seconds


if TYPE_CHECKING:
    from collections.abc import Iterator


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows Sandbox teardown is Windows-only")

# Chosen so a self-exit can never be confused with a termination: Windows
# stamps 1 on a process it kills, and 0 is what almost anything returns.
_SELF_EXIT_CODE: Final[int] = 42
_SHORT_LIVED_S: Final[int] = 3
_LONG_LIVED_S: Final[int] = 120
_WAIT_BUDGET_S: Final[float] = 30.0
_IMPATIENT_BUDGET_S: Final[float] = 2.0
# The window the backend itself gives HCS, read from the backend.
_TEARDOWN_WINDOW_S: Final[float] = production_seconds("_VM_TEARDOWN_TIMEOUT")
_ESCALATION_CEILING_S: Final[float] = _TEARDOWN_WINDOW_S * 4


def _spawn(seconds: int, exit_code: int) -> Popen[bytes]:
    """Start a real process that lives for a while and then exits on its own.

    Args:
        seconds: Roughly how long the process stays alive.
        exit_code: Code it exits with when it finishes by itself.

    Returns:
        Popen[bytes]: The running process.
    """
    return Popen(
        ["cmd.exe", "/c", f"ping -n {seconds + 1} 127.0.0.1 >nul & exit /b {exit_code}"],
        stdout=DEVNULL,
        stderr=DEVNULL,
        stdin=DEVNULL,
    )


class _TeardownSandbox(WindowsSandbox):
    """Exposes the stop-path internals without tripping ``reportPrivateUsage``."""

    def use_process(self, process: Popen[bytes] | None) -> None:
        """Stand a real process in for the launcher this instance spawned.

        Args:
            process: Process to treat as the launcher.
        """
        self.process = process

    def use_worker_pid(self, pid: int | None) -> None:
        """Stand a real process in for the vmwp worker backing the VM.

        Args:
            pid: Worker process id.
        """
        self._worker_pid = pid

    def worker_pid(self) -> int | None:
        """Return the worker pid the instance still considers live.

        Returns:
            int | None: The tracked worker pid.
        """
        return self._worker_pid

    async def await_pid_exit(self, pid: int, budget_seconds: float) -> bool:
        """Forward to :meth:`WindowsSandbox._await_pid_exit`.

        Args:
            pid: Process to watch.
            budget_seconds: Seconds to wait for it.

        Returns:
            bool: True if that process left within the window.
        """
        return await self._await_pid_exit(pid, budget_seconds)

    async def retire_worker(self) -> None:
        """Forward to :meth:`WindowsSandbox._terminate_sandbox_worker`."""
        await self._terminate_sandbox_worker(ProcessManager.get_instance())


@pytest.fixture
def reaped() -> Iterator[list[Popen[bytes]]]:
    """Kill anything a test leaves running, however it failed.

    Yields:
        list[Popen[bytes]]: Registry of processes to reap on teardown.
    """
    started: list[Popen[bytes]] = []
    try:
        yield started
    finally:
        for process in started:
            if process.poll() is None:
                process.kill()
            process.wait()


@pytest.mark.asyncio
async def test_the_wait_watches_the_pid_it_was_given_not_the_launcher(reaped: list[Popen[bytes]]) -> None:
    """Waiting on one process must not be satisfied by a different one.

    The launcher outlives nothing here - it is the long-lived process - so a
    wait that watches it instead of the pid it was handed cannot return inside
    the budget. This is the exact confusion that reported ``graceful_close_ok``
    for a session that was still up.

    Args:
        reaped: Fixture registry that terminates leftovers.
    """
    launcher = _spawn(_LONG_LIVED_S, 0)
    watched = _spawn(_SHORT_LIVED_S, _SELF_EXIT_CODE)
    reaped.extend((launcher, watched))

    sandbox = _TeardownSandbox()
    sandbox.use_process(launcher)

    started = time.monotonic()
    exited = await sandbox.await_pid_exit(watched.pid, _WAIT_BUDGET_S)
    elapsed = time.monotonic() - started

    assert exited, (
        f"the wait gave up after {elapsed:.1f}s on a process that exits in about {_SHORT_LIVED_S}s; "
        f"it must have been watching the launcher, which is still running"
    )
    assert launcher.poll() is None, "the launcher exited during the wait, so this run cannot tell the two processes apart"
    assert elapsed < _WAIT_BUDGET_S, (
        f"the wait ran the full {_WAIT_BUDGET_S:.0f}s budget rather than returning when the watched process left"
    )


@pytest.mark.asyncio
async def test_the_wait_reports_failure_when_the_process_outlives_the_budget(reaped: list[Popen[bytes]]) -> None:
    """A process that is still up when the window closes must not read as gone.

    Args:
        reaped: Fixture registry that terminates leftovers.
    """
    stubborn = _spawn(_LONG_LIVED_S, 0)
    reaped.append(stubborn)

    sandbox = _TeardownSandbox()
    sandbox.use_process(None)

    exited = await sandbox.await_pid_exit(stubborn.pid, _IMPATIENT_BUDGET_S)

    assert not exited, "the wait reported a still-running process as gone, which is what licenses skipping the force kill"
    assert stubborn.poll() is None, "the process under test died on its own; the assertion above proved nothing"


@pytest.mark.asyncio
async def test_a_worker_that_is_unwinding_is_left_alone(reaped: list[Popen[bytes]]) -> None:
    """The worker must be given its teardown window instead of being killed.

    The worker exits on its own with a code nothing else produces. If the stop
    path killed it, Windows would stamp its own code instead, so the exit code
    alone separates "waited for it" from "shot it".

    Args:
        reaped: Fixture registry that terminates leftovers.
    """
    worker = _spawn(_SHORT_LIVED_S, _SELF_EXIT_CODE)
    reaped.append(worker)

    sandbox = _TeardownSandbox()
    sandbox.use_process(None)
    sandbox.use_worker_pid(worker.pid)

    await sandbox.retire_worker()

    assert worker.poll() is not None, "the worker is still running after the stop path returned"
    assert worker.returncode == _SELF_EXIT_CODE, (
        f"the worker exited {worker.returncode}, not the {_SELF_EXIT_CODE} it exits with under its own control; "
        f"it was terminated during the teardown that releases the VM"
    )
    assert sandbox.worker_pid() is None, "the instance still tracks a worker it has finished with"


@pytest.mark.asyncio
async def test_a_worker_that_never_leaves_is_still_forced(reaped: list[Popen[bytes]]) -> None:
    """Patience is bounded: a worker that outlasts the window is still retired.

    Args:
        reaped: Fixture registry that terminates leftovers.
    """
    worker = _spawn(_LONG_LIVED_S, 0)
    reaped.append(worker)

    sandbox = _TeardownSandbox()
    sandbox.use_process(None)
    sandbox.use_worker_pid(worker.pid)

    started = time.monotonic()
    await asyncio.wait_for(sandbox.retire_worker(), timeout=_ESCALATION_CEILING_S)
    elapsed = time.monotonic() - started

    assert elapsed >= _TEARDOWN_WINDOW_S - 1.0, (
        f"the stop path escalated after {elapsed:.1f}s, inside the {_TEARDOWN_WINDOW_S:.0f}s teardown window; "
        f"that is the impatience that killed the worker mid-unwind and leaked the VM"
    )
    assert sandbox.worker_pid() is None, "a worker that outlived its teardown window was left tracked and never retired"
