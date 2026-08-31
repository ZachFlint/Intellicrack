# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""One long-running job at the head of the FIFO must not defeat the history bound.

``JobQueue._evict()`` trims the oldest terminal (``done``/``failed``) records
once the log exceeds ``_HISTORY_LIMIT``. If the job that happens to sit at the
front of the queue -- the oldest submitted -- is still ``running``, eviction
that only ever inspects that front entry finds an active job and gives up
immediately, no matter how many finished records have piled up behind it. This
case submits one job that blocks on a gate, floods the queue with far more
finished jobs than the history bound, and insists the run log still ends up
bounded once they finish, with the earliest of them evicted -- purely through
the public :class:`~hexbench.jobs.JobQueue` surface.
"""

from __future__ import annotations

import threading
import time
import unittest
from typing import Final

from hexbench.dispatch import InvocationResult
from hexbench.jobs import DONE, RUNNING, JobError, JobQueue
from hexbench.tests._support import Assertions


_HISTORY_LIMIT: Final = 512
"""Mirrors the private bound in ``hexbench.jobs``; this suite does not import it."""

_EXCESS: Final = 64
"""How far past the bound this test floods the queue, to give eviction real work to do."""

_WORKERS: Final = 8
_STUCK_TIMEOUT: Final = 30.0
_WAIT_TIMEOUT: Final = 60.0
_POLL_INTERVAL: Final = 0.005
_RUNNING_WAIT: Final = 10.0


def _stub_result(operation: str) -> InvocationResult:
    """Build a minimal, valid invocation result for a synthetic job.

    Args:
        operation: Name to record as the operation that ran.

    Returns:
        InvocationResult: A result carrying no payload, sufficient for the run log.
    """
    return InvocationResult(operation=operation, value=None, raw=None, duration_ms=0.0, created_handle=None, document=None)


def _blocking_job(gate: threading.Event) -> InvocationResult:
    """Run a job that does not finish until its gate is set.

    Args:
        gate: Event the job waits on before returning.

    Returns:
        InvocationResult: A stub result, returned once the gate opens.
    """
    gate.wait(_STUCK_TIMEOUT)
    return _stub_result("stuck")


def _await_state(queue: JobQueue, job_id: str, state: str, timeout: float) -> None:
    """Poll a job until it reaches a given state, tolerating early eviction.

    Args:
        queue: Queue the job was submitted to.
        job_id: Identifier of the job to watch.
        state: State to wait for.
        timeout: Seconds to wait before giving up.

    Raises:
        AssertionError: If the job neither reached the state nor was evicted
            within the timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            record = queue.poll(job_id)
        except JobError:
            return
        if record.state in {state, DONE}:
            return
        time.sleep(_POLL_INTERVAL)
    message = f"job {job_id} did not reach state {state!r} within {timeout} seconds"
    raise AssertionError(message)


class EvictionBypassTests(Assertions, unittest.TestCase):
    """A stuck head-of-queue job must not block eviction of finished jobs behind it."""

    def test_finished_jobs_behind_a_stuck_head_job_still_get_evicted(self) -> None:
        """The run log must stay bounded even while the oldest job is still running."""
        queue = JobQueue(workers=_WORKERS)
        gate = threading.Event()
        try:
            stuck_id = queue.submit(lambda: _blocking_job(gate), operation="stuck", handle=None)
            _await_state(queue, stuck_id, RUNNING, _RUNNING_WAIT)
            self.equal(queue.poll(stuck_id).state, RUNNING, "stuck job state before flooding the queue")

            trailing_ids = [
                queue.submit(lambda: _stub_result("fast"), operation="fast", handle=None) for _ in range(_HISTORY_LIMIT + _EXCESS)
            ]
            _await_state(queue, trailing_ids[-1], DONE, _WAIT_TIMEOUT)

            flush_id = queue.submit(lambda: _stub_result("flush"), operation="flush", handle=None)
            _await_state(queue, flush_id, DONE, _WAIT_TIMEOUT)

            total = len(queue.recent(limit=10_000))
            self.require(
                total <= _HISTORY_LIMIT,
                f"run log holds {total} records with a stuck head job, but the bound is {_HISTORY_LIMIT}; "
                "a job that finished long ago behind the stuck one was never evicted",
            )
            self.raises(
                JobError,
                "polling the earliest finished job once the log is bounded",
                lambda: queue.poll(trailing_ids[0]),
            )
        finally:
            gate.set()
            queue.shutdown()


if __name__ == "__main__":
    unittest.main()
