# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""A ``submit()`` that loses the race against ``shutdown()`` must fail cleanly.

``JobQueue.submit()`` checks ``self._closed`` and records the new job under its
lock, then calls ``ThreadPoolExecutor.submit()`` outside that lock. If the pool
was shut down between those two steps, the executor raises a bare
``RuntimeError`` instead of the queue's own :class:`~hexbench.jobs.JobError`,
and the ``pending`` record it already inserted is orphaned -- never settled,
never visible as failed, permanently stuck in the run log.

This is reproduced deterministically, without reaching into the queue's
private state, by patching ``ThreadPoolExecutor.submit`` itself (a public
method of a public standard-library class) to behave exactly as it does once
``Executor.shutdown()`` has run: raise ``RuntimeError('cannot schedule new
futures after shutdown')``. That is precisely the failure mode a real
``submit()``/``shutdown()`` race produces, reached here without timing luck.
"""

from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Final
from unittest import mock

from hexbench.jobs import JobError, JobQueue
from hexbench.tests._support import Assertions


if TYPE_CHECKING:
    from hexbench.dispatch import InvocationResult


_SHUTDOWN_MESSAGE: Final = "cannot schedule new futures after shutdown"


def _never_runs() -> InvocationResult:
    """Stand in for work that must never actually execute in this test.

    Returns:
        InvocationResult: Never returns; always raises.

    Raises:
        AssertionError: Unconditionally, since the mocked executor must refuse
            to schedule this callable in the first place.
    """
    message = "this job's callable ran, but the pool should have refused to schedule it"
    raise AssertionError(message)


class SubmitShutdownRaceTests(Assertions, unittest.TestCase):
    """``submit()`` racing a pool that has already begun shutting down."""

    def test_submit_raises_job_error_not_a_bare_runtime_error(self) -> None:
        """The queue's own ``JobError`` must reach the caller, not the executor's raw ``RuntimeError``."""
        queue = JobQueue(workers=1)
        try:
            with mock.patch.object(ThreadPoolExecutor, "submit", side_effect=RuntimeError(_SHUTDOWN_MESSAGE)):
                self.raises(
                    JobError,
                    "submit() while the executor is mid-shutdown",
                    lambda: queue.submit(_never_runs, operation="noop", handle=None),
                )
        finally:
            queue.shutdown()

    def test_submit_does_not_leave_an_orphaned_pending_record_behind(self) -> None:
        """A job that lost the race must not linger in the run log forever as ``pending``."""
        queue = JobQueue(workers=1)
        try:
            before = queue.recent(limit=10_000)
            with mock.patch.object(ThreadPoolExecutor, "submit", side_effect=RuntimeError(_SHUTDOWN_MESSAGE)):
                self.raises(
                    JobError,
                    "submit() while the executor is mid-shutdown",
                    lambda: queue.submit(_never_runs, operation="noop", handle=None),
                )
            after = queue.recent(limit=10_000)
            self.equal(after, before, "job log before and after the failed submission")
        finally:
            queue.shutdown()


if __name__ == "__main__":
    unittest.main()
