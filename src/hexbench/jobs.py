# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Background execution of invocations, and the session's record of what has run.

Several engine operations take long enough that running them on the request
thread would freeze the editor: a digram matrix over a large file, an entropy map
with a small block size, a hash of a whole image. Those go through :class:`JobQueue`,
which runs them on a small thread pool and lets the client poll.

The queue doubles as the session's run log. :meth:`JobQueue.recent` backs the
visible history panel, and :meth:`JobQueue.exercised` backs the coverage meter,
so it deliberately remembers which operations have completed successfully even
after their individual records have aged out of the log.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from functools import partial
from typing import TYPE_CHECKING, Final

from hexbench.dispatch import encode_document, translate_exception
from hexbench.registry import RegistryError


if TYPE_CHECKING:
    from collections.abc import Callable
    from concurrent.futures import Future

    from hexbench.codec import JsonValue
    from hexbench.dispatch import InvocationResult


__all__ = ["JobError", "JobQueue", "JobRecord"]

PENDING: Final = "pending"
RUNNING: Final = "running"
DONE: Final = "done"
FAILED: Final = "failed"

_ACTIVE_STATES: Final[frozenset[str]] = frozenset({PENDING, RUNNING})
_JOB_ID_BYTES: Final = 9
_HISTORY_LIMIT: Final = 512
_DEFAULT_WORKERS: Final = 4
_DEFAULT_RECENT: Final = 100
_SHUTDOWN_TIMEOUT: Final = 5.0
_CANCELLED_MESSAGE: Final = "the job was cancelled before it could run"


class JobError(RegistryError):
    """Raised when a job identifier is not known to the queue."""


@dataclass(frozen=True, slots=True)
class JobRecord:
    """The visible state of one submitted job.

    Attributes:
        job_id: Opaque identifier used to poll the job.
        operation: Name of the catalogued operation the job runs.
        handle: Document the job acts on, or ``None`` when it acts on none.
        state: One of ``pending``, ``running``, ``done`` or ``failed``.
        submitted_at: Unix time at which the job entered the queue.
        started_at: Unix time at which a worker picked the job up.
        finished_at: Unix time at which the job reached a terminal state.
        result: JSON rendering of the outcome, present once the job is done.
        error: JSON rendering of the failure, present once the job has failed.
    """

    job_id: str
    operation: str
    handle: str | None
    state: str
    submitted_at: float
    started_at: float | None
    finished_at: float | None
    result: JsonValue | None
    error: JsonValue | None


class JobQueue:
    """A bounded run log over a small pool of worker threads."""

    def __init__(self, workers: int = _DEFAULT_WORKERS) -> None:
        """Start a pool of workers ready to accept invocations.

        Args:
            workers: Number of worker threads. Keeping this small matters:
                every worker that is inside a long engine call holds that
                document's lock for the duration.
        """
        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="hexbench-job")
        self._lock = threading.Lock()
        self._records: dict[str, JobRecord] = {}
        self._raw: dict[str, bytes] = {}
        self._order: deque[str] = deque()
        self._exercised: set[str] = set()
        self._closed = False

    def submit(self, run: Callable[[], InvocationResult], *, operation: str, handle: str | None) -> str:
        """Queue an invocation for background execution.

        Args:
            run: Zero argument callable that performs the invocation.
            operation: Name of the catalogued operation being run.
            handle: Document the invocation acts on, or ``None``.

        Returns:
            str: Identifier to poll the job with.

        Raises:
            JobError: If the queue has already been shut down, including the
                case where ``shutdown()`` closed the underlying executor in the
                narrow window between this call's own closed check and its
                attempt to schedule the job.
        """
        job_id = secrets.token_urlsafe(_JOB_ID_BYTES)
        record = JobRecord(
            job_id=job_id,
            operation=operation,
            handle=handle,
            state=PENDING,
            submitted_at=time.time(),
            started_at=None,
            finished_at=None,
            result=None,
            error=None,
        )
        with self._lock:
            if self._closed:
                message = "the job queue has been shut down and accepts no further work"
                raise JobError(message)
            self._records[job_id] = record
            self._order.append(job_id)
            self._evict()
        try:
            future = self._executor.submit(self._run, job_id, run)
        except RuntimeError as exc:
            with self._lock:
                self._records.pop(job_id, None)
                if job_id in self._order:
                    self._order.remove(job_id)
            message = "the job queue has been shut down and accepts no further work"
            raise JobError(message) from exc
        future.add_done_callback(partial(self._settle, job_id))
        return job_id

    def poll(self, job_id: str) -> JobRecord:
        """Read the current state of one job.

        Args:
            job_id: Identifier returned by :meth:`submit`.

        Returns:
            JobRecord: The job's current state.

        Raises:
            JobError: If no job with that identifier is in the log.
        """
        with self._lock:
            record = self._records.get(job_id)
        if record is None:
            message = f"no job with id {job_id!r}"
            raise JobError(message)
        return record

    def recent(self, limit: int = _DEFAULT_RECENT) -> tuple[JobRecord, ...]:
        """List the most recently submitted jobs.

        Args:
            limit: Maximum number of records to return. Values below one yield
                an empty result.

        Returns:
            tuple[JobRecord, ...]: Job records, most recently submitted first.
        """
        if limit < 1:
            return ()
        with self._lock:
            ordered = list(self._order)
            records = [self._records[job_id] for job_id in reversed(ordered) if job_id in self._records]
        return tuple(records[:limit])

    def take_raw(self, job_id: str) -> bytes | None:
        """Remove and return the untruncated binary result of a finished job.

        The payload is handed over exactly once so a large export does not sit
        in memory after the client has downloaded it.

        Args:
            job_id: Identifier returned by :meth:`submit`.

        Returns:
            bytes | None: The binary result, or ``None`` if the job produced
            none or it has already been taken.
        """
        with self._lock:
            return self._raw.pop(job_id, None)

    def exercised(self) -> frozenset[str]:
        """List every operation that has completed successfully this session.

        Retained independently of the run log, so ageing a job record out of the
        log never makes the coverage meter go backwards.

        Returns:
            frozenset[str]: Names of the operations that have succeeded.
        """
        with self._lock:
            return frozenset(self._exercised)

    def shutdown(self, timeout: float = _SHUTDOWN_TIMEOUT) -> None:
        """Stop accepting work and wait a bounded time for the pool to drain.

        Jobs that have not started are cancelled. A job already inside a long
        engine call cannot be interrupted, so the wait is bounded and the
        remaining workers are left to finish as daemon threads.

        Args:
            timeout: Seconds to wait for running jobs to finish.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
        closer = threading.Thread(
            target=self._executor.shutdown,
            kwargs={"wait": True, "cancel_futures": True},
            name="hexbench-job-shutdown",
            daemon=True,
        )
        closer.start()
        closer.join(timeout)

    def _evict(self) -> None:
        """Drop the oldest terminal records once the log exceeds its limit.

        The caller must hold the queue lock. Jobs that are still pending or
        running are never evicted, since a client may still be polling them.
        Eviction scans the whole queue rather than stopping at the first
        active record it meets, so one long-running job sitting at the head
        of the FIFO can never by itself prevent completed records behind it
        from being trimmed.
        """
        excess = len(self._order) - _HISTORY_LIMIT
        if excess <= 0:
            return
        survivors: deque[str] = deque()
        for job_id in self._order:
            record = self._records.get(job_id)
            if excess > 0 and (record is None or record.state not in _ACTIVE_STATES):
                self._records.pop(job_id, None)
                self._raw.pop(job_id, None)
                excess -= 1
                continue
            survivors.append(job_id)
        self._order = survivors

    def _run(self, job_id: str, run: Callable[[], InvocationResult]) -> InvocationResult:
        """Mark a job as running and perform its invocation on a worker thread.

        Args:
            job_id: Identifier of the job being run.
            run: Zero argument callable that performs the invocation.

        Returns:
            InvocationResult: Whatever the invocation produced.
        """
        self._amend(job_id, lambda record: replace(record, state=RUNNING, started_at=time.time()))
        return run()

    def _settle(self, job_id: str, future: Future[InvocationResult]) -> None:
        """Record the terminal state of a job once its future completes.

        Reading the outcome from the future rather than wrapping the call in a
        broad ``except`` means no failure mode can be swallowed silently.

        Args:
            job_id: Identifier of the job that finished.
            future: The completed future for that job.
        """
        if future.cancelled():
            self._fail(job_id, {"kind": "cancelled", "status": 0, "message": _CANCELLED_MESSAGE})
            return
        failure = future.exception()
        if failure is not None:
            translated = translate_exception(failure)
            self._fail(job_id, {"kind": translated.kind, "status": translated.status, "message": str(translated)})
            return
        self._succeed(job_id, future.result())

    def _succeed(self, job_id: str, result: InvocationResult) -> None:
        """Store a successful outcome and count the operation as exercised.

        Args:
            job_id: Identifier of the job that finished.
            result: The invocation's result.
        """
        payload = _result_payload(result)
        with self._lock:
            self._exercised.add(result.operation)
            if result.raw is not None:
                self._raw[job_id] = result.raw
        self._amend(job_id, lambda record: replace(record, state=DONE, finished_at=time.time(), result=payload))

    def _fail(self, job_id: str, error: dict[str, JsonValue]) -> None:
        """Store a failed outcome.

        Args:
            job_id: Identifier of the job that failed.
            error: JSON rendering of the failure.
        """
        self._amend(job_id, lambda record: replace(record, state=FAILED, finished_at=time.time(), error=error))

    def _amend(self, job_id: str, revise: Callable[[JobRecord], JobRecord]) -> None:
        """Replace one job record under the queue lock.

        A record that has already aged out of the log is left alone rather than
        resurrected.

        Args:
            job_id: Identifier of the job to amend.
            revise: Callable producing the replacement record.
        """
        with self._lock:
            current = self._records.get(job_id)
            if current is None:
                return
            self._records[job_id] = revise(current)


def _result_payload(result: InvocationResult) -> JsonValue:
    """Render an invocation result for the run log.

    Args:
        result: The invocation's result.

    Returns:
        JsonValue: Object carrying the return value, the timing, and whether an
        untruncated binary payload is waiting to be collected.
    """
    return {
        "operation": result.operation,
        "value": result.value,
        "duration_ms": result.duration_ms,
        "created_handle": result.created_handle,
        "document": encode_document(result.document) if result.document is not None else None,
        "raw_length": len(result.raw) if result.raw is not None else 0,
        "raw_available": result.raw is not None,
    }
