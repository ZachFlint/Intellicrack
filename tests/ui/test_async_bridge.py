# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the async bridge infrastructure.

Validates BridgeCallWorker, run_bridge_coroutine (blocking),
run_bridge_coroutine_async (non-blocking), and shutdown_bridge_loop.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.logging import IntellicrackLogger, get_logger, get_stdlib_root_logger
from intellicrack.core.types import RateLimitError
from intellicrack.ui.panels import async_bridge as async_bridge_mod
from intellicrack.ui.panels.async_bridge import (
    BridgeCallWorker,
    drain_bridge_workers,
    run_bridge_coroutine,
    shutdown_bridge_loop,
)


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


ASYNC_RETURN_VALUE = 42
ASYNC_WAIT_MS = 50
POLL_INTERVAL_MS = 10
MAX_WAIT_MS = 3000

_LOG_LEVEL = "DEBUG"
_LOG_FILENAME = "intellicrack.log"
# Emitted by both the rich renderer structlog prefers and the plain fallback it
# uses when rich is absent, so the check does not depend on which one ran.
_TRACEBACK_MARKER = "Traceback (most recent call last)"
_CALL_ERROR_EVENT = "async_bridge_call_error"
_WORKER_FAILED_EVENT = "async_bridge_worker_failed"


@pytest.fixture(autouse=True, scope="session")
def _cleanup_bridge_loop() -> Generator[None]:
    """Shut down the persistent bridge event loop after all async bridge tests.

    Yields:
        None: Nothing (fixture exists for cleanup only).
    """
    yield
    shutdown_bridge_loop()
    time.sleep(0.1)


@pytest.fixture
def rendered_bridge_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[Path]:
    """Point the real logging pipeline at a file and hand back its path.

    ``caplog`` is useless here: the module logs through structlog, and a
    ``caplog.at_level`` block around a worker collected an empty record list on
    a run whose own stdout carried the rendered event. The rendering also
    matters in its own right -- ``exc_info`` only becomes the traceback block
    seen in live logs once the production renderer formats it -- so the file
    written here is the artifact under test rather than a stand-in for it.

    The module's logger is rebound because structlog caches a bound logger on
    first use and never revisits that decision, so a module already used under
    an earlier test's configuration would keep writing there. The replacement
    comes from the same production factory under the same name.

    Args:
        tmp_path: Per-test directory the log is written into.
        monkeypatch: Fixture used to rebind the module logger for the test.

    Yields:
        Path: The log file the production pipeline writes to.
    """
    log_dir = tmp_path / "logs"
    IntellicrackLogger.configure(
        level=_LOG_LEVEL,
        log_dir=log_dir,
        file_enabled=True,
        console_enabled=False,
        json_file=False,
    )
    monkeypatch.setattr(async_bridge_mod, "_logger", get_logger(async_bridge_mod.__name__))
    try:
        yield log_dir / _LOG_FILENAME
    finally:
        root_logger = get_stdlib_root_logger()
        for handler in list(root_logger.handlers):
            root_logger.removeHandler(handler)
            handler.close()


def _read_bridge_log(log_file: Path, required_event: str) -> str:
    """Read back what the production pipeline rendered, proving it wrote here.

    Args:
        log_file: The log file the pipeline wrote to.
        required_event: An event the run under test must have produced. Without
            it, an absent traceback or absent crash event would be satisfied by
            a log this module never reached.

    Returns:
        str: The rendered log, including any traceback blocks.
    """
    assert log_file.exists(), "the logging pipeline wrote no file, so nothing was observed"
    text = log_file.read_text(encoding="utf-8")
    assert required_event in text, (
        f"the log holds no {required_event!r} record, so the worker was not writing to this file "
        "and anything missing from it proves nothing"
    )
    return text


def _run_worker_to_error(worker: BridgeCallWorker, qapp: QApplication, errors: list[object]) -> None:
    """Start a worker and pump the event loop until its error is delivered.

    Args:
        worker: The worker under test, with ``call_error`` already connected.
        qapp: Qt application fixture used to pump queued signals.
        errors: The list ``call_error`` appends to, polled for delivery.
    """
    worker.start()
    deadline = time.monotonic() + MAX_WAIT_MS / 1000
    while not errors and time.monotonic() < deadline:
        qapp.processEvents()
        time.sleep(POLL_INTERVAL_MS / 1000)


@pytest.mark.usefixtures("qapp")
class TestRunBridgeCoroutineBlocking:
    """Tests for the blocking run_bridge_coroutine variant."""

    @staticmethod
    def test_returns_coroutine_result() -> None:
        """Verify blocking call returns the coroutine's result."""

        async def simple_coro() -> int:
            await asyncio.sleep(0)
            return ASYNC_RETURN_VALUE

        result = run_bridge_coroutine(simple_coro())
        assert result == ASYNC_RETURN_VALUE

    @staticmethod
    def test_returns_none_result() -> None:
        """Verify blocking call propagates None return correctly."""

        async def none_coro() -> None:
            await asyncio.sleep(0)

        result = run_bridge_coroutine(none_coro())
        assert result is None

    @staticmethod
    def test_raises_on_coroutine_exception() -> None:
        """Verify blocking call propagates coroutine exceptions."""

        async def failing_coro() -> None:
            await asyncio.sleep(0)
            msg = "bridge failure"
            raise RuntimeError(msg)

        with pytest.raises(RuntimeError, match="bridge failure"):
            run_bridge_coroutine(failing_coro())

    @staticmethod
    def test_returns_string_result() -> None:
        """Verify blocking call handles string results."""
        expected = "disassembly output"

        async def string_coro() -> str:
            await asyncio.sleep(0)
            return expected

        result = run_bridge_coroutine(string_coro())
        assert result == expected

    @staticmethod
    def test_returns_dict_result() -> None:
        """Verify blocking call handles dict results."""
        expected: dict[str, int] = {"rax": 0x1234, "rbx": 0x5678}

        async def dict_coro() -> dict[str, int]:
            await asyncio.sleep(0)
            return expected

        result = run_bridge_coroutine(dict_coro())
        assert result == expected


@pytest.mark.usefixtures("qapp")
class TestRunBridgeCoroutineAsync:
    """Tests for the non-blocking run_bridge_coroutine_async variant.

    Uses BridgeCallWorker directly to hold references and avoid
    premature garbage collection of QThread objects.
    """

    @staticmethod
    def test_success_callback_invoked(qapp: QApplication) -> None:
        """Verify call_finished signal delivers the coroutine result.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        received: list[object] = []

        async def simple_coro() -> int:
            await asyncio.sleep(0)
            return ASYNC_RETURN_VALUE

        worker = BridgeCallWorker(simple_coro())
        _ = worker.call_finished.connect(received.append)
        worker.start()

        deadline = time.monotonic() + MAX_WAIT_MS / 1000
        while not received and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(POLL_INTERVAL_MS / 1000)

        assert len(received) == 1
        assert received[0] == ASYNC_RETURN_VALUE

    @staticmethod
    def test_error_callback_invoked(qapp: QApplication) -> None:
        """Verify call_error signal delivers the exception on failure.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        errors: list[object] = []

        async def failing_coro() -> None:
            await asyncio.sleep(0)
            msg = "async bridge error"
            raise ValueError(msg)

        worker = BridgeCallWorker(failing_coro())
        _ = worker.call_error.connect(errors.append)
        worker.start()

        deadline = time.monotonic() + MAX_WAIT_MS / 1000
        while not errors and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(POLL_INTERVAL_MS / 1000)

        assert len(errors) == 1
        assert isinstance(errors[0], ValueError)
        assert str(errors[0]) == "async bridge error"

    @staticmethod
    def test_worker_completes_without_callbacks(qapp: QApplication) -> None:
        """Verify a worker completes even without connected callbacks.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """

        async def noop_coro() -> int:
            await asyncio.sleep(0)
            return 1

        worker = BridgeCallWorker(noop_coro())
        worker.start()

        deadline = time.monotonic() + MAX_WAIT_MS / 1000
        while worker.isRunning() and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(POLL_INTERVAL_MS / 1000)

        assert not worker.isRunning()


@pytest.mark.usefixtures("qapp")
class TestBridgeCallWorker:
    """Tests for BridgeCallWorker QThread."""

    @staticmethod
    def test_emits_call_finished_signal(qapp: QApplication) -> None:
        """Verify call_finished signal emits the coroutine result.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        results: list[object] = []

        async def coro() -> str:
            await asyncio.sleep(0)
            return "worker_result"

        worker = BridgeCallWorker(coro())
        worker.call_finished.connect(results.append)
        worker.start()

        deadline = time.monotonic() + MAX_WAIT_MS / 1000
        while not results and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(POLL_INTERVAL_MS / 1000)

        assert results == ["worker_result"]

    @staticmethod
    def test_emits_call_error_signal(qapp: QApplication) -> None:
        """Verify call_error signal emits the exception on failure.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        errors: list[object] = []

        async def bad_coro() -> None:
            await asyncio.sleep(0)
            msg = "worker error"
            raise RuntimeError(msg)

        worker = BridgeCallWorker(bad_coro())
        worker.call_error.connect(errors.append)
        worker.start()

        deadline = time.monotonic() + MAX_WAIT_MS / 1000
        while not errors and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(POLL_INTERVAL_MS / 1000)

        assert len(errors) == 1
        assert isinstance(errors[0], RuntimeError)

    @staticmethod
    def test_provider_error_is_logged_as_a_call_error_not_a_worker_crash(
        qapp: QApplication,
        rendered_bridge_log: Path,
    ) -> None:
        """A ``ProviderError`` is routine, so it must not log a worker-crash traceback.

        Bad credentials, rate limits and unreachable bridges all reach this
        handler as ``IntellicrackError`` subclasses and are handed to the
        caller's ``on_error`` for display. Logging every one of them through
        ``logger.exception`` stamped a full traceback under a generic
        "worker failed" event, which buried the tracebacks that mean something.

        Args:
            qapp: Qt application fixture used to pump the event loop.
            rendered_bridge_log: Log file the production pipeline renders into.
        """
        errors: list[object] = []

        async def rate_limited() -> None:
            await asyncio.sleep(0)
            msg = "rate limit exceeded for model claude-opus-5"
            raise RateLimitError(msg)

        worker = BridgeCallWorker(rate_limited())
        worker.call_error.connect(errors.append)
        _run_worker_to_error(worker, qapp, errors)

        assert len(errors) == 1, "the provider error never reached the caller"
        assert isinstance(errors[0], RateLimitError), f"call_error carried {type(errors[0]).__name__}"

        text = _read_bridge_log(rendered_bridge_log, _CALL_ERROR_EVENT)
        assert _WORKER_FAILED_EVENT not in text, "a routine provider error was logged as an unexpected worker failure"
        assert _TRACEBACK_MARKER not in text, "a routine provider error rendered a full traceback into the log"

    @staticmethod
    def test_unexpected_failure_still_logs_a_worker_crash_with_traceback(
        qapp: QApplication,
        rendered_bridge_log: Path,
    ) -> None:
        """A non-domain exception must keep its traceback and crash classification.

        The counterpart to the provider-error gate: narrowing the traceback to
        domain errors only is correct, silencing it for everything is not.

        Args:
            qapp: Qt application fixture used to pump the event loop.
            rendered_bridge_log: Log file the production pipeline renders into.
        """
        errors: list[object] = []

        async def boom() -> None:
            await asyncio.sleep(0)
            msg = "worker plumbing broke"
            raise RuntimeError(msg)

        worker = BridgeCallWorker(boom())
        worker.call_error.connect(errors.append)
        _run_worker_to_error(worker, qapp, errors)

        assert len(errors) == 1, "the unexpected failure never reached the caller"

        text = _read_bridge_log(rendered_bridge_log, _WORKER_FAILED_EVENT)
        assert _TRACEBACK_MARKER in text, "an unexpected worker failure was logged without a traceback"


@pytest.mark.usefixtures("qapp")
class TestDrainBridgeWorkers:
    """Tests for ``drain_bridge_workers``, the shutdown-safety worker drain."""

    @staticmethod
    def test_drain_blocks_until_a_running_worker_finishes(qapp: QApplication) -> None:
        """drain_bridge_workers must wait for a still-running worker to finish.

        Starts a real ``BridgeCallWorker`` whose coroutine occupies its worker
        thread on the persistent bridge loop, so the OS thread is genuinely
        mid-flight when the drain begins. ``drain_bridge_workers`` must block
        until that thread has finished; that finished state is the precondition
        which prevents ``QThread: Destroyed while thread is still running`` at
        application shutdown. Were the drain to return without waiting, the
        worker would still report ``isRunning()`` immediately afterwards, so
        this assertion is falsified by removing the wait.

        Args:
            qapp: Qt application fixture used to pump queued signals.
        """
        completed: list[object] = []
        coro_seconds = 0.25

        async def _timed() -> str:
            await asyncio.sleep(coro_seconds)
            return "drained"

        worker = BridgeCallWorker(_timed())
        _ = worker.call_finished.connect(completed.append)
        worker.start()

        start_deadline = time.monotonic() + MAX_WAIT_MS / 1000
        while not worker.isRunning() and time.monotonic() < start_deadline:
            time.sleep(POLL_INTERVAL_MS / 1000)
        assert worker.isRunning(), "worker thread never started; test premise not established"

        drained = drain_bridge_workers(timeout_ms=MAX_WAIT_MS)

        assert not worker.isRunning(), (
            "drain_bridge_workers returned while the worker thread was still running; a QThread "
            "destroyed in this state aborts the process at shutdown"
        )
        assert drained >= 1, "drain_bridge_workers did not count the retained in-flight worker"

        qapp.processEvents()
        assert completed == ["drained"], "worker did not run its coroutine to completion before the drain returned"

    @staticmethod
    def test_drain_counts_already_finished_worker(qapp: QApplication) -> None:
        """A worker that has already finished is counted, exercising the non-running branch.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """

        async def _quick() -> int:
            await asyncio.sleep(0)
            return 7

        worker = BridgeCallWorker(_quick())
        worker.start()

        deadline = time.monotonic() + MAX_WAIT_MS / 1000
        while worker.isRunning() and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(POLL_INTERVAL_MS / 1000)
        assert not worker.isRunning(), "worker did not finish within the wait budget"

        drained = drain_bridge_workers(timeout_ms=MAX_WAIT_MS)

        assert drained >= 1, "drain_bridge_workers failed to count an already-finished retained worker"


@pytest.mark.usefixtures("qapp")
class TestBridgeLoopShutdownRobustness:
    """Tests that in-flight workers survive a mid-flight loop teardown."""

    @staticmethod
    def test_worker_abandons_a_stopped_loop_instead_of_zombieing() -> None:
        """A worker still running when the loop is shut down must exit promptly.

        Starts a genuinely long-running coroutine on a real ``BridgeCallWorker``
        so the worker's OS thread is mid-``future.result`` when
        ``shutdown_bridge_loop`` stops the shared loop. Because the loop is
        stopped, that future can never complete; a worker that waited on it
        unbounded would block its thread forever, becoming an unjoinable zombie
        whose ``QThread`` aborts the process at teardown. The worker must instead
        detect the dead loop, cancel the future, and finish - so ``wait`` returns
        ``True`` quickly. Removing the dead-loop detection in
        :meth:`BridgeCallWorker._await_future` leaves the thread running and
        falsifies the final assertion.
        """
        worker_join_budget_ms = 3000
        start_deadline = time.monotonic() + MAX_WAIT_MS / 1000

        async def _long() -> int:
            await asyncio.sleep(30)
            return 1

        worker = BridgeCallWorker(_long())
        worker.start()
        while not worker.isRunning() and time.monotonic() < start_deadline:
            time.sleep(POLL_INTERVAL_MS / 1000)
        assert worker.isRunning(), "worker thread never started; test premise not established"

        shutdown_bridge_loop()

        assert worker.wait(worker_join_budget_ms), (
            "worker stayed blocked on the stopped loop instead of abandoning its future; "
            "a QThread left running in this state aborts the process at teardown"
        )
        assert worker.isFinished()


class TestEnsureLoop:
    """Tests for the persistent event loop management."""

    @staticmethod
    def test_returns_running_loop() -> None:
        """Verify _ensure_loop returns a running event loop."""
        loop = async_bridge_mod.ensure_loop()
        assert loop.is_running()

    @staticmethod
    def test_returns_same_loop_on_repeated_calls() -> None:
        """Verify _ensure_loop returns the same loop instance."""
        loop1 = async_bridge_mod.ensure_loop()
        loop2 = async_bridge_mod.ensure_loop()
        assert loop1 is loop2


class TestShutdownBridgeLoop:
    """Tests for shutdown_bridge_loop cleanup."""

    @staticmethod
    def test_shutdown_is_idempotent() -> None:
        """Verify shutdown_bridge_loop can be called multiple times safely."""
        shutdown_bridge_loop()
        shutdown_bridge_loop()
