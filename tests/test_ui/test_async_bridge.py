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
import concurrent.futures
import threading
import time
from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.panels import async_bridge as async_bridge_mod
from intellicrack.ui.panels.async_bridge import (
    BridgeCallWorker,
    run_bridge_coroutine,
    shutdown_bridge_loop,
)


if TYPE_CHECKING:
    from collections.abc import Generator

    from PyQt6.QtWidgets import QApplication


ASYNC_RETURN_VALUE = 42
ASYNC_WAIT_MS = 50
POLL_INTERVAL_MS = 10
MAX_WAIT_MS = 3000
LONG_RUN_SLEEP_S = 0.4


@pytest.fixture(autouse=True, scope="session")
def _cleanup_bridge_loop() -> Generator[None]:
    """Shut down the persistent bridge event loop after all async bridge tests.

    Yields:
        None: Nothing (fixture exists for cleanup only).
    """
    yield
    shutdown_bridge_loop()
    time.sleep(0.1)


@pytest.mark.usefixtures("qapp")
class TestRunBridgeCoroutineBlocking:
    """Tests for the blocking run_bridge_coroutine variant.

    These tests exercise the real persistent background event loop, not an
    instant-complete stub. The oracle for each result-passthrough case is a
    value computed *inside* the coroutine from arguments the test controls
    (so the test never freezes a constant the implementation already knows),
    plus an independent assertion that the work ran on the dedicated loop
    thread rather than the calling thread.
    """

    @staticmethod
    def test_runs_on_dedicated_background_thread_not_caller() -> None:
        """Verify the coroutine executes on the persistent loop thread, off the caller.

        The independent oracle is ``threading.get_ident()`` captured on the
        test thread before the call. The blocking runner must submit the
        coroutine to the background loop via ``run_coroutine_threadsafe``;
        if it instead ran the coroutine inline on the caller the captured
        identifiers would match and this assertion would fail.
        """
        caller_ident = threading.get_ident()

        async def report_thread() -> int:
            await asyncio.sleep(0)
            return threading.get_ident()

        worker_ident = run_bridge_coroutine(report_thread())
        assert isinstance(worker_ident, int)
        assert worker_ident != caller_ident
        loop_thread = async_bridge_mod._state.thread
        assert loop_thread is not None
        assert worker_ident == loop_thread.ident

    @staticmethod
    def test_computes_result_from_caller_supplied_inputs() -> None:
        """Verify the blocking call returns the coroutine's computed value verbatim.

        The expected value is derived from operands the test owns and is not
        a literal the coroutine returns unconditionally, so the assertion
        cannot pass by construction.
        """
        operands = (0x1234, 0x5678, 0x9ABC)

        async def sum_operands() -> int:
            await asyncio.sleep(0)
            return sum(operands)

        result = run_bridge_coroutine(sum_operands())
        assert result == 0x1234 + 0x5678 + 0x9ABC

    @staticmethod
    def test_returns_none_result() -> None:
        """Verify blocking call propagates a None return distinct from scheduling None.

        A coroutine that explicitly returns ``None`` and one that was merely
        scheduled on a running loop both yield ``None`` from the public API.
        Here there is no running loop on the calling thread, so the runner
        must block on the future; the side-effect flag proves the coroutine
        body actually executed to completion rather than being fire-and-forget.
        """
        executed: list[str] = []

        async def none_coro() -> None:
            await asyncio.sleep(0)
            executed.append("ran")

        result = run_bridge_coroutine(none_coro())
        assert result is None
        assert executed == ["ran"]

    @staticmethod
    def test_long_running_coroutine_blocks_until_complete() -> None:
        """Verify the runner blocks for the full duration of a slow coroutine.

        The independent oracle is wall-clock elapsed time measured around the
        blocking call. A genuine blocking-until-done runner cannot return
        before the coroutine's ``asyncio.sleep`` finishes, so elapsed time
        must be at least the sleep duration and the sentinel must be set.
        """
        completed = threading.Event()

        async def slow_coro() -> str:
            await asyncio.sleep(LONG_RUN_SLEEP_S)
            completed.set()
            return "done"

        start = time.monotonic()
        result = run_bridge_coroutine(slow_coro())
        elapsed = time.monotonic() - start

        assert result == "done"
        assert completed.is_set()
        assert elapsed >= LONG_RUN_SLEEP_S

    @staticmethod
    def test_raises_specific_exception_propagated_from_call_depth() -> None:
        """Verify an exception raised several awaits deep surfaces to the caller intact.

        The exception is raised at the bottom of a three-level coroutine call
        chain. The runner must propagate the *same* exception type and message
        out of ``future.result()`` without swallowing or wrapping it.
        """

        async def level_three() -> None:
            await asyncio.sleep(0)
            msg = "ghidra decompile failed at depth"
            raise ValueError(msg)

        async def level_two() -> None:
            await level_three()

        async def level_one() -> None:
            await level_two()

        with pytest.raises(ValueError, match="ghidra decompile failed at depth"):
            run_bridge_coroutine(level_one())

    @staticmethod
    def test_cancelled_inner_task_propagates_cancelled_error() -> None:
        """Verify cancellation of an awaited inner task surfaces to the caller.

        The cross-thread runner waits on a ``concurrent.futures.Future`` whose
        underlying coroutine task is cancelled, so ``future.result()`` raises
        ``concurrent.futures.CancelledError`` rather than returning ``None``.
        The coroutine spawns a real child task on the live loop, cancels it,
        and awaits it; the cleanup flag set in the child's ``finally`` block
        proves teardown ran before the cancellation propagated out of the
        blocking call.
        """
        cleaned_up = threading.Event()

        async def child() -> None:
            try:
                await asyncio.sleep(LONG_RUN_SLEEP_S)
            finally:
                cleaned_up.set()

        async def parent() -> None:
            loop = asyncio.get_running_loop()
            task = loop.create_task(child())
            await asyncio.sleep(0)
            _ = task.cancel()
            await task

        with pytest.raises(concurrent.futures.CancelledError):
            run_bridge_coroutine(parent())
        assert cleaned_up.is_set()

    @staticmethod
    def test_returns_dict_result_structure_preserved() -> None:
        """Verify a structured register-snapshot result is returned field-for-field.

        The dict is assembled inside the coroutine from caller-owned register
        names and values, then asserted key-by-key so a regression that drops,
        reorders into a different mapping, or coerces values would be caught.
        """
        register_values = (("rax", 0x1234), ("rbx", 0x5678), ("rip", 0x401000))

        async def build_snapshot() -> dict[str, int]:
            await asyncio.sleep(0)
            return dict(register_values)

        result = run_bridge_coroutine(build_snapshot())
        assert result == {"rax": 0x1234, "rbx": 0x5678, "rip": 0x401000}
        assert isinstance(result, dict)
        assert list(result.keys()) == ["rax", "rbx", "rip"]
        assert result["rip"] == 0x401000


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
