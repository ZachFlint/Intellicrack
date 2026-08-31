# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for audit F13/F10 -- the async-worker lifetime fix.

Before the fix, ``MainWindow._run_async`` built a throwaway ``AsyncWorker``
``QThread`` with a brand-new ``asyncio`` event loop per call and retained only a
single overwritable ``self._current_worker`` reference. Two effects followed:

* **F13** -- an overlapping operation dropped the previous worker's only Python
  reference, so the still-running ``QThread`` could be garbage-collected
  mid-flight and crash the GUI thread.
* **F10** -- because each call closed its private loop in ``finally``, an
  asyncio primitive created on one call's loop and awaited on a later call
  raised "Event loop is closed".

The fix routes ``_run_async`` through ``run_bridge_coroutine_async`` on the
single persistent bridge event loop, whose worker registry pins each worker for
the lifetime of its OS thread and whose loop is never closed between calls.

Every test drives the real ``MainWindow._run_async`` seam against a real
``Config``/``Orchestrator`` and the real persistent bridge loop -- no mocked
dispatch. Each is falsified by reverting to the throwaway ``AsyncWorker``.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import pytest

from intellicrack.ui import app as app_module
from intellicrack.ui.app import MainWindow

from .conftest import NoOpSandboxManager


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from PyQt6.QtWidgets import QApplication

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator


_POLL_INTERVAL_S: float = 0.01
_MAX_WAIT_S: float = 5.0


@pytest.fixture
def main_window(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[MainWindow]:
    """Construct a real, unshown ``MainWindow`` with a no-op sandbox manager.

    Args:
        qapp: QApplication instance required by Qt widgets.
        real_config: Real Config instance from the shared fixtures.
        real_orchestrator: Real Orchestrator instance from the shared fixtures.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        MainWindow: A constructed, unshown MainWindow instance.
    """
    _ = qapp
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    window = MainWindow(real_config, real_orchestrator)
    yield window
    window.close()


def _pump_until(qapp: QApplication, predicate: Callable[[], object], *, timeout_s: float = _MAX_WAIT_S) -> None:
    """Pump the Qt event loop until ``predicate()`` is truthy or time runs out.

    Args:
        qapp: QApplication used to dispatch queued cross-thread signals.
        predicate: Zero-argument callable returning a truthiness value.
        timeout_s: Maximum wall-clock time to keep pumping, in seconds.
    """
    deadline = time.monotonic() + timeout_s
    while not predicate() and time.monotonic() < deadline:
        qapp.processEvents()
        time.sleep(_POLL_INTERVAL_S)
    qapp.processEvents()


class TestAsyncWorkerRetired:
    """The throwaway per-call worker must be gone from the module."""

    @staticmethod
    def test_asyncworker_class_removed() -> None:
        """``ui.app`` must no longer expose the throwaway ``AsyncWorker``.

        The structural fix retires the per-call ``QThread``/new-loop worker
        entirely in favour of the persistent bridge loop. If a future change
        reintroduces ``AsyncWorker`` (the F13 root cause), this gate fails.
        """
        assert not hasattr(app_module, "AsyncWorker"), (
            "AsyncWorker (throwaway per-call event loop; F13 root cause) was reintroduced into ui.app"
        )


@pytest.mark.usefixtures("qapp")
class TestRunAsyncPersistentLoop:
    """``_run_async`` must run coroutines to completion on the persistent loop."""

    @staticmethod
    def test_single_coroutine_runs_to_completion(qapp: QApplication, main_window: MainWindow) -> None:
        """A coroutine dispatched via ``_run_async`` actually executes.

        Observes a real side effect produced only when the coroutine body runs
        to completion on a driven event loop, proving dispatch reaches a live
        loop rather than a never-advanced task.

        Args:
            qapp: QApplication fixture used to pump queued signals.
            main_window: Real MainWindow under test.
        """
        observed: list[str] = []

        async def _op() -> str:
            await asyncio.sleep(0)
            observed.append("ran")
            return "ran"

        main_window._run_async(_op())
        _pump_until(qapp, lambda: bool(observed))

        assert observed == ["ran"]

    @staticmethod
    def test_two_overlapping_coroutines_both_complete(qapp: QApplication, main_window: MainWindow) -> None:
        """Two overlapping ``_run_async`` calls must both deliver.

        The first coroutine is slower than the second, so the second is
        dispatched while the first is still in flight. Under the old
        single-``_current_worker`` design the second dispatch overwrote the
        first worker's only reference; here both must run to completion.

        Args:
            qapp: QApplication fixture used to pump queued signals.
            main_window: Real MainWindow under test.
        """
        observed: list[str] = []

        async def _slow() -> str:
            await asyncio.sleep(0.3)
            observed.append("slow")
            return "slow"

        async def _fast() -> str:
            await asyncio.sleep(0.02)
            observed.append("fast")
            return "fast"

        expected_count = 2
        main_window._run_async(_slow())
        main_window._run_async(_fast())
        _pump_until(qapp, lambda: len(observed) >= expected_count)

        assert sorted(observed) == ["fast", "slow"]

    @staticmethod
    def test_loop_bound_primitive_reused_across_calls(qapp: QApplication, main_window: MainWindow) -> None:
        """F10 gate: an asyncio primitive survives a second ``_run_async`` call.

        Creates an ``asyncio.Event`` on the persistent loop during the first
        dispatch, then awaits it during a second dispatch. Because both run on
        the same never-closed loop, no "Event loop is closed" is raised and the
        waiter completes. With the old throwaway loop (closed in ``finally``),
        the primitive would belong to a dead loop and the waiter would fail.

        Args:
            qapp: QApplication fixture used to pump queued signals.
            main_window: Real MainWindow under test.
        """
        holder: list[asyncio.Event] = []
        errors: list[str] = []
        done: list[str] = []

        async def _create_and_set() -> None:
            await asyncio.sleep(0)
            event = asyncio.Event()
            holder.append(event)
            event.set()

        main_window._run_async(_create_and_set())
        _pump_until(qapp, lambda: bool(holder))
        assert holder, "first dispatch never created the loop-bound event"

        async def _await_event() -> None:
            try:
                await asyncio.wait_for(holder[0].wait(), timeout=2.0)
            except RuntimeError as exc:  # e.g. "Event loop is closed" / cross-loop binding
                errors.append(str(exc))
                return
            done.append("awaited")

        main_window._run_async(_await_event())
        _pump_until(qapp, lambda: bool(done or errors))

        assert not errors, f"loop-bound primitive failed across dispatches (F10 regression): {errors}"
        assert done == ["awaited"]
