# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for the shared worker-liveness guards (S19-R08 root cause).

``GenericCallableWorker`` wires ``finished -> deleteLater``
(``ui/panels/hex_editor``'s worker sites all rely on this), so once a worker
finishes and the event loop processes the deferred delete, callers keep only a
dangling sip wrapper. Probing that wrapper with ``QThread.isRunning`` raises
``RuntimeError: wrapped C/C++ object ... has been deleted`` rather than
returning ``False`` -- the exact crash that aborted ``_load_file_impl`` mid
file-switch (S19-R08).

The whole-class fix centralises every re-arm probe onto two helpers in
``ui/panels/async_bridge.py``:

* :func:`worker_is_running` -- report liveness, treating both ``None`` and a
  deleted wrapper as "not running" instead of raising.
* :func:`discard_worker` -- schedule a finished worker for deletion, tolerating
  a wrapper whose C++ object is already gone.

These tests drive the real helpers against a **genuinely destroyed** real
``GenericCallableWorker`` C++ object (not a mock): the worker runs to
completion, its ``deleteLater`` is pumped through the event loop until the
wrapper is dangling, and only then are the helpers exercised. Reverting either
helper's ``try/except RuntimeError`` to a bare ``isRunning()``/``deleteLater()``
turns these RED -- the destroyed-wrapper probe propagates ``RuntimeError``.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QEvent

from intellicrack.ui.panels.async_bridge import (
    GenericCallableWorker,
    discard_worker,
    worker_is_running,
)


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


_WORKER_WAIT_MS: Final[int] = 15000
_EVENT_PUMP_ITERATIONS: Final[int] = 50


def _wrapper_is_deleted(worker: GenericCallableWorker) -> bool:
    """Report whether a worker's underlying C++ object has been destroyed.

    Probing a live ``QThread`` wrapper returns a bool; probing one whose C++
    object ``deleteLater`` already destroyed raises ``RuntimeError``. That raise
    is the dangling state the guards must tolerate.

    Args:
        worker: The worker wrapper to probe.

    Returns:
        bool: ``True`` if probing ``isRunning`` raises ``RuntimeError``.
    """
    try:
        _ = worker.isRunning()
    except RuntimeError:
        return True
    return False


def _make_dead_worker(app: QApplication) -> GenericCallableWorker:
    """Build a finished ``GenericCallableWorker`` and destroy its C++ object.

    Runs a trivial callable to completion, then posts and pumps the deferred
    delete until the returned Python wrapper is dangling -- reproducing the
    live post-completion state a rapid re-arm sequence produces.

    Args:
        app: The running ``QApplication`` whose event loop is pumped.

    Returns:
        GenericCallableWorker: A wrapper whose C++ object has been destroyed.
    """
    worker = GenericCallableWorker(lambda: 0)
    worker.start()
    try:
        finished = worker.wait(_WORKER_WAIT_MS)
    except RuntimeError:
        finished = True
    assert finished, "the trivial worker must finish within the bounded wait"

    if not _wrapper_is_deleted(worker):
        worker.deleteLater()
    for _ in range(_EVENT_PUMP_ITERATIONS):
        if _wrapper_is_deleted(worker):
            break
        app.processEvents()
        app.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)

    assert _wrapper_is_deleted(worker), (
        "test precondition: the worker's C++ object must be destroyed (its wrapper dangling) before probing the guards"
    )
    return worker


class TestWorkerIsRunning:
    """``worker_is_running`` must never raise on ``None`` or a dead wrapper."""

    @staticmethod
    def test_none_reports_not_running() -> None:
        """A ``None`` worker is reported as not running."""
        assert worker_is_running(None) is False

    @staticmethod
    def test_live_running_worker_reports_true(qapp: QApplication) -> None:
        """A genuinely in-flight worker is reported as running.

        Guards against a degenerate implementation that always returns
        ``False`` (which would pass every dead-wrapper case yet silently break
        the "skip while a real scan is in flight" contract every re-arm site
        depends on). The worker's callable blocks on a real
        :class:`threading.Event` so the thread is provably still executing when
        the helper is probed; the event is released afterwards so the worker
        finishes cleanly.

        Args:
            qapp: Session QApplication fixture (event loop for the worker).
        """
        _ = qapp
        release = threading.Event()
        entered = threading.Event()

        def _block() -> int:
            entered.set()
            release.wait(timeout=_WORKER_WAIT_MS / 1000.0)
            return 0

        worker = GenericCallableWorker(_block)
        worker.start()
        try:
            assert entered.wait(timeout=_WORKER_WAIT_MS / 1000.0), "worker thread never began executing"
            assert worker_is_running(worker) is True, "an in-flight worker must be reported as running"
        finally:
            release.set()
            if not _wrapper_is_deleted(worker):
                assert worker.wait(_WORKER_WAIT_MS), "worker must finish after the block is released"

    @staticmethod
    def test_deleted_wrapper_reports_not_running_instead_of_raising(qapp: QApplication) -> None:
        """A destroyed-C++ wrapper is reported as not running, never raising.

        This is the S19-R08 gate: reverting the ``try/except RuntimeError`` in
        ``worker_is_running`` makes this raise ``RuntimeError`` (dangling
        wrapper) instead of returning ``False``.

        Args:
            qapp: Session QApplication fixture (event loop for deferred deletes).
        """
        dead = _make_dead_worker(qapp)
        assert worker_is_running(dead) is False


class TestDiscardWorker:
    """``discard_worker`` must tolerate ``None`` and an already-destroyed wrapper."""

    @staticmethod
    def test_none_is_a_noop() -> None:
        """Discarding ``None`` neither raises nor does anything observable."""
        assert discard_worker(None) is None

    @staticmethod
    def test_deleted_wrapper_is_swallowed_not_raised(qapp: QApplication) -> None:
        """Discarding an already-destroyed wrapper must not raise.

        Reverting the ``try/except RuntimeError`` in ``discard_worker`` makes
        the second ``deleteLater`` on the dangling wrapper raise
        ``RuntimeError``.

        Args:
            qapp: Session QApplication fixture (event loop for deferred deletes).
        """
        dead = _make_dead_worker(qapp)
        assert discard_worker(dead) is None
