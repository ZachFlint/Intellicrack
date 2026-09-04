# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gate for S19-R08 at the shared ``_spawn_hex_worker`` re-arm site.

``HashingMixin._spawn_hex_worker`` (``ui/panels/hex_editor/hashing.py``) is the
shared entry that every hashing/CRC computation routes through to start a
background ``GenericCallableWorker`` "unless one is already running". Its
supersede logic probes the caller-supplied ``existing`` worker and eagerly
schedules it for deletion before arming a fresh one.

A ``GenericCallableWorker`` wires ``finished -> deleteLater``, so a previously
finished worker handed back as ``existing`` may already be a dangling sip
wrapper. The whole-class S19-R08 fix routes this site through
``worker_is_running(existing)`` (liveness probe that tolerates the dead
wrapper) and ``discard_worker(existing)`` (deletion that tolerates an
already-destroyed C++ object).

This test drives the real ``_spawn_hex_worker`` on a real ``HexEditorPanel``
with a **genuinely destroyed** prior worker as ``existing``: it asserts the
method treats the dead wrapper as "not running", arms and returns a fresh live
worker, and never raises. Reverting either helper at this site back to a bare
``existing.isRunning()`` / ``existing.deleteLater()`` turns this RED -- the
dangling-wrapper probe raises ``RuntimeError``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtCore import QEvent

from intellicrack.ui.panels.async_bridge import GenericCallableWorker
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore backend required for HexEditorPanel")


_WORKER_WAIT_MS: Final[int] = 15000
_EVENT_PUMP_ITERATIONS: Final[int] = 50


def _wrapper_is_deleted(worker: GenericCallableWorker) -> bool:
    """Report whether a worker's underlying C++ object has been destroyed.

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
    assert finished, "the trivial prior worker must finish within the bounded wait"

    if not _wrapper_is_deleted(worker):
        worker.deleteLater()
    for _ in range(_EVENT_PUMP_ITERATIONS):
        if _wrapper_is_deleted(worker):
            break
        app.processEvents()
        app.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)

    assert _wrapper_is_deleted(worker), (
        "test precondition: the prior worker's C++ object must be destroyed before it is handed back as 'existing'"
    )
    return worker


class TestSpawnHexWorkerDeletedGuard:
    """``_spawn_hex_worker`` must re-arm cleanly when the prior worker wrapper is dead."""

    @staticmethod
    def test_spawn_supersedes_a_deleted_prior_worker(qapp: QApplication) -> None:
        """A dead ``existing`` worker must be superseded, not crash the spawn.

        Args:
            qapp: Session QApplication fixture (event loop for deferred deletes).
        """
        panel = HexEditorPanel()
        try:
            dead = _make_dead_worker(qapp)
            ran: list[str] = []
            errors: list[object] = []

            def _compute() -> int:
                ran.append("computed")
                return 0

            def _on_success(_result: object) -> None:
                return None

            fresh = panel._spawn_hex_worker(
                dead,
                _compute,
                (),
                _on_success,
                errors.append,
            )

            assert isinstance(fresh, GenericCallableWorker), (
                "a dead prior worker must be treated as not running, so a fresh worker is armed and returned"
            )
            assert fresh is not dead, "the fresh worker must replace the dangling wrapper"

            try:
                finished = fresh.wait(_WORKER_WAIT_MS)
            except RuntimeError:
                finished = True
            assert finished, "the freshly armed worker must run to completion"
            qapp.processEvents()

            assert ran == ["computed"], "the fresh worker must actually execute the supplied callable"
            assert errors == [], f"the spawn path must not surface an error: {errors}"
        finally:
            panel._cleanup()
