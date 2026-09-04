# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gate for S19-R08: a file switch must survive a dead statistics worker.

``HexEditorPanel._load_file_impl`` (``ui/panels/hex_editor/panel.py``) calls
``_update_statistics`` on every ``load_file``. That method supersedes any prior
statistics computation by probing the stored ``_statistics_worker`` before
arming a new one. A ``GenericCallableWorker`` wires ``finished -> deleteLater``,
so after the first file's statistics scan finishes and the event loop processes
the deferred delete, the panel keeps only a dangling sip wrapper in
``_statistics_worker``.

Before the whole-class fix the probe was a bare ``worker_attr.isRunning()``:
on the dangling wrapper it raised ``RuntimeError`` (the C++ object is gone),
which escaped ``_update_statistics`` and aborted ``_load_file_impl`` *before*
the bookmark-tree reset at the tail of the method. Live, that manifested as
S19-D24/D25: switching binaries crashed the load and left the previous file's
bookmark rows stranded in the Bookmarks tree.

This test reproduces that state deterministically: it loads a real PE, lets the
statistics worker finish, forces its C++ object to be destroyed while the panel
still holds the wrapper, adds a bookmark, then drives a real ``load_file``
switch to a *different* real PE. It asserts (a) the switch returns ``True`` --
no ``RuntimeError`` aborted the load -- and (b) the Bookmarks tree was reset to
the second file's (empty) state, proving ``_load_file_impl`` ran to completion
past the statistics probe.

Reverting the ``worker_is_running(worker_attr)`` guard in
``statistics.py:_update_statistics`` back to ``worker_attr.isRunning()`` turns
this RED: the switch raises ``RuntimeError`` and ``load_file`` returns ``False``
(and the stale bookmark row survives).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtCore import QEvent

from intellicrack.ui.panels.async_bridge import GenericCallableWorker
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore backend required for real hex documents")


_WORKER_WAIT_MS: Final[int] = 15000
_EVENT_PUMP_ITERATIONS: Final[int] = 50


def _wrapper_is_deleted(worker: GenericCallableWorker) -> bool:
    """Report whether a worker's underlying C++ object has been destroyed.

    Args:
        worker: The statistics worker wrapper to probe.

    Returns:
        bool: ``True`` if probing ``isRunning`` raises ``RuntimeError``.
    """
    try:
        _ = worker.isRunning()
    except RuntimeError:
        return True
    return False


def _force_cpp_deletion(worker: GenericCallableWorker, app: QApplication) -> None:
    """Destroy a finished worker's C++ object while its Python wrapper survives.

    Args:
        worker: A finished statistics worker whose C++ object should be destroyed.
        app: The running ``QApplication`` whose event loop is pumped.
    """
    if not _wrapper_is_deleted(worker):
        worker.deleteLater()
    for _ in range(_EVENT_PUMP_ITERATIONS):
        if _wrapper_is_deleted(worker):
            return
        app.processEvents()
        app.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


class TestStatisticsWorkerDeletedGuardOnSwitch:
    """Switching files must not crash when the prior statistics worker wrapper is dead."""

    @staticmethod
    def test_file_switch_survives_deleted_statistics_worker(
        qapp: QApplication,
        real_pe_dll: Path,
        real_pe_exe: Path,
    ) -> None:
        """A real file switch must complete (and reset bookmarks) with a dead statistics worker.

        Args:
            qapp: Session QApplication fixture (event loop for deferred deletes).
            real_pe_dll: Path to a real ``kernel32.dll`` fixture (file A).
            real_pe_exe: Path to a real system PE executable fixture (file B).
        """
        panel = HexEditorPanel()
        try:
            assert panel.load_file(real_pe_dll) is True, "loading file A must succeed"
            assert panel.document is not None
            assert panel._bookmarks_tree is not None

            worker = panel._statistics_worker
            assert isinstance(worker, GenericCallableWorker), "loading a file must arm a statistics worker"

            try:
                finished = worker.wait(_WORKER_WAIT_MS)
            except RuntimeError:
                finished = True
            assert finished, "the statistics worker must finish within the bounded wait"

            _force_cpp_deletion(worker, qapp)
            assert _wrapper_is_deleted(worker), "test precondition: the stored statistics worker wrapper must be dangling before the switch"
            assert panel._statistics_worker is worker, "the panel must still hold the dangling wrapper"

            panel.document.add_bookmark(0x40, 1, "OnlyInFileA", "#00FF00")
            panel._refresh_bookmarks_tree()
            qapp.processEvents()
            assert panel._bookmarks_tree.topLevelItemCount() == 1, "setup precondition: file A must show its own bookmark"

            assert panel.load_file(real_pe_exe) is True, (
                "switching to file B must succeed -- a dead statistics worker probe must not abort the load"
            )
            qapp.processEvents()

            assert panel._bookmarks_tree.topLevelItemCount() == 0, (
                "the file switch must run to completion past the statistics probe and reset the Bookmarks tree; "
                f"it still shows {panel._bookmarks_tree.topLevelItemCount()} stale row(s) from file A"
            )
        finally:
            panel._cleanup()
