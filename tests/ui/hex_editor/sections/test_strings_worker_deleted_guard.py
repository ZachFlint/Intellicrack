# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gate: re-arming the strings scan must not crash on a deleted prior worker.

``SectionsMixin._populate_strings`` (``ui/panels/hex_editor/sections.py``) is
invoked from ``HexEditorPanel._load_file_impl`` (``panel.py:826``) on every file
load. It supersedes any in-flight extraction by probing the previously stored
``_strings_worker`` with ``isRunning()`` before starting a fresh one.

A ``GenericCallableWorker`` wires ``finished -> deleteLater``
(``async_bridge.py:379``), so once a scan finishes and the event loop processes
the deferred delete, the panel keeps only a dangling sip wrapper in
``_strings_worker`` (the finished handler never nulls it). Probing that wrapper
with ``isRunning()`` raises ``RuntimeError`` -- the C/C++ object has been deleted
-- rather than returning ``False``, crashing ``_populate_strings`` and, with it,
the next file load.

This test drives the real, unmodified worker against a real
``intellicrack_hexcore`` document backed by a real System32 PE: it loads a file,
lets the strings worker finish, forces its ``deleteLater`` to destroy the C++
object while the panel still holds the wrapper, proves the dangling state is real
(``isRunning`` raises), and then asserts a second ``_populate_strings`` neither
raises nor reuses the dead worker.

Reverting the ``try/except RuntimeError`` guard in ``_populate_strings`` turns
this RED: the second ``_populate_strings`` propagates the ``RuntimeError`` and the
test errors out.
"""

from __future__ import annotations

import shutil
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


def _copy_to_writable(source: Path, dest_dir: Path) -> Path:
    """Copy a real binary fixture into a writable temp directory.

    The System32 originals are read-only; loading operates on a private
    writable copy so nothing touches the shared fixture.

    Args:
        source: Real binary fixture to copy.
        dest_dir: Writable destination directory (a pytest ``tmp_path``).

    Returns:
        Path: Path to the writable copy.
    """
    dest = dest_dir / source.name
    shutil.copyfile(source, dest)
    return dest


def _wrapper_is_deleted(worker: GenericCallableWorker) -> bool:
    """Report whether a worker's underlying C++ object has been destroyed.

    Probing a live ``QThread`` wrapper returns a bool; probing one whose C++
    object ``deleteLater`` already destroyed raises ``RuntimeError``. That raise
    is the definition of the dangling state under test.

    Args:
        worker: The strings worker wrapper to probe.

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

    Posts a deferred delete and pumps the event loop (including deferred-delete
    events) until the wrapper is dangling, reproducing the state a rapid sequence
    of file loads produces in the live GUI.

    Args:
        worker: A finished strings worker whose C++ object should be destroyed.
        app: The running ``QApplication`` whose event loop is pumped.
    """
    if not _wrapper_is_deleted(worker):
        worker.deleteLater()
    for _ in range(_EVENT_PUMP_ITERATIONS):
        if _wrapper_is_deleted(worker):
            return
        app.processEvents()
        app.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


class TestStringsWorkerDeletedGuard:
    """Re-arming the strings scan must tolerate a previously deleted worker wrapper."""

    @staticmethod
    def test_populate_strings_survives_deleted_prior_worker(
        qapp: QApplication,
        real_pe_dll: Path,
        tmp_path: Path,
    ) -> None:
        """A second ``_populate_strings`` must not crash when the prior worker's C++ object is gone.

        Args:
            qapp: Session QApplication fixture (event loop for deferred deletes).
            real_pe_dll: Path to a real ``kernel32.dll`` fixture.
            tmp_path: Pytest-provided writable temp directory.
        """
        target = _copy_to_writable(real_pe_dll, tmp_path)

        panel = HexEditorPanel()
        try:
            assert panel.load_file(target) is True
            first = panel._strings_worker
            assert isinstance(first, GenericCallableWorker), "loading a file must arm a strings worker"

            try:
                finished = first.wait(_WORKER_WAIT_MS)
            except RuntimeError:
                finished = True
            assert finished, "the strings worker must finish within the bounded wait"

            _force_cpp_deletion(first, qapp)

            assert _wrapper_is_deleted(first), (
                "test precondition: the stored strings worker wrapper must be dangling "
                "(its C++ object destroyed by deleteLater) before re-arming"
            )
            assert panel._strings_worker is first, "the panel must still hold the dangling wrapper"

            panel._populate_strings()

            second = panel._strings_worker
            assert isinstance(second, GenericCallableWorker), "re-arming must create a fresh strings worker"
            assert second is not first, "the fresh worker must replace the deleted wrapper"
        finally:
            panel._cleanup()
