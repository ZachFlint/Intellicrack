# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression test for finding H3: hex-editor panel teardown must stop every worker.

Pre-fix, ``HexEditorPanel._cleanup`` interrupted only ``_statistics_worker``,
``_search_worker``, and ``_numeric_search_worker``. The four other
``GenericCallableWorker`` ``QThread`` objects created without a Qt parent
(``_diff_worker``, ``_strings_worker``, ``_sig_worker``, ``_script_worker``)
were never stopped, so closing the panel mid-run destroyed a live ``QThread``
and aborted the process; a mid-flight diff also stranded its
``NamedTemporaryFile``. This test starts seven real interruptible worker threads
plus a real snapshot tempfile, drives the production ``_cleanup`` orchestration,
and asserts every thread was joined (stopped) and the tempfile removed. A worker
whose body only exits on ``isInterruptionRequested`` stays running forever unless
teardown interrupts and joins it, so ``not worker.isRunning()`` after cleanup is
a real, falsifiable gate.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtCore import QThread
from PyQt6.QtWidgets import QApplication, QWidget

from intellicrack.ui.panels.async_bridge import GenericCallableWorker
from intellicrack.ui.panels.hex_editor.comparison import ComparisonMixin
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_WORKER_ATTRS: Final[tuple[str, ...]] = (
    "_statistics_worker",
    "_search_worker",
    "_numeric_search_worker",
    "_diff_worker",
    "_strings_worker",
    "_sig_worker",
    "_script_worker",
)
_NEW_WORKER_ATTRS: Final[tuple[str, ...]] = (
    "_diff_worker",
    "_strings_worker",
    "_sig_worker",
    "_script_worker",
)
_RUNNING_POLL_MS: Final[int] = 5
_RUNNING_DEADLINE_S: Final[float] = 5.0
_JOIN_WAIT_MS: Final[int] = 5000


@pytest.fixture(scope="module")
def qapp() -> Iterator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt thread construction.

    Yields:
        QApplication: The active Qt application for the test process.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


def _block_until_interrupted() -> None:
    """Loop on the worker thread until cooperative interruption is requested.

    Mirrors the cancellation contract the real hexcore workers honour: the body
    only returns once ``QThread.requestInterruption`` has been called on the
    owning thread, so the thread remains running until the panel teardown
    interrupts and joins it.
    """
    thread = QThread.currentThread()
    if thread is None:
        return
    while not thread.isInterruptionRequested():
        thread.msleep(_RUNNING_POLL_MS)


class _StubHexWidget:
    """Minimal hex-widget stand-in recording the detach performed on teardown."""

    def __init__(self) -> None:
        """Initialise with no recorded document detach."""
        self.set_document_calls: list[object] = []

    def set_document(self, document: object) -> None:
        """Record the document reference passed by the panel teardown.

        Args:
            document: Document reference the panel installs (``None`` on close).
        """
        self.set_document_calls.append(document)


class _CleanupHarness(QWidget):
    """Harness exercising the real ``HexEditorPanel._cleanup`` orchestration.

    Installs seven real ``GenericCallableWorker`` threads plus the attributes
    ``_cleanup`` reads, then borrows the production ``_cleanup``,
    ``_stop_pending_workers``, and ``_cleanup_diff_temp`` implementations via
    ``getattr`` so any refactor of the teardown path is exercised without
    re-implementing it here.
    """

    def __init__(self, diff_temp_path: Path) -> None:
        """Initialise the harness with started worker threads and a snapshot file.

        Args:
            diff_temp_path: Path of a real on-disk file standing in for a
                stranded diff ``NamedTemporaryFile``.
        """
        super().__init__()
        for attr in _WORKER_ATTRS:
            setattr(self, attr, GenericCallableWorker(_block_until_interrupted))
        self.state_holder: object | None = None
        self._state_callback: object | None = None
        self.document: object | None = object()
        self.file_path: Path | None = diff_temp_path
        self._original_data_cache: dict[int, int] = {0: 1}
        self._search_results: list[tuple[int, int]] = [(0, 1)]
        self._hex_widget: _StubHexWidget | None = _StubHexWidget()
        self._diff_temp_path: Path | None = diff_temp_path

    def start_all_workers(self) -> list[GenericCallableWorker]:
        """Start every worker thread and wait until each reports running.

        Returns:
            list[GenericCallableWorker]: The started workers, in attribute order,
                captured so tests can query them after ``_cleanup`` clears the
                panel attributes.
        """
        workers: list[GenericCallableWorker] = []
        for attr in _WORKER_ATTRS:
            worker: GenericCallableWorker = getattr(self, attr)
            worker.start()
            workers.append(worker)
        deadline = time.monotonic() + _RUNNING_DEADLINE_S
        for worker in workers:
            while not worker.isRunning() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert worker.isRunning(), "precondition: worker thread must be running before cleanup"
        return workers

    def _stop_pending_workers(self) -> None:
        """Delegate to the production worker-shutdown implementation."""
        getattr(HexEditorPanel, "_stop_pending_workers")(self)

    def _cleanup_diff_temp(self) -> None:
        """Delegate to the production diff-tempfile cleanup implementation."""
        getattr(ComparisonMixin, "_cleanup_diff_temp")(self)

    def run_cleanup(self) -> None:
        """Invoke the production ``_cleanup`` against this harness."""
        getattr(HexEditorPanel, "_cleanup")(self)


def _join_leftover(workers: list[GenericCallableWorker]) -> None:
    """Interrupt and join any worker still running to avoid leaking threads.

    Args:
        workers: Worker threads captured before cleanup.
    """
    for worker in workers:
        if worker.isRunning():
            worker.requestInterruption()
            worker.wait(_JOIN_WAIT_MS)


@pytest.mark.usefixtures("qapp")
class TestCleanupStopsEveryWorker:
    """H3: panel teardown must interrupt/join every worker and remove the diff tempfile."""

    @staticmethod
    def test_all_seven_workers_joined(qapp: QApplication, tmp_path: Path) -> None:
        """Assert every worker thread (including the four previously leaked) is stopped.

        Args:
            qapp: Qt application fixture (kept alive for thread construction).
            tmp_path: Pytest-provided temporary directory.
        """
        del qapp
        temp_file = tmp_path / "intellicrack_diff_snapshot.bin"
        temp_file.write_bytes(b"\x00\x01\x02\x03")
        harness = _CleanupHarness(temp_file)
        workers = harness.start_all_workers()

        try:
            harness.run_cleanup()

            for attr, worker in zip(_WORKER_ATTRS, workers, strict=True):
                assert not worker.isRunning(), f"{attr} thread must be joined (stopped) after cleanup"
                assert getattr(harness, attr) is None, f"{attr} reference must be cleared to None after cleanup"
        finally:
            _join_leftover(workers)

    @staticmethod
    def test_previously_leaked_workers_specifically_joined(qapp: QApplication, tmp_path: Path) -> None:
        """Assert the four workers the pre-fix code ignored are now joined.

        Args:
            qapp: Qt application fixture (kept alive for thread construction).
            tmp_path: Pytest-provided temporary directory.
        """
        del qapp
        temp_file = tmp_path / "diff.bin"
        temp_file.write_bytes(b"data")
        harness = _CleanupHarness(temp_file)
        workers = harness.start_all_workers()
        by_attr = dict(zip(_WORKER_ATTRS, workers, strict=True))

        try:
            harness.run_cleanup()

            for attr in _NEW_WORKER_ATTRS:
                assert not by_attr[attr].isRunning(), f"{attr} was leaked pre-fix and must now be joined on cleanup"
        finally:
            _join_leftover(workers)

    @staticmethod
    def test_diff_tempfile_removed_on_teardown(qapp: QApplication, tmp_path: Path) -> None:
        """Assert a stranded diff snapshot tempfile is deleted during cleanup.

        Args:
            qapp: Qt application fixture (kept alive for thread construction).
            tmp_path: Pytest-provided temporary directory.
        """
        del qapp
        temp_file = tmp_path / "intellicrack_diff_stranded.bin"
        temp_file.write_bytes(b"snapshot")
        harness = _CleanupHarness(temp_file)
        workers = harness.start_all_workers()
        assert temp_file.exists(), "precondition: snapshot tempfile must exist before cleanup"

        try:
            harness.run_cleanup()

            assert not temp_file.exists(), "diff snapshot tempfile must be removed on panel teardown"
        finally:
            _join_leftover(workers)
