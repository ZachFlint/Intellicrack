# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for GUI audit findings M10 and M11 in ``StatisticsMixin``.

M10 -- ``_update_statistics`` computed the ``GenericCallableWorker``'s Qt
parent with ``self if isinstance(self, QThread) else None``. ``self`` here is
the ``HexEditorPanel`` (a ``QWidget``-derived object), never a ``QThread``,
so that check is always ``False`` and the statistics worker was always
parented to ``None`` -- unlike every other worker-launch site in the
``hex_editor`` package, which correctly checks ``isinstance(self, QWidget)``.
An unparented worker never joins the panel's Qt object tree, so it is not
torn down by normal Qt parent-child cascade deletion. The fix replaces the
``QThread`` check with a ``QWidget`` check, matching the sibling mixins.

M11 -- ``_on_show_digram_matrix`` called the native ``document.digram_matrix``
FFI scan and the subsequent 65536-element Python list conversion directly
inside the button-click slot, on the GUI thread, before opening the matrix
dialog. This blocked the whole application's event loop for the duration of
the scan, unlike the sibling ``_update_statistics`` method (which already
offloads its comparable-cost computation to a ``GenericCallableWorker``). The
fix moves the computation into a module-level ``compute_digram_matrix``
function dispatched through a ``GenericCallableWorker``, opening the dialog
only from the worker's ``call_finished`` callback on the GUI thread.

Each test below drives the real ``StatisticsMixin`` slots through a small
``QWidget`` harness backed by document doubles (for M11, one whose
``digram_matrix`` sleeps and records the identity of the OS thread that
executed it), asserting real, falsifiable outcomes without mocking Qt or the
mixin itself.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtWidgets import QLabel, QTreeWidget, QWidget

from intellicrack.ui.panels.async_bridge import GenericCallableWorker
from intellicrack.ui.panels.hex_editor.statistics import StatisticsMixin
from intellicrack.ui.panels.hex_editor.widgets import DigramMatrixDialog


if TYPE_CHECKING:
    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_DOC_SLEEP_S: Final[float] = 0.5
_FAST_RETURN_BUDGET_S: Final[float] = 0.25
_WAIT_TIMEOUT_MS: Final[int] = 10_000
_DIGRAM_MATRIX_SIZE: Final[int] = 65536


class _StatsDocument:
    """Document double exposing only the byte-statistics method.

    Provides just enough surface for ``compute_statistics`` to succeed
    without touching the optional entropy/distribution/classification
    hooks, which ``StatisticsMixin`` treats as absent via ``getattr``.
    """

    def byte_statistics(self) -> list[tuple[int, int]]:
        """Return a small fixed byte-frequency table.

        Returns:
            list[tuple[int, int]]: Two (byte value, count) pairs.
        """
        return [(0x00, 10), (0x41, 5)]


class _SlowDigramDocument:
    """Document double whose ``digram_matrix`` sleeps, then records its thread.

    ``digram_matrix`` sleeps ``_DOC_SLEEP_S`` before returning and records
    the identity of the OS thread that executed it. A code path that still
    calls it synchronously on the GUI thread will (a) block the caller for
    the sleep duration and (b) record the GUI thread's own identity; a
    worker-backed code path does neither.
    """

    def __init__(self) -> None:
        """Initialise the call counter and the per-method thread-identity log."""
        self.call_threads: dict[str, int] = {}
        self.digram_matrix_calls: int = 0

    def digram_matrix(self) -> list[int]:
        """Simulate a slow full-document digram-matrix scan.

        Returns:
            list[int]: A flattened 65536-element digram frequency matrix
                filled with a fixed count per cell.
        """
        time.sleep(_DOC_SLEEP_S)
        self.call_threads["digram_matrix"] = threading.get_ident()
        self.digram_matrix_calls += 1
        return [1] * _DIGRAM_MATRIX_SIZE


class _StatisticsHarness(QWidget, StatisticsMixin):
    """Minimal real ``StatisticsMixin`` consumer used to drive the GUI slots.

    Overrides the main-thread result callback for the digram matrix to
    additionally record the identity of the thread that executed it and the
    result it received, so tests can assert that callback ran on the GUI
    thread with the worker's computed matrix rather than the caller mutating
    state directly.
    """

    def __init__(self, document: object) -> None:
        """Wire the mixin's required attribute slots to a document double.

        Args:
            document: Document double the statistics/digram slots will
                call into.
        """
        QWidget.__init__(self)
        self._document = document
        self.document = document
        self._statistics_tree: QTreeWidget | None = None
        self._entropy_graph = None
        self._byte_dist_widget = None
        self._entropy_label: QLabel | None = None
        self._null_pct_label: QLabel | None = None
        self._printable_pct_label: QLabel | None = None
        self._control_pct_label: QLabel | None = None
        self._high_pct_label: QLabel | None = None
        self._classification_label: QLabel | None = None
        self._statistics_worker: GenericCallableWorker | None = None
        self._digram_worker: GenericCallableWorker | None = None
        self.main_thread_calls: dict[str, int] = {}
        self.dialog_opened_with: list[int] | None = None

    def update_statistics(self) -> None:
        """Invoke the mixin's statistics-update slot as a public test entry point."""
        self._update_statistics()

    def statistics_worker(self) -> GenericCallableWorker | None:
        """Return the in-flight (or most recently started) statistics worker.

        Returns:
            GenericCallableWorker | None: The worker instance, or ``None``
                if no statistics update has been started yet.
        """
        return self._statistics_worker

    def show_digram_matrix(self) -> None:
        """Invoke the mixin's show-digram-matrix slot as a public test entry point."""
        self._on_show_digram_matrix()

    def digram_worker(self) -> GenericCallableWorker | None:
        """Return the in-flight (or most recently started) digram worker.

        Returns:
            GenericCallableWorker | None: The worker instance, or ``None``
                if no digram-matrix computation has been started yet.
        """
        return self._digram_worker

    def _on_digram_matrix_computed(self, result: object) -> None:
        """Record the calling thread and result, then apply default handling.

        Args:
            result: The flattened digram matrix list from the background worker.
        """
        self.main_thread_calls["digram_matrix_computed"] = threading.get_ident()
        if isinstance(result, list):
            self.dialog_opened_with = result
        super()._on_digram_matrix_computed(result)


def test_m10_statistics_worker_parented_to_widget(qtbot: QtBot) -> None:
    """M10: the statistics worker's Qt parent must be the panel widget itself.

    Pre-fix, ``_update_statistics`` computed ``parent_obj`` with
    ``self if isinstance(self, QThread) else None``. ``self`` is a
    ``QWidget``-derived harness, never a ``QThread``, so that check is
    always ``False`` and ``worker.parent()`` would always be ``None``. The
    fix checks ``isinstance(self, QWidget)`` instead, so the worker must now
    be parented to the harness widget.

    Args:
        qtbot: pytest-qt bot fixture used to wait on the worker's completion
            signal so the background thread is drained before teardown.
    """
    harness = _StatisticsHarness(_StatsDocument())
    try:
        harness.update_statistics()

        worker = harness.statistics_worker()
        assert isinstance(worker, GenericCallableWorker), "_update_statistics did not dispatch a GenericCallableWorker"
        assert worker.parent() is harness, (
            "statistics worker is not parented to the panel widget; pre-fix "
            "isinstance(self, QThread) is always False for a QWidget-derived "
            "panel, so parent_obj was always None"
        )

        with qtbot.waitSignal(worker.call_finished, timeout=_WAIT_TIMEOUT_MS):
            pass
    finally:
        harness.deleteLater()


def test_m11_digram_matrix_offloads_to_worker_thread(qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
    """M11: ``_on_show_digram_matrix`` must run ``document.digram_matrix`` off the GUI thread.

    Drives the real slot with a document whose ``digram_matrix`` sleeps for
    ``_DOC_SLEEP_S``. Pre-fix, the slot called ``document.digram_matrix``
    (and the subsequent 65536-element list comprehension) inline: the call
    would then block for the full sleep duration, the document would record
    the GUI thread's own identity as the caller, and there would be no
    ``_digram_worker`` attribute to type-check as a ``GenericCallableWorker``.
    Each of those checks fails pre-fix and passes post-fix.

    Args:
        qtbot: pytest-qt bot fixture used to wait on the worker's completion
            signal.
        monkeypatch: pytest fixture used to make the modal
            ``DigramMatrixDialog.exec()`` return immediately instead of
            blocking the test on real user input.
    """
    monkeypatch.setattr(DigramMatrixDialog, "exec", lambda _self: 0)

    gui_thread = threading.get_ident()
    document = _SlowDigramDocument()
    harness = _StatisticsHarness(document)
    try:
        started = time.perf_counter()
        harness.show_digram_matrix()
        elapsed = time.perf_counter() - started

        assert elapsed < _FAST_RETURN_BUDGET_S, (
            f"_on_show_digram_matrix blocked the calling thread for {elapsed:.3f}s "
            f"(document.digram_matrix sleeps {_DOC_SLEEP_S}s); a call that is still "
            "synchronous on the GUI thread would take at least that long."
        )

        worker = harness.digram_worker()
        assert isinstance(worker, GenericCallableWorker), "_on_show_digram_matrix did not dispatch a GenericCallableWorker"

        with qtbot.waitSignal(worker.call_finished, timeout=_WAIT_TIMEOUT_MS):
            pass

        assert document.digram_matrix_calls == 1

        bg_thread = document.call_threads.get("digram_matrix")
        assert bg_thread is not None
        assert bg_thread != gui_thread, "document.digram_matrix executed on the GUI thread instead of a background worker"

        callback_thread = harness.main_thread_calls.get("digram_matrix_computed")
        assert callback_thread == gui_thread, "the callback that opens the digram dialog did not run back on the GUI thread"

        assert harness.dialog_opened_with is not None, "the digram dialog callback never received the computed matrix"
        assert len(harness.dialog_opened_with) == _DIGRAM_MATRIX_SIZE
    finally:
        harness.deleteLater()
