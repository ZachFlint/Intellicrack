# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for GUI-audit finding H2 in ``_tail_reader``.

H2 — ``LogFileTailReader.stop()`` used to block the GUI thread with a
synchronous ``self._initial_worker.wait(2000)`` and, worse, left the
:class:`~intellicrack.ui.log_viewer._tail_reader.InitialLoadWorker`
parented to the reader (``parent=self``). ``LogViewerWindow`` calls
``stop()`` from both ``_on_reload_from_disk`` and ``closeEvent`` and then
calls ``self._tail_reader.deleteLater()`` on the reader; while the worker
was still a Qt child of the reader, that deferred deletion cascaded into
the still-running ``QThread`` and aborted the process ("QThread: Destroyed
while thread is still running").

The fix removes the ``parent=`` argument (so the worker's lifetime is
independent of the reader), makes the worker self-delete via
``worker.finished.connect(worker.deleteLater)``, and replaces the blocking
``wait()`` in ``stop()`` with a non-blocking detach that disconnects the
reader's slots from the worker's signals instead of waiting for it.

Each test below drives real ``QThread`` objects (no mocks) and uses a
deterministic ``time.sleep`` inside a real ``InitialLoadWorker`` subclass to
win the race against ``stop()`` instead of depending on disk-I/O timing.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, override

import pytest

from intellicrack.ui.log_viewer._tail_reader import InitialLoadWorker, LogFileTailReader


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")

_SLOW_WORKER_DELAY_S: float = 0.5
_STOP_MUST_RETURN_WITHIN_S: float = 0.2


def _write_lines(path: Path, *entries: dict[str, object]) -> None:
    """Append JSON-Lines entries to a log file.

    Args:
        path: Target log file.
        *entries: Records to encode as JSON Lines.
    """
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for entry in entries:
            handle.write(json.dumps(entry))
            handle.write("\n")


def _entry(event: str, level: str = "INFO") -> dict[str, object]:
    """Build a structlog-style payload.

    Args:
        event: Event identifier.
        level: Log level.

    Returns:
        dict[str, object]: JSON-serializable record.
    """
    return {
        "timestamp": "2026-07-02 10:00:00",
        "level": level,
        "logger": "intellicrack.tests",
        "module": "m",
        "function": "f",
        "line_number": 1,
        "event": event,
        "extras_marker": True,
    }


class _SlowInitialLoadWorker(InitialLoadWorker):
    """A real :class:`InitialLoadWorker` that sleeps before loading.

    Disk reads of a small test fixture complete in well under a
    millisecond, which makes any race against ``LogFileTailReader.stop()``
    unreliable. Sleeping first, inside the real worker thread, guarantees
    ``isRunning()`` stays ``True`` for a known, generous window while still
    exercising the real historical-load code path via ``super().run()``.
    """

    def __init__(self, log_path: Path, max_bytes: int, delay_seconds: float) -> None:
        """Initialize the slow worker.

        Args:
            log_path: Absolute path to the JSON-Lines log file.
            max_bytes: Maximum number of trailing bytes to read.
            delay_seconds: Seconds to sleep before performing the real load.
        """
        super().__init__(log_path, max_bytes)
        self._delay_seconds: float = delay_seconds

    @override
    def run(self) -> None:
        """Sleep for the configured delay, then perform the real load."""
        time.sleep(self._delay_seconds)
        super().run()


def _attach_worker(reader: LogFileTailReader, worker: InitialLoadWorker) -> None:
    """Wire a worker to a reader exactly as ``LogFileTailReader.start()`` does.

    Args:
        reader: The reader whose slots should observe the worker's signals.
        worker: The (possibly slowed) worker to attach and start.
    """
    worker.records_ready.connect(reader._on_initial_records)
    worker.offset_ready.connect(reader._on_initial_offset)
    worker.finished.connect(reader._on_initial_finished)
    worker.finished.connect(worker.deleteLater)
    reader._initial_worker = worker
    worker.start()


def test_h2_initial_worker_created_without_parent(qtbot: QtBot, tmp_path: Path) -> None:
    """The historical-load worker must not be parented to the reader.

    Pre-fix, ``start()`` constructed ``InitialLoadWorker(..., parent=self)``,
    so a ``deleteLater()`` on the reader (as ``LogViewerWindow`` issues from
    both ``_on_reload_from_disk`` and ``closeEvent``) cascades Qt's
    parent-child destruction into the still-running ``QThread``. The check
    below is made immediately after ``start()`` returns, before any signal
    delivery, so it is not subject to any scheduling race.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    log_path = tmp_path / "logs.jsonl"
    _write_lines(log_path, _entry("a"))
    reader = LogFileTailReader(log_path)

    reader.start()
    worker = reader._initial_worker
    assert worker is not None, "start() did not create an initial-load worker"
    assert worker.parent() is None, (
        "initial-load worker is still parented to the reader; "
        "reader.deleteLater() would cascade into the running QThread and crash the process"
    )

    # Let the (near-instant, single-line) worker finish and self-delete
    # without polling isRunning() again: once destroyed, any further method
    # call on the wrapper raises RuntimeError, and that race is irrelevant
    # to the assertion already made above.
    qtbot.wait(200)
    reader._initial_worker = None
    reader.stop()


def test_h2_worker_self_deletes_after_finishing(qtbot: QtBot, tmp_path: Path) -> None:
    """The worker must self-delete via ``finished -> deleteLater`` when done.

    Pre-fix, ``finished`` was only connected to the reader's
    ``_on_initial_finished`` slot, so a completed worker was never scheduled
    for deletion on its own; it lingered until the parent reader itself was
    destroyed. If ``worker.destroyed`` never fires, ``waitUntil`` below times
    out and the test fails.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    log_path = tmp_path / "logs.jsonl"
    _write_lines(log_path, _entry("a"))
    reader = LogFileTailReader(log_path)

    reader.start()
    worker = reader._initial_worker
    assert worker is not None, "start() did not create an initial-load worker"

    destroyed_flags: list[bool] = []
    worker.destroyed.connect(lambda: destroyed_flags.append(True))

    qtbot.waitUntil(lambda: bool(destroyed_flags), timeout=3_000)

    # The worker object is now destroyed; detach the stale reference before
    # calling stop() so its watcher teardown does not dereference it.
    reader._initial_worker = None
    reader.stop()


def test_h2_stop_does_not_block_gui_thread_for_running_worker(qtbot: QtBot, tmp_path: Path) -> None:
    """``stop()`` must return promptly instead of waiting on a running worker.

    Pre-fix ``stop()`` executed ``self._initial_worker.wait(2000)`` whenever
    ``isRunning()`` was true. With the worker's real body delayed by
    ``_SLOW_WORKER_DELAY_S`` (0.5 s), that call would block the calling
    (GUI) thread for roughly that long before returning, and the worker
    would already be finished by the time ``stop()`` returned. Post-fix,
    ``stop()`` merely disconnects and detaches, so it returns almost
    instantly and the worker is still running immediately afterward.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    log_path = tmp_path / "logs.jsonl"
    _write_lines(log_path, _entry("a"))
    reader = LogFileTailReader(log_path)

    worker = _SlowInitialLoadWorker(log_path, reader._max_initial_bytes, _SLOW_WORKER_DELAY_S)
    _attach_worker(reader, worker)
    qtbot.waitUntil(worker.isRunning, timeout=1_000)

    started = time.perf_counter()
    reader.stop()
    elapsed = time.perf_counter() - started

    assert elapsed < _STOP_MUST_RETURN_WITHIN_S, f"stop() blocked the GUI thread for {elapsed:.3f}s waiting on the still-running worker"
    assert worker.isRunning(), "worker must still be running immediately after stop() returns; stop() waited for it to finish"

    # Let the detached worker finish and self-delete in the background
    # without polling isRunning() (which would raise RuntimeError once the
    # object is actually destroyed); the assertions above already captured
    # the behaviour under test.
    qtbot.wait(int((_SLOW_WORKER_DELAY_S + 1.0) * 1000))


def test_h2_stop_detaches_signals_before_late_worker_finishes(qtbot: QtBot, tmp_path: Path) -> None:
    """A worker that finishes after ``stop()`` must not mutate the reader.

    Pre-fix, ``stop()`` never disconnected the worker's signals from the
    reader's slots. Because the pre-fix ``wait(2000)`` call blocked the GUI
    thread without pumping its own event loop, the worker's queued
    cross-thread signals were only delivered *after* ``stop()`` returned and
    the test resumed pumping events -- so the reader still absorbed
    ``record_emitted``/``initial_load_complete`` and updated ``_last_offset``
    from a worker it had supposedly stopped. Post-fix, those slots are
    disconnected inside ``stop()``, so a late-finishing worker's signals are
    silently dropped and none of that state changes.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    log_path = tmp_path / "logs.jsonl"
    _write_lines(log_path, _entry("a"))
    reader = LogFileTailReader(log_path)

    worker = _SlowInitialLoadWorker(log_path, reader._max_initial_bytes, _SLOW_WORKER_DELAY_S)
    _attach_worker(reader, worker)
    qtbot.waitUntil(worker.isRunning, timeout=1_000)

    received: list[dict[str, object]] = []
    reader.record_emitted.connect(received.append)
    completed_offsets: list[int] = []
    reader.initial_load_complete.connect(completed_offsets.append)

    reader.stop()
    # Let the detached worker finish emitting on its own; do not poll
    # isRunning() again (it would raise RuntimeError once the worker's
    # finished -> deleteLater self-connection destroys the object).
    qtbot.wait(int((_SLOW_WORKER_DELAY_S + 1.0) * 1000))

    assert not received, f"reader processed records from a worker that stop() should have detached: {received}"
    assert not completed_offsets, f"initial_load_complete fired from a worker that stop() should have detached: {completed_offsets}"
    assert reader._last_offset == 0, "stop() did not prevent the late-finishing worker from mutating reader state"
