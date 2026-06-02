# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit4 B7 F-0026: TrackedRefreshWorker error surfacing.

These tests verify that when ProcessManager raises inside
TrackedRefreshWorker.run(), the worker emits ``refresh_error`` with the
failure reason and does NOT emit ``refresh_finished`` with an empty list
(the old silent-swallow behaviour).  Each test would fail against the
pre-fix code where the exception was swallowed and ``refresh_finished``
was always emitted with ``result == []``.
"""

from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QCoreApplication, QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication

import intellicrack.ui.panels.process_panel.workers as _workers_module
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.ui.panels.process_panel.workers import TrackedRefreshWorker


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

_FAILURE_MESSAGE: str = "ProcessManager unavailable in test"


@pytest.fixture(scope="module")
def qapp() -> QCoreApplication:
    """Ensure exactly one QApplication exists for these widget tests.

    Returns:
        QCoreApplication: The running application instance.
    """
    existing = QApplication.instance()
    if existing is not None:
        return existing
    return QApplication([])


@pytest.fixture
def real_tracked_child() -> Iterator[tuple[int, str]]:
    """Register a real long-lived child process with the live ProcessManager.

    Spawns an actual Python interpreter that blocks on stdin (so it stays
    alive for the duration of the test), registers it with the real
    ProcessManager singleton, and yields its identity for assertions. The
    singleton and the child are torn down afterwards so no global state
    leaks between tests.

    Yields:
        tuple[int, str]: The ``(pid, name)`` of the registered child process.
    """
    ProcessManager.reset_instance()
    manager = ProcessManager.get_instance()
    name = "audit4_b7_tracked_child"
    proc = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.read()"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        manager.register(proc, name, ProcessType.EXTERNAL_TOOL)
        assert proc.pid is not None
        yield proc.pid, name
    finally:
        if proc.stdin is not None:
            proc.stdin.close()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        ProcessManager.reset_instance()


def _pump_until(predicate: Callable[[], bool], qapp: QCoreApplication, timeout_ms: int = 5000) -> bool:
    """Spin the Qt event loop until ``predicate()`` returns truthy or ``timeout_ms`` elapses.

    Args:
        predicate: Zero-argument callable whose truth value is checked after each pump.
        qapp: Running QCoreApplication used to drain pending events.
        timeout_ms: Maximum total milliseconds to wait.

    Returns:
        bool: True if the predicate became truthy within the timeout.
    """
    elapsed_ms = 0
    step_ms = 25
    while elapsed_ms < timeout_ms:
        if predicate():
            return True
        loop = QEventLoop()
        QTimer.singleShot(step_ms, loop.quit)
        loop.exec()
        qapp.processEvents()
        elapsed_ms += step_ms
    return predicate()


class _RaisingProcessManager:
    """Replacement for ProcessManager whose get_instance raises RuntimeError.

    Substituted into the ``workers`` module namespace during tests so that
    TrackedRefreshWorker.run() encounters a real exception on the actual
    ProcessManager call site — the same code path that was broken before
    the fix.
    """

    @staticmethod
    def get_instance() -> None:
        """Raise RuntimeError to simulate a ProcessManager failure.

        Raises:
            RuntimeError: Always.
        """
        raise RuntimeError(_FAILURE_MESSAGE)


class TestTrackedRefreshWorkerError:
    """Tests that verify error-path behaviour of TrackedRefreshWorker (F-0026)."""

    def test_error_emits_refresh_error_signal(
        self,
        qapp: QCoreApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Worker emits ``refresh_error`` when ProcessManager.get_instance raises.

        This test would FAIL without the fix because the pre-fix code caught
        the exception, logged it, and fell through to
        ``refresh_finished.emit([])`` — ``refresh_error`` did not exist.

        Args:
            qapp: Qt application fixture.
            monkeypatch: pytest monkeypatch fixture for temporary module patching.
        """
        monkeypatch.setattr(_workers_module, "ProcessManager", _RaisingProcessManager)

        error_messages: list[str] = []
        worker = TrackedRefreshWorker()
        worker.refresh_error.connect(error_messages.append)

        worker.start()
        finished = _pump_until(lambda: not worker.isRunning(), qapp)
        assert finished, "Worker did not finish within timeout"

        assert len(error_messages) == 1, f"Expected exactly one refresh_error emission, got {len(error_messages)}"
        assert _FAILURE_MESSAGE in error_messages[0], f"Error message {error_messages[0]!r} does not contain the failure reason"
        worker.deleteLater()

    def test_error_does_not_emit_refresh_finished(
        self,
        qapp: QCoreApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Worker must NOT emit ``refresh_finished`` when an exception occurs.

        Without the fix, a caught error fell through to
        ``refresh_finished.emit([])`` making an empty list indistinguishable
        from a successful refresh of a genuinely empty tracked list.

        Args:
            qapp: Qt application fixture.
            monkeypatch: pytest monkeypatch fixture for temporary module patching.
        """
        monkeypatch.setattr(_workers_module, "ProcessManager", _RaisingProcessManager)

        finished_payloads: list[list[object]] = []
        worker = TrackedRefreshWorker()
        worker.refresh_finished.connect(finished_payloads.append)

        worker.start()
        _pump_until(lambda: not worker.isRunning(), qapp)

        assert len(finished_payloads) == 0, (
            "refresh_finished was emitted on failure — empty list is indistinguishable "
            f"from a real empty result; got payloads: {finished_payloads}"
        )
        worker.deleteLater()

    def test_error_message_contains_prefix(
        self,
        qapp: QCoreApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Error signal payload begins with 'Refresh failed:' prefix.

        The panel consumer matches against this prefix to surface the right
        status message to the user.

        Args:
            qapp: Qt application fixture.
            monkeypatch: pytest monkeypatch fixture for temporary module patching.
        """
        monkeypatch.setattr(_workers_module, "ProcessManager", _RaisingProcessManager)

        error_messages: list[str] = []
        worker = TrackedRefreshWorker()
        worker.refresh_error.connect(error_messages.append)

        worker.start()
        _pump_until(lambda: not worker.isRunning(), qapp)

        assert error_messages, "No refresh_error signal was emitted"
        assert error_messages[0].startswith("Refresh failed:"), (
            f"Expected message to start with 'Refresh failed:', got: {error_messages[0]!r}"
        )
        worker.deleteLater()

    def test_success_emits_finished_with_real_snapshot(
        self,
        qapp: QCoreApplication,
        real_tracked_child: tuple[int, str],
    ) -> None:
        """Worker emits ``refresh_finished`` carrying the real tracked-process snapshot.

        Drives the worker against the live ProcessManager singleton holding a
        single real, running child process. Asserts the emitted payload is
        exactly the serialized snapshot of that process (correct pid, name,
        process_type, and a ``Running`` status), and that the error signal
        stays silent. This is a falsifiable gate on the success wiring: if
        ``refresh_finished`` were not emitted, carried a wrong field, or the
        running-state classification regressed, the exact-match assertions fail.

        Args:
            qapp: Qt application fixture.
            real_tracked_child: ``(pid, name)`` of a real registered child process.
        """
        child_pid, child_name = real_tracked_child

        finished_payloads: list[list[dict[str, str | int | None]]] = []
        error_messages: list[str] = []
        worker = TrackedRefreshWorker()
        worker.refresh_finished.connect(finished_payloads.append)
        worker.refresh_error.connect(error_messages.append)

        worker.start()
        finished = _pump_until(lambda: not worker.isRunning(), qapp)
        assert finished, "Worker did not finish within timeout"

        assert error_messages == [], f"refresh_error fired on the success path: {error_messages}"
        assert len(finished_payloads) == 1, f"Expected exactly one refresh_finished emission, got {len(finished_payloads)}"

        snapshot = finished_payloads[0]
        records = [rec for rec in snapshot if rec["pid"] == child_pid]
        assert len(records) == 1, f"Registered child pid {child_pid} not uniquely present in snapshot: {snapshot}"

        record = records[0]
        assert record["name"] == child_name, f"Wrong name in snapshot record: {record}"
        assert record["process_type"] == ProcessType.EXTERNAL_TOOL.value, f"Wrong process_type in snapshot record: {record}"
        assert record["status"] == "Running", f"Live child should classify as Running, got: {record}"

        registered_at = record["registered_at"]
        assert isinstance(registered_at, str), f"registered_at must be serialized to a string, got {registered_at!r}"
        assert len(registered_at) == len("YYYY-MM-DD HH:MM:SS"), f"registered_at not in expected format: {registered_at!r}"

        worker.deleteLater()

    def test_refresh_error_signal_delivers_payload_through_connected_slot(
        self,
        qapp: QCoreApplication,
    ) -> None:
        """``refresh_error`` is a typed ``str`` signal that delivers payloads to a real slot.

        Rather than merely asserting the attribute exists, this connects a
        real slot, emits a representative error payload, pumps the Qt event
        loop, and asserts the slot received exactly that string. This proves
        the signal is wired with the right arity and type: emitting a
        non-string payload across the ``pyqtSignal(str)`` boundary raises, and
        a missing/renamed signal raises ``AttributeError`` on connect.

        Args:
            qapp: Qt application fixture.
        """
        worker = TrackedRefreshWorker()

        received: list[str] = []
        worker.refresh_error.connect(received.append)

        payload = "Refresh failed: ProcessManager unavailable"
        worker.refresh_error.emit(payload)
        delivered = _pump_until(lambda: len(received) == 1, qapp)
        assert delivered, "Connected slot never received the emitted refresh_error payload"
        assert received == [payload], f"Slot received wrong payload across pyqtSignal(str): {received}"

        with pytest.raises(TypeError):
            worker.refresh_error.emit(object())

        worker.deleteLater()
