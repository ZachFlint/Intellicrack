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

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QCoreApplication, QEventLoop, QTimer, pyqtBoundSignal
from PyQt6.QtWidgets import QApplication

import intellicrack.ui.panels.process_panel.workers as _workers_module
from intellicrack.ui.panels.process_panel.workers import TrackedRefreshWorker


if TYPE_CHECKING:
    from collections.abc import Callable

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

    def test_refresh_error_signal_is_string_typed_and_connectable(
        self,
        qapp: QCoreApplication,
    ) -> None:
        """``refresh_error`` is a string-typed pyqtBoundSignal that delivers payloads intact.

        This replaces the former ``hasattr`` smoke test.  It would fail if:

        - ``refresh_error`` were removed from the class
        - its type signature were changed away from a single ``str`` argument
        - the signal were replaced with a plain attribute

        Args:
            qapp: Qt application fixture (ensures a QCoreApplication exists).
        """
        worker = TrackedRefreshWorker()
        sig = worker.refresh_error
        assert isinstance(sig, pyqtBoundSignal), (
            f"refresh_error must be a pyqtBoundSignal, got {type(sig).__name__}"
        )
        assert "QString" in sig.signal, (
            f"refresh_error must carry a single str argument; signal descriptor: {sig.signal!r}"
        )
        received: list[str] = []
        sig.connect(received.append)
        sentinel = "Refresh failed: synthetic-sentinel-abc123"
        sig.emit(sentinel)
        qapp.processEvents()
        worker.deleteLater()
        assert received == [sentinel], (
            f"emit/receive round-trip failed: expected [{sentinel!r}], got {received}"
        )
