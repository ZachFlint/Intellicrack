# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for the GUI audit findings in ``sandbox_config``.

Each test targets one audit finding and fails against the pre-fix behaviour:

* ``TestH18StopViaManagerAsyncDispatch`` (H18): stopping a manager-backed
  sandbox must dispatch ``SandboxManager.destroy_all`` to the persistent
  background bridge loop instead of blocking the GUI thread on
  ``asyncio.run``, and must still finish (success or failure) via the
  ``sandbox_stopped`` signal.
* ``TestM15SandboxTestWorkerLifecycle`` (M15): ``SandboxTestWorker`` must be
  given the dialog as its Qt parent, and closing or rejecting the dialog
  while a test is in flight must cancel the worker and its subprocess.
* ``TestM16TaskkillDispatchOffGuiThread`` (M16): the PID-based and
  name-based ``taskkill`` stop paths must dispatch ``ProcessManager.run_tracked``
  to a background worker thread instead of blocking the GUI thread.
* ``TestM66StatusLabelWrapping`` (M66): the availability status label must
  word-wrap, expose a tooltip mirroring its text, and claim layout stretch
  instead of being compressed by a trailing stretch item.

All tests drive real ``SandboxMonitorWidget`` / ``SandboxConfigDialog`` /
``SandboxTestWorker`` instances under an offscreen ``QApplication``. Tests
that spawn a real OS process are marked ``spawns_process``.
"""

from __future__ import annotations

import asyncio
import sys
import threading
import time
from typing import TYPE_CHECKING, NoReturn

import pytest
from PyQt6.QtWidgets import QApplication, QHBoxLayout, QMessageBox

from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.subprocess_compat import CREATE_NO_WINDOW, CompletedProcess, Popen
from intellicrack.ui import sandbox_config
from intellicrack.ui.sandbox_config import SandboxConfigDialog, SandboxMonitorWidget, SandboxTestWorker

from .conftest import SignalRecorder


if TYPE_CHECKING:
    from collections.abc import Callable

    from pytestqt.qtbot import QtBot


class _NullSignal:
    """No-op stand-in for a bound ``pyqtSignal`` used by stub workers."""

    def connect(self, callback: Callable[..., object]) -> None:
        """Discard the connection request.

        Args:
            callback: Slot that would have received the signal.
        """
        del callback


class _StubAvailabilityWorker:
    """Stand-in for ``GenericCallableWorker`` that never starts a background thread.

    Keeps ``SandboxConfigDialog`` construction free of the real Windows
    Sandbox availability probe (a PowerShell subprocess) so the H18/M15/M66
    gate tests below do not depend on that probe's host environment and do
    not spawn an unrelated OS process on every dialog construction.
    """

    def __init__(
        self,
        func: Callable[..., object],
        /,
        *args: object,
        exceptions: tuple[type[BaseException], ...] = (),
        parent: object = None,
        **kwargs: object,
    ) -> None:
        """Capture and discard the callable without starting a background thread.

        Args:
            func: Callable the real worker would execute off-thread (discarded).
            *args: Positional arguments (discarded).
            exceptions: Exception tuple (discarded).
            parent: Qt parent (discarded).
            **kwargs: Keyword arguments (discarded).
        """
        del func, args, exceptions, parent, kwargs
        self.call_finished: _NullSignal = _NullSignal()
        self.call_error: _NullSignal = _NullSignal()

    def start(self) -> None:
        """Do nothing; the stub never runs the probe and never emits a result."""
        return


def _build_dialog(monkeypatch: pytest.MonkeyPatch) -> SandboxConfigDialog:
    """Construct a ``SandboxConfigDialog`` without the real availability probe or popups.

    Args:
        monkeypatch: Fixture used to stub the availability worker and the
            informational/warning popups so the dialog can be driven
            headlessly under an offscreen QApplication.

    Returns:
        SandboxConfigDialog: A dialog with ``_is_available`` forced to
        ``True`` so ``_test_sandbox`` proceeds past its availability guard.
    """
    monkeypatch.setattr(sandbox_config, "GenericCallableWorker", _StubAvailabilityWorker)
    monkeypatch.setattr(sandbox_config, "show_info", lambda *_a, **_k: QMessageBox.StandardButton.Ok)
    monkeypatch.setattr(sandbox_config, "show_warning", lambda *_a, **_k: QMessageBox.StandardButton.Ok)
    dialog = SandboxConfigDialog()
    dialog._is_available = True
    return dialog


class _SlowSandboxManager:
    """Minimal async stand-in for a ``SandboxManager`` with real, measurable latency.

    Exercises the exact coroutine shape ``SandboxMonitorWidget._stop_via_manager``
    dispatches (an ``async def destroy_all(self)`` coroutine) using a real
    ``asyncio.sleep`` delay in place of VM/container teardown latency, so the
    async-dispatch fix can be measured against genuine wall-clock and
    ordering behaviour instead of a mocked awaitable.

    Attributes:
        delay_s: Simulated teardown latency, in seconds.
        should_fail: When ``True``, ``destroy_all`` raises after the delay.
        call_count: Number of times ``destroy_all`` ran to (or past) the delay.
    """

    delay_s: float
    should_fail: bool
    call_count: int

    def __init__(self, delay_s: float, *, should_fail: bool = False) -> None:
        """Initialise the stand-in manager.

        Args:
            delay_s: Simulated teardown latency, in seconds.
            should_fail: When ``True``, ``destroy_all`` raises ``RuntimeError``
                after the delay instead of returning normally.
        """
        self.delay_s = delay_s
        self.should_fail = should_fail
        self.call_count = 0

    async def destroy_all(self) -> None:
        """Simulate variable-latency VM/container teardown.

        Raises:
            RuntimeError: When constructed with ``should_fail=True``.
        """
        await asyncio.sleep(self.delay_s)
        self.call_count += 1
        if self.should_fail:
            msg = "simulated teardown failure"
            raise RuntimeError(msg)


@pytest.mark.usefixtures("qapp")
class TestH18StopViaManagerAsyncDispatch:
    """H18: sandbox teardown via ``SandboxManager`` must not block the GUI thread."""

    @staticmethod
    def test_h18_manager_stop_does_not_block_gui_thread_and_completes_via_signal(qtbot: QtBot) -> None:
        """``_stop_sandbox`` must return before teardown finishes and emit ``sandbox_stopped`` only once it does.

        Pre-fix, ``_stop_via_manager`` called ``asyncio.run(manager.destroy_all())``
        directly on the calling thread, so ``_stop_sandbox`` would not return
        until the full simulated teardown latency had elapsed, and
        ``sandbox_stopped`` would already have fired by the time this method
        returned. Post-fix the coroutine is dispatched to the persistent
        background bridge loop via ``run_bridge_coroutine_async``, so this
        call must return promptly with ``sandbox_stopped`` not yet emitted.

        Args:
            qtbot: pytest-qt bot used to pump the event loop for the async callback.
        """
        manager = _SlowSandboxManager(delay_s=0.8)
        widget = SandboxMonitorWidget(sandbox_manager=manager)
        widget.set_running(is_running=True)
        recorder = SignalRecorder()
        _: object = widget.sandbox_stopped.connect(recorder)
        try:
            start = time.monotonic()
            widget._stop_sandbox()
            dispatch_elapsed = time.monotonic() - start

            assert dispatch_elapsed < 0.4, (
                f"_stop_sandbox blocked the calling thread for {dispatch_elapsed:.3f}s; teardown appears to still be awaited synchronously"
            )
            assert recorder.times_called == 0, "sandbox_stopped fired before the dispatched teardown could have completed"

            qtbot.waitUntil(lambda: recorder.times_called == 1, timeout=5000)
            assert manager.call_count == 1
            assert not widget._stop_btn.isEnabled()
        finally:
            widget.deleteLater()

    @staticmethod
    def test_h18_manager_stop_failure_still_dispatches_asynchronously_and_finishes(qtbot: QtBot) -> None:
        """A failing teardown must not block the GUI thread and must still finish via the error callback.

        Pre-fix, an exception raised out of ``asyncio.run(manager.destroy_all())``
        was caught inline on the GUI thread and the function returned early;
        the trailing ``set_running``/``sandbox_stopped`` calls that lived in
        the (then-synchronous) caller were skipped on that path. Post-fix the
        failure is delivered asynchronously to ``_on_manager_stop_failed``,
        which still runs the stop-finish sequence and surfaces the error text.

        Args:
            qtbot: pytest-qt bot used to pump the event loop for the async callback.
        """
        manager = _SlowSandboxManager(delay_s=0.5, should_fail=True)
        widget = SandboxMonitorWidget(sandbox_manager=manager)
        widget.set_running(is_running=True)
        recorder = SignalRecorder()
        _: object = widget.sandbox_stopped.connect(recorder)
        try:
            widget._stop_sandbox()
            assert recorder.times_called == 0, "sandbox_stopped fired before the dispatched teardown could have failed"

            qtbot.waitUntil(lambda: recorder.times_called == 1, timeout=5000)
            assert manager.call_count == 1, "the coroutine dispatched to the background loop never ran"
            assert "[Error stopping sandbox:" in widget._output_text.toPlainText()
            assert not widget._stop_btn.isEnabled()
        finally:
            widget.deleteLater()


class TestM15SandboxTestWorkerLifecycle:
    """M15: the sandbox test worker must be Qt-parented and cancelled on dialog teardown."""

    @staticmethod
    def test_m15_test_worker_is_parented_to_the_dialog(qapp: QApplication, qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
        """``_test_sandbox`` must construct ``SandboxTestWorker`` with the dialog as its Qt parent.

        Pre-fix ``SandboxTestWorker(...)`` was constructed with no ``parent``
        argument, so the QThread's only Qt-level owner was ``None`` and the
        worker survived purely on the Python attribute reference. Post-fix
        the worker's Qt ``parent()`` must be the dialog itself.

        Args:
            qapp: Session QApplication fixture.
            qtbot: pytest-qt bot used to pump the event loop while the worker finishes.
            monkeypatch: Fixture used to stub the availability probe/popups
                and to make the (never-actually-installed) sandbox launch
                fail immediately and harmlessly via ``FileNotFoundError``.
        """
        _ = qapp

        def _raise_file_not_found(*_args: object, **_kwargs: object) -> NoReturn:
            """Simulate ``WindowsSandbox.exe`` not being installed.

            Args:
                *_args: Positional arguments forwarded by the caller (unused).
                **_kwargs: Keyword arguments forwarded by the caller (unused).

            Raises:
                FileNotFoundError: Always, standing in for a missing WindowsSandbox.exe.
            """
            msg = "WindowsSandbox.exe"
            raise FileNotFoundError(msg)

        dialog = _build_dialog(monkeypatch)
        monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *_a, **_k: QMessageBox.StandardButton.Yes))
        monkeypatch.setattr(sandbox_config, "Popen", _raise_file_not_found)
        try:
            dialog._test_sandbox()
            worker = dialog._test_worker
            assert worker is not None
            assert worker.parent() is dialog, "SandboxTestWorker was not given the dialog as its Qt parent"

            qtbot.waitUntil(lambda: not worker.isRunning(), timeout=5000)
        finally:
            dialog.deleteLater()

    @staticmethod
    @pytest.mark.spawns_process
    def test_m15_closing_dialog_cancels_the_inflight_sandbox_test(
        qapp: QApplication,
        qtbot: QtBot,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Closing the dialog (title-bar X / ``closeEvent``) must cancel the in-flight test worker.

        Pre-fix ``SandboxConfigDialog`` had no ``closeEvent`` override, so
        ``QDialog.closeEvent`` simply accepted the close and the worker
        thread plus its already-launched subprocess kept running detached
        from the now-closed dialog. Post-fix ``closeEvent`` calls
        ``_cancel_test``, which must stop the worker's thread and terminate
        its real subprocess well before that process's own 30 second sleep
        would end on its own.

        Args:
            qapp: Session QApplication fixture.
            qtbot: pytest-qt bot used to pump the event loop while waiting on the worker.
            monkeypatch: Fixture used to stub the availability probe/popups
                and substitute a real, killable subprocess for the actual
                Windows Sandbox launch.
        """
        _ = qapp

        def _run_long_lived_subprocess(worker_self: SandboxTestWorker) -> None:
            """Populate ``self._process`` with a real, long-sleeping subprocess and block on it.

            Args:
                worker_self: The ``SandboxTestWorker`` instance ``run`` is bound to.
            """
            worker_self._process = Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                creationflags=CREATE_NO_WINDOW,
            )
            ProcessManager.get_instance().register(
                worker_self._process,
                name="gate-test-fake-sandbox",
                process_type=ProcessType.SANDBOX,
            )
            worker_self._process.wait()
            success = True
            worker_self.finished.emit(success, "fake sandbox test finished")

        dialog = _build_dialog(monkeypatch)
        dialog.show()
        QApplication.processEvents()
        monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *_a, **_k: QMessageBox.StandardButton.Yes))
        monkeypatch.setattr(SandboxTestWorker, "run", _run_long_lived_subprocess)
        try:
            dialog._test_sandbox()
            worker = dialog._test_worker
            assert worker is not None
            qtbot.waitUntil(worker.isRunning, timeout=3000)
            qtbot.waitUntil(lambda: worker._process is not None, timeout=3000)
            process = worker._process
            assert process is not None
            assert process.poll() is None, "test premise: the fake sandbox process must still be alive"

            dialog.close()

            qtbot.waitUntil(lambda: not worker.isRunning(), timeout=8000)
            assert process.poll() is not None, "closing the dialog did not terminate the in-flight sandbox process"
        finally:
            dialog.deleteLater()

    @staticmethod
    @pytest.mark.spawns_process
    def test_m15_rejecting_dialog_cancels_the_inflight_sandbox_test(
        qapp: QApplication,
        qtbot: QtBot,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Rejecting the dialog (Cancel button / Escape / ``reject``) must cancel the in-flight test worker.

        Pre-fix ``button_box.rejected.connect(self.reject)`` routed straight
        to the unmodified ``QDialog.reject`` (also what Escape triggers),
        which never touched ``_test_worker``. Post-fix ``reject`` calls
        ``_cancel_test`` first, which must stop the worker's thread and
        terminate its real subprocess.

        Args:
            qapp: Session QApplication fixture.
            qtbot: pytest-qt bot used to pump the event loop while waiting on the worker.
            monkeypatch: Fixture used to stub the availability probe/popups
                and substitute a real, killable subprocess for the actual
                Windows Sandbox launch.
        """
        _ = qapp

        def _run_long_lived_subprocess(worker_self: SandboxTestWorker) -> None:
            """Populate ``self._process`` with a real, long-sleeping subprocess and block on it.

            Args:
                worker_self: The ``SandboxTestWorker`` instance ``run`` is bound to.
            """
            worker_self._process = Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                creationflags=CREATE_NO_WINDOW,
            )
            ProcessManager.get_instance().register(
                worker_self._process,
                name="gate-test-fake-sandbox",
                process_type=ProcessType.SANDBOX,
            )
            worker_self._process.wait()
            success = True
            worker_self.finished.emit(success, "fake sandbox test finished")

        dialog = _build_dialog(monkeypatch)
        monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *_a, **_k: QMessageBox.StandardButton.Yes))
        monkeypatch.setattr(SandboxTestWorker, "run", _run_long_lived_subprocess)
        try:
            dialog._test_sandbox()
            worker = dialog._test_worker
            assert worker is not None
            qtbot.waitUntil(worker.isRunning, timeout=3000)
            qtbot.waitUntil(lambda: worker._process is not None, timeout=3000)
            process = worker._process
            assert process is not None
            assert process.poll() is None, "test premise: the fake sandbox process must still be alive"

            dialog.reject()

            qtbot.waitUntil(lambda: not worker.isRunning(), timeout=8000)
            assert process.poll() is not None, "rejecting the dialog did not terminate the in-flight sandbox process"
        finally:
            dialog.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestM16TaskkillDispatchOffGuiThread:
    """M16: PID/name-based sandbox stop must not block the GUI thread on ``taskkill``."""

    @staticmethod
    def test_m16_pid_kill_dispatches_off_gui_thread(qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
        """Stopping by PID must dispatch ``run_tracked`` to a worker thread, not the GUI thread.

        Pre-fix ``_dispatch_pid_kill`` called ``ProcessManager.run_tracked``
        directly inside the GUI-thread click handler with a 10 second
        timeout, so the call blocked the caller for up to 10 seconds.
        Post-fix the call is dispatched to a ``GenericCallableWorker``
        background QThread, so this call must return promptly and the
        callable must run on a different thread than the caller.

        Args:
            qtbot: pytest-qt bot used to pump the event loop for the worker callback.
            monkeypatch: Fixture used to replace ``ProcessManager.run_tracked``
                with a slow, thread-recording stand-in so the dispatch can be
                measured deterministically without depending on a real
                ``taskkill`` binary or target process.
        """
        main_thread_id = threading.get_ident()
        call_thread_ids: list[int] = []

        def _fake_run_tracked(
            _process_manager_self: ProcessManager,
            args: list[str],
            name: str,
            **_kwargs: object,
        ) -> CompletedProcess[str]:
            """Record the calling thread, simulate ``taskkill`` latency, and return a benign result.

            Args:
                _process_manager_self: Bound ``ProcessManager`` instance (unused).
                args: Command and arguments the real implementation would execute.
                name: Human-readable process name (unused; accepted for signature parity).
                **_kwargs: Remaining keyword arguments, e.g. ``check``, ``timeout``,
                    ``creationflags`` (unused).

            Returns:
                CompletedProcess[str]: A synthetic success result.
            """
            del name
            call_thread_ids.append(threading.get_ident())
            time.sleep(0.5)
            return CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(ProcessManager, "run_tracked", _fake_run_tracked)

        widget = SandboxMonitorWidget()
        widget.set_running(is_running=True, pid=999_999)
        recorder = SignalRecorder()
        _: object = widget.sandbox_stopped.connect(recorder)
        try:
            start = time.monotonic()
            widget._stop_sandbox()
            dispatch_elapsed = time.monotonic() - start

            assert dispatch_elapsed < 0.25, f"_stop_sandbox blocked the GUI thread for {dispatch_elapsed:.3f}s waiting on taskkill"
            assert recorder.times_called == 0, "sandbox_stopped fired before the dispatched taskkill could have completed"

            qtbot.waitUntil(lambda: recorder.times_called == 1, timeout=5000)
            assert call_thread_ids, "run_tracked (taskkill) was never invoked"
            assert call_thread_ids[0] != main_thread_id, "taskkill ran on the GUI thread instead of a background worker thread"
        finally:
            widget.deleteLater()

    @staticmethod
    def test_m16_name_kill_dispatches_off_gui_thread(qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
        """Stopping by process name must dispatch ``run_tracked`` to a worker thread, not the GUI thread.

        Pre-fix ``_invoke_taskkill_by_name`` (called from ``_terminate_sandbox_by_name``)
        called ``ProcessManager.run_tracked`` directly on the GUI thread with
        a 10 second timeout. Post-fix the call is dispatched to a
        ``GenericCallableWorker`` background QThread.

        Args:
            qtbot: pytest-qt bot used to pump the event loop for the worker callback.
            monkeypatch: Fixture used to replace ``ProcessManager.run_tracked``
                with a slow, thread-recording stand-in so the dispatch can be
                measured deterministically without depending on a real
                ``taskkill`` binary.
        """
        main_thread_id = threading.get_ident()
        call_thread_ids: list[int] = []

        def _fake_run_tracked(
            _process_manager_self: ProcessManager,
            args: list[str],
            name: str,
            **_kwargs: object,
        ) -> CompletedProcess[str]:
            """Record the calling thread, simulate ``taskkill`` latency, and return a benign result.

            Args:
                _process_manager_self: Bound ``ProcessManager`` instance (unused).
                args: Command and arguments the real implementation would execute.
                name: Human-readable process name (unused; accepted for signature parity).
                **_kwargs: Remaining keyword arguments, e.g. ``check``, ``timeout``,
                    ``creationflags`` (unused).

            Returns:
                CompletedProcess[str]: A synthetic success result.
            """
            del name
            call_thread_ids.append(threading.get_ident())
            time.sleep(0.5)
            return CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(ProcessManager, "run_tracked", _fake_run_tracked)

        widget = SandboxMonitorWidget()
        recorder = SignalRecorder()
        _: object = widget.sandbox_stopped.connect(recorder)
        try:
            start = time.monotonic()
            widget._stop_sandbox()
            dispatch_elapsed = time.monotonic() - start

            assert dispatch_elapsed < 0.25, f"_stop_sandbox blocked the GUI thread for {dispatch_elapsed:.3f}s waiting on taskkill"
            assert recorder.times_called == 0, "sandbox_stopped fired before the dispatched taskkill could have completed"

            qtbot.waitUntil(lambda: recorder.times_called == 1, timeout=5000)
            assert call_thread_ids, "run_tracked (taskkill) was never invoked"
            assert call_thread_ids[0] != main_thread_id, "taskkill ran on the GUI thread instead of a background worker thread"
        finally:
            widget.deleteLater()


class TestM66StatusLabelWrapping:
    """M66: the availability status label must wrap, tooltip, and claim layout space."""

    @staticmethod
    def test_m66_unavailable_reason_wraps_instead_of_being_clipped(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """A long unavailability reason must word-wrap and not be clipped to one line.

        Pre-fix the label had no ``setWordWrap(True)`` and was followed by
        ``status_layout.addStretch()``, so a long OS-error reason either
        overran the dialog or was compressed to a single clipped line.
        Post-fix the label wraps, so at a realistic column width the
        required rendering height for a long reason exceeds a single line.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: Fixture used to stub the availability probe/popups.
        """
        _ = qapp
        dialog = _build_dialog(monkeypatch)
        try:
            long_reason = (
                "Could not determine Windows Sandbox status: WinError 1058: The service cannot be "
                "started, either because it is disabled or because it has no enabled devices "
                "associated with it."
            )
            dialog._set_unavailable(long_reason)

            label = dialog._status_label
            assert label.wordWrap() is True, "status label does not word-wrap"

            column_width = 300
            fm = label.fontMetrics()
            assert fm.horizontalAdvance(label.text()) > column_width, (
                "test premise: the long reason must not fit on one line at the probed width"
            )
            single_line_height = fm.height()
            wrapped_height = label.heightForWidth(column_width)
            assert wrapped_height > single_line_height * 1.5, (
                f"label did not wrap at width={column_width}: wrapped_height={wrapped_height}, single_line_height={single_line_height}"
            )
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_m66_unavailable_and_available_states_expose_matching_tooltip(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Both availability states must set a tooltip mirroring the visible text.

        Pre-fix the label had no tooltip at all, so a clipped or overflowing
        reason had no fallback way for the user to read the full text.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: Fixture used to stub the availability probe/popups.
        """
        _ = qapp
        dialog = _build_dialog(monkeypatch)
        try:
            dialog._set_unavailable("WinError 5: Access is denied.")
            assert dialog._status_label.toolTip() == "Windows Sandbox unavailable: WinError 5: Access is denied."

            dialog._set_available()
            assert dialog._status_label.toolTip() == "Windows Sandbox is available"
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_m66_status_label_claims_layout_stretch_instead_of_being_squeezed(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The status label must own layout stretch instead of a trailing spacer owning it.

        Pre-fix ``status_layout.addWidget(self._status_label)`` was followed
        by ``status_layout.addStretch()``, giving all the stretch to the
        trailing spacer and leaving the label pinned to its unwrapped
        ``sizeHint`` width inside the ``QHBoxLayout``. Post-fix the label
        itself is added with stretch factor ``1`` and there is no competing
        trailing stretch item.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: Fixture used to stub the availability probe/popups.
        """
        _ = qapp
        dialog = _build_dialog(monkeypatch)
        try:
            status_layout = dialog._status_frame.layout()
            assert isinstance(status_layout, QHBoxLayout)
            label_index = status_layout.indexOf(dialog._status_label)
            assert label_index >= 0
            assert status_layout.stretch(label_index) == 1, "status label does not claim layout stretch"
        finally:
            dialog.deleteLater()
