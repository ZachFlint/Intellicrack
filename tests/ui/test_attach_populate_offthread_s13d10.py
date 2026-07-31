# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for S13-D10: the "Attached" confirmation must never block.

Before the fix, ``ProcessTab._on_attach``'s success handler showed the post-attach confirmation via the blocking
``QMessageBox.information`` convenience function *before* emitting ``process_attached``. Because that call opens an application-modal nested
Qt event loop, nothing scheduled after it -- including the ``process_attached`` emission that triggers sibling-tab auto-populate (region /
module / thread enumeration, dispatched off the UI thread through the project's existing ``run_bridge_coroutine_logged`` /
``BridgeCallWorker`` pattern) -- could run until a user dismissed the dialog, and OK/close did nothing in the meantime.

The fix (in ``ProcessTab._on_attach`` / ``ProcessTab._show_attached_confirmation``) reorders the handler to emit ``process_attached`` first,
scheduling auto-populate before the dialog exists, and shows the confirmation as a non-modal ``QMessageBox`` so it can never gate anything on
the UI thread regardless of how long background work takes.

Both tests drive the real ``ProcessTab._on_attach`` entry point against a real ``ProcessBridge`` attached to the live test process
(``os.getpid()``), with ``open_process`` wrapped in a test-local subclass that adds a deliberate delay so the async round trip is non-trivial
-- proving the dialog and the signal emission are not serialized behind a blocking dialog.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import TYPE_CHECKING, Final, override

import pytest
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import QMessageBox

from intellicrack.bridges.process import ProcessAccessRights, ProcessBridge
from intellicrack.ui.panels.process_panel.process_tab import ProcessTab


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from PyQt6.QtWidgets import QApplication

_MAX_WAIT_S: Final[float] = 6.0
_POLL_INTERVAL_S: Final[float] = 0.02
_WATCH_INTERVAL_MS: Final[int] = 5
_OPEN_DELAY_S: Final[float] = 0.4


class _DelayedOpenProcessBridge(ProcessBridge):
    """A ``ProcessBridge`` whose ``open_process`` sleeps before doing the real Win32 open.

    Stands in for a target whose post-attach work is non-trivial without touching the locked ``bridges/process.py`` module: the delay is
    injected purely at this test-local subclass boundary, and the underlying open call is the real ``ProcessBridge`` implementation against
    the live test process.
    """

    @override
    async def open_process(self, pid: int, access: ProcessAccessRights = "all") -> bool:
        """Sleep for ``_OPEN_DELAY_S`` then perform the real process open.

        Args:
            pid: Process ID to open.
            access: Access rights required.

        Returns:
            bool: True if the underlying open succeeded.
        """
        await asyncio.sleep(_OPEN_DELAY_S)
        return await super().open_process(pid, access)


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive an async bridge coroutine to completion on a private event loop.

    Args:
        coro: The awaitable coroutine to execute.

    Returns:
        T: The resolved result of the coroutine.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _pump_until(qapp: QApplication, predicate: Callable[[], bool], timeout_s: float = _MAX_WAIT_S) -> bool:
    """Pump the Qt event loop until ``predicate`` is satisfied or ``timeout_s`` elapses.

    Args:
        qapp: The QApplication instance whose event loop is pumped.
        predicate: Zero-argument callable polled after each pump.
        timeout_s: Maximum wall-clock seconds to keep pumping.

    Returns:
        bool: True if ``predicate`` became truthy before the deadline.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        qapp.processEvents()
        time.sleep(_POLL_INTERVAL_S)
    return bool(predicate())


@pytest.fixture
def tab(qapp: QApplication) -> Generator[ProcessTab]:
    """Create a ``ProcessTab`` wired to a real, delay-injected ``ProcessBridge``.

    Args:
        qapp: Session QApplication fixture from ``tests/ui/conftest.py``.

    Yields:
        ProcessTab: Tab attached to a fresh ``_DelayedOpenProcessBridge``, with the current test process's own PID pre-selected so
        ``_on_attach`` has a real, live target to open.
    """
    bridge = _DelayedOpenProcessBridge()
    _run(bridge.initialize())
    t = ProcessTab()
    t.set_bridge(bridge)
    t._selected_pid = os.getpid()
    yield t
    t.cleanup()
    qapp.processEvents()
    _run(bridge.close())
    t.deleteLater()
    qapp.processEvents()


class TestAttachConfirmationDoesNotBlockUIThread:
    """S13-D10: the Attached confirmation must never gate anything on the UI thread."""

    def test_on_attach_returns_before_open_process_delay_elapses(self, tab: ProcessTab, qapp: QApplication) -> None:
        """``_on_attach`` must return promptly even though ``open_process`` sleeps first.

        The bridge call is dispatched through the existing off-thread ``run_bridge_coroutine_logged`` / ``BridgeCallWorker`` pattern; if
        that dispatch were ever replaced with a synchronous/blocking call, ``_on_attach`` would itself block for ``_OPEN_DELAY_S`` and this
        assertion would fail.

        Args:
            tab: ProcessTab fixture wired to the delay-injected bridge.
            qapp: Session QApplication fixture.
        """
        started = time.monotonic()
        tab._on_attach()
        elapsed = time.monotonic() - started

        assert elapsed < _OPEN_DELAY_S / 2, (
            f"_on_attach blocked the UI thread for {elapsed:.3f}s waiting on open_process instead of dispatching it off-thread"
        )

        attached = _pump_until(qapp, lambda: tab._attached_pid == os.getpid())
        assert attached, "attach never completed after being dispatched off-thread"

    def test_confirmation_is_nonmodal_and_shown_after_signal_is_emitted(self, tab: ProcessTab, qapp: QApplication) -> None:
        """The Attached dialog must be non-modal and must appear only after ``process_attached`` fires.

        A ``QTimer`` armed before the attach is dispatched polls for the confirmation dialog on every iteration of the Qt event loop --
        including inside a nested modal loop, since Qt timers still fire there -- so this assertion is safe against both the fixed
        (non-modal) and a reverted (modal) implementation: whichever kind of dialog appears gets detected and closed the moment it shows,
        without ever depending on a human clicking it, which is what makes it safe to run unattended instead of risking an indefinite hang.

        Args:
            tab: ProcessTab fixture wired to the delay-injected bridge.
            qapp: Session QApplication fixture.
        """
        state: dict[str, object] = {"signal_emitted": False, "box": None, "modality": None, "emitted_before_shown": None}

        def _on_process_attached(_pid: int) -> None:
            """Record that ``process_attached`` has fired.

            Args:
                _pid: Attached process ID (unused; only the firing matters here).
            """
            state["signal_emitted"] = True

        tab.process_attached.connect(_on_process_attached)

        watcher = QTimer()
        watcher.setInterval(_WATCH_INTERVAL_MS)

        def _check() -> None:
            """Detect the first QMessageBox parented under ``tab`` and close it.

            Captures its modality and whether ``process_attached`` had already fired by the time it appeared, then dismisses it so neither
            a modal nor a non-modal dialog can stall the test.
            """
            boxes = tab.findChildren(QMessageBox)
            if not boxes:
                return
            box = boxes[0]
            state["box"] = box
            state["modality"] = box.windowModality()
            state["emitted_before_shown"] = state["signal_emitted"]
            watcher.stop()
            box.close()

        watcher.timeout.connect(_check)
        watcher.start()

        tab._on_attach()
        found = _pump_until(qapp, lambda: state["box"] is not None)
        watcher.stop()

        assert found, "no 'Attached' confirmation dialog ever appeared after a successful attach"
        assert state["modality"] == Qt.WindowModality.NonModal, (
            f"Attached confirmation must be non-modal so OK/close stay responsive; got {state['modality']!r}"
        )
        assert state["emitted_before_shown"] is True, (
            "process_attached must be emitted before the confirmation dialog is shown, so sibling-tab auto-populate is scheduled "
            "immediately instead of waiting for the dialog to be dismissed"
        )

        attached = _pump_until(qapp, lambda: tab._attached_pid == os.getpid())
        assert attached, "_attached_pid was never set to the target PID after attach completed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
