# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared helpers for FIX UNIT 14a real-data process-panel coverage tests.

These helpers drive the *real* :class:`~intellicrack.bridges.process.ProcessBridge`
against the *real* running Python interpreter process so the process-panel
tab widgets render genuine Win32 enumeration data (real thread IDs, real
loaded DLLs such as ``ntdll.dll``/``kernel32.dll``, real token privileges,
real process-image memory). No bridge method under test is mocked; a real
Windows backend performs every enumeration.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import TYPE_CHECKING, overload

import pytest
from PyQt6.QtCore import QEventLoop, QTimer

from intellicrack.bridges.process import ProcessBridge
from intellicrack.ui.panels.async_bridge import ensure_loop


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from PyQt6.QtWidgets import QApplication


def require_windows() -> None:
    """Skip the calling test when not running on Windows.

    The process-panel tabs enumerate live Win32 process state via the real
    :class:`ProcessBridge`; that backend exists only on Windows (host or the
    Windows Docker container).
    """
    if sys.platform != "win32":
        pytest.skip("Real ProcessBridge enumeration requires Windows")


@overload
def run_bridge_sync[T](coro: Coroutine[object, object, T]) -> T: ...


def run_bridge_sync(coro: Coroutine[object, object, object]) -> object:
    """Execute a bridge coroutine to completion on the persistent loop.

    Runs ``coro`` on the same background event loop the UI panels use so the
    real bridge state created here (open process handle, attached PID) is
    visible to subsequent panel-driven refreshes dispatched through
    :func:`run_bridge_coroutine_logged`.

    Args:
        coro: Bridge coroutine to await.

    Returns:
        object: The coroutine's result.
    """
    loop = ensure_loop()
    return asyncio.run_coroutine_threadsafe(coro, loop).result()


class RealProcessBridgeProbe(ProcessBridge):
    """Real ProcessBridge subclass exposing a typed raw-memory read.

    The production raw-read helper is protected; exposing it from this
    subclass lets tests read genuine process memory while remaining fully
    type-correct (protected members are accessible in subclasses).
    """

    def read_bytes(self, address: int, size: int) -> bytes:
        """Read raw bytes from the attached process via the real Win32 read.

        Args:
            address: Virtual address to read from.
            size: Number of bytes to read.

        Returns:
            bytes: The genuine bytes read from process memory.
        """
        return self._sync_read_memory(address, size)


def make_real_bridge_attached_to_self() -> RealProcessBridgeProbe:
    """Create a real ProcessBridge initialized and attached to this process.

    Opens the current interpreter process with full access so memory, thread,
    module, and privilege enumeration return genuine data.

    Returns:
        RealProcessBridgeProbe: Initialized bridge attached to ``os.getpid()``.
    """
    bridge = RealProcessBridgeProbe()
    run_bridge_sync(bridge.initialize())
    run_bridge_sync(bridge.open_process(os.getpid(), "all"))
    return bridge


def close_real_bridge(bridge: ProcessBridge) -> None:
    """Close the process handle held by ``bridge``.

    Args:
        bridge: Bridge whose open process handle should be released.
    """
    run_bridge_sync(bridge.close())


def pump_until(
    qapp: QApplication,
    predicate: Callable[[], bool],
    timeout_ms: int = 8000,
) -> bool:
    """Pump the Qt event loop until ``predicate`` is truthy or timeout elapses.

    The panel refreshes dispatch to a background worker thread and deliver
    results via queued Qt signals, so the calling test must drive the event
    loop for the table-population callbacks to run on the main thread.

    Args:
        qapp: The live :class:`QApplication` whose event loop to drive.
        predicate: Zero-argument callable returning truthy when finished.
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
        _ = QTimer.singleShot(step_ms, loop.quit)
        _ = loop.exec()
        qapp.processEvents()
        elapsed_ms += step_ms
    return predicate()
