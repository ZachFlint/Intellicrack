# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Pytest configuration for the MainWindow test package.

Supplies the modal-dialog release valve every test in this directory needs.
``MainWindow`` raises real blocking dialogs from its failure handlers -- the
session-load failure path and the generic async error handler both call a
static ``QMessageBox`` method -- and a container has no user to dismiss them,
so a single driven failure would otherwise stall the whole directory until the
harness timeout.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QEvent, QTimer
from PyQt6.QtWidgets import QApplication, QMessageBox

from intellicrack.ui.panels.async_bridge import drain_bridge_workers


if TYPE_CHECKING:
    from collections.abc import Iterator

_MODAL_POLL_INTERVAL_MS: int = 5


def _dismiss_active_modal() -> None:
    """Close the active modal ``QMessageBox`` if one is open."""
    widget = QApplication.activeModalWidget()
    if isinstance(widget, QMessageBox):
        widget.done(int(QMessageBox.StandardButton.Ok))


@pytest.fixture(autouse=True)
def _release_error_dialogs() -> Iterator[None]:
    """Dismiss any real error dialog a driven failure handler opens.

    A dispatched failure is not delivered until its worker is joined and the
    queued signal is processed, which the package-level
    ``_drain_bridge_workers_after_test`` does. That fixture lives in the parent
    conftest, so it is set up first and therefore torn down *last* -- after
    this timer would have stopped -- and the dialog it triggers would open with
    no dismisser running. Draining here, before the timer stops, keeps the
    delivery inside the window this fixture guards.

    Yields:
        None: Control passes to the test with the dismisser timer running.
    """
    timer = QTimer()
    timer.setInterval(_MODAL_POLL_INTERVAL_MS)
    timer.timeout.connect(_dismiss_active_modal)
    timer.start()
    try:
        yield
    finally:
        drain_bridge_workers()
        app = QApplication.instance()
        if app is not None:
            app.processEvents()
            app.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
            app.processEvents()
        timer.stop()
        timer.timeout.disconnect(_dismiss_active_modal)
