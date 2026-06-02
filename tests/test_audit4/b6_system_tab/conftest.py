# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared fixtures for audit4 b6 SystemTab tests.

Exposes a real GUI harness that lets the user-visible warning paths introduced
for F-0022 and F-0023 run the genuine ``QMessageBox.warning`` modal dialog while
still keeping the suite non-blocking.

Rather than replacing ``QMessageBox.warning`` with a fake (which would mask
whether the production warning mechanism actually fires and with what content),
the harness installs a repeating ``QTimer`` that detects the real modal
``QMessageBox`` Qt creates, records its genuine ``windowTitle()``/``text()``, and
dismisses it via the real ``done()`` call so the blocking static method returns
normally. Tests can therefore assert on the real dialog content that production
code displayed.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication, QMessageBox


if TYPE_CHECKING:
    from collections.abc import Iterator


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_POLL_INTERVAL_MS: int = 5


class WarningRecorder:
    """Records every real ``QMessageBox.warning`` modal shown during a test.

    The recorder is driven by a repeating Qt timer that runs inside the nested
    event loop opened by the blocking ``QMessageBox.warning`` static method. When
    it finds an active modal ``QMessageBox`` it captures the dialog's real title
    and text, then closes it with the ``Ok`` result so the production call
    returns. Captured entries preserve display order.

    Attributes:
        captured: Ordered list of ``(title, text)`` pairs from each real dialog.
    """

    captured: list[tuple[str, str]]

    def __init__(self) -> None:
        """Initialise an empty recorder."""
        self.captured = []

    def dismiss_active_modal(self) -> None:
        """Capture and close the active modal ``QMessageBox`` if one is open."""
        widget = QApplication.activeModalWidget()
        if isinstance(widget, QMessageBox):
            self.captured.append((widget.windowTitle(), widget.text()))
            widget.done(int(QMessageBox.StandardButton.Ok))

    @property
    def titles(self) -> list[str]:
        """Return the titles of every captured warning dialog, in order.

        Returns:
            list[str]: Dialog window titles in display order.
        """
        return [title for title, _ in self.captured]

    @property
    def messages(self) -> list[str]:
        """Return the message text of every captured warning dialog, in order.

        Returns:
            list[str]: Dialog message bodies in display order.
        """
        return [text for _, text in self.captured]


@pytest.fixture(autouse=True)
def warning_recorder() -> Iterator[WarningRecorder]:
    """Capture real ``QMessageBox.warning`` dialogs without faking them.

    A live ``QApplication`` is ensured so Qt can create the genuine modal, and a
    repeating timer dismisses each real warning dialog after recording its title
    and text. Because the production ``QMessageBox.warning`` call executes in
    full, tests can assert that warnings fired and what they said.

    Yields:
        WarningRecorder: Recorder exposing the captured dialog title/text pairs.
    """
    existing = QApplication.instance()
    app = existing if isinstance(existing, QApplication) else QApplication([])
    recorder = WarningRecorder()

    timer = QTimer()
    timer.setInterval(_POLL_INTERVAL_MS)
    timer.timeout.connect(recorder.dismiss_active_modal)
    timer.start()
    try:
        yield recorder
    finally:
        timer.stop()
        timer.timeout.disconnect(recorder.dismiss_active_modal)
        app.processEvents()
