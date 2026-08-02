# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D09: sandbox panel failures must raise a visible error dialog.

Before this fix every failure path in ``SandboxPanel`` only appended a
``"[-] ..."`` line to the Console tab. There was not a single ``QMessageBox``
in the whole panel, so a failed Create, Destroy, Restart, Run, snapshot or
command execution was completely invisible unless the user happened to be
looking at the Console tab at that moment.

These tests drive the real panel handlers with real exceptions and let the
genuine blocking ``QMessageBox`` that ``dialogs_helpers.show_error`` creates
open for real. A repeating ``QTimer`` finds the live modal, records its actual
``windowTitle()``/``text()``, and dismisses it so the blocking static call
returns - the same technique the SystemTab warning harness uses. Nothing about
the dialog mechanism is faked, so removing the dialog call makes the recorder
capture nothing and the assertions fail.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication, QMessageBox

from intellicrack.ui.panels.sandbox_panel import SandboxPanel


if TYPE_CHECKING:
    from collections.abc import Iterator


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_POLL_INTERVAL_MS: int = 5


class ModalRecorder:
    """Records and dismisses the real modal dialogs a test triggers.

    A repeating Qt timer runs inside the nested event loop opened by the
    blocking ``QMessageBox`` static methods. Every modal it finds is recorded
    as a ``(title, text)`` pair in display order and then closed so the
    production call returns instead of hanging.

    Attributes:
        captured: Ordered ``(title, text)`` pairs from each real dialog shown.
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
        """Titles of every captured dialog, in display order.

        Returns:
            list[str]: Dialog window titles.
        """
        return [title for title, _ in self.captured]

    @property
    def messages(self) -> list[str]:
        """Message bodies of every captured dialog, in display order.

        Returns:
            list[str]: Dialog message bodies.
        """
        return [text for _, text in self.captured]


@pytest.fixture
def modal_recorder(qapp: QApplication) -> Iterator[ModalRecorder]:
    """Capture the real modal dialogs raised during a test.

    Args:
        qapp: Session ``QApplication`` required for real modal creation.

    Yields:
        ModalRecorder: Recorder exposing the captured title/text pairs.
    """
    recorder = ModalRecorder()
    timer = QTimer()
    timer.setInterval(_POLL_INTERVAL_MS)
    timer.timeout.connect(recorder.dismiss_active_modal)
    timer.start()
    try:
        yield recorder
    finally:
        timer.stop()
        timer.timeout.disconnect(recorder.dismiss_active_modal)
        qapp.processEvents()


def test_create_failure_raises_a_real_error_dialog(modal_recorder: ModalRecorder) -> None:
    """A failed Create must raise a real dialog carrying the backend error text.

    Args:
        modal_recorder: Recorder that dismisses the genuine modal.
    """
    panel = SandboxPanel()
    failure = RuntimeError("Windows Sandbox is not installed on this host")

    panel._on_create_error(failure)

    assert modal_recorder.captured, "a failed sandbox create raised no dialog at all"
    assert modal_recorder.titles == ["Sandbox Creation Failed"], f"unexpected dialog titles: {modal_recorder.titles!r}"
    assert "Windows Sandbox is not installed on this host" in modal_recorder.messages[0], (
        f"dialog body must carry the real error text, got {modal_recorder.messages[0]!r}"
    )


def test_create_failure_still_logs_to_the_console(modal_recorder: ModalRecorder) -> None:
    """The dialog must be added to the console line, not replace it.

    Args:
        modal_recorder: Recorder that dismisses the genuine modal.
    """
    panel = SandboxPanel()

    panel._on_create_error(RuntimeError("qemu-system-x86_64 not found"))

    console_text = panel._console_output.toPlainText()
    assert "[-] Failed to create sandbox: qemu-system-x86_64 not found" in console_text, (
        f"the console record was dropped; console holds {console_text!r}"
    )
    assert modal_recorder.captured, "console logging must not have replaced the dialog"


@pytest.mark.parametrize(
    ("handler_name", "expected_title", "expected_console"),
    [
        ("_on_destroy_error", "Sandbox Destroy Failed", "[-] Failed to destroy sandbox: boom"),
        ("_on_restart_error", "Sandbox Restart Failed", "[-] Failed to restart sandbox: boom"),
        ("_on_run_binary_error", "Sandbox Execution Failed", "[-] Execution failed: boom"),
        ("_on_take_snapshot_error", "Snapshot Failed", "[-] Snapshot failed: boom"),
        ("_on_restore_snapshot_error", "Snapshot Restore Failed", "[-] Restore failed: boom"),
        ("_on_delete_snapshot_error", "Snapshot Deletion Failed", "[-] Snapshot deletion failed: boom"),
        ("_on_execute_command_error", "Command Execution Failed", "[-] Command execution failed: boom"),
        ("_on_screenshot_error", "Screenshot Failed", "[-] Screenshot failed: boom"),
        ("_on_copy_in_error", "Copy Into Sandbox Failed", "[-] Copy into sandbox failed: boom"),
        ("_on_pause_vm_error", "VM Pause Failed", "[-] VM pause failed: boom"),
    ],
)
def test_every_user_initiated_failure_path_raises_a_dialog(
    modal_recorder: ModalRecorder,
    handler_name: str,
    expected_title: str,
    expected_console: str,
) -> None:
    """Each toolbar action's error handler must surface a dialog and a console line.

    Args:
        modal_recorder: Recorder that dismisses the genuine modal.
        handler_name: Name of the real panel error handler to drive.
        expected_title: Exact dialog window title the handler must use.
        expected_console: Exact console line the handler must still write.
    """
    panel = SandboxPanel()
    handler = getattr(panel, handler_name)

    handler(RuntimeError("boom"))

    assert modal_recorder.titles == [expected_title], (
        f"{handler_name} produced dialogs {modal_recorder.titles!r}, expected [{expected_title!r}]"
    )
    assert "boom" in modal_recorder.messages[0]
    assert expected_console in panel._console_output.toPlainText()


def test_recurring_status_poll_failure_raises_no_dialog(modal_recorder: ModalRecorder) -> None:
    """The five-second status poll must never open a dialog, however often it fails.

    Args:
        modal_recorder: Recorder that would capture any modal that appeared.
    """
    panel = SandboxPanel()

    panel._on_poll_status_error(RuntimeError("status rpc down"))
    panel._on_poll_status_error(RuntimeError("status rpc down"))
    panel._on_poll_status_error(RuntimeError("status rpc down"))
    QApplication.processEvents()

    assert modal_recorder.captured == [], f"the recurring poll timer must not spawn dialogs, got {modal_recorder.captured!r}"
