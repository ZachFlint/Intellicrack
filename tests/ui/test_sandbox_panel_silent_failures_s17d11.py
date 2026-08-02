# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D11: the panel's two silent failure paths must surface.

Two failures used to vanish entirely:

(a) ``_connect_vnc_display`` passed ``on_error=lambda _: _logger.debug(
    "vnc_port_query_failed")``, dropping the error text on the floor at debug
    level, so a VM Display that never connected left no usable evidence.
(b) ``_on_poll_status_error`` discarded its exception argument completely and
    only rewrote the status label.

Both are now reported at warning level with the real error text and mirrored
into the Console tab. Because the status poll fires every five seconds, its
report is de-duplicated on the error text rather than repeated identically
forever - which is also asserted here, so a "fix" that floods the console fails
too.
"""

from __future__ import annotations

import os

import pytest
from structlog.testing import capture_logs

from intellicrack.ui.panels.sandbox_panel import SandboxPanel


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _warning_entries(captured: list[dict[str, object]]) -> list[dict[str, object]]:
    """Filter captured structlog entries down to warning level and above.

    Args:
        captured: Entries collected by ``structlog.testing.capture_logs``.

    Returns:
        list[dict[str, object]]: Entries logged at warning or higher.
    """
    return [entry for entry in captured if str(entry.get("log_level")) in {"warning", "error", "critical"}]


@pytest.mark.usefixtures("qapp")
def test_vnc_port_query_failure_reaches_console_and_warning_log() -> None:
    """A failed VNC port query must be logged at warning level with its error text."""
    panel = SandboxPanel()
    panel.sandbox_id = "sbx-vnc"

    with capture_logs() as captured:
        panel._on_vnc_port_error(RuntimeError("VNC port is not allocated on this QEMU sandbox"))

    console_text = panel._console_output.toPlainText()
    assert "VNC port is not allocated on this QEMU sandbox" in console_text, (
        f"the VNC port query error never reached the console; console holds {console_text!r}"
    )
    warnings = _warning_entries(captured)
    assert warnings, f"the VNC port query failure produced no warning-level record; captured {captured!r}"
    assert any(entry.get("error") == "VNC port is not allocated on this QEMU sandbox" for entry in warnings), (
        f"the warning record dropped the real error text: {warnings!r}"
    )


@pytest.mark.usefixtures("qapp")
def test_status_poll_failure_reaches_console_and_warning_log() -> None:
    """A failed status poll must report the real error, not just relabel the indicator."""
    panel = SandboxPanel()

    with capture_logs() as captured:
        panel._on_poll_status_error(RuntimeError("manager was shut down"))

    assert panel._status_indicator.text() == "Active (status unavailable)"
    console_text = panel._console_output.toPlainText()
    assert "manager was shut down" in console_text, f"the poll failure never reached the console; console holds {console_text!r}"
    warnings = _warning_entries(captured)
    assert warnings, f"the status poll failure produced no warning-level record; captured {captured!r}"
    assert any(entry.get("error") == "manager was shut down" for entry in warnings), (
        f"the warning record dropped the real error text: {warnings!r}"
    )


@pytest.mark.usefixtures("qapp")
def test_repeated_identical_poll_failures_are_reported_once() -> None:
    """An unchanged poll failure must not be re-appended on every five-second tick."""
    panel = SandboxPanel()

    for _ in range(5):
        panel._on_poll_status_error(RuntimeError("manager was shut down"))

    console_text = panel._console_output.toPlainText()
    assert console_text.count("manager was shut down") == 1, f"a persistent outage flooded the console: {console_text!r}"


@pytest.mark.usefixtures("qapp")
def test_changed_poll_error_is_reported_again() -> None:
    """A different poll error must be reported even after an earlier one was seen."""
    panel = SandboxPanel()

    panel._on_poll_status_error(RuntimeError("manager was shut down"))
    panel._on_poll_status_error(RuntimeError("connection refused"))

    console_text = panel._console_output.toPlainText()
    assert "manager was shut down" in console_text
    assert "connection refused" in console_text, "a new failure mode must not be suppressed by the de-duplication"


@pytest.mark.usefixtures("qapp")
def test_poll_recovery_rearms_the_failure_report() -> None:
    """A successful poll between two identical failures must re-arm the report."""
    panel = SandboxPanel()

    panel._on_poll_status_error(RuntimeError("manager was shut down"))
    panel._on_poll_status_success({"active_count": 1, "instances": []})
    panel._on_poll_status_error(RuntimeError("manager was shut down"))

    console_text = panel._console_output.toPlainText()
    assert console_text.count("manager was shut down") == 2, f"a recurrence after recovery must be reported again: {console_text!r}"
