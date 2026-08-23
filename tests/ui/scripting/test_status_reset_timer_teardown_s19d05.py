# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for S19-D05: ``ScriptManagerPanel`` status-reset QTimer lifetime.

Both ``_on_validate`` and ``acknowledge_execution`` used to arm their
status-bar reset via an ownerless ``QTimer.singleShot(_STATUS_RESET_MS,
reset_status)``, where ``reset_status`` closed over ``self`` and touched
``self._status_bar``. That timer is driven by Qt's global timer system, not by
the panel's own object tree, so nothing cancels it when the panel (and its
child ``QStatusBar``) is torn down before the delay elapses. When it later
fired against the deleted ``QStatusBar`` it raised::

    RuntimeError: wrapped C/C++ object of type QStatusBar has been deleted

which surfaced as an intermittent teardown crash in combined UI test runs.

Both gates below construct a real ``ScriptManagerPanel`` under a real,
offscreen ``QApplication``, arm the status-reset timer through one of the two
call sites, force-delete the panel's underlying C++ object with
``PyQt6.sip.delete`` before the delay elapses (mirroring a Scripts tab being
closed mid-flight), then pump the real Qt event loop well past the delay.
PyQt6 routes an exception raised inside a queued slot invocation to
``sys.excepthook`` rather than back to whichever caller pumped the loop, so
each gate installs a capturing hook for the pump and asserts nothing landed
in it.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Final

from PyQt6 import sip
from PyQt6.QtCore import QEventLoop, QTimer

from intellicrack.core.script_gen import ScriptManager, ScriptValidator
from intellicrack.ui.panels.script_manager import _STATUS_RESET_MS, ScriptManagerPanel


if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication

# Margin added on top of the panel's own status-reset delay so the pumped
# event loop reliably outlasts a timer armed just before teardown.
_PUMP_MARGIN_MS: Final[int] = 750


def _pump_event_loop(duration_ms: int) -> None:
    """Run the real Qt event loop for at least ``duration_ms`` milliseconds.

    Args:
        duration_ms: Minimum time, in milliseconds, to keep the loop running.
    """
    loop = QEventLoop()
    QTimer.singleShot(duration_ms, loop.quit)
    loop.exec()


def _assert_status_reset_survives_teardown(panel: ScriptManagerPanel) -> None:
    """Delete ``panel``'s C++ object and confirm its pending timer stays silent.

    Args:
        panel: The panel under test, with its status-reset timer already armed.
    """
    captured: list[BaseException] = []
    original_hook = sys.excepthook

    def _capture(
        exc_type: type[BaseException],
        exc_value: BaseException,
        exc_tb: object,
    ) -> None:
        del exc_type, exc_tb
        captured.append(exc_value)

    sip.delete(panel)

    sys.excepthook = _capture
    try:
        _pump_event_loop(_STATUS_RESET_MS + _PUMP_MARGIN_MS)
    finally:
        sys.excepthook = original_hook

    assert not captured, f"status-reset timer fired against a torn-down panel: {captured!r}"


class TestStatusResetTimerSurvivesPanelTeardown:
    """A pending status-reset timer must never fire against a deleted panel."""

    def test_acknowledge_execution_timer_survives_teardown(self, qapp: QApplication) -> None:
        """``acknowledge_execution`` must not leak a status-reset callback past panel teardown.

        Args:
            qapp: Session ``QApplication`` fixture required for widget construction.
        """
        del qapp
        panel = ScriptManagerPanel()
        panel.acknowledge_execution("probe", "result text")

        _assert_status_reset_survives_teardown(panel)

    def test_validate_timer_survives_teardown(self, qapp: QApplication, tmp_path: Path) -> None:
        """``_on_validate`` must not leak a status-reset callback past panel teardown.

        Args:
            qapp: Session ``QApplication`` fixture required for widget construction.
            tmp_path: Pytest temporary directory backing the script manager storage.
        """
        del qapp
        panel = ScriptManagerPanel()
        panel.set_backend(ScriptManager(scripts_dir=tmp_path / "scripts"), ScriptValidator())

        python_index = panel._type_combo.findData("python")
        assert python_index >= 0, "python is not present in the Scripts panel type combo"
        panel._type_combo.setCurrentIndex(python_index)
        panel._name_edit.setText("probe")
        panel._editor.set_content("print('probe')")

        panel._on_validate()

        _assert_status_reset_survives_teardown(panel)
