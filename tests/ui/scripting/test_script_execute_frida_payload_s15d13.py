# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Live Frida gate for the Scripts panel Execute button.

Driving Execute for the ``frida`` script type against a genuinely attached
process showed the panel rendering ``{}`` for a script that had answered:
``_execute_script_and_wait`` merged only object payloads into its result and
dropped every other ``send()`` value, even though such a payload still
completed the wait. ``send("text")`` is the most common shape a hand-written
Frida script uses, so the Scripts panel discarded exactly the output a user
would ask for.

Everything here is real: a real child process is spawned, the real
``FridaBridge`` attaches to it, the real ``ToolOutputPanel`` /
``ScriptManagerPanel`` widgets dispatch Execute, and the expected value is
derived from the live process through the unchanged object-payload path rather
than restated as a constant.
"""

from __future__ import annotations

import sys
import time
from typing import TYPE_CHECKING, Final

import frida
import pytest
from PyQt6.QtWidgets import QMessageBox

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.script_gen import ScriptManager
from intellicrack.core.subprocess_compat import DEVNULL, Popen
from intellicrack.ui.panels.async_bridge import drain_bridge_workers, run_bridge_coroutine
from intellicrack.ui.panels.script_manager import _STATUS_RESET_MS, ScriptManagerPanel
from intellicrack.ui.tools import ToolOutputPanel


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


pytestmark = pytest.mark.spawns_process

# Idle child process Frida attaches to. It must outlive the attach and stay
# quiet, so it sleeps in a loop rather than exiting.
_CHILD_SOURCE: Final[str] = "import time\nwhile True:\n    time.sleep(0.5)\n"
_CHILD_STARTUP_S: Final[float] = 2.0

_SETUP_TIMEOUT_S: Final[float] = 180.0
_EXECUTE_DEADLINE_S: Final[float] = 15.0
_EVENT_PUMP_INTERVAL_S: Final[float] = 0.01

_STATUS_RESET_MARGIN_S: Final[float] = 0.5

_STRING_MARKER: Final[str] = "AUDIT_FRIDA_SEND"
_OBJECT_SCRIPT: Final[str] = f'send({{ marker: "{_STRING_MARKER}", arch: Process.arch }});'
_STRING_SCRIPT: Final[str] = f'send("{_STRING_MARKER}:" + Process.arch);'

# A script that faults inside the Frida runtime the way a real one does when
# it attaches to an export the target does not have.
_FAULT_MARKER: Final[str] = "AUDIT_FRIDA_FAULT"
_FAULT_SCRIPT: Final[str] = f'throw new Error("{_FAULT_MARKER}");'


def _settle_pending_status_timers(qapp: QApplication) -> None:
    """Let the panel's pending status-reset single-shot timers fire before teardown.

    ``acknowledge_execution`` arms a ``QTimer.singleShot`` that restores the
    status-bar style ``_STATUS_RESET_MS`` later. Destroying the panel while one
    is still pending leaves a callback holding a deleted ``QStatusBar``, which
    surfaces as a Qt event-loop exception in whichever later test happens to
    pump the loop long enough for it to fire.

    Args:
        qapp: Live ``QApplication`` whose event loop is pumped.
    """
    deadline = time.monotonic() + _STATUS_RESET_MS / 1000.0 + _STATUS_RESET_MARGIN_S
    while time.monotonic() < deadline:
        qapp.processEvents()
        time.sleep(_EVENT_PUMP_INTERVAL_S)


@pytest.fixture(autouse=True)
def _auto_dismiss_blocking_dialogs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auto-answer blocking ``QMessageBox`` modals so headless UI drives never hang.

    Args:
        monkeypatch: Pytest fixture used to replace the blocking static methods.
    """
    monkeypatch.setattr(QMessageBox, "question", lambda *_a, **_k: QMessageBox.StandardButton.No)
    monkeypatch.setattr(QMessageBox, "critical", lambda *_a, **_k: QMessageBox.StandardButton.Ok)
    monkeypatch.setattr(QMessageBox, "warning", lambda *_a, **_k: QMessageBox.StandardButton.Ok)
    monkeypatch.setattr(QMessageBox, "information", lambda *_a, **_k: QMessageBox.StandardButton.Ok)


@pytest.fixture
def attached_frida_panels(
    qapp: QApplication,
    tmp_path: Path,
) -> Iterator[tuple[ToolOutputPanel, ScriptManagerPanel]]:
    """Wire a real Scripts panel to a ``FridaBridge`` attached to a real child process.

    The bridge is initialised and attached on the shared bridge event loop, the
    same loop the panel's Execute dispatch uses, so no asyncio primitive is
    touched from two loops.

    Args:
        qapp: Session ``QApplication`` fixture required for widget construction.
        tmp_path: Pytest temporary directory backing the script manager storage.

    Yields:
        tuple[ToolOutputPanel, ScriptManagerPanel]: The tool panel with an
            attached Frida bridge, and its Scripts panel.
    """
    child = Popen([sys.executable, "-c", _CHILD_SOURCE], stdout=DEVNULL, stderr=DEVNULL)
    time.sleep(_CHILD_STARTUP_S)
    bridge = FridaBridge()
    panel = ToolOutputPanel()
    try:
        run_bridge_coroutine(bridge.initialize(), timeout_s=_SETUP_TIMEOUT_S)
        try:
            run_bridge_coroutine(bridge.attach(child.pid), timeout_s=_SETUP_TIMEOUT_S)
        except frida.ProcessNotFoundError as exc:
            pytest.skip(f"frida could not attach to the spawned child process: {exc}")
        except frida.PermissionDeniedError as exc:
            pytest.skip(f"frida injection is not permitted in this environment: {exc}")

        panel.frida_bridge = bridge
        panel.wire_script_backend(ScriptManager(scripts_dir=tmp_path / "scripts"))
        script_panel = panel.add_script_panel()
        assert isinstance(script_panel, ScriptManagerPanel)
        yield panel, script_panel
    finally:
        _ = drain_bridge_workers()
        _settle_pending_status_timers(qapp)
        run_bridge_coroutine(bridge.detach(), timeout_s=_SETUP_TIMEOUT_S)
        child.terminate()
        panel.deleteLater()
        qapp.processEvents()


def _press_execute(qapp: QApplication, script_panel: ScriptManagerPanel, name: str, content: str) -> str:
    """Drive the Scripts panel's Execute button once for the frida type.

    Args:
        qapp: Live ``QApplication`` used to pump events.
        script_panel: The real ``ScriptManagerPanel`` under test.
        name: Script name to type into the name edit.
        content: Frida JavaScript to load into the editor.

    Returns:
        str: Text left in the panel's result pane once it settles.
    """
    index = script_panel._type_combo.findData("frida")
    assert index >= 0, "frida is not present in the Scripts panel type combo"
    script_panel._type_combo.setCurrentIndex(index)
    script_panel._name_edit.setText(name)
    script_panel._editor.set_content(content)
    script_panel._result_pane.setPlainText("")

    started = time.monotonic()
    script_panel._on_execute()
    qapp.processEvents()
    while script_panel._execution_in_progress and time.monotonic() - started < _EXECUTE_DEADLINE_S:
        qapp.processEvents()
        time.sleep(_EVENT_PUMP_INTERVAL_S)
    qapp.processEvents()

    assert not script_panel._execution_in_progress, f"{name}: Execute never settled"
    return script_panel._result_pane.toPlainText()


class TestFridaSendPayloadReachesTheResultPane:
    """Execute must surface whatever an attached Frida script sends back."""

    def test_a_string_send_payload_is_surfaced_not_discarded(
        self,
        qapp: QApplication,
        attached_frida_panels: tuple[ToolOutputPanel, ScriptManagerPanel],
    ) -> None:
        """``send("text")`` must reach the result pane, not collapse to an empty mapping.

        The expected architecture token is read out of the live process first
        through the object-payload path, which this change does not touch, so
        the assertion is anchored to what the attached process actually reports
        rather than to a hard-coded value.

        Args:
            qapp: Session ``QApplication`` fixture used to pump events.
            attached_frida_panels: Tool panel with an attached Frida bridge and
                its Scripts panel.
        """
        _, script_panel = attached_frida_panels

        object_result = _press_execute(qapp, script_panel, "Audit_frida_object", _OBJECT_SCRIPT)
        arch = next(
            (token for token in ("x64", "ia32", "arm64", "arm") if f"'{token}'" in object_result),
            "",
        )
        assert arch, f"precondition: object payload did not report an architecture: {object_result!r}"

        string_result = _press_execute(qapp, script_panel, "Audit_frida_string", _STRING_SCRIPT)

        assert f"{_STRING_MARKER}:{arch}" in string_result, f"the script's string payload never reached the result pane: {string_result!r}"

    def test_an_object_send_payload_still_contributes_its_own_keys(
        self,
        qapp: QApplication,
        attached_frida_panels: tuple[ToolOutputPanel, ScriptManagerPanel],
    ) -> None:
        """``send({...})`` must keep flattening into the result, unchanged by the string fix.

        Args:
            qapp: Session ``QApplication`` fixture used to pump events.
            attached_frida_panels: Tool panel with an attached Frida bridge and
                its Scripts panel.
        """
        _, script_panel = attached_frida_panels

        result = _press_execute(qapp, script_panel, "Audit_frida_object", _OBJECT_SCRIPT)

        assert "'marker'" in result, f"object payload keys missing from the result pane: {result!r}"
        assert _STRING_MARKER in result, f"object payload value missing from the result pane: {result!r}"

    def test_a_failing_script_reports_the_runtime_s_own_description(
        self,
        qapp: QApplication,
        attached_frida_panels: tuple[ToolOutputPanel, ScriptManagerPanel],
    ) -> None:
        """A script that faults must surface Frida's description, not a bare failure line.

        The thrown message is produced inside the injected script by the real
        Frida runtime and travels back as the error message's description, so a
        result pane that only says "script execution failed" proves the
        description was thrown away between the runtime and the user.

        Args:
            qapp: Session ``QApplication`` fixture used to pump events.
            attached_frida_panels: Tool panel with an attached Frida bridge and
                its Scripts panel.
        """
        _, script_panel = attached_frida_panels

        result = _press_execute(qapp, script_panel, "Audit_frida_fault", _FAULT_SCRIPT)

        assert "error" in result.lower(), f"a faulting script was not reported as a failure: {result!r}"
        assert _FAULT_MARKER in result, f"the runtime's own description of the fault never reached the result pane: {result!r}"
