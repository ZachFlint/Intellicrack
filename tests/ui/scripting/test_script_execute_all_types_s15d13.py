# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Live-drive gates for the Scripts panel Execute button, all five script types.

S15-D13 was originally diagnosed as "no executor injected, ``script_execute``
signal unconnected", which was retired as stale once the executor was wired on
both routes. What that retirement never established is the part these gates
cover: that pressing Execute actually reaches
``ToolOutputPanel._execute_script`` for **every** script type, and that a tool
which is not connected produces a surfaced diagnostic rather than a silent
nothing, a hang, or a fabricated success.

Every test drives the real ``ToolOutputPanel`` and ``ScriptManagerPanel``
widgets under the offscreen Qt platform with a real ``ScriptManager`` backend.
Nothing about the execution path is stubbed: the ``python`` type runs a genuine
subprocess, the four bridge types construct their real bridges, and the live
class drives a real rizin/radare2 backend over a real PE file and asserts on
values only the real engine can produce.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtWidgets import QMessageBox

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.core.script_gen import ScriptManager
from intellicrack.ui.panels.async_bridge import drain_bridge_workers, run_bridge_coroutine
from intellicrack.ui.panels.script_manager import (
    _EXECUTION_TIMEOUT_MS,
    _STATUS_RESET_MS,
    ScriptManagerPanel,
)
from intellicrack.ui.tools import _EMPTY_SCRIPT_RESULT, ToolOutputPanel


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


# Every script type the Scripts panel offers, in ``ScriptTypeInfo`` id form.
_ALL_SCRIPT_TYPES: Final[tuple[str, ...]] = ("python", "frida", "ghidra", "cutter", "x64dbg")

# Substring that must appear in the surfaced result for each bridge-backed
# type, proving the type's own branch of ``_execute_script`` ran rather than
# the fallthrough or some other type's branch.
_BRIDGE_LABELS: Final[dict[str, str]] = {
    "frida": "frida",
    "ghidra": "ghidra",
    "cutter": "cutter",
    "x64dbg": "x64dbg",
}

_PYTHON_SCRIPT: Final[str] = 'print("AUDIT_PY_OUTPUT:", 6 * 7)'
_PYTHON_MARKER: Final[str] = "AUDIT_PY_OUTPUT: 42"

# A script body per bridge type. Content is irrelevant to the unconnected-tool
# gates (the bridge refuses before parsing it) but must be non-empty so the
# panel does not short-circuit on its "empty script" guard.
_BRIDGE_SCRIPT: Final[str] = "// intellicrack audit probe\n"

# Wall-clock ceiling for one Execute round trip. The panel arms a
# ``_EXECUTION_TIMEOUT_MS`` watchdog, so anything approaching that value is the
# hang this gate exists to detect; half of it is a generous bound for a
# refusal that should take milliseconds.
_EXECUTE_DEADLINE_S: Final[float] = _EXECUTION_TIMEOUT_MS / 1000.0 / 2.0

# Ceiling for the blocking bridge setup calls made on the shared bridge loop.
_SETUP_TIMEOUT_S: Final[float] = 180.0

_EVENT_PUMP_INTERVAL_S: Final[float] = 0.01

# Margin added to the panel's own status-reset delay when settling its pending
# single-shot timers before teardown.
_STATUS_RESET_MARGIN_S: Final[float] = 0.5


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


class ExecuteOutcome:
    """Everything observable about one Execute press on the Scripts panel."""

    def __init__(
        self,
        *,
        result: str,
        status: str,
        busy: bool,
        button_enabled: bool,
        elapsed_s: float,
        signal_emissions: list[tuple[str, str, str]],
    ) -> None:
        """Record one Execute outcome.

        Args:
            result: Text left in the panel's result pane.
            status: Text left on the panel's status bar.
            busy: Whether the panel was still in its executing state.
            button_enabled: Whether the Execute button was re-enabled.
            elapsed_s: Wall-clock seconds the press took to settle.
            signal_emissions: ``script_execute`` emissions observed, which must
                stay empty whenever the injected executor is used.
        """
        self.result = result
        self.status = status
        self.busy = busy
        self.button_enabled = button_enabled
        self.elapsed_s = elapsed_s
        self.signal_emissions = signal_emissions


def _press_execute(
    qapp: QApplication,
    script_panel: ScriptManagerPanel,
    *,
    script_type: str,
    name: str,
    content: str,
    deadline_s: float = _EXECUTE_DEADLINE_S,
) -> ExecuteOutcome:
    """Drive the Scripts panel's Execute button once and collect the outcome.

    Selects ``script_type`` in the real type combo, fills in the real name
    edit and editor, records every ``script_execute`` signal emission, invokes
    the panel's own Execute handler and then pumps the Qt event loop until the
    panel leaves its executing state or ``deadline_s`` elapses.

    Args:
        qapp: Live ``QApplication`` used to pump events.
        script_panel: The real ``ScriptManagerPanel`` under test.
        script_type: ``ScriptTypeInfo`` id to select in the type combo.
        name: Script name to type into the name edit.
        content: Script source to load into the editor.
        deadline_s: Maximum wall-clock seconds to wait for the panel to settle.

    Returns:
        ExecuteOutcome: Observed result pane, status bar, busy state, button
            state, elapsed time and ``script_execute`` emissions.
    """
    emissions: list[tuple[str, str, str]] = []
    connection = script_panel.script_execute.connect(
        lambda emitted_name, emitted_type, emitted_content: emissions.append(
            (emitted_name, emitted_type, emitted_content),
        ),
    )

    try:
        index = script_panel._type_combo.findData(script_type)
        assert index >= 0, f"{script_type}: not present in the Scripts panel type combo"
        script_panel._type_combo.setCurrentIndex(index)
        script_panel._name_edit.setText(name)
        script_panel._editor.set_content(content)
        script_panel._result_pane.setPlainText("")

        started = time.monotonic()
        script_panel._on_execute()
        qapp.processEvents()
        while script_panel._execution_in_progress and time.monotonic() - started < deadline_s:
            qapp.processEvents()
            time.sleep(_EVENT_PUMP_INTERVAL_S)
        elapsed = time.monotonic() - started
        qapp.processEvents()

        return ExecuteOutcome(
            result=script_panel._result_pane.toPlainText(),
            status=script_panel._status_bar.currentMessage(),
            busy=script_panel._execution_in_progress,
            button_enabled=script_panel._execute_btn.isEnabled(),
            elapsed_s=elapsed,
            signal_emissions=emissions,
        )
    finally:
        _ = script_panel.script_execute.disconnect(connection)


@pytest.fixture
def wired_panels(qapp: QApplication, tmp_path: Path) -> Iterator[tuple[ToolOutputPanel, ScriptManagerPanel]]:
    """Build a real ``ToolOutputPanel`` with its Scripts tab wired to a real backend.

    Uses the deferred wiring route (``wire_script_backend`` before
    ``add_script_panel``), which is the route the application takes when the
    Scripts tab is materialised after the backend is wired.

    Args:
        qapp: Session ``QApplication`` fixture required for widget construction.
        tmp_path: Pytest temporary directory backing the script manager storage.

    Yields:
        tuple[ToolOutputPanel, ScriptManagerPanel]: The tool panel and its
            Scripts panel, both real widgets.
    """
    panel = ToolOutputPanel()
    try:
        panel.wire_script_backend(ScriptManager(scripts_dir=tmp_path / "scripts"))
        script_panel = panel.add_script_panel()
        assert isinstance(script_panel, ScriptManagerPanel)
        yield panel, script_panel
    finally:
        _ = drain_bridge_workers()
        _settle_pending_status_timers(qapp)
        panel.deleteLater()
        qapp.processEvents()


class TestExecuteReachesTheExecutorForEveryScriptType:
    """Execute must dispatch through the injected executor for all five types."""

    @pytest.mark.parametrize("script_type", _ALL_SCRIPT_TYPES)
    def test_execute_uses_the_executor_and_never_the_unconnected_signal(
        self,
        qapp: QApplication,
        wired_panels: tuple[ToolOutputPanel, ScriptManagerPanel],
        script_type: str,
    ) -> None:
        """Pressing Execute must run the executor and leave a surfaced result, for every type.

        The ``script_execute`` signal is the fallback the panel emits only when
        no executor is injected; no production owner connects it, so an
        emission means the press went nowhere. This asserts the emission never
        happens, that the panel leaves its executing state well inside its own
        watchdog window, and that the pane carries a type-specific result.

        Args:
            qapp: Session ``QApplication`` fixture used to pump events.
            wired_panels: Real tool panel and its wired Scripts panel.
            script_type: Script type under test.
        """
        _, script_panel = wired_panels
        content = _PYTHON_SCRIPT if script_type == "python" else _BRIDGE_SCRIPT

        outcome = _press_execute(
            qapp,
            script_panel,
            script_type=script_type,
            name=f"Audit_{script_type}",
            content=content,
        )

        assert not outcome.signal_emissions, (
            f"{script_type}: Execute fell back to the unconnected script_execute signal "
            f"instead of the injected executor: {outcome.signal_emissions}"
        )
        assert not outcome.busy, f"{script_type}: panel never left the executing state within {_EXECUTE_DEADLINE_S:.0f}s"
        assert outcome.button_enabled, f"{script_type}: Execute button was left disabled"
        assert outcome.elapsed_s < _EXECUTE_DEADLINE_S, f"{script_type}: Execute took {outcome.elapsed_s:.1f}s"
        assert "[timeout]" not in outcome.result, f"{script_type}: Execute hit the panel's timeout path"
        assert outcome.status.startswith("Executed:"), f"{script_type}: unexpected status {outcome.status!r}"

        if script_type == "python":
            assert _PYTHON_MARKER in outcome.result, f"python: real subprocess stdout missing from the result pane: {outcome.result!r}"
        else:
            assert _BRIDGE_LABELS[script_type] in outcome.result.lower(), (
                f"{script_type}: result pane does not name the dispatched bridge: {outcome.result!r}"
            )

    @pytest.mark.parametrize("script_type", sorted(_BRIDGE_LABELS))
    def test_an_unconnected_tool_is_reported_not_silently_swallowed(
        self,
        qapp: QApplication,
        wired_panels: tuple[ToolOutputPanel, ScriptManagerPanel],
        script_type: str,
    ) -> None:
        """A bridge that is not connected must surface a diagnostic, never a blank pane.

        No external debugger, decompiler or instrumentation host is attached in
        this process, so each bridge type must refuse. The refusal has to reach
        the user: a non-empty result naming the tool and describing a failure.
        A blank pane, the no-output marker, or a bare success would all be the
        silent-nothing failure mode this gate exists to catch.

        Args:
            qapp: Session ``QApplication`` fixture used to pump events.
            wired_panels: Real tool panel and its wired Scripts panel.
            script_type: Bridge-backed script type under test.
        """
        _, script_panel = wired_panels

        outcome = _press_execute(
            qapp,
            script_panel,
            script_type=script_type,
            name=f"Audit_{script_type}",
            content=_BRIDGE_SCRIPT,
        )

        assert outcome.result.strip(), f"{script_type}: Execute left the result pane blank"
        assert outcome.result.strip() != _EMPTY_SCRIPT_RESULT, f"{script_type}: an unconnected tool reported no-output instead of a failure"
        assert _BRIDGE_LABELS[script_type] in outcome.result.lower(), (
            f"{script_type}: diagnostic does not name the tool: {outcome.result!r}"
        )
        lowered = outcome.result.lower()
        assert any(token in lowered for token in ("error", "not available", "not connected", "not running")), (
            f"{script_type}: result reads as a success even though the tool is not connected: {outcome.result!r}"
        )


@pytest.mark.spawns_process
class TestExecuteAgainstARealRizinBackend:
    """Execute against a genuinely connected tool must surface the tool's own output."""

    @staticmethod
    def _loaded_cutter_bridge(binary: Path) -> CutterBridge:
        """Build a bridge with a real rizin/radare2 backend holding ``binary``.

        The bridge is initialised and loaded on the shared bridge event loop --
        the same loop the panel's Execute dispatch uses -- so the asyncio
        primitives inside the bridge are never touched from two loops.

        Args:
            binary: Real on-disk binary to load into the backend.

        Returns:
            CutterBridge: Bridge with the binary loaded.
        """
        bridge = CutterBridge()
        run_bridge_coroutine(bridge.initialize(), timeout_s=_SETUP_TIMEOUT_S)
        if not run_bridge_coroutine(bridge.is_available(), timeout_s=_SETUP_TIMEOUT_S):
            pytest.skip("rizin/radare2 backend not discoverable on PATH")
        _ = run_bridge_coroutine(bridge.load_binary(binary), timeout_s=_SETUP_TIMEOUT_S)
        return bridge

    def test_execute_surfaces_real_backend_output(
        self,
        qapp: QApplication,
        wired_panels: tuple[ToolOutputPanel, ScriptManagerPanel],
        real_pe_dll: Path,
    ) -> None:
        """A cutter script must run on the real backend and show its real answer.

        ``i~format`` asks rizin for the loaded file's container format; for a
        64-bit Windows system DLL the engine answers ``pe64``. That value comes
        from the real parser, so the assertion cannot pass without the whole
        Execute path -- panel, executor, bridge, external process -- working.

        Args:
            qapp: Session ``QApplication`` fixture used to pump events.
            wired_panels: Real tool panel and its wired Scripts panel.
            real_pe_dll: Session fixture resolving a real System32 PE DLL.
        """
        panel, script_panel = wired_panels
        panel.cutter_bridge = self._loaded_cutter_bridge(real_pe_dll)

        outcome = _press_execute(
            qapp,
            script_panel,
            script_type="cutter",
            name="Audit_cutter_live",
            content="i~format",
        )

        assert not outcome.busy, "live cutter Execute never settled"
        assert "pe64" in outcome.result.lower(), f"real rizin output missing from the result pane: {outcome.result!r}"

    def test_a_command_with_no_output_reports_no_output_rather_than_a_blank_pane(
        self,
        qapp: QApplication,
        wired_panels: tuple[ToolOutputPanel, ScriptManagerPanel],
        real_pe_dll: Path,
    ) -> None:
        """A successful backend command that prints nothing must not blank the result pane.

        ``s 0x1000`` is a real, successful rizin seek that returns an empty
        string. Forwarding that verbatim replaces the "Executing ..." line with
        an empty pane, which is indistinguishable from Execute having done
        nothing; the asynchronous bridge path must mark it the same way the
        synchronous python path does.

        Args:
            qapp: Session ``QApplication`` fixture used to pump events.
            wired_panels: Real tool panel and its wired Scripts panel.
            real_pe_dll: Session fixture resolving a real System32 PE DLL.
        """
        panel, script_panel = wired_panels
        bridge = self._loaded_cutter_bridge(real_pe_dll)
        panel.cutter_bridge = bridge

        raw = run_bridge_coroutine(bridge.execute_command("s 0x1000"), timeout_s=_SETUP_TIMEOUT_S)
        assert not raw, f"precondition: the seek must produce no backend output, got {raw!r}"

        outcome = _press_execute(
            qapp,
            script_panel,
            script_type="cutter",
            name="Audit_cutter_silent",
            content="s 0x1000",
        )

        assert not outcome.busy, "live cutter Execute never settled"
        assert outcome.result.strip() == _EMPTY_SCRIPT_RESULT, (
            f"a silent-but-successful backend command left {outcome.result!r} in the result pane"
        )
