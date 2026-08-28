# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the S17-D10 follow-on found by driving the real panel.

S17-D10 gates the QEMU-only controls in ``_apply_backend_capability_gating``,
and ``_set_sandbox_controls_active`` disables every sandbox-active control when
the instance goes away. Both were bypassed afterwards: each operation handler
re-enabled its own control with a bare ``setEnabled(True)`` when its bridge call
completed, and that completion can land *after* the state it was gated against
has changed.

The sequence needs no VM: press Destroy, then press a sandbox operation before
the destroy lands. Driven live on 2026-08-15 through the real bridge that left
``screenshot_btn`` enabled with ``sandbox_id is None`` - a control offered with
no sandbox behind it, where pressing it produced nothing at all, because
``_on_screenshot`` returns at its own ``sandbox_id`` guard.

Which of the two in-flight calls finishes first is decided by the order two
``QThread`` instances happen to reach the shared event loop, so these tests do
not race them. They establish the post-destroy state through a genuine
end-to-end Destroy, take the genuine ``ToolError`` the real bridge raises for
the destroyed instance, and hand it to the same completion slot
``run_bridge_coroutine_logged`` invokes as ``on_error``. Nothing about the
panel state, the error, or the dialog is fabricated.

The two end-to-end tests either side of them keep the gate discriminating: a
failure on a *live* sandbox must still restore its control, and a failure on a
Windows instance must not reinstate the QEMU-only ones.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication, QMessageBox

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.types import ToolError
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.manager import SandboxManager
from intellicrack.ui.panels.sandbox_panel import SandboxPanel
from tests.sandbox.conftest import LocalProcessSandbox


if TYPE_CHECKING:
    from collections.abc import Iterator

    from intellicrack.sandbox.base import SandboxBase
    from intellicrack.sandbox.manager import SandboxType
    from intellicrack.sandbox.qemu import QEMUConfig


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_POLL_INTERVAL_MS: int = 5
_PUMP_SLICE_SECONDS: float = 0.01
_SETTLE_TIMEOUT_SECONDS: float = 30.0

_QEMU_ONLY_CONTROLS: tuple[str, ...] = (
    "snapshot_btn",
    "restore_btn",
    "delete_snap_btn",
    "_refresh_snapshots_btn",
    "continue_btn",
    "pause_btn",
    "_pending_messages_btn",
    "screenshot_btn",
    "pcap_btn",
    "extract_files_btn",
    "_anti_evasion_btn",
)

_SHARED_CONTROLS: tuple[str, ...] = (
    "destroy_btn",
    "restart_btn",
    "_run_btn",
    "_exec_cmd_btn",
    "memdump_btn",
    "copy_in_btn",
    "copy_out_btn",
    "yara_btn",
    "iocs_btn",
    "timeline_btn",
    "behaviors_btn",
    "_detect_c2_btn",
    "_diff_btn",
)

_CREATED_LINE: str = "[+] Sandbox created"
_DESTROYED_LINE: str = "[+] Sandbox destroyed"


class _LocalBackendManager(SandboxManager):
    """Real manager whose backend factory yields real local-process sandboxes."""

    def _build_sandbox(
        self,
        sandbox_type: SandboxType,
        config: SandboxConfig | None = None,
        qemu_config: QEMUConfig | None = None,
    ) -> SandboxBase:
        """Build a real local-process backend for either sandbox type.

        Args:
            sandbox_type: Sandbox type requested by the manager. Unused: the
                same real backend serves both, so the only difference between
                the cases is the type recorded on the instance.
            config: Generic configuration the manager forwarded.
            qemu_config: QEMU configuration the manager forwarded. Unused by
                the local backend.

        Returns:
            SandboxBase: A real ``LocalProcessSandbox``.
        """
        del sandbox_type, qemu_config
        return LocalProcessSandbox(config or SandboxConfig())


class _ModalDismisser:
    """Dismisses the real error dialogs the driven panel opens.

    ``_report_failure`` opens a genuinely blocking ``QMessageBox``. A repeating
    timer closes each one so the production call returns, and records that it
    was there - which is what proves the failure handler under test really ran.

    Attributes:
        titles: Window titles of the dialogs closed, in display order.
    """

    titles: list[str]

    def __init__(self) -> None:
        """Initialise an empty dismisser."""
        self.titles = []

    def tick(self) -> None:
        """Close the active modal message box, if one is open."""
        widget = QApplication.activeModalWidget()
        if isinstance(widget, QMessageBox):
            self.titles.append(widget.windowTitle())
            widget.done(int(QMessageBox.StandardButton.Ok))


@pytest.fixture
def dismisser(qapp: QApplication) -> Iterator[_ModalDismisser]:
    """Run a modal dismisser for the duration of a test.

    Args:
        qapp: Session ``QApplication`` required for real modal creation.

    Yields:
        _ModalDismisser: Recorder of the dialogs it closed.
    """
    recorder = _ModalDismisser()
    timer = QTimer()
    timer.setInterval(_POLL_INTERVAL_MS)
    timer.timeout.connect(recorder.tick)
    timer.start()
    try:
        yield recorder
    finally:
        timer.stop()
        timer.timeout.disconnect(recorder.tick)
        qapp.processEvents()


def _console(panel: SandboxPanel) -> str:
    """Read the panel's console text.

    Args:
        panel: Panel under test.

    Returns:
        str: Everything the panel has logged to its Console tab.
    """
    return panel._console_output.toPlainText()


def _pump_until(app: QApplication, panel: SandboxPanel, marker: str) -> None:
    """Spin the Qt event loop until a console marker appears.

    Args:
        app: Running application whose events must be dispatched.
        panel: Panel whose console is watched.
        marker: Substring that ends the wait.

    Raises:
        AssertionError: If the marker never appears within the timeout.
    """
    deadline = time.monotonic() + _SETTLE_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        app.processEvents()
        if marker in _console(panel):
            app.processEvents()
            return
        time.sleep(_PUMP_SLICE_SECONDS)
    msg = f"{marker!r} never appeared; console holds {_console(panel)!r}"
    raise AssertionError(msg)


def _active_panel(app: QApplication, sandbox_type: str) -> SandboxPanel:
    """Build a panel on a real bridge and drive a real Create through it.

    Args:
        app: Running application whose events must be dispatched.
        sandbox_type: Combo entry to select before pressing Create.

    Returns:
        SandboxPanel: Panel with a live instance of the requested type.
    """
    panel = SandboxPanel()
    bridge = SandboxBridge()
    bridge.attach_manager(_LocalBackendManager())
    panel.set_bridge(bridge)
    panel.sandbox_type_combo.setCurrentText(sandbox_type)
    panel.create_btn.click()
    _pump_until(app, panel, _CREATED_LINE)
    return panel


def _destroy_and_capture_late_error(
    app: QApplication,
    panel: SandboxPanel,
    operation: str,
    instance_id: str,
) -> ToolError:
    """Destroy the sandbox for real, then capture the error a late call raises.

    Args:
        app: Running application whose events must be dispatched.
        panel: Panel whose Destroy button is pressed.
        operation: ``SandboxBridge`` coroutine the in-flight operation would
            have been waiting on.
        instance_id: Instance the operation had addressed.

    Returns:
        ToolError: The real error the bridge raises once the instance is gone.

    Raises:
        AssertionError: If the destroy left the panel active, or the bridge
            accepted the operation against the destroyed instance.
    """
    panel.destroy_btn.click()
    _pump_until(app, panel, _DESTROYED_LINE)
    if panel.sandbox_id is not None or panel._controls_active:
        msg = f"test premise: the destroy must leave the panel inactive; sandbox_id={panel.sandbox_id!r}"
        raise AssertionError(msg)

    bridge = panel.get_bridge()
    if bridge is None:
        msg = "test premise: the panel must still hold its bridge"
        raise AssertionError(msg)

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(getattr(bridge, operation)(instance_id))
    except ToolError as exc:
        return exc
    finally:
        loop.close()
    msg = f"test premise: {operation} accepted a destroyed instance, so no late failure exists"
    raise AssertionError(msg)


def test_qemu_only_control_stays_gated_when_its_failure_lands_after_a_destroy(
    qapp: QApplication,
    dismisser: _ModalDismisser,
) -> None:
    """A screenshot failing after Destroy must not switch its control back on.

    Args:
        qapp: Session ``QApplication``.
        dismisser: Closes the real failure dialog the handler raises.
    """
    panel = _active_panel(qapp, "QEMU")
    instance_id = panel.sandbox_id
    assert instance_id is not None, "test premise: the create produced an instance id"
    assert panel.screenshot_btn.isEnabled(), "test premise: a QEMU instance offers Screenshot"

    late_error = _destroy_and_capture_late_error(qapp, panel, "screenshot", instance_id)
    panel._on_screenshot_error(late_error)
    qapp.processEvents()

    assert dismisser.titles == ["Screenshot Failed"], f"the real failure handler did not run: {dismisser.titles!r}"
    assert instance_id in _console(panel), "the console must carry the real backend error"
    still_enabled = [name for name in _QEMU_ONLY_CONTROLS if getattr(panel, name).isEnabled()]
    assert still_enabled == [], f"controls stayed live after the sandbox was destroyed: {still_enabled}"
    assert panel.create_btn.isEnabled(), "Create must be offered again once the sandbox is gone"


def test_shared_control_stays_disabled_when_its_failure_lands_after_a_destroy(
    qapp: QApplication,
    dismisser: _ModalDismisser,
) -> None:
    """A memory dump failing after Destroy must not switch its control back on.

    Args:
        qapp: Session ``QApplication``.
        dismisser: Closes the real failure dialog the handler raises.
    """
    panel = _active_panel(qapp, "Windows Sandbox")
    instance_id = panel.sandbox_id
    assert instance_id is not None, "test premise: the create produced an instance id"
    assert panel.memdump_btn.isEnabled(), "test premise: a live sandbox offers Memory Dump"

    late_error = _destroy_and_capture_late_error(qapp, panel, "memory_dump", instance_id)
    panel._on_memory_dump_error(late_error)
    qapp.processEvents()

    assert dismisser.titles == ["Memory Dump Failed"], f"the real failure handler did not run: {dismisser.titles!r}"
    still_enabled = [name for name in _SHARED_CONTROLS if getattr(panel, name).isEnabled()]
    assert still_enabled == [], f"controls stayed live after the sandbox was destroyed: {still_enabled}"


def test_a_failure_on_a_live_sandbox_still_restores_its_control(
    qapp: QApplication,
    dismisser: _ModalDismisser,
) -> None:
    """The restore must not become a blanket disable: a live sandbox keeps its controls.

    Args:
        qapp: Session ``QApplication``.
        dismisser: Closes the real failure dialog the handler raises.
    """
    panel = _active_panel(qapp, "QEMU")

    panel.screenshot_btn.trigger()
    _pump_until(qapp, panel, "[-] Screenshot failed")

    assert dismisser.titles == ["Screenshot Failed"], f"the real failure handler did not run: {dismisser.titles!r}"
    assert panel.sandbox_id is not None, "test premise: the sandbox is still live"
    assert panel.screenshot_btn.isEnabled(), "a failed operation on a live QEMU sandbox must leave its control usable"
    assert panel.memdump_btn.isEnabled(), "the failure must not disable the untouched controls"


def test_windows_backend_keeps_the_qemu_controls_gated_after_a_shared_failure(
    qapp: QApplication,
    dismisser: _ModalDismisser,
) -> None:
    """A failure on a Windows instance must not reinstate the QEMU-only controls.

    Memory Dump on Windows Sandbox first enumerates guest processes via
    ``SandboxBridge.list_guest_processes`` so the user can pick a
    ``target_pid`` (S17-D10b). The real ``LocalProcessSandbox`` test double
    behind this panel does not override ``list_processes``, so it inherits
    ``SandboxBase``'s "not implemented" failure - a genuine backend error,
    surfaced through the same ``Memory Dump Failed`` dialog and console path
    the pre-picker code used for a direct ``memory_dump`` failure.

    Args:
        qapp: Session ``QApplication``.
        dismisser: Closes the real failure dialog the handler raises.
    """
    panel = _active_panel(qapp, "Windows Sandbox")
    assert not panel.screenshot_btn.isEnabled(), "test premise: Windows gates Screenshot out"

    panel.memdump_btn.trigger()
    _pump_until(qapp, panel, "[-] Failed to enumerate guest processes")

    assert dismisser.titles == ["Memory Dump Failed"], f"the real failure handler did not run: {dismisser.titles!r}"
    assert panel.memdump_btn.isEnabled(), "the shared control must come back on a live Windows sandbox"
    still_enabled = [name for name in _QEMU_ONLY_CONTROLS if getattr(panel, name).isEnabled()]
    assert still_enabled == [], f"QEMU-only controls became live on a Windows instance: {still_enabled}"
