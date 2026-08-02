# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D10: sandbox controls must be gated by backend capability.

``_set_sandbox_controls_active`` used to enable every control whenever an
instance was active, regardless of which backend was selected. On the Windows
backend that made Snapshots, VM Control (Pause/Continue), Pending Messages,
Screenshot, PCAP capture, Extract Dropped Files, Apply Anti-Evasion and the VM
Display live but broken: ``WindowsSandbox`` inherits the ``SandboxBase``
snapshot/guest-agent implementations that raise "not supported", has no QMP
pause/continue, and inherits ``vnc_port = None``, while ``SandboxBridge``
rejects the remaining operations outright for any instance whose
``sandbox_type`` is not ``"qemu"``.

The capability claims asserted here are checked against the real backend
classes as well, so the gate stays honest if a future backend gains one of the
operations. The bridge-level half of that anchor - proving the rejection the
gating exists to avoid - lives in
``tests/bridges/test_sandbox_bridge_qemu_only_ops_s17d10.py``.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import QEMUSandbox
from intellicrack.sandbox.windows import WindowsSandbox
from intellicrack.ui.panels.sandbox_panel import SandboxPanel


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

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


def _enabled(panel: SandboxPanel, name: str) -> bool:
    """Read the enabled state of a named panel control.

    Args:
        panel: Panel under test.
        name: Attribute name of the control.

    Returns:
        bool: True when the control is enabled.
    """
    control = getattr(panel, name)
    return bool(control.isEnabled())


@pytest.mark.usefixtures("qapp")
def test_windows_backend_disables_qemu_only_controls() -> None:
    """Activating a Windows sandbox must leave the QEMU-only controls disabled."""
    panel = SandboxPanel()
    panel.sandbox_type_combo.setCurrentText("Windows Sandbox")

    panel._set_sandbox_controls_active(active=True)

    still_enabled = [name for name in _QEMU_ONLY_CONTROLS if _enabled(panel, name)]
    assert still_enabled == [], f"controls the Windows backend cannot service are enabled: {still_enabled}"
    assert not panel._output_tabs.isTabEnabled(panel._vnc_tab_index), "the VM Display tab must be disabled for a backend with no VNC port"


@pytest.mark.usefixtures("qapp")
def test_windows_backend_keeps_shared_controls_enabled() -> None:
    """Gating must not disable the controls the Windows backend does implement."""
    panel = SandboxPanel()
    panel.sandbox_type_combo.setCurrentText("Windows Sandbox")

    panel._set_sandbox_controls_active(active=True)

    disabled = [name for name in _SHARED_CONTROLS if not _enabled(panel, name)]
    assert disabled == [], f"shared controls were wrongly gated out: {disabled}"


@pytest.mark.usefixtures("qapp")
def test_qemu_backend_enables_qemu_only_controls() -> None:
    """Selecting QEMU before activation must enable every QEMU-only control."""
    panel = SandboxPanel()
    panel.sandbox_type_combo.setCurrentText("QEMU")

    panel._set_sandbox_controls_active(active=True)

    disabled = [name for name in _QEMU_ONLY_CONTROLS if not _enabled(panel, name)]
    assert disabled == [], f"QEMU-capable controls stayed disabled: {disabled}"
    assert panel._output_tabs.isTabEnabled(panel._vnc_tab_index)


@pytest.mark.usefixtures("qapp")
def test_switching_type_while_inactive_reapplies_the_gating() -> None:
    """Changing the combo while inactive must re-evaluate the gating on the next activation."""
    panel = SandboxPanel()
    panel.sandbox_type_combo.setCurrentText("Windows Sandbox")
    panel._set_sandbox_controls_active(active=True)
    assert not panel.snapshot_btn.isEnabled(), "test premise: Windows starts gated out"

    panel._set_sandbox_controls_active(active=False)
    panel.sandbox_type_combo.setCurrentText("QEMU")
    panel._set_sandbox_controls_active(active=True)

    disabled = [name for name in _QEMU_ONLY_CONTROLS if not _enabled(panel, name)]
    assert disabled == [], f"switching to QEMU while inactive did not re-enable: {disabled}"


@pytest.mark.usefixtures("qapp")
def test_type_change_signal_regates_live_controls() -> None:
    """The combo's own change signal must re-gate controls without another activation call."""
    panel = SandboxPanel()
    panel.sandbox_type_combo.setCurrentText("QEMU")
    panel._set_sandbox_controls_active(active=True)
    assert panel.pause_btn.isEnabled(), "test premise: QEMU enables VM control"

    panel.sandbox_type_combo.setCurrentText("Windows Sandbox")

    assert not panel.pause_btn.isEnabled(), "selecting the Windows backend must re-gate the QEMU-only VM controls immediately"
    assert not panel._output_tabs.isTabEnabled(panel._vnc_tab_index)


@pytest.mark.usefixtures("qapp")
def test_deactivation_disables_everything_on_qemu() -> None:
    """Deactivating must disable the QEMU-only controls even while QEMU is selected."""
    panel = SandboxPanel()
    panel.sandbox_type_combo.setCurrentText("QEMU")
    panel._set_sandbox_controls_active(active=True)

    panel._set_sandbox_controls_active(active=False)

    still_enabled = [name for name in _QEMU_ONLY_CONTROLS if _enabled(panel, name)]
    assert still_enabled == [], f"controls stayed live with no sandbox: {still_enabled}"
    assert panel.create_btn.isEnabled()


def test_windows_backend_really_rejects_the_gated_operations() -> None:
    """The gating premise must match the real backend classes, not an assumption.

    Drives the genuine ``WindowsSandbox`` snapshot API and reads its real
    ``vnc_port`` property, and contrasts them with ``QEMUSandbox``, so the gate
    is anchored to actual backend capability.
    """
    config = SandboxConfig()
    windows = WindowsSandbox(config)
    qemu = QEMUSandbox(config, None)

    with pytest.raises(SandboxError):
        asyncio.run(windows.take_snapshot("gate-probe"))
    with pytest.raises(SandboxError):
        asyncio.run(windows.list_snapshots())

    assert windows.vnc_port is None, "Windows backend must not advertise a VNC port"
    assert not hasattr(windows, "qmp"), "Windows backend has no QMP channel, so no VM pause/continue"
    assert hasattr(qemu, "qmp"), "QEMU backend must expose the QMP channel the VM controls drive"
    assert hasattr(qemu, "agent"), "QEMU backend must expose the guest-agent channel"
    assert not hasattr(windows, "agent"), "Windows backend has no guest-agent channel"
