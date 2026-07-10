# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""FIX UNIT 14a real-data coverage for ``process_panel.base``.

Audit shard 14 flagged the existing ProcessPanel base tests (F-0001/F-0002)
for verifying the architecture and privilege status labels only against a
scripted ``_RecordingBridge`` that returns fake results. These tests instead
wire a real :class:`ProcessBridge` to the panel and attach it to the running
interpreter, so the status bar updates from genuine ``detect_architecture``
and ``get_token_privileges`` Win32 queries. Assertions check real, verifiable
values: the architecture label must reflect the real architecture of this
process and the privilege label must reflect the real debug-privilege state of
this process's access token.
"""

from __future__ import annotations

import os
import struct
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.panels.process_panel.base import ProcessPanel
from tests._helpers.realcov_process_panel import (
    close_real_bridge,
    make_real_bridge_attached_to_self,
    pump_until,
    require_windows,
    run_bridge_sync,
)


if TYPE_CHECKING:
    from collections.abc import Iterator

    from intellicrack.bridges.process import ProcessBridge

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture
def qapp() -> Iterator[QApplication]:
    """Provide a live QApplication for widget construction.

    Yields:
        QApplication: The running application instance.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


@pytest.fixture
def real_bridge() -> Iterator[ProcessBridge]:
    """Provide a real ProcessBridge attached to the current process.

    Yields:
        ProcessBridge: Bridge initialized and attached to this process.
    """
    require_windows()
    bridge = make_real_bridge_attached_to_self()
    try:
        yield bridge
    finally:
        close_real_bridge(bridge)


class _ProcessPanelProbe(ProcessPanel):
    """Test subclass exposing typed accessors to protected panel members."""

    def attach(self, pid: int) -> None:
        """Drive the real attach state transition for ``pid``.

        Args:
            pid: PID to attach to.
        """
        self._on_process_attached(pid)

    def detach(self) -> None:
        """Drive the detach state transition."""
        self._on_process_detached()

    def arch_text(self) -> str:
        """Return the architecture status-label text.

        Returns:
            str: Current arch label such as ``"Arch: x86_64"``.
        """
        return self._status_arch.text()

    def priv_text(self) -> str:
        """Return the privilege status-label text.

        Returns:
            str: Current privilege label such as ``"Privilege: Standard"``.
        """
        return self._status_priv.text()

    def pid_text(self) -> str:
        """Return the PID status-label text.

        Returns:
            str: Current PID label such as ``"PID: 1234"``.
        """
        return self._status_pid.text()

    def state_text(self) -> str:
        """Return the attachment-state status-label text.

        Returns:
            str: Current state label such as ``"Attached"``.
        """
        return self._status_state.text()


@pytest.fixture
def panel(qapp: QApplication, real_bridge: ProcessBridge) -> Iterator[_ProcessPanelProbe]:
    """Create a ProcessPanel probe wired to the real bridge.

    Args:
        qapp: QApplication fixture (ensures Qt initialised).
        real_bridge: Real ProcessBridge attached to this process.

    Yields:
        _ProcessPanelProbe: A panel driving the real bridge against this process.
    """
    del qapp
    widget = _ProcessPanelProbe()
    widget.set_bridge(real_bridge)
    yield widget
    widget.deleteLater()


def _expected_self_arch() -> str:
    """Return the architecture string this interpreter must report.

    The pointer width of the running interpreter distinguishes a 32-bit from a
    64-bit Python process; the real ``detect_architecture`` cascade must agree.

    Returns:
        str: ``"x86_64"`` on a 64-bit interpreter, otherwise ``"x86"``.
    """
    return "x86_64" if struct.calcsize("P") == 8 else "x86"


def test_arch_label_reflects_real_process_architecture(qapp: QApplication, panel: _ProcessPanelProbe) -> None:
    """The arch status label must show this process's real architecture.

    Args:
        qapp: Qt application driving the event loop.
        panel: ProcessPanel probe bound to the real bridge.
    """
    panel.attach(os.getpid())

    updated = pump_until(qapp, lambda: panel.arch_text() not in {"Arch: --", "Arch: Unknown"})
    assert updated, f"arch label never updated from real detection; got {panel.arch_text()!r}"
    assert panel.arch_text() == f"Arch: {_expected_self_arch()}"


def test_privilege_label_reflects_real_token(
    qapp: QApplication,
    real_bridge: ProcessBridge,
    panel: _ProcessPanelProbe,
) -> None:
    """The privilege label must match the real debug-privilege state.

    Reads the genuine token privileges and computes whether
    ``SeDebugPrivilege`` is present and enabled, then drives the panel and
    asserts the rendered label matches the real token state exactly.

    Args:
        qapp: Qt application driving the event loop.
        real_bridge: Real bridge attached to this process.
        panel: ProcessPanel probe bound to the real bridge.
    """
    real_privs = run_bridge_sync(real_bridge.get_token_privileges(os.getpid()))
    has_debug = any(str(p.get("name", "")) == "SeDebugPrivilege" and bool(p.get("enabled", False)) for p in real_privs)
    expected = "Privilege: Debug" if has_debug else "Privilege: Standard"

    panel.attach(os.getpid())

    updated = pump_until(qapp, lambda: panel.priv_text() == expected)
    assert updated, f"privilege label {panel.priv_text()!r} did not match real token state {expected!r}"


def test_status_pid_and_state_reflect_real_attach(qapp: QApplication, panel: _ProcessPanelProbe) -> None:
    """Attaching the real PID must surface that PID and the attached state.

    Args:
        qapp: Qt application driving the event loop.
        panel: ProcessPanel probe bound to the real bridge.
    """
    del qapp
    real_pid = os.getpid()
    panel.attach(real_pid)

    assert panel.pid_text() == f"PID: {real_pid}"
    assert panel.state_text() == "Attached"


def test_detach_resets_labels_after_real_attach(qapp: QApplication, panel: _ProcessPanelProbe) -> None:
    """After a real attach, detaching must reset the status labels.

    Args:
        qapp: Qt application driving the event loop.
        panel: ProcessPanel probe bound to the real bridge.
    """
    panel.attach(os.getpid())
    _ = pump_until(qapp, lambda: panel.arch_text() != "Arch: --")

    panel.detach()
    assert panel.pid_text() == "PID: --"
    assert panel.arch_text() == "Arch: --"
    assert panel.priv_text() == "Privilege: Standard"
    assert panel.state_text() == "Detached"
