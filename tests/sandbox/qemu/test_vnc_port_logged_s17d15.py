# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D15: ``enable_vnc_display`` must log the port it assigned.

``enable_vnc_display`` emitted ``vnc_display_enabled`` with ``vnc_port`` read
before any port was assigned, so the structured record always carried ``None``
and told nobody which display QEMU would be reachable on. ``vnc_port`` itself
stayed ``None`` until the launch command was built, so a caller that switched a
sandbox to VNC could not learn the port before the guest booted.

The tests capture the real structured record emitted by a real call and assert
the logged value equals the port that is actually reserved and actually handed
to QEMU on the command line. Logging an unassigned attribute fails them.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Final

import structlog.testing

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import AcceleratorType, GuestOS, QEMUConfig, QEMUSandbox


if TYPE_CHECKING:
    from pathlib import Path

    from structlog.typing import EventDict


_VNC_PORT_BASE: Final[int] = 5900
_VNC_PORT_MAX: Final[int] = 5999
_VNC_ENABLED_EVENT: Final[str] = "vnc_display_enabled"


class _CommandBuildingSandbox(QEMUSandbox):
    """QEMU sandbox exposing the real launch-command builder to tests."""

    def prepare(self, qemu_path: Path) -> None:
        """Install a resolved QEMU binary path and accelerator for building.

        Args:
            qemu_path: Path recorded as the resolved QEMU executable.
        """
        self._qemu_path = qemu_path
        self._accelerator = AcceleratorType.TCG
        self._accelerator_cached = True

    def build_command(self) -> list[str]:
        """Build the real QEMU launch argv for the current configuration.

        Returns:
            list[str]: The argv the backend would launch QEMU with.
        """
        return asyncio.run(self._build_qemu_command())


def _make_disk_image(tmp_path: Path) -> Path:
    """Create a real, minimal qcow2 file so the command builder accepts it.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        Path: Path to the created qcow2 image file.
    """
    image = tmp_path / "guest.qcow2"
    image.write_bytes(b"QFI\xfb" + (3).to_bytes(4, "big") + bytes(64))
    return image


def _vnc_enabled_record(captured: list[EventDict]) -> EventDict:
    """Return the single ``vnc_display_enabled`` record from a capture.

    Args:
        captured: Records collected by :func:`structlog.testing.capture_logs`.

    Returns:
        EventDict: The one matching structured log record.
    """
    matches = [record for record in captured if record.get("event") == _VNC_ENABLED_EVENT]
    assert len(matches) == 1, f"expected exactly one {_VNC_ENABLED_EVENT} record, got {matches}"
    return matches[0]


class TestEnableVncDisplayLogsTheAssignedPort:
    """The structured record must name the port the sandbox reserved."""

    def test_logged_vnc_port_is_a_real_port_number(self) -> None:
        """The record carries an int in the VNC range, not an unassigned None.

        This is the S17-D15 gate: logging before assignment yields ``None``.
        """
        sandbox = QEMUSandbox(SandboxConfig(), QEMUConfig())

        with structlog.testing.capture_logs() as captured:
            sandbox.enable_vnc_display()

        logged_port = _vnc_enabled_record(captured)["vnc_port"]

        assert isinstance(logged_port, int), f"vnc_port was not assigned before logging: {logged_port!r}"
        assert _VNC_PORT_BASE <= logged_port <= _VNC_PORT_MAX

    def test_logged_vnc_port_matches_the_exposed_property(self) -> None:
        """The logged value is the very port the sandbox now reports."""
        sandbox = QEMUSandbox(SandboxConfig(), QEMUConfig())

        with structlog.testing.capture_logs() as captured:
            sandbox.enable_vnc_display()

        logged_port = _vnc_enabled_record(captured)["vnc_port"]

        assert sandbox.vnc_port is not None, "enabling VNC left no port on the sandbox"
        assert logged_port == sandbox.vnc_port

    def test_switching_to_vnc_still_rewrites_the_display_mode(self) -> None:
        """Reserving the port must not disturb the configuration rewrite."""
        sandbox = QEMUSandbox(SandboxConfig(), QEMUConfig(guest_os=GuestOS.LINUX, cpu_cores=3))

        sandbox.enable_vnc_display()

        assert sandbox.qemu_config.display == "vnc"
        assert sandbox.qemu_config.guest_os is GuestOS.LINUX
        assert sandbox.qemu_config.cpu_cores == 3


class TestReservedPortReachesQemu:
    """The reported port must be the display QEMU is actually launched on."""

    def test_launch_argv_uses_the_logged_display_number(self, tmp_path: Path) -> None:
        """``-vnc`` names the display derived from the reserved port.

        Args:
            tmp_path: Per-test temporary directory.
        """
        qemu_path = tmp_path / "qemu-system-x86_64.exe"
        qemu_path.write_bytes(b"MZ")
        sandbox = _CommandBuildingSandbox(
            SandboxConfig(),
            QEMUConfig(guest_os=GuestOS.LINUX, image_path=_make_disk_image(tmp_path)),
        )
        sandbox.prepare(qemu_path)

        with structlog.testing.capture_logs() as captured:
            sandbox.enable_vnc_display()
        logged_port = _vnc_enabled_record(captured)["vnc_port"]

        cmd = sandbox.build_command()

        assert cmd[cmd.index("-vnc") + 1] == f":{logged_port - _VNC_PORT_BASE}"
        assert sandbox.vnc_port == logged_port, "the launch overwrote the port that was reported to the caller"
