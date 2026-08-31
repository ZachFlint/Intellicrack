# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S18-D14: "Enable networking in sandbox" has to reach the virtual machine.

The dialog ships the box **unchecked** and warns that ticking it "allows sandbox to access
external resources", the bridge builds that answer into ``SandboxConfig.network_enabled``,
and the QEMU backend then never mentioned the field: ``_build_qemu_command`` emitted one
fully routed ``-netdev user`` plus ``virtio-net-pci`` for every run. Measured on a real
Windows guest booted with networking configured off, the guest fetched
``msftconnecttest.com`` over HTTP, resolved ``v10.events.data.microsoft.com`` and completed
a TCP connection to it on 443, and reached ``8.8.8.8:53``.

The fix is ``restrict=on`` rather than dropping the NIC, and that distinction is what this
gate is really protecting: both control channels reach the guest over ``hostfwd`` rules on
that same netdev, so a fix that isolated the guest by removing its network would take the
guest agent with it and no sandbox would ever start. Every assertion below is made on the
argv the production builder emits, and the hostfwd clauses are asserted in the restricted
case too.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import AcceleratorType, GuestOS, QEMUConfig, QEMUSandbox


if TYPE_CHECKING:
    from pathlib import Path


_NETDEV_FLAG: Final[str] = "-netdev"
_RESTRICT_CLAUSE: Final[str] = "restrict=on"
_AGENT_FORWARD_SUFFIX: Final[str] = "-:4445"
_SSH_FORWARD_SUFFIX: Final[str] = "-:22"
_NIC_DEVICE: Final[str] = "virtio-net-pci,netdev=net0"


class _NetworkSandbox(QEMUSandbox):
    """``QEMUSandbox`` given only what a live virtual machine would provide.

    The working directory, the share and the accelerator are arranged here; the
    argv builder under test is the production one.
    """

    def use_workspace(self, temp_dir: Path) -> None:
        """Point the sandbox at a working directory and its shared folder.

        Args:
            temp_dir: Directory standing in for the sandbox's own temp dir.
        """
        self._temp_dir = temp_dir
        self._shared_folder = temp_dir / "shared"
        (self._shared_folder / "monitor").mkdir(parents=True, exist_ok=True)

    def force_accelerator(self, accelerator: AcceleratorType) -> None:
        """Record an accelerator without probing this host's hardware.

        Args:
            accelerator: Accelerator the command builder should select for.
        """
        self._accelerator = accelerator
        self._accelerator_cached = True

    def set_qemu_path(self, qemu_path: Path) -> None:
        """Install the QEMU binary path the command builder reports.

        Args:
            qemu_path: Path recorded as the resolved QEMU executable.
        """
        self._qemu_path = qemu_path

    def build_command(self) -> list[str]:
        """Build the QEMU launch command line through the real builder.

        Returns:
            list[str]: The argv the launcher would start QEMU with.
        """
        return asyncio.run(self._build_qemu_command())


def _netdev_value(argv: list[str]) -> str:
    """Return the ``-netdev`` argument the builder emitted.

    Args:
        argv: The QEMU command line under test.

    Returns:
        str: The value that followed ``-netdev``.
    """
    assert _NETDEV_FLAG in argv, f"the builder emitted no {_NETDEV_FLAG} at all: {argv}"
    return argv[argv.index(_NETDEV_FLAG) + 1]


def _build(tmp_path: Path, config: SandboxConfig) -> list[str]:
    """Build a launch command line for a Windows guest under ``config``.

    Args:
        tmp_path: Directory used as the sandbox working directory.
        config: The generic sandbox configuration under test.

    Returns:
        list[str]: The argv the launcher would start QEMU with.
    """
    image = tmp_path / "guest.qcow2"
    image.write_bytes(b"QFI\xfb")
    sandbox = _NetworkSandbox(
        config=config,
        qemu_config=QEMUConfig(
            guest_os=GuestOS.WINDOWS,
            image_path=image,
            display="none",
        ),
    )
    sandbox.use_workspace(tmp_path)
    sandbox.force_accelerator(AcceleratorType.TCG)
    sandbox.set_qemu_path(tmp_path / "qemu-system-x86_64.exe")
    return sandbox.build_command()


class TestNetworkingOffIsolatesTheGuest:
    """``network_enabled=False`` has to reach the netdev QEMU is launched with."""

    def test_networking_off_restricts_the_user_network(self, tmp_path: Path) -> None:
        """A sandbox configured without networking gets a restricted netdev."""
        netdev = _netdev_value(_build(tmp_path, SandboxConfig(network_enabled=False)))
        assert _RESTRICT_CLAUSE in netdev, f"networking was configured off and the guest still got a routed network: {netdev}"

    def test_the_shipped_default_is_restricted(self, tmp_path: Path) -> None:
        """An unconfigured sandbox is isolated, because the dialog ships the box unchecked."""
        assert SandboxConfig().network_enabled is False, "this gate assumes the shipped default is networking off; it is not"
        netdev = _netdev_value(_build(tmp_path, SandboxConfig()))
        assert _RESTRICT_CLAUSE in netdev, f"the default sandbox is not isolated: {netdev}"

    def test_networking_on_leaves_the_guest_routed(self, tmp_path: Path) -> None:
        """A sandbox configured with networking keeps a fully routed netdev."""
        netdev = _netdev_value(_build(tmp_path, SandboxConfig(network_enabled=True)))
        assert _RESTRICT_CLAUSE not in netdev, f"networking was configured on and the guest was isolated anyway: {netdev}"


class TestIsolationNeverCostsTheControlChannel:
    """Restricting the guest must not take the guest-agent channel with it."""

    @pytest.mark.parametrize("network_enabled", [False, True])
    def test_both_host_forwards_survive(self, tmp_path: Path, *, network_enabled: bool) -> None:
        """The agent and ssh forwards are on the netdev whichever way it is configured.

        Args:
            tmp_path: Directory used as the sandbox working directory.
            network_enabled: Whether the sandbox is configured with networking.
        """
        argv = _build(tmp_path, SandboxConfig(network_enabled=network_enabled))
        netdev = _netdev_value(argv)
        assert _AGENT_FORWARD_SUFFIX in netdev, f"the guest-agent forward is gone, so no sandbox could start: {netdev}"
        assert _SSH_FORWARD_SUFFIX in netdev, f"the ssh forward is gone: {netdev}"
        assert _NIC_DEVICE in argv, f"the NIC itself was removed, which the forwards above depend on: {argv}"
