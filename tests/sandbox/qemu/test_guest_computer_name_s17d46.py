# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gates for S17-D46: the guest must answer to the name it was provisioned with.

The provisioner declares a ``computer_name`` and emits it into the ``specialize``
pass, and the finished guest answered to a Windows-generated name instead.

Measured on the live ``windows11-intellicrack-v4-clean`` guest on 2026-08-09,
which is what rules out every earlier hypothesis. The name is not lost in
transit: ``$env:COMPUTERNAME.Length`` evaluated *inside* the guest returns 7.
It is not a rename waiting for a reboot: ``ComputerName``,
``ActiveComputerName``, ``Tcpip\Parameters\Hostname`` and ``NV Hostname`` all
read ``LAPTOP-``. It is not a pass that never ran: ``unattend.xml`` in the guest
still carries ``<ComputerName>IC-SANDBOX</ComputerName>``, ``setupact.log``
records ``MarkUnattendSettingAsProcessed: [UserData\ComputerName]`` and
``UnattendGC\setupact.log`` records ``[Shell Unattend] ComputerName set to
IC-SANDBOX``.

What Setup then logged is the mechanism::

    [windeploy.exe] OrchestrateDetermineComputerNameChange:
        Did Setup change computer name? TRUE
        Could OOBE change computer name? FALSE
    [windeploy.exe] Reboot required after setup.exe and PostSysprep commands,
                    before launching OOBE.

The declared name is accepted and then does not survive that reboot, and the
name in force afterwards matches none of the four names Setup handled
(``MININT-44HQ1TL``, ``ANALYST-R1TB08F`` - generated from the ``analyst``
account's full name - ``WIN-TUQUTF8JI6U``, and ``IC-SANDBOX``). So the answer
file cannot be the place this is fixed; the finished guest has to assert the
name itself, which is what ``computer_name_enforcement_command`` does.

The live gate runs the production command against a real Windows guest over the
real guest agent and reads the result out of the registry. It asserts its own
precondition first - that the guest does *not* already hold the target name -
so it cannot pass by accident on a guest that was already named correctly.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest
import pytest_asyncio

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig
from scripts.sandbox.provision_windows_guest import (
    UnattendSettings,
    computer_name_enforcement_command,
    first_logon_commands,
)


if TYPE_CHECKING:
    from collections.abc import AsyncIterator


# Deliberately not the provisioner's default: a name the image cannot already
# be holding is what makes the live assertion mean something.
_TARGET_NAME: Final[str] = "IC-D46-GATE"

_GUEST_IMAGE: Final[Path] = Path("D:/Intellicrack/tools/qemu/images/windows11-intellicrack-v4-clean.qcow2")
_PENDING_NAME_KEY: Final[str] = r"HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"
_ACTIVE_NAME_KEY: Final[str] = r"HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName"
_REG_SZ: Final[str] = "REG_SZ"

# The local account is irrelevant to what these gates measure; it only has to
# be a value, and the same one serves for both fields.
_ACCOUNT: Final[str] = "analyst"

_BOOT_BUDGET_S: Final[float] = 900.0
_COMMAND_LIMIT_S: Final[int] = 120
_GUEST_MEMORY_MB: Final[int] = 8192
_GUEST_CORES: Final[int] = 4


def _settings(computer_name: str) -> UnattendSettings:
    """Build answer-file settings that differ only in the declared name.

    Args:
        computer_name: NetBIOS name to declare.

    Returns:
        UnattendSettings: Settings suitable for rendering first-logon commands.
    """
    return UnattendSettings(
        image_name="Windows 11 Pro",
        product_key=None,
        admin_user=_ACCOUNT,
        admin_password=_ACCOUNT,
        computer_name=computer_name,
        locale="en-US",
        timezone="UTC",
        driver_letters=("D", "E"),
        driver_directory="drivers",
        disable_guest_firewall=True,
        answer_script="install-agent.cmd",
    )


def _registry_value(output: str, value_name: str) -> str:
    """Extract a ``REG_SZ`` value from ``reg query`` output.

    Args:
        output: Raw stdout of a ``reg query`` invocation.
        value_name: Name of the value to read.

    Returns:
        str: The value's data, empty when the value carries no data.

    Raises:
        AssertionError: If the value is absent from the output.
    """
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(value_name) and _REG_SZ in stripped:
            return stripped.split(_REG_SZ, 1)[1].strip()
    message = f"{value_name} was not present in the guest's registry output: {output!r}"
    raise AssertionError(message)


class _LiveGuest:
    """A running Windows guest reachable over the real guest agent."""

    def __init__(self, bridge: SandboxBridge, instance_id: str) -> None:
        """Bind the guest to the bridge that created it.

        Args:
            bridge: Bridge the instance belongs to.
            instance_id: Identifier of the running instance.
        """
        self._bridge = bridge
        self._instance_id = instance_id

    async def run(self, command: str) -> str:
        """Run a command in the guest and return its stdout.

        Args:
            command: Command line to execute inside the guest.

        Returns:
            str: The command's standard output.
        """
        result: dict[str, Any] = await self._bridge.execute(self._instance_id, command, time_limit=_COMMAND_LIMIT_S)
        return str(result["stdout"])

    async def registry_name(self, key: str) -> str:
        """Read a computer-name value out of the guest registry.

        Args:
            key: Registry key holding a ``ComputerName`` value.

        Returns:
            str: The name recorded under that key.
        """
        return _registry_value(await self.run(f"reg query {key} /v ComputerName"), "ComputerName")


@pytest_asyncio.fixture
async def live_guest() -> AsyncIterator[_LiveGuest]:
    """Boot the provisioned Windows guest through the production bridge.

    Yields:
        _LiveGuest: A guest whose agent answers commands.
    """
    assert _GUEST_IMAGE.is_file(), f"the provisioned Windows guest image is missing: {_GUEST_IMAGE}"

    bridge = SandboxBridge()
    await bridge.initialize()
    config = QEMUConfig(
        guest_os=GuestOS.WINDOWS,
        image_path=_GUEST_IMAGE,
        cpu_cores=_GUEST_CORES,
        memory_mb=_GUEST_MEMORY_MB,
        display="vnc",
        agent_connect_timeout=_BOOT_BUDGET_S,
        guest_agent_ready_timeout=_BOOT_BUDGET_S,
    )
    created = await bridge.create(
        sandbox_type="qemu",
        timeout_seconds=int(_BOOT_BUDGET_S),
        memory_limit_mb=_GUEST_MEMORY_MB,
        qemu_config=config,
    )
    instance_id = str(created["instance_id"])
    try:
        yield _LiveGuest(bridge, instance_id)
    finally:
        await bridge.destroy(instance_id)
        await bridge.shutdown()


class TestTheProvisionerAssertsItsDeclaredName:
    """The declared name has to be enforced from inside the finished guest."""

    def test_first_logon_enforces_the_declared_name(self) -> None:
        """The first-logon sequence must carry the enforcement command.

        Setup's ``specialize`` pass does not keep the name past the pre-OOBE
        reboot, so a provisioner that only writes the answer file produces a
        guest with the wrong name. The command has to be wired into the run
        that happens after that reboot.
        """
        settings = _settings(_TARGET_NAME)
        commands = [command for command, _ in first_logon_commands(settings)]

        assert computer_name_enforcement_command(_TARGET_NAME) in commands, (
            f"nothing in the first-logon sequence asserts the declared name, so the guest keeps whatever Windows generated: {commands}"
        )

    def test_the_enforcement_command_tracks_the_declared_name(self) -> None:
        """A different declared name must produce a different command.

        This is what stops the wiring gate above from passing on a command
        that names a constant rather than the name the caller asked for.
        """
        other = f"{_TARGET_NAME}2"
        assert computer_name_enforcement_command(_TARGET_NAME) != computer_name_enforcement_command(other), (
            "the enforcement command ignores the declared name"
        )


@pytest.mark.asyncio
class TestTheEnforcementCommandRenamesARealGuest:
    """The command has to work on the guest that exposed the defect."""

    async def test_the_declared_name_is_committed_in_the_guest(self, live_guest: _LiveGuest) -> None:
        """Running the production command must commit the declared name.

        Args:
            live_guest: A booted Windows guest reachable over the guest agent.
        """
        active_before = await live_guest.registry_name(_ACTIVE_NAME_KEY)
        pending_before = await live_guest.registry_name(_PENDING_NAME_KEY)
        assert active_before, "the guest reported an empty active computer name, so the registry read measures nothing"
        assert active_before != _TARGET_NAME, (
            f"the guest already answers to {_TARGET_NAME}, so this run could not tell a working rename from a no-op"
        )
        assert pending_before != _TARGET_NAME, f"the guest already had {_TARGET_NAME} pending before the command ran"

        await live_guest.run(computer_name_enforcement_command(_TARGET_NAME))

        pending_after = await live_guest.registry_name(_PENDING_NAME_KEY)
        assert pending_after == _TARGET_NAME, (
            f"the guest still holds {pending_after!r} after the provisioner's own enforcement command ran, "
            f"so a provisioned guest keeps a name nobody asked for (was {pending_before!r})"
        )
