# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D48: stopping a sandbox must power the guest off, not yank it.

``QEMUSandbox._stop_impl`` used to disconnect both agent channels and then send
QMP ``quit``, which ends the QEMU process immediately with the guest never told
anything. That is a power-cord yank, and it has two consequences. Whatever the
in-guest monitors had buffered but not yet flushed to the shared volume is
gone, so the run's telemetry is silently short. And the guest filesystem is
left dirty: the Windows guest built for wave 6H booted in 37 seconds, was
stopped that way, and came back into Windows Recovery reporting that the
installation "couldn't be repaired".

Two shutdown channels exist and neither was used. qemu-guest-agent's
``guest-shutdown`` runs inside the guest, and QMP's ``system_powerdown``
presses the virtual ACPI power button. QEMU exits on its own once its guest
powers off, so the process itself is the completion signal.

Everything here runs against real peers, not doubles of the code under test:

* :class:`QmpProtocolServer` and :class:`GuestAgentProtocolServer` are the
  genuine asyncio servers shared by every QEMU channel gate. The client under
  test opens real sockets and writes real protocol frames to them. The agent
  server answers ``guest-shutdown`` with silence, which is what a live agent
  does - it is already powering the guest off when the reply would have been
  written.
* A real child process stands in for QEMU. The guest model wires the shutdown
  request to that process exiting, exactly as a real guest powering off makes
  QEMU exit, so the production code observes compliance the same way it does
  against a live VM: by waiting on the process.

A stubborn guest is modelled by leaving the stand-in process running, which is
what gates the other half of the fix - a guest that will not comply must still
be cut off within a bounded time.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import TYPE_CHECKING, Any, Final

import pytest
import pytest_asyncio

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig, QEMUSandbox
from tests.sandbox.qemu.guest_agent_server import (
    GuestAgentProtocolServer,
    QmpProtocolServer,
    decode_object,
)


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

# A child that stays up until something ends it, standing in for the QEMU
# process whose lifetime tracks its guest's.
_IDLE_CHILD_SOURCE: Final[str] = "import time; time.sleep(600)"

# The QGA schema's own names. Restated deliberately: they are QEMU's contract,
# not ours, and a rename on our side has to turn this red rather than follow.
_GUEST_SHUTDOWN_COMMAND: Final[str] = "guest-shutdown"
_GUEST_SHUTDOWN_MODE: Final[str] = "powerdown"
_ACPI_POWERDOWN_COMMAND: Final[str] = "system_powerdown"
_QUIT_COMMAND: Final[str] = "quit"

# Generous enough that a compliant guest is never cut off for being slow.
_COMPLIANT_BUDGET_S: Final[float] = 20.0
# Small enough that the stubborn-guest test does not idle: the budget is split
# across the two open channels, so this is two waits of half a second.
_STUBBORN_BUDGET_S: Final[float] = 1.0
_EXIT_WAIT_S: Final[float] = 10.0
_STILL_RUNNING_PROBE_S: Final[float] = 0.5


class _StopTestSandbox(QEMUSandbox):
    """``QEMUSandbox`` exposing the stop-path internals to test code.

    Only public wrappers are added; every wrapped method is the real
    production implementation.
    """

    async def connect_qmp(self) -> None:
        """Drive the real :meth:`QEMUSandbox._connect_and_verify_qmp`."""
        await self._connect_and_verify_qmp()

    async def open_guest_agent_channel(self) -> None:
        """Drive the real :meth:`QEMUSandbox._connect_guest_agent_channel`."""
        await self._connect_guest_agent_channel()

    async def await_qemu_exit(self, time_limit: float) -> bool:
        """Drive the real :meth:`QEMUSandbox._await_qemu_exit`.

        Args:
            time_limit: Seconds to wait before giving up.

        Returns:
            bool: True when QEMU is no longer running.
        """
        return await self._await_qemu_exit(time_limit)

    def watch_pid(self, pid: int) -> None:
        """Track QEMU by PID alone, as the daemonized launch path does.

        Args:
            pid: PID of the process standing in for a daemonized QEMU.
        """
        self.process = None
        self._qemu_pid = pid


class _StandInQemu:
    """A real child process whose lifetime models a QEMU hosting a guest.

    Attributes:
        process: The running child.
    """

    process: asyncio.subprocess.Process

    def __init__(self, process: asyncio.subprocess.Process) -> None:
        """Retain the child and start with no power-off watchers.

        Args:
            process: The running child standing in for QEMU.
        """
        self.process = process
        self._watchers: list[asyncio.Task[None]] = []

    def power_off_when(self, requested: asyncio.Event) -> None:
        """Make the guest obey one shutdown channel.

        A guest that powers off takes QEMU down with it, so honouring a
        request means ending this process.

        Args:
            requested: Event a protocol server sets when the request arrives.
        """
        self._watchers.append(asyncio.create_task(self._power_off(requested)))

    async def _power_off(self, requested: asyncio.Event) -> None:
        """Wait for the request, then end the process.

        Args:
            requested: Event a protocol server sets when the request arrives.
        """
        await requested.wait()
        if self.process.returncode is None:
            self.process.terminate()

    async def close(self) -> None:
        """Cancel every watcher and make sure the child is gone."""
        for watcher in self._watchers:
            watcher.cancel()
            try:
                await watcher
            except asyncio.CancelledError:
                continue
        self._watchers.clear()
        if self.process.returncode is None:
            self.process.kill()
        await self.process.wait()


@pytest_asyncio.fixture
async def qmp_server() -> AsyncIterator[QmpProtocolServer]:
    """Start the real QMP-shaped server.

    Yields:
        QmpProtocolServer: A listening QMP server.
    """
    server = QmpProtocolServer()
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


@pytest_asyncio.fixture
async def ga_server() -> AsyncIterator[GuestAgentProtocolServer]:
    """Start the real qemu-guest-agent-shaped server.

    Yields:
        GuestAgentProtocolServer: A listening guest-agent server.
    """
    server = GuestAgentProtocolServer()
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


@pytest_asyncio.fixture
async def stand_in_qemu() -> AsyncIterator[_StandInQemu]:
    """Spawn the real child process that stands in for QEMU.

    Yields:
        _StandInQemu: The running stand-in, killed on teardown.
    """
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        _IDLE_CHILD_SOURCE,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stand_in = _StandInQemu(process)
    try:
        yield stand_in
    finally:
        await stand_in.close()


def _make_sandbox(
    qmp_port: int,
    ga_channel_port: int,
    shutdown_budget: float,
) -> _StopTestSandbox:
    """Build a sandbox wired to the two protocol servers.

    Args:
        qmp_port: Port of the QMP-shaped server.
        ga_channel_port: Port of the guest-agent-shaped server. The sandbox
            derives it as ``agent_port + 1``, so ``agent_port`` is set one
            below it.
        shutdown_budget: Seconds the guest is given to power itself off.

    Returns:
        _StopTestSandbox: Sandbox ready for direct method invocation.
    """
    cfg = QEMUConfig(
        guest_os=GuestOS.LINUX,
        monitor_port=qmp_port,
        agent_port=ga_channel_port - 1,
        guest_shutdown_timeout=shutdown_budget,
    )
    return _StopTestSandbox(config=SandboxConfig(), qemu_config=cfg)


def _shutdown_requests(server: GuestAgentProtocolServer) -> list[dict[str, Any]]:
    """Return every ``guest-shutdown`` object as it arrived on the wire.

    Reading the raw inbound bytes rather than the server's parsed record keeps
    the assertion on what the production client actually transmitted.

    Args:
        server: Guest-agent server that received the traffic.

    Returns:
        list[dict[str, Any]]: Decoded ``guest-shutdown`` request objects.
    """
    requests: list[dict[str, Any]] = []
    for raw in bytes(server.received).split(b"\n"):
        stripped = raw.strip().lstrip(b"\xff")
        if not stripped.startswith(b"{"):
            continue
        try:
            decoded = decode_object(stripped)
        except json.JSONDecodeError:
            continue
        if decoded.get("execute") == _GUEST_SHUTDOWN_COMMAND:
            requests.append(decoded)
    return requests


class TestTheGuestIsAskedToPowerItselfOff:
    """A stop must reach the guest before it reaches the QEMU process."""

    @pytest.mark.asyncio
    async def test_stop_powers_the_guest_down_through_the_agent_and_never_quits(
        self,
        qmp_server: QmpProtocolServer,
        ga_server: GuestAgentProtocolServer,
        stand_in_qemu: _StandInQemu,
    ) -> None:
        """The agent is asked to power the guest off and QEMU is left to exit.

        Args:
            qmp_server: Real QMP-shaped server.
            ga_server: Real guest-agent-shaped server.
            stand_in_qemu: Real process standing in for QEMU.
        """
        sandbox = _make_sandbox(qmp_server.port, ga_server.port, _COMPLIANT_BUDGET_S)
        await sandbox.connect_qmp()
        await sandbox.open_guest_agent_channel()
        sandbox.process = stand_in_qemu.process
        sandbox.state.status = "running"
        stand_in_qemu.power_off_when(ga_server.shutdown_requested)

        await asyncio.wait_for(sandbox.stop(), timeout=_EXIT_WAIT_S)

        assert ga_server.shutdown_modes == [_GUEST_SHUTDOWN_MODE], (
            f"the guest was never asked to power itself off: agent saw {ga_server.commands}"
        )
        assert stand_in_qemu.process.returncode is not None, "QEMU was still running after stop() returned"
        assert _QUIT_COMMAND not in qmp_server.commands, (
            f"a guest that powered itself off was killed anyway: monitor saw {qmp_server.commands}"
        )
        assert _ACPI_POWERDOWN_COMMAND not in qmp_server.commands, (
            "the ACPI power button was pressed even though the agent had already shut the guest down"
        )
        assert _GUEST_SHUTDOWN_COMMAND not in qmp_server.commands, (
            "guest-shutdown went to the QMP monitor, which answers it with CommandNotFound"
        )
        assert sandbox.process is None
        assert sandbox.state.status == "stopped"

    @pytest.mark.asyncio
    async def test_the_shutdown_request_carries_the_powerdown_mode_on_the_wire(
        self,
        qmp_server: QmpProtocolServer,
        ga_server: GuestAgentProtocolServer,
        stand_in_qemu: _StandInQemu,
    ) -> None:
        """The bytes sent are the QGA request a live agent acts on.

        Args:
            qmp_server: Real QMP-shaped server.
            ga_server: Real guest-agent-shaped server.
            stand_in_qemu: Real process standing in for QEMU.
        """
        sandbox = _make_sandbox(qmp_server.port, ga_server.port, _COMPLIANT_BUDGET_S)
        await sandbox.connect_qmp()
        await sandbox.open_guest_agent_channel()
        sandbox.process = stand_in_qemu.process
        sandbox.state.status = "running"
        stand_in_qemu.power_off_when(ga_server.shutdown_requested)

        await asyncio.wait_for(sandbox.stop(), timeout=_EXIT_WAIT_S)

        requests = _shutdown_requests(ga_server)
        assert requests == [
            {
                "execute": _GUEST_SHUTDOWN_COMMAND,
                "arguments": {"mode": _GUEST_SHUTDOWN_MODE},
            },
        ], f"the shutdown request on the wire was {requests}; a live agent would not power the guest off"

    @pytest.mark.asyncio
    async def test_stop_presses_the_acpi_power_button_when_no_agent_is_open(
        self,
        qmp_server: QmpProtocolServer,
        stand_in_qemu: _StandInQemu,
    ) -> None:
        """A guest whose agent never came up is still asked, over QMP.

        Args:
            qmp_server: Real QMP-shaped server.
            stand_in_qemu: Real process standing in for QEMU.
        """
        sandbox = _make_sandbox(qmp_server.port, qmp_server.port + 1, _COMPLIANT_BUDGET_S)
        await sandbox.connect_qmp()
        sandbox.process = stand_in_qemu.process
        sandbox.state.status = "running"
        stand_in_qemu.power_off_when(qmp_server.powerdown_requested)

        await asyncio.wait_for(sandbox.stop(), timeout=_EXIT_WAIT_S)

        assert _ACPI_POWERDOWN_COMMAND in qmp_server.commands, f"the guest was never asked to power off: monitor saw {qmp_server.commands}"
        assert stand_in_qemu.process.returncode is not None, "QEMU was still running after stop() returned"
        assert _QUIT_COMMAND not in qmp_server.commands, (
            f"a guest that powered itself off was killed anyway: monitor saw {qmp_server.commands}"
        )
        assert sandbox.state.status == "stopped"


class TestAGuestThatWillNotComplyIsStillCutOff:
    """The graceful path must be bounded, not a way to leave a VM running."""

    @pytest.mark.asyncio
    async def test_both_channels_are_tried_before_qemu_is_terminated(
        self,
        qmp_server: QmpProtocolServer,
        ga_server: GuestAgentProtocolServer,
        stand_in_qemu: _StandInQemu,
    ) -> None:
        """A stubborn guest gets both requests, then loses its power.

        Args:
            qmp_server: Real QMP-shaped server.
            ga_server: Real guest-agent-shaped server.
            stand_in_qemu: Real process standing in for QEMU, which never
                exits on its own here.
        """
        sandbox = _make_sandbox(qmp_server.port, ga_server.port, _STUBBORN_BUDGET_S)
        await sandbox.connect_qmp()
        await sandbox.open_guest_agent_channel()
        sandbox.process = stand_in_qemu.process
        sandbox.state.status = "running"

        await asyncio.wait_for(sandbox.stop(), timeout=_EXIT_WAIT_S)

        assert ga_server.shutdown_modes == [_GUEST_SHUTDOWN_MODE], f"the agent channel was never tried: agent saw {ga_server.commands}"
        assert _ACPI_POWERDOWN_COMMAND in qmp_server.commands, (
            f"a guest whose agent ignored the request never had its power button pressed: monitor saw {qmp_server.commands}"
        )
        assert _QUIT_COMMAND in qmp_server.commands, f"a guest that never powered off was left running: monitor saw {qmp_server.commands}"
        assert stand_in_qemu.process.returncode is not None, "the VM outlived the sandbox that owned it"
        assert sandbox.process is None
        assert sandbox.state.status == "stopped"


class TestTheExitWaitWatchesADaemonizedQemuToo:
    """Where QEMU daemonizes there is no child handle, only a PID."""

    @pytest.mark.asyncio
    async def test_a_live_pid_is_reported_running_and_a_dead_one_is_not(
        self,
        qmp_server: QmpProtocolServer,
        stand_in_qemu: _StandInQemu,
    ) -> None:
        """The PID path distinguishes a running QEMU from an exited one.

        Args:
            qmp_server: Real QMP-shaped server, needed only to build a sandbox.
            stand_in_qemu: Real process standing in for a daemonized QEMU.
        """
        sandbox = _make_sandbox(qmp_server.port, qmp_server.port + 1, _COMPLIANT_BUDGET_S)
        sandbox.watch_pid(stand_in_qemu.process.pid)

        assert not await sandbox.await_qemu_exit(_STILL_RUNNING_PROBE_S), (
            "a running QEMU was reported as exited, so a stop would skip the forced teardown"
        )

        stand_in_qemu.process.terminate()
        await stand_in_qemu.process.wait()

        assert await sandbox.await_qemu_exit(_EXIT_WAIT_S), (
            "an exited QEMU was reported as still running, so a clean shutdown would be killed anyway"
        )
