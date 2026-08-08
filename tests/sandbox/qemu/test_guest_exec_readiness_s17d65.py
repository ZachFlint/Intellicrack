# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D65: a "ready" guest agent has to have run a command.

``_ensure_guest_agent_ready`` declared the agent ready as soon as
``guest-ping`` came back. A ping is answered by the agent's dispatch loop and
says nothing about ``guest-exec``, which has to reach the guest's process
creation path - and on Windows those two become usable minutes apart.

Measured on a cold ``windows11-intellicrack-v4`` boot driven through the real
``SandboxBridge``: QEMU started at 20:01:42, the channel synchronised and
``guest-ping`` was answered at 20:01:54, and the first real command -
``cmd.exe /c fsutil fsinfo drives``, the drive probe that locates the shared
volume - was still unanswered when its ten-second reply deadline expired. The
resync that followed went unanswered too, and ``start()`` failed at 20:02:09
with ``qemu-guest-agent guest-exec failed to launch the monitor agent script``.
Twenty-nine seconds had passed of a nine-hundred-second
``guest_agent_ready_timeout``, so the guest was given none of the time it was
configured to get.

The fix makes readiness mean a command completed, and gives that proof the rest
of the configured budget rather than a single ten-second attempt.

These gates run the production readiness path against
:class:`GuestAgentProtocolServer`, a real TCP server speaking the
qemu-guest-agent wire protocol. Its ``stall_command`` holds back the first
reply to one command exactly as the live agent did, so the client under test
meets the same stream it met on the real guest.
"""

from __future__ import annotations

import time
from typing import Final

import pytest

from intellicrack.core.types import SandboxError
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import (
    QEMU_GA_EXEC_TIMEOUT,
    GuestOS,
    QEMUConfig,
    QEMUSandbox,
)
from tests.sandbox.qemu.guest_agent_server import GuestAgentProtocolServer


_EXEC_COMMAND: Final[str] = "guest-exec"
# Long enough that the first guest-exec is still unanswered when the client's
# reply deadline expires, which is the condition the live guest produced.
_STALL_SECONDS: Final[float] = QEMU_GA_EXEC_TIMEOUT + 2.0
# Room for the stalled attempt, the resync behind it and a retry.
_SLOW_GUEST_BUDGET_S: Final[float] = _STALL_SECONDS + 30.0
# Short: this budget is meant to run out, and the test waits for it to.
_HOPELESS_GUEST_BUDGET_S: Final[float] = 6.0
_READY_GUEST_BUDGET_S: Final[float] = 30.0
_ONE_PROBE: Final[int] = 1
_TWO_PROBES: Final[int] = 2
# Only ever used to build a sandbox whose probe command is read; nothing
# connects to it.
_UNCONNECTED_PORT: Final[int] = 65000


class _ReadinessSandbox(QEMUSandbox):
    """``QEMUSandbox`` exposing the readiness handshake to test code.

    The wrapped method is the real production implementation; only a public
    entry point and a teardown helper are added.
    """

    async def ensure_agent_ready(self) -> None:
        """Drive the real :meth:`QEMUSandbox._ensure_guest_agent_ready`."""
        await self._ensure_guest_agent_ready()

    async def close_client(self) -> None:
        """Disconnect the guest-agent client if one was opened."""
        if self._qga is not None:
            await self._qga.disconnect()
            self._qga = None

    def probe_command(self) -> tuple[str, list[str]]:
        """Return the probe the production code issues for this guest family.

        Returns:
            tuple[str, list[str]]: Executable and argument list, taken from the
            production implementation so the gate cannot drift from it.
        """
        return self._guest_exec_probe()


def _make_sandbox(channel_port: int, budget: float) -> _ReadinessSandbox:
    """Build a sandbox whose agent channel points at a test server.

    Args:
        channel_port: Port of the guest-agent-shaped server. The sandbox
            derives it as ``agent_port + 1``, so ``agent_port`` is set one
            below it.
        budget: Seconds allowed for the whole readiness handshake.

    Returns:
        _ReadinessSandbox: Sandbox ready for direct method invocation.
    """
    config = QEMUConfig(
        guest_os=GuestOS.WINDOWS,
        agent_port=channel_port - 1,
        guest_agent_ready_timeout=budget,
    )
    return _ReadinessSandbox(config=SandboxConfig(), qemu_config=config)


async def _run_readiness(server: GuestAgentProtocolServer, budget: float) -> float:
    """Drive the readiness handshake against a running agent server.

    Args:
        server: The listening guest-agent server.
        budget: Seconds allowed for the whole handshake.

    Returns:
        float: Seconds the handshake took.
    """
    sandbox = _make_sandbox(server.port, budget)
    started = time.monotonic()
    try:
        await sandbox.ensure_agent_ready()
    finally:
        await sandbox.close_client()
    return time.monotonic() - started


@pytest.fixture
def probe_command_line() -> str:
    """Return the probe command line the production code issues.

    Returns:
        str: Executable and arguments joined by spaces, taken from the
        production implementation so the gate cannot drift from it.
    """
    path, args = _make_sandbox(_UNCONNECTED_PORT, _READY_GUEST_BUDGET_S).probe_command()
    return " ".join([path, *args])


@pytest.mark.asyncio
class TestReadinessMeansTheAgentRanSomething:
    """Answering a ping is not evidence that the guest can execute anything."""

    async def test_a_ready_agent_is_proved_by_one_command(self, probe_command_line: str) -> None:
        """A responsive agent must be accepted, and probed exactly once.

        Args:
            probe_command_line: The command line the production probe issues.
        """
        server = GuestAgentProtocolServer()
        await server.start()
        try:
            await _run_readiness(server, _READY_GUEST_BUDGET_S)
        finally:
            await server.stop()

        assert server.commands.count(_EXEC_COMMAND) == _ONE_PROBE, (
            f"readiness ran {server.commands.count(_EXEC_COMMAND)} commands in the guest, not one: {server.commands}"
        )
        assert server.command_lines() == [probe_command_line], (
            f"the guest was asked to run something other than the production probe: {server.command_lines()}"
        )

    async def test_readiness_is_not_reproved_on_every_call(self) -> None:
        """Once the guest has run a command, later callers must not probe again."""
        server = GuestAgentProtocolServer()
        await server.start()
        sandbox = _make_sandbox(server.port, _READY_GUEST_BUDGET_S)
        try:
            await sandbox.ensure_agent_ready()
            await sandbox.ensure_agent_ready()
        finally:
            await sandbox.close_client()
            await server.stop()

        assert server.commands.count(_EXEC_COMMAND) == _ONE_PROBE, (
            f"a proved agent was probed again, costing every caller a guest command: {server.commands}"
        )


@pytest.mark.asyncio
class TestASlowGuestKeepsTheBudgetItWasGiven:
    """A command that times out with budget left is a retry, not a failure."""

    async def test_a_command_lost_to_the_reply_deadline_is_retried(self) -> None:
        """The agent that answered late must still be reached.

        The server holds back the first ``guest-exec`` past the client's reply
        deadline, which is exactly what the live Windows guest did twelve
        seconds into its boot. Readiness has to survive that and come back once
        the guest answers, instead of failing the whole start.
        """
        server = GuestAgentProtocolServer(stall_command=_EXEC_COMMAND, stall_seconds=_STALL_SECONDS)
        await server.start()
        try:
            elapsed = await _run_readiness(server, _SLOW_GUEST_BUDGET_S)
        finally:
            await server.stop()

        assert server.commands.count(_EXEC_COMMAND) >= _TWO_PROBES, (
            f"the lost command was never retried, so a slow guest is still fatal: {server.commands}"
        )
        assert elapsed >= QEMU_GA_EXEC_TIMEOUT, (
            f"readiness returned in {elapsed:.1f}s, before the stalled command could even have timed out"
        )

    async def test_an_agent_that_runs_nothing_fails_with_its_budget_named(self) -> None:
        """An agent that answers pings but no commands must not pass as ready.

        This is the false-green the live run hit from the other side: the
        channel is up, the agent is talking, and nothing it is asked to run
        ever runs. That has to be a failure, and it has to say so.
        """
        server = GuestAgentProtocolServer(unsupported_commands=frozenset({_EXEC_COMMAND}))
        await server.start()
        started = time.monotonic()
        try:
            with pytest.raises(SandboxError, match="ran no command inside the guest"):
                await _run_readiness(server, _HOPELESS_GUEST_BUDGET_S)
        finally:
            await server.stop()
        elapsed = time.monotonic() - started

        assert server.commands.count(_EXEC_COMMAND) >= _ONE_PROBE, "the guest was never asked to run anything at all"
        assert elapsed >= _HOPELESS_GUEST_BUDGET_S, f"readiness gave up after {elapsed:.1f}s of a {_HOPELESS_GUEST_BUDGET_S:.0f}s budget"


@pytest.mark.asyncio
async def test_the_server_really_stalls_the_first_command() -> None:
    """The stall has to outlast the reply deadline, or the gates prove nothing."""
    server = GuestAgentProtocolServer(stall_command=_EXEC_COMMAND, stall_seconds=_STALL_SECONDS)
    await server.start()
    sandbox = _make_sandbox(server.port, _SLOW_GUEST_BUDGET_S)
    try:
        await sandbox.ensure_agent_ready()
    finally:
        await sandbox.close_client()
        await server.stop()

    assert _STALL_SECONDS > QEMU_GA_EXEC_TIMEOUT, (
        f"a {_STALL_SECONDS:.0f}s stall is inside the {QEMU_GA_EXEC_TIMEOUT:.0f}s reply deadline, so nothing was lost"
    )
    assert len(server.exec_records) >= _TWO_PROBES, (
        "the stalled command produced no second attempt, so the server did not model a late agent"
    )
