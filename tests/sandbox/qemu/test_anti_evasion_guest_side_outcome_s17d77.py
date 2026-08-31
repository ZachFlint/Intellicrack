# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D77: anti-evasion must not report guest-side failure as success.

``apply_anti_evasion`` reports two kinds of technique. The launch-time SMBIOS
and CPUID arguments are read off the fixed launch profile and cannot fail. The
Windows registry patches and the MAC randomisation run real commands in the
guest and can. The pre-fix code appended a technique only on ``exit_code == 0``
and did nothing otherwise, so a run whose agent was never connected - or whose
every guest command timed out - reported the very same clean success, listing
only the launch-time arguments, as a run in which everything worked.

Measured live on 2026-08-09: the call ran **151.5 s** against a guest whose
agent could not execute a command, every registry write and the MAC
randomisation timed out, and it returned ``count: 4`` naming only the four
launch-time arguments while the panel printed ``Anti-evasion applied``.

These gates drive the real :meth:`QEMUSandbox.apply_anti_evasion`. The guest
agent is the boundary being controlled - a scripted stand-in that returns a
chosen exit code and records what it was asked to run - so nothing here
restates the in-guest registry logic; the set of commands attempted comes from
the production :meth:`QEMUSandbox._anti_evasion_registry_commands`, and the
count of guest-side techniques the control expects is derived from it rather
than hardcoded.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Final, cast

import pytest

from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import (
    AcceleratorType,
    GuestAgentClient,
    GuestOS,
    QEMUConfig,
    QEMUSandbox,
)


if TYPE_CHECKING:
    from collections.abc import Sequence


_PROFILE: Final = "default"
_LAUNCH_TIME_TECHNIQUE_COUNT: Final[int] = 4  # three SMBIOS tables plus the CPUID mask.
_MAC_TECHNIQUE: Final[str] = "mac_address_randomize"
_REGISTRY_TECHNIQUE: Final[str] = "registry_patch"


class _AntiEvasionSandbox(QEMUSandbox):
    """A sandbox in ``running`` state whose QMP and agent are supplied by the test."""

    def prepare(self, agent: GuestAgentClient | None) -> None:
        """Put the sandbox in the state ``apply_anti_evasion`` expects.

        Args:
            agent: The guest agent to install, or None for no agent at all.
        """
        self._accelerator = AcceleratorType.TCG
        self._accelerator_cached = True
        self.state.status = "running"
        # apply_anti_evasion only checks the monitor is present, never calls it.
        setattr(self, "_qmp", object())
        self._agent = agent

    def registry_command_count(self) -> int:
        """Ask the production code how many registry commands a run attempts.

        Deriving the count from the inherited
        :meth:`QEMUSandbox._anti_evasion_registry_commands` keeps the control
        honest without restating the guest-side command set in the test.

        Returns:
            int: Number of registry commands this profile dispatches.
        """
        commands = self._anti_evasion_registry_commands(_PROFILE, "AAAAAAAAAAAAAAAA", "C:\\Windows\\System32\\reg.exe")
        return len(commands)


class _ScriptedAgent(GuestAgentClient):
    """A connected guest agent that answers every command with a fixed exit code.

    This is the transport boundary, not a restatement of guest logic: it does
    no registry work, it only reports the exit code the guest would have
    returned, and it records every command so a test can prove the production
    code actually attempted the guest-side work.
    """

    def __init__(self, exit_code: int) -> None:
        """Record the exit code every command will be answered with.

        Args:
            exit_code: Exit code returned for each command.
        """
        super().__init__(host="127.0.0.1", port=4445)
        self.connected = True
        self._exit_code = exit_code
        self.commands: list[str] = []

    async def send_command(
        self,
        command: str,
        args: Sequence[str] | None = None,
        time_limit: float = 30.0,
    ) -> tuple[int, str, str]:
        """Record the command and answer with the scripted exit code.

        Args:
            command: Command name being dispatched.
            args: Argument list (recorded only through the command name).
            time_limit: Timeout in seconds (ignored).

        Returns:
            tuple[int, str, str]: The scripted exit code and empty streams.
        """
        del args, time_limit
        self.commands.append(command)
        return (self._exit_code, "", "")


class _AbsentAgent(GuestAgentClient):
    """A guest agent that reports itself disconnected and refuses any command."""

    def __init__(self) -> None:
        """Construct the agent without opening a socket, left disconnected."""
        super().__init__(host="127.0.0.1", port=4445)
        self.connected = False

    async def send_command(
        self,
        command: str,
        args: Sequence[str] | None = None,
        time_limit: float = 30.0,
    ) -> tuple[int, str, str]:
        """Fail loudly: a disconnected agent must never be asked to run anything.

        Args:
            command: Command name (ignored).
            args: Argument list (ignored).
            time_limit: Timeout in seconds (ignored).

        Returns:
            tuple[int, str, str]: Never returns.

        Raises:
            AssertionError: Always; reaching here is the bug under test.
        """
        del command, args, time_limit
        msg = "a disconnected agent must not be dispatched a command"
        raise AssertionError(msg)


def _make_sandbox(agent: GuestAgentClient | None) -> _AntiEvasionSandbox:
    """Build a running Windows sandbox with the given agent.

    Args:
        agent: The guest agent to install, or None for no agent.

    Returns:
        _AntiEvasionSandbox: A sandbox ready for ``apply_anti_evasion``.
    """
    cfg = QEMUConfig(guest_os=GuestOS.WINDOWS, anti_evasion_profile=_PROFILE)
    sandbox = _AntiEvasionSandbox(config=SandboxConfig(), qemu_config=cfg)
    sandbox.prepare(agent)
    return sandbox


class TestGuestSideAntiEvasionReportsItsOutcome:
    """Anti-evasion must succeed only when the guest-side work it attempted did."""

    def test_a_disconnected_agent_makes_the_call_fail(self) -> None:
        """The live case: no agent, so no guest-side hardening, so not a success.

        The launch-time arguments were still applied, but reporting them as a
        clean success is exactly the defect - a caller cannot tell that the
        guest was never hardened.
        """
        sandbox = _make_sandbox(_AbsentAgent())

        with pytest.raises(SandboxError) as raised:
            asyncio.run(sandbox.apply_anti_evasion(_PROFILE))

        assert _PROFILE in str(raised.value), f"the failure does not name the profile: {raised.value}"

    def test_no_agent_at_all_makes_the_call_fail(self) -> None:
        """A Windows sandbox that never attached an agent must not report success."""
        sandbox = _make_sandbox(None)

        with pytest.raises(SandboxError):
            asyncio.run(sandbox.apply_anti_evasion(_PROFILE))

    def test_failing_guest_commands_make_the_call_fail(self) -> None:
        """Every guest command failing must be reported, not swallowed.

        The scripted agent answers each command with a non-zero exit code -
        the timeout case the live run hit - and the call must raise rather than
        return the launch-time-only success it used to.
        """
        agent = _ScriptedAgent(exit_code=1)
        sandbox = _make_sandbox(agent)

        with pytest.raises(SandboxError):
            asyncio.run(sandbox.apply_anti_evasion(_PROFILE))

        assert agent.commands, "the production code never attempted any guest-side command"

    def test_all_guest_commands_succeeding_reports_full_success(self) -> None:
        """The control: when the guest-side work succeeds, the call still succeeds.

        Without this a broken fix that raised unconditionally would satisfy the
        three failure tests. It also proves the guest-side techniques are
        reported on top of the launch-time ones, using a count taken from the
        production command set rather than a hardcoded number.
        """
        agent = _ScriptedAgent(exit_code=0)
        sandbox = _make_sandbox(agent)

        result: dict[str, Any] = asyncio.run(sandbox.apply_anti_evasion(_PROFILE))

        expected_registry = sandbox.registry_command_count()
        expected_total = _LAUNCH_TIME_TECHNIQUE_COUNT + expected_registry + 1

        techniques = cast("list[str]", result["techniques"])
        assert result["count"] == expected_total, f"expected {expected_total} techniques, got {result['count']}: {techniques}"
        assert techniques.count(_REGISTRY_TECHNIQUE) == expected_registry
        assert _MAC_TECHNIQUE in techniques
        assert len(agent.commands) == expected_registry + 1, f"unexpected guest command set: {agent.commands}"
