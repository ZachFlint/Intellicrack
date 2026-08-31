# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D68: a QEMU that dies must be noticed, not waited on.

On Windows the virtual machine is a long-lived foreground child spawned with
piped stdout and stderr, and nothing read either pipe for the life of the
guest. Two consequences were measured live on 2026-08-08, in a session that had
been running for three minutes:

* Both the Intellicrack agent channel and the qemu-guest-agent channel failed
  with ``[WinError 64]`` at the same instant. Two unrelated clients cannot lose
  their sockets together because of a client bug - the peer had gone. The
  teardown that followed confirmed it: ``qemu_already_exited_before_shutdown``.
  The QEMU process had died and nothing in the sandbox had noticed.
* Nothing said why. The exit status and everything QEMU wrote on its way out
  went into a pipe no one ever read, so the only account of the death was
  discarded. That is the same evidence S17-D39 has been waiting on.

Each misdiagnosis that followed was worse than silence. ``run_command`` sat out
its full ninety-second deadline and reported "command timed out", as if the
guest were merely slow. The channel-recovery path spent its reconnect budget
dialling a socket with no listener and then reported that the guest "may
already be running" the command - of a machine that no longer existed.

Four properties are gated, each against a real process or a real socket:

* **An unread pipe wedges the machine.** A child that writes more than the
  operating system's pipe buffer holds blocks inside ``write`` until someone
  drains it. The recorder must keep a flooding child running to completion.
* **The last words survive the process.** The exit status and the tail of what
  QEMU wrote must outlive it, tagged with the stream each line came from.
* **A command is not issued to a machine that is gone.** ``run_command`` must
  say the machine stopped, and name its exit status, rather than waiting.
* **A dead machine is not a recoverable channel.** The agent client must report
  the machine's death rather than reconnecting to a socket that answers, and
  must not deliver the command to the guest model on the other side.

Nothing here is simulated. The flood, the exit statuses and the machine whose
death drives the liveness probe are all real child processes; the agent channel
is a real loopback socket carrying the production readiness handshake.
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import (
    GuestAgentClient,
    GuestOS,
    QEMUConfig,
    QemuOutputRecorder,
    QEMUSandbox,
    QemuTermination,
)
from tests.sandbox.qemu.guest_agent_server import GuestCommandResult, IntellicrackAgentServer


if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


# A drained child finishes in well under a second; an undrained one never
# finishes at all. Any value between the two settles the question, and this one
# is generous enough to survive a loaded container.
_DRAIN_DEADLINE_S: Final[float] = 45.0
_TERMINATION_POLL_S: Final[float] = 0.05
_CLEANUP_READ_SIZE: Final[int] = 65536

# Comfortably more than any pipe buffer the platform might hand out, so a child
# that is not drained is certain to block rather than merely risk it.
_FLOOD_LINES: Final[int] = 4000
_FLOOD_PADDING: Final[int] = 48
_LAST_FLOOD_LINE: Final[str] = f"qemu warning {_FLOOD_LINES - 1:05d}"
_FLOOD_EXIT_CODE: Final[int] = 7
_RETAINED_TAIL_LINES: Final[int] = 8

# Real QEMU output. The stderr line is verbatim the death S17-D39 has been
# chasing, and is exactly what the unread pipe was throwing away.
_QEMU_STDOUT_LINE: Final[str] = "char device redirected to COM1"
_QEMU_STDERR_LINE: Final[str] = "qemu-system-x86_64: WHPX: Unexpected VP exit code 4"
_CRASH_EXIT_CODE: Final[int] = 3

_VM_EXIT_CODE: Final[int] = 5
_VM_LAST_WORDS: Final[str] = "stderr: qemu-system-x86_64: terminating on signal"

_CONNECT_BUDGET_S: Final[float] = 15.0
_RETRY_INTERVAL_S: Final[float] = 0.25
_COMMAND_BUDGET_S: Final[float] = 10.0
_CLOSE_OBSERVED_BUDGET_S: Final[float] = 10.0
_CLOSE_POLL_INTERVAL_S: Final[float] = 0.02

# Long enough that a path which waits it out is unmistakably distinguishable
# from one that answers immediately.
_UNREACHED_TIMEOUT_S: Final[int] = 120
_FAIL_FAST_BUDGET_S: Final[float] = 20.0

_FAILED_COMMAND_EXIT: Final[int] = -1
_ONE_CONNECTION: Final[int] = 1
_ONE_EXECUTION: Final[int] = 1

# Substrings carrying the contract of each message, rather than whole sentences
# that would break on any rewording.
_MACHINE_GONE_TEXT: Final[str] = "no longer running"
_AGENT_MACHINE_STOPPED_TEXT: Final[str] = "the virtual machine stopped"

_FIRST_COMMAND: Final[tuple[str, tuple[str, ...]]] = ("cmd.exe", ("/c", "echo", "first"))
_SECOND_COMMAND: Final[tuple[str, tuple[str, ...]]] = ("C:\\intellicrack\\work\\target.exe", ("--analyze",))

_FLOOD_PROGRAM: Final[str] = f"""
import sys

for index in range({_FLOOD_LINES}):
    sys.stderr.write("qemu warning %05d " % index + "-" * {_FLOOD_PADDING} + "\\n")
sys.stderr.flush()
sys.stdout.write("flood complete\\n")
sys.stdout.flush()
raise SystemExit({_FLOOD_EXIT_CODE})
"""

_CRASH_PROGRAM: Final[str] = f"""
import sys

sys.stdout.write({_QEMU_STDOUT_LINE!r} + "\\n")
sys.stdout.flush()
sys.stderr.write({_QEMU_STDERR_LINE!r} + "\\n")
sys.stderr.flush()
raise SystemExit({_CRASH_EXIT_CODE})
"""

_LONG_LIVED_PROGRAM: Final[str] = f"""
import sys

sys.stdin.read()
raise SystemExit({_VM_EXIT_CODE})
"""


async def _spawn_child(tmp_path: Path, program: str, name: str) -> asyncio.subprocess.Process:
    """Launch a real child process running ``program`` with piped streams.

    Args:
        tmp_path: Directory the program source is written to.
        program: Python source for the child to execute.
        name: File name stem for the written program.

    Returns:
        asyncio.subprocess.Process: The spawned child, with stdout and stderr
        piped exactly as the sandbox spawns QEMU.
    """
    source = tmp_path / f"{name}.py"
    source.write_text(program, encoding="utf-8")
    return await asyncio.create_subprocess_exec(
        sys.executable,
        str(source),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


async def _await_termination(recorder: QemuOutputRecorder, budget: float) -> QemuTermination | None:
    """Wait for the recorder to observe its process ending.

    Args:
        recorder: Recorder draining the process under test.
        budget: Seconds to wait before giving up.

    Returns:
        QemuTermination | None: The recorded termination, or ``None`` if the
        process never ended within ``budget``.
    """
    started = time.monotonic()
    while time.monotonic() - started < budget:
        termination = recorder.termination
        if termination is not None:
            return termination
        await asyncio.sleep(_TERMINATION_POLL_S)
    return None


async def _drain_to_eof(stream: asyncio.StreamReader | None) -> None:
    """Read one stream until it ends, discarding what it carries.

    Args:
        stream: Stream to read to exhaustion; ``None`` when it was never piped.
    """
    if stream is None:
        return
    while await stream.read(_CLEANUP_READ_SIZE):
        pass


async def _release_flooding_child(process: asyncio.subprocess.Process, recorder: QemuOutputRecorder) -> None:
    """Stop the recorder, then empty the child's pipes so it can finish.

    A child that has filled its pipes is blocked inside ``write`` and cannot
    end until something reads them. Terminating it is not a substitute: the
    parent still holds the read ends, and the exit is not observed until they
    are emptied. So the drain the recorder was supposed to perform is performed
    here instead, which lets a recorder that never drained be reported as the
    failed assertion it is rather than as a test that never returns.

    The recorder is stopped first so that only one reader is ever waiting on a
    stream.

    Args:
        process: Child whose streams are to be emptied and whose status is
            then collected.
        recorder: Recorder to stop before reading the streams directly.
    """
    await recorder.aclose()
    await asyncio.gather(_drain_to_eof(process.stdout), _drain_to_eof(process.stderr))
    await process.wait()


async def _wait_until_channel_lost(client: GuestAgentClient, budget: float) -> None:
    """Wait for the client to notice the agent hung up on it.

    Args:
        client: Client whose channel the agent has closed.
        budget: Seconds to wait before giving up.
    """
    started = time.monotonic()
    while time.monotonic() - started < budget:
        if not client.is_connected:
            return
        await asyncio.sleep(_CLOSE_POLL_INTERVAL_S)


def _modelled_guest(path: str, args: Sequence[str]) -> GuestCommandResult:
    """Answer one in-guest command with output naming the invocation.

    Args:
        path: Executable the client asked the guest to run.
        args: Argument list passed with the executable.

    Returns:
        GuestCommandResult: Success carrying the invocation as its stdout.
    """
    return GuestCommandResult(exit_code=0, stdout=" ".join([path, *args]), stderr="")


class TestOutputRecorderKeepsTheMachineRunning:
    """QEMU's piped output must be drained for as long as it is running."""

    @pytest.mark.asyncio
    async def test_a_flooding_process_runs_to_completion(self, tmp_path: Path) -> None:
        """A child writing past the pipe buffer must not block forever.

        Args:
            tmp_path: Pytest-provided directory for the child's program.
        """
        process = await _spawn_child(tmp_path, _FLOOD_PROGRAM, "flood")
        recorder = QemuOutputRecorder(process, tail_lines=_RETAINED_TAIL_LINES)
        recorder.start()
        try:
            termination = await _await_termination(recorder, _DRAIN_DEADLINE_S)
        finally:
            await _release_flooding_child(process, recorder)

        assert termination is not None, (
            f"the process wrote more than one pipe buffer and never finished within {_DRAIN_DEADLINE_S}s; "
            "an undrained pipe blocks the writer, which is the guest freezing with no record of why"
        )
        assert termination.returncode == _FLOOD_EXIT_CODE, (
            f"expected the child's own exit status {_FLOOD_EXIT_CODE}, got {termination.returncode}"
        )
        assert len(termination.output_tail) == _RETAINED_TAIL_LINES, (
            f"the retained tail must stay bounded at {_RETAINED_TAIL_LINES} lines, "
            f"got {len(termination.output_tail)} after {_FLOOD_LINES} lines of output"
        )
        assert any(_LAST_FLOOD_LINE in line for line in termination.output_tail), (
            f"the tail must keep the newest output; {_LAST_FLOOD_LINE!r} is missing from {termination.output_tail}"
        )

    @pytest.mark.asyncio
    async def test_the_exit_status_and_last_words_outlive_the_process(self, tmp_path: Path) -> None:
        """What QEMU said as it died must survive the process that said it.

        Args:
            tmp_path: Pytest-provided directory for the child's program.
        """
        process = await _spawn_child(tmp_path, _CRASH_PROGRAM, "crash")
        recorder = QemuOutputRecorder(process)
        recorder.start()
        try:
            termination = await _await_termination(recorder, _DRAIN_DEADLINE_S)
        finally:
            await recorder.aclose()

        assert termination is not None, "the process ended but no termination was recorded"
        assert termination.returncode == _CRASH_EXIT_CODE, f"expected exit status {_CRASH_EXIT_CODE}, got {termination.returncode}"
        assert f"stdout: {_QEMU_STDOUT_LINE}" in termination.output_tail, (
            f"stdout must be retained and tagged with its stream; tail was {termination.output_tail}"
        )
        assert f"stderr: {_QEMU_STDERR_LINE}" in termination.output_tail, (
            f"the line explaining the death must be retained and tagged; tail was {termination.output_tail}"
        )

        described = termination.describe()
        assert str(_CRASH_EXIT_CODE) in described, f"the rendered account must name the exit status: {described!r}"
        assert _QEMU_STDERR_LINE in described, f"the rendered account must carry QEMU's own words: {described!r}"


class TestCommandsAreNotIssuedToADeadMachine:
    """A command cannot run on a machine that has stopped, so none is sent."""

    @pytest.mark.asyncio
    async def test_run_command_reports_the_stopped_machine_rather_than_waiting(self, tmp_path: Path) -> None:
        """A stopped machine must be reported, not waited out as a slow guest.

        Args:
            tmp_path: Pytest-provided directory for the child's program.
        """
        process = await _spawn_child(tmp_path, _CRASH_PROGRAM, "crash")
        await process.wait()

        sandbox = QEMUSandbox(SandboxConfig(), QEMUConfig(guest_os=GuestOS.WINDOWS))
        sandbox.state.status = "running"
        sandbox.process = process

        assert sandbox.qemu_termination() is not None, (
            "a process that has already exited must be reported as terminated even with no recorder attached"
        )

        started = time.monotonic()
        with pytest.raises(SandboxError, match=_MACHINE_GONE_TEXT) as raised:
            await sandbox.run_command("cmd.exe /c echo probe", time_limit=_UNREACHED_TIMEOUT_S)
        elapsed = time.monotonic() - started

        assert str(_CRASH_EXIT_CODE) in str(raised.value), f"the failure must name the machine's exit status: {raised.value!r}"
        assert elapsed < _FAIL_FAST_BUDGET_S, (
            f"the machine was already gone, so the command must fail immediately; it took {elapsed:.1f}s "
            f"of its {_UNREACHED_TIMEOUT_S}s deadline"
        )


class TestADeadMachineIsNotARecoverableChannel:
    """Losing the channel and losing the machine are different failures."""

    @pytest.mark.asyncio
    async def test_the_agent_reports_the_stopped_machine_and_sends_nothing(self, tmp_path: Path) -> None:
        """A machine that stopped must not be answered by reconnecting.

        Args:
            tmp_path: Pytest-provided directory for the child's program.
        """
        machine = await _spawn_child(tmp_path, _LONG_LIVED_PROGRAM, "machine")

        def probe_machine() -> QemuTermination | None:
            """Report the real child process's death, if it has died.

            Returns:
                QemuTermination | None: How the machine ended, or ``None``
                while it is still running.
            """
            code = machine.returncode
            if code is None:
                return None
            return QemuTermination(returncode=code, output_tail=(_VM_LAST_WORDS,))

        server = IntellicrackAgentServer(responder=_modelled_guest, close_after_replies=1)
        port = await server.start()
        client = GuestAgentClient(port=port, vm_terminated=probe_machine)
        try:
            assert await client.connect(time_limit=_CONNECT_BUDGET_S, retry_interval=_RETRY_INTERVAL_S), (
                "the agent server is listening, so the first connection must succeed"
            )

            first = await client.send_command(_FIRST_COMMAND[0], list(_FIRST_COMMAND[1]), time_limit=_COMMAND_BUDGET_S)
            assert first[0] == 0, f"the first command ran on a live machine and must succeed: {first!r}"

            await _wait_until_channel_lost(client, _CLOSE_OBSERVED_BUDGET_S)

            if machine.stdin is not None:
                machine.stdin.close()
            await machine.wait()

            second = await client.send_command(
                _SECOND_COMMAND[0],
                list(_SECOND_COMMAND[1]),
                time_limit=_COMMAND_BUDGET_S,
            )
        finally:
            await client.disconnect()
            await server.stop()
            if machine.returncode is None:
                machine.kill()
                await machine.wait()

        assert second[0] == _FAILED_COMMAND_EXIT, f"a command that never ran must not report success: {second!r}"
        assert _AGENT_MACHINE_STOPPED_TEXT in second[2], (
            f"the failure must say the machine stopped rather than hedging about the channel: {second[2]!r}"
        )
        assert str(_VM_EXIT_CODE) in second[2], f"the failure must name the machine's exit status: {second[2]!r}"
        assert _VM_LAST_WORDS in second[2], f"the failure must carry what the machine said as it died: {second[2]!r}"
        assert server.accepted == _ONE_CONNECTION, (
            f"the machine was gone, so no reconnection should have been attempted; the server accepted {server.accepted} connections"
        )
        assert len(server.requests) == _ONE_EXECUTION, (
            f"only the first command may ever reach the guest; the server received {server.requests}"
        )
