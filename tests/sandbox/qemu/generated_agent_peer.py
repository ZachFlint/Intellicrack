# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""The generated Windows guest agent, running as a real ``powershell.exe``.

``QEMUSandbox._create_guest_agent_script`` writes the in-guest agent's whole
source, so anything a test says about what the guest does can either be lifted
out of that source or invented. This module lifts it: whole lines, whole
functions and whole dispatch branches are copied verbatim out of the generated
``agent.ps1`` and assembled into a script a real ``powershell.exe`` runs over a
real socket, which is how the guest runs them.

Only the accept loop belongs to the harness, and the listener statement is a
parameter rather than a fixture of it, because which address that statement
binds is itself a production property worth gating - see
:mod:`tests.sandbox.qemu.test_guest_agent_bind_s17d35`, which passes the
generated statement through unedited, while
:mod:`tests.sandbox.qemu.test_guest_command_protocol_s17d26` substitutes a
loopback listener on a free port so several protocol cases can run at once.
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Final

from tests.sandbox.qemu.powershell_script import matching_bracket


if TYPE_CHECKING:
    from pathlib import Path

POWERSHELL: Final[str] = "powershell.exe"
"""Interpreter the guest starts ``agent.ps1`` with, and this harness with it."""

AGENT_SCRIPT_NAME: Final[str] = "agent.ps1"
"""Name the application writes the generated Windows agent under."""

MONITOR_DIRECTORY: Final[str] = "monitor"
"""Directory of the shared folder the agent and its monitors are written to."""

ERROR_ACTION_LINE: Final[str] = "$ErrorActionPreference"
MONITOR_DIR_LINE: Final[str] = "$monitorDir ="
SHARE_ROOT_LINE: Final[str] = "$shareRoot ="
SHARE_ROOT_PREFIX_LINE: Final[str] = "$shareRootPrefix ="
SHARE_ROOT_PREFIX_FALLBACK_LINE: Final[str] = "if (-not $shareRootPrefix"
SYSTEM_DRIVE_LINE: Final[str] = "$systemDrive ="
SYSTEM_DRIVE_FALLBACK_LINE: Final[str] = "if (-not $systemDrive)"
SYSTEM_ROOT_LINE: Final[str] = "$systemRoot ="
SYSTEM_ROOT_FALLBACK_LINE: Final[str] = "if (-not $systemRoot)"
WORK_ROOT_LINE: Final[str] = "$workRoot ="
WORK_ROOT_PREFIX_LINE: Final[str] = "$workRootPrefix ="
WORK_ROOT_PREFIX_FALLBACK_LINE: Final[str] = "if (-not $workRootPrefix"
ALLOWED_NAMES_LINE: Final[str] = "$allowedNames ="
ALLOWED_ROOTS_LINE: Final[str] = "$allowedRoots ="
QUOTE_CHAR_LINE: Final[str] = "$quoteChar ="
LISTENER_LINE: Final[str] = "$listener ="

PING_BRANCH_HEADER: Final[str] = "if ($request.type -eq 'ping') {"
EXECUTE_BRANCH_HEADER: Final[str] = "elseif ($request.type -eq 'execute') {"

ALLOWLIST_FUNCTION: Final = re.compile(r"function\s+Test-AllowedCommand\s*\([^)]*\)\s*\{")
SEND_MESSAGE_FUNCTION: Final = re.compile(r"function\s+Send-Message\s*\([^)]*\)\s*\{")
SHELL_CALLEE_FUNCTION: Final = re.compile(r"function\s+Test-ShellParsedCallee\s*\([^)]*\)\s*\{")
SHELL_ARGUMENT_FUNCTION: Final = re.compile(r"function\s+ConvertTo-ShellCommandLineArgument\s*\([^)]*\)\s*\{")
ARGUMENT_FUNCTION: Final = re.compile(r"function\s+ConvertTo-CommandLineArgument\s*\([^)]*\)\s*\{")
INVOKE_FUNCTION: Final = re.compile(r"function\s+Invoke-GuestCommand\s*\([^)]*\)\s*\{")

_DECLARED_FUNCTION: Final = re.compile(r"^[ \t]*function\s+(?P<name>[A-Za-z]+-[A-Za-z]+)\s*\(", re.MULTILINE)
_TOP_LEVEL_ASSIGNMENT: Final = re.compile(r"^[ \t]*\$(?P<name>\w+)\s*=", re.MULTILINE)
_ERR_INCOMPLETE_LIFT: Final[str] = (
    "the peer lifts code that uses {kind} {name!r} without lifting its declaration; "
    "PowerShell resolves it late and the agent sets $ErrorActionPreference to SilentlyContinue, "
    "so the peer would answer with the wrong result rather than fail"
)

LOOPBACK_LISTENER_STATEMENT: Final[str] = (
    "$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), $Port)"
)
"""Listener a caller passes when it wants the peer on a port of its choosing."""

_ERR_NO_FRAGMENT: Final[str] = "the generated agent script contains no {fragment}"
_ERR_AMBIGUOUS_FRAGMENT: Final[str] = "the generated agent script contains {count} lines beginning {fragment!r}"
_ERR_UNCLOSED_FRAGMENT: Final[str] = "the block opened by {fragment!r} is never closed in the generated agent script"
_ERR_PEER_FAILED: Final[str] = "the in-guest agent peer failed: exit {code}, stderr {stderr!r}"

_PEER_EXIT_TIMEOUT: Final[float] = 15.0


def script_line(script: str, beginning: str) -> str:
    """Return the one line of the generated agent script starting with ``beginning``.

    Args:
        script: Full text of the generated ``agent.ps1``.
        beginning: Text the wanted line begins with, ignoring indentation.

    Returns:
        str: The line itself, stripped of indentation.

    Raises:
        AssertionError: If the script holds no such line, or more than one.
    """
    matched = [line.strip() for line in script.splitlines() if line.strip().startswith(beginning)]
    if len(matched) != 1:
        raise AssertionError(_ERR_AMBIGUOUS_FRAGMENT.format(count=len(matched), fragment=beginning))
    return matched[0]


def script_block(script: str, start: int, opening: int, fragment: str) -> str:
    """Return the braced block of the generated agent script, verbatim.

    Args:
        script: Full text of the generated ``agent.ps1``.
        start: Index the returned text begins at.
        opening: Index of the block's opening brace.
        fragment: Description of the block, for the failure message.

    Returns:
        str: Source from ``start`` through the matching closing brace.

    Raises:
        AssertionError: If the block is never closed.
    """
    closing = matching_bracket(script, opening)
    if closing < 0:
        raise AssertionError(_ERR_UNCLOSED_FRAGMENT.format(fragment=fragment))
    return script[start : closing + 1]


def script_function(script: str, header: re.Pattern[str]) -> str:
    """Return one whole function of the generated agent script, verbatim.

    Args:
        script: Full text of the generated ``agent.ps1``.
        header: Pattern matching the function's declaration through its opening
            brace.

    Returns:
        str: The function's declaration and body.

    Raises:
        AssertionError: If the script declares no such function.
    """
    declaration = header.search(script)
    if declaration is None:
        raise AssertionError(_ERR_NO_FRAGMENT.format(fragment=header.pattern))
    return script_block(script, declaration.start(), declaration.end() - 1, header.pattern)


def script_branch(script: str, header: str) -> str:
    """Return one request branch of the generated agent's dispatch, verbatim.

    Args:
        script: Full text of the generated ``agent.ps1``.
        header: The branch's whole declaration through its opening brace.

    Returns:
        str: The whole ``if``/``elseif`` statement the header opens, which is
        where the agent decides what a request of that type means.

    Raises:
        AssertionError: If the script has no such branch.
    """
    start = script.find(header)
    if start < 0:
        raise AssertionError(_ERR_NO_FRAGMENT.format(fragment=header))
    return script_block(script, start, start + len(header) - 1, header)


def verify_lift_is_complete(agent_script: str, peer_script: str) -> None:
    """Fail unless the peer carries the declaration of everything it lifted.

    The generated agent sets ``$ErrorActionPreference`` to ``SilentlyContinue``
    and PowerShell binds both function calls and variables late, so a fragment
    lifted without something it depends on does not fail: the call is skipped or
    the variable reads as ``$null``, and the peer answers with a result that
    looks exactly like the behaviour under test. That has already happened once
    - ``ConvertTo-CommandLineArgument`` was lifted while a global it used was
    not, and its output was byte-identical to the defect it was meant to gate.
    So the dependency set is checked here rather than trusted.

    Only names the generated agent itself declares are considered, so this
    cannot mistake a harness statement or a PowerShell built-in for a missing
    lift. Indentation is not part of what a declaration is: the agent serves its
    command channel from a script block, so the functions and the variables this
    peer lifts are nested inside it, and an anchor that demanded column zero
    would quietly stop covering every one of them.

    Args:
        agent_script: Full text of the generated ``agent.ps1``.
        peer_script: The assembled peer script.

    Raises:
        AssertionError: If the peer uses an agent function or an agent global
            whose declaration it does not carry.
    """
    for name in {match["name"] for match in _DECLARED_FUNCTION.finditer(agent_script)}:
        if name in peer_script and not re.search(rf"^function\s+{re.escape(name)}\s*\(", peer_script, re.MULTILINE):
            raise AssertionError(_ERR_INCOMPLETE_LIFT.format(kind="the function", name=name))

    for name in {match["name"] for match in _TOP_LEVEL_ASSIGNMENT.finditer(agent_script)}:
        used = re.search(rf"\${re.escape(name)}\b", peer_script)
        assigned = re.search(rf"\${re.escape(name)}\s*=[^=]", peer_script)
        if used is not None and assigned is None:
            raise AssertionError(_ERR_INCOMPLETE_LIFT.format(kind="the variable", name=f"${name}"))


def build_peer_script(agent_script: str, *, listener_statement: str) -> str:
    """Build the in-guest agent peer out of the generated agent's own statements.

    Everything that decides or performs anything - the roots the allowlist is
    built from, the allowlist itself, the reply framing and both dispatch
    branches - is the generated script's own source, unedited. Only the accept
    loop that hands requests to those branches is written here.

    Lifting the readiness branch rather than answering the probe here is what
    makes this peer a gate on it: the production client handshakes before it
    reports itself connected, so if the generated agent ever stopped answering
    that probe, nothing could connect to this peer at all.

    Args:
        agent_script: Full text of the generated ``agent.ps1``.
        listener_statement: Statement that assigns ``$listener``. Pass
            :data:`LOOPBACK_LISTENER_STATEMENT` to bind loopback on the
            ``-Port`` the peer was started with, or the generated script's own
            listener line to run the production one.

    Returns:
        str: A runnable PowerShell script that answers the agent protocol.
    """
    peer_script = (
        "\r\n".join(
            [
                "param([int]$Port)",
                script_line(agent_script, ERROR_ACTION_LINE),
                script_line(agent_script, MONITOR_DIR_LINE),
                script_line(agent_script, SHARE_ROOT_LINE),
                script_line(agent_script, SHARE_ROOT_PREFIX_LINE),
                script_line(agent_script, SHARE_ROOT_PREFIX_FALLBACK_LINE),
                script_line(agent_script, SYSTEM_DRIVE_LINE),
                script_line(agent_script, SYSTEM_DRIVE_FALLBACK_LINE),
                script_line(agent_script, SYSTEM_ROOT_LINE),
                script_line(agent_script, SYSTEM_ROOT_FALLBACK_LINE),
                script_line(agent_script, WORK_ROOT_LINE),
                script_line(agent_script, WORK_ROOT_PREFIX_LINE),
                script_line(agent_script, WORK_ROOT_PREFIX_FALLBACK_LINE),
                script_line(agent_script, ALLOWED_NAMES_LINE),
                script_line(agent_script, ALLOWED_ROOTS_LINE),
                script_line(agent_script, QUOTE_CHAR_LINE),
                script_function(agent_script, ALLOWLIST_FUNCTION),
                script_function(agent_script, SEND_MESSAGE_FUNCTION),
                script_function(agent_script, SHELL_CALLEE_FUNCTION),
                script_function(agent_script, SHELL_ARGUMENT_FUNCTION),
                script_function(agent_script, ARGUMENT_FUNCTION),
                script_function(agent_script, INVOKE_FUNCTION),
                listener_statement,
                "$listener.Start()",
                "$client = $listener.AcceptTcpClient()",
                "$stream = $client.GetStream()",
                "$reader = New-Object System.IO.StreamReader($stream)",
                "while ($client.Connected) {",
                "    $line = $reader.ReadLine()",
                "    if ($null -eq $line) { break }",
                "    $request = ConvertFrom-Json $line",
                script_branch(agent_script, PING_BRANCH_HEADER),
                script_branch(agent_script, EXECUTE_BRANCH_HEADER),
                "}",
                "$client.Close()",
                "$listener.Stop()",
            ],
        )
        + "\r\n"
    )
    verify_lift_is_complete(agent_script, peer_script)
    return peer_script


class GeneratedAgentPeer:
    """The generated in-guest agent, running as a real ``powershell.exe`` process.

    Attributes:
        port: Port the peer was started with, which the ``-Port`` parameter of
            its script is bound to.
    """

    port: int

    def __init__(self, script_path: Path, port: int) -> None:
        """Prepare the peer.

        Args:
            script_path: Peer script assembled from the generated agent.
            port: Port the peer is started with.
        """
        self._script_path = script_path
        self.port = port
        self._process: asyncio.subprocess.Process | None = None

    async def start(self) -> None:
        """Launch the peer process."""
        self._process = await asyncio.create_subprocess_exec(
            POWERSHELL,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(self._script_path),
            "-Port",
            str(self.port),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def abandon(self) -> None:
        """Kill the peer without judging how it ended.

        For the caller that is already reporting a failure of its own: the peer
        is then still blocked in ``AcceptTcpClient``, so :meth:`stop` would wait
        out its whole exit timeout and then raise over a peer that did nothing
        wrong, burying the real failure.
        """
        process = self._process
        if process is None:
            return
        self._process = None
        process.kill()
        await process.communicate()

    async def stop(self) -> None:
        """Wait for the peer to finish and fail the test if it broke.

        The peer ends by itself once the client under test closes the
        connection. A peer that instead died of its own fault would otherwise
        show up as a client-side timeout, which reads like a production defect.

        Raises:
            AssertionError: If the peer exited with a failure status or wrote
                anything to its standard error.
        """
        process = self._process
        if process is None:
            return
        self._process = None
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=_PEER_EXIT_TIMEOUT)
        except TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()
        diagnostics = stderr.decode(errors="replace").strip()
        if process.returncode or diagnostics:
            raise AssertionError(
                _ERR_PEER_FAILED.format(
                    code=process.returncode,
                    stderr=diagnostics or stdout.decode(errors="replace").strip(),
                ),
            )
