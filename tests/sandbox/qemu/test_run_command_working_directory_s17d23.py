# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S17-D23: ``run_command`` must land in the working directory asked for.

``QEMUSandbox.run_command`` applies a working directory by prefixing a ``cd``
to the command line it hands the guest's own interpreter. Composing that prefix
as ``cd <dir> && <command>`` has two defects, and each is gated separately here:

* ``cmd.exe`` needs ``cd /d``. Without it a directory on a volume other than
  the shell's current one only updates *that volume's* remembered directory and
  leaves the shell where it stood - and ``cd`` still exits 0, so the command
  runs somewhere else and the sandbox reports success. The Windows guest below
  keeps a per-volume current directory exactly as ``cmd.exe`` does, and the
  volume the shell starts on carries a file of the same name as the one in the
  working directory, so a command that never moved returns the wrong file's
  contents rather than merely failing.
* The directory has to survive as a single token. ``/bin/bash`` splits an
  unquoted path on its spaces, so ``cd`` receives two operands and answers
  ``too many arguments``; nothing after the ``&&`` then runs at all.

  ``cmd.exe`` is the more forgiving of the two: with command extensions its
  ``CD`` takes the whole remainder of the line as the path, spaces included, so
  the Windows guest here accepts an unquoted spaced directory the way a real
  one does. What it records is the operand *vector* the line produced, which is
  where the difference remains visible - and the contract the fix has to hold
  is that the directory arrives as one operand, not as however many words it
  happens to contain.

Both guests are real peers: an in-guest
:class:`tests.sandbox.qemu.guest_agent_server.IntellicrackAgentServer` listens
on a loopback port, the production :class:`GuestAgentClient` connects to it,
and every command line the sandbox composes is parsed and executed by the guest
model against a real directory tree on disk. Nothing is stubbed.

The shared-folder fallback composes its own ``cd`` line into a generated
script, from the same helper; that line is executed here too, in one shell with
the command that follows it, which is how the script runs it.
"""

from __future__ import annotations

import shlex
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestAgentClient, GuestOS, QEMUConfig, QEMUSandbox
from tests.sandbox.qemu.guest_agent_server import GuestCommandResult, IntellicrackAgentServer


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Sequence
    from pathlib import Path

_TWO_CHARACTERS: Final[int] = 2
_WINDOWS_SHELL: Final[str] = "cmd.exe"
_WINDOWS_SHELL_FLAG: Final[str] = "/c"
_LINUX_SHELL: Final[str] = "/bin/bash"
_LINUX_SHELL_FLAG: Final[str] = "-c"
_SEPARATOR: Final[str] = "\\"
_CHAIN: Final[str] = "&&"
_CHANGE_DIRECTORY: Final[str] = "cd"
_DRIVE_SWITCH: Final[str] = "/d"

# The share landed on E: and the guest booted from D:, so a working directory
# on the share is always on a different volume from the one the in-guest agent
# - and therefore every shell it starts - is sitting on.
_SHARE_DRIVE: Final[str] = "E:"
_SYSTEM_DRIVE: Final[str] = "D:"
_WINDOWS_START_DIRECTORY: Final[str] = "D:\\WinNT\\system32"
_WINDOWS_WORK_DIRECTORY: Final[str] = "E:\\work"
_WINDOWS_SPACED_WORK_DIRECTORY: Final[str] = "E:\\work dir"
_LINUX_START_DIRECTORY: Final[str] = "/"
_LINUX_WORK_DIRECTORY: Final[str] = "/mnt/shared/work"
_LINUX_SPACED_WORK_DIRECTORY: Final[str] = "/mnt/shared/work dir"

_PAYLOAD_NAME: Final[str] = "payload.txt"
_WORK_PAYLOAD: Final[str] = "collected from the working directory\n"
_DECOY_PAYLOAD: Final[str] = "collected from the directory the shell started in\n"
_READ_COMMAND_WINDOWS: Final[str] = f"type {_PAYLOAD_NAME}"
_READ_COMMAND_LINUX: Final[str] = f"cat {_PAYLOAD_NAME}"

_NOT_FOUND_EXIT: Final[int] = 1
_COMMAND_NOT_FOUND_EXIT: Final[int] = 127
_BASH_USAGE_EXIT: Final[int] = 1
_AGENT_CONNECT_TIMEOUT: Final[float] = 5.0
_COMMAND_TIME_LIMIT: Final[int] = 5


def _split_windows_line(line: str) -> list[str]:
    """Split one ``cmd.exe`` command line into operands.

    Double quotes group an operand and are removed with it; every unquoted run
    of whitespace ends one.

    Args:
        line: Command line as the interpreter received it.

    Returns:
        list[str]: Operands with their grouping quotes stripped.
    """
    operands: list[str] = []
    current: list[str] = []
    quoted = False
    for char in line:
        if char == '"':
            quoted = not quoted
            continue
        if char.isspace() and not quoted:
            if current:
                operands.append("".join(current))
                current = []
            continue
        current.append(char)
    if current:
        operands.append("".join(current))
    return operands


def _split_chain(line: str, operands: Sequence[str]) -> list[str]:
    """Split a command line at its top-level ``&&`` separators.

    Both interpreters parse the separator before the command that precedes it,
    so a ``cd`` never sees the rest of the chain however lenient it is about
    what else it takes.

    Args:
        line: Command line as the interpreter received it.
        operands: The line's operands, already tokenised by that interpreter.

    Returns:
        list[str]: One raw command text per link of the chain.
    """
    if _CHAIN not in operands:
        return [line.strip()]
    return [segment.strip() for segment in line.split(_CHAIN)]


@dataclass
class _WindowsShell:
    """The volume-aware current directory one ``cmd.exe`` instance carries.

    ``cmd.exe`` remembers a current directory per volume and has exactly one
    current volume; ``cd`` moves the former and only ``cd /d`` moves the
    latter.

    Attributes:
        drive: Volume the shell is currently on.
        directories: Current directory of every volume the shell has one for.
    """

    drive: str
    directories: dict[str, str] = field(default_factory=dict)

    def current(self) -> str:
        """Return the directory this shell resolves relative paths against.

        Returns:
            str: Absolute directory on the shell's current volume.
        """
        return self.directories.get(self.drive, f"{self.drive}{_SEPARATOR}")


class _WindowsGuestShell:
    """A Windows guest whose ``cmd.exe`` really changes directory.

    Every ``/c`` invocation gets a fresh shell starting where the in-guest
    agent's own process sits, because that is what the agent's launcher hands
    each command. The volumes are backed by real directories on the host, so a
    command that reads a file reads whichever file the shell's current
    directory actually holds.

    Attributes:
        change_directory_operands: The operand vector of every ``cd`` the guest
            parsed, which is where an unquoted path is still visible even
            though ``CD`` goes on to accept it.
        command_lines: Every command line the guest was handed.
    """

    change_directory_operands: list[tuple[str, ...]]
    command_lines: list[str]

    def __init__(self, volumes: dict[str, Path], start_directory: str = _WINDOWS_START_DIRECTORY) -> None:
        """Configure the modelled guest.

        Args:
            volumes: Host directory backing each volume the guest owns, keyed
                by drive designator.
            start_directory: Directory every shell the agent starts begins in.
        """
        self._volumes = dict(volumes)
        self._start_directory = start_directory
        self.change_directory_operands = []
        self.command_lines = []

    def __call__(self, path: str, args: Sequence[str]) -> GuestCommandResult:
        """Execute one dispatched command against the modelled guest.

        Args:
            path: Executable the host dispatched.
            args: Argument list passed with it.

        Returns:
            GuestCommandResult: Exit status and captured output.
        """
        argv = list(args)
        if path.lower() != _WINDOWS_SHELL or argv[:1] != [_WINDOWS_SHELL_FLAG]:
            return GuestCommandResult(
                exit_code=_COMMAND_NOT_FOUND_EXIT,
                stdout="",
                stderr=f"'{path}' is not recognized as an internal or external command",
            )
        line = " ".join(argv[1:])
        self.command_lines.append(line)
        return self.run_lines([line])

    def run_lines(self, lines: Sequence[str]) -> GuestCommandResult:
        """Run consecutive command lines in one shell, as a batch file does.

        Args:
            lines: Command lines to run in order.

        Returns:
            GuestCommandResult: Output of the whole run, stopping at the first
            command that fails.
        """
        shell = _WindowsShell(drive=self._start_directory[:2], directories={self._start_directory[:2]: self._start_directory})
        stdout: list[str] = []
        result = GuestCommandResult(exit_code=0, stdout="", stderr="")
        for line in lines:
            for command in _split_chain(line, _split_windows_line(line)):
                result = self._run_command(shell, command)
                stdout.append(result.stdout)
                if result.exit_code != 0:
                    return GuestCommandResult(exit_code=result.exit_code, stdout="".join(stdout), stderr=result.stderr)
        return GuestCommandResult(exit_code=result.exit_code, stdout="".join(stdout), stderr=result.stderr)

    def _run_command(self, shell: _WindowsShell, command: str) -> GuestCommandResult:
        """Run one command of a chain in the given shell.

        Args:
            shell: Shell whose current directory the command resolves against.
            command: Raw text of the command.

        Returns:
            GuestCommandResult: Outcome of the command.
        """
        operands = _split_windows_line(command)
        if not operands:
            return GuestCommandResult(exit_code=0, stdout="", stderr="")
        name = operands[0].lower()
        if name == _CHANGE_DIRECTORY:
            return self._run_change_directory(shell, command, operands[1:])
        if name == "type":
            return self._run_type(shell, operands[1:])
        return GuestCommandResult(
            exit_code=_COMMAND_NOT_FOUND_EXIT,
            stdout="",
            stderr=f"'{operands[0]}' is not recognized as an internal or external command",
        )

    def _run_change_directory(self, shell: _WindowsShell, command: str, operands: Sequence[str]) -> GuestCommandResult:
        r"""Change directory the way ``cmd.exe``'s ``CD`` really does.

        With command extensions enabled - the default - ``CD`` takes the whole
        remainder of the command as the path rather than its first word, so an
        unquoted directory carrying spaces is still found. What it will not do
        without ``/d`` is move the shell to another volume: the volume's own
        current directory is updated and the shell stays where it was, with
        nothing in the exit status to say so.

        Args:
            shell: Shell being moved.
            command: Raw text of the ``cd`` command.
            operands: Operands following ``cd``.

        Returns:
            GuestCommandResult: Exit 0 when the directory exists.
        """
        self.change_directory_operands.append(tuple(operands))
        switched = bool(operands) and operands[0].lower() == _DRIVE_SWITCH
        remainder = command.strip()[len(_CHANGE_DIRECTORY) :].strip()
        if switched:
            remainder = remainder[len(_DRIVE_SWITCH) :].strip()
        target = remainder.strip('"')
        if not target:
            return GuestCommandResult(exit_code=0, stdout=f"{shell.current()}\n", stderr="")

        drive, directory = self._resolve_directory(shell, target)
        host_directory = self._host_path(drive, directory)
        if host_directory is None or not host_directory.is_dir():
            return GuestCommandResult(
                exit_code=_NOT_FOUND_EXIT,
                stdout="",
                stderr="The system cannot find the path specified.",
            )
        shell.directories[drive] = directory
        if switched:
            shell.drive = drive
        return GuestCommandResult(exit_code=0, stdout="", stderr="")

    @staticmethod
    def _resolve_directory(shell: _WindowsShell, target: str) -> tuple[str, str]:
        """Resolve one ``cd`` operand to an absolute volume and directory.

        Args:
            shell: Shell the operand is resolved against.
            target: Operand as ``CD`` received it.

        Returns:
            tuple[str, str]: Volume designator and absolute directory on it.
        """
        if len(target) >= _TWO_CHARACTERS and target[1] == ":":
            drive = target[:2].upper()
            remainder = target[2:].lstrip(_SEPARATOR)
            base = f"{drive}{_SEPARATOR}"
            return drive, f"{base}{remainder}".rstrip(_SEPARATOR) or base
        current = shell.current().rstrip(_SEPARATOR)
        return shell.drive, f"{current}{_SEPARATOR}{target.lstrip(_SEPARATOR)}"

    def _run_type(self, shell: _WindowsShell, operands: Sequence[str]) -> GuestCommandResult:
        """Print one file, resolved against the shell's current directory.

        Args:
            shell: Shell whose current directory the operand resolves against.
            operands: Operands following ``type``.

        Returns:
            GuestCommandResult: Exit 0 with the file's contents.
        """
        if not operands:
            return GuestCommandResult(exit_code=_NOT_FOUND_EXIT, stdout="", stderr="The syntax of the command is incorrect.")
        drive, target = self._resolve_directory(shell, operands[0])
        host_file = self._host_path(drive, target)
        if host_file is None or not host_file.is_file():
            return GuestCommandResult(
                exit_code=_NOT_FOUND_EXIT,
                stdout="",
                stderr=f"The system cannot find the file specified. - {operands[0]}",
            )
        return GuestCommandResult(exit_code=0, stdout=host_file.read_text(encoding="utf-8"), stderr="")

    def _host_path(self, drive: str, guest_path: str) -> Path | None:
        """Translate an absolute in-guest path to the host path backing it.

        Args:
            drive: Volume the path is on.
            guest_path: Absolute in-guest path.

        Returns:
            Path | None: Backing host path, or None for a volume this guest
            does not have.
        """
        root = self._volumes.get(drive.upper())
        if root is None:
            return None
        relative = guest_path[len(drive) :].strip(_SEPARATOR)
        return root.joinpath(*relative.split(_SEPARATOR)) if relative else root


class _LinuxGuestShell:
    """A Linux guest whose ``/bin/bash`` really changes directory.

    The command line is split into words by :mod:`shlex`, which applies the
    shell's own quoting rules, so an unquoted path carrying a space arrives as
    two words and ``cd`` refuses it the way ``bash`` does - and the ``&&``
    chain stops there.

    Attributes:
        change_directory_operands: Word vector of every ``cd`` the guest ran.
        command_lines: Every command line the guest was handed.
    """

    change_directory_operands: list[tuple[str, ...]]
    command_lines: list[str]

    def __init__(self, root: Path, start_directory: str = _LINUX_START_DIRECTORY) -> None:
        """Configure the modelled guest.

        Args:
            root: Host directory backing the guest's filesystem root.
            start_directory: Directory every shell the agent starts begins in.
        """
        self._root = root
        self._start_directory = start_directory
        self.change_directory_operands = []
        self.command_lines = []

    def __call__(self, path: str, args: Sequence[str]) -> GuestCommandResult:
        """Execute one dispatched command against the modelled guest.

        Args:
            path: Executable the host dispatched.
            args: Argument list passed with it.

        Returns:
            GuestCommandResult: Exit status and captured output.
        """
        argv = list(args)
        if path != _LINUX_SHELL or argv[:1] != [_LINUX_SHELL_FLAG]:
            return GuestCommandResult(
                exit_code=_COMMAND_NOT_FOUND_EXIT,
                stdout="",
                stderr=f"{path}: command not found",
            )
        line = " ".join(argv[1:])
        self.command_lines.append(line)
        return self.run_lines([line])

    def run_lines(self, lines: Sequence[str]) -> GuestCommandResult:
        """Run consecutive command lines in one shell, as a script does.

        Args:
            lines: Command lines to run in order.

        Returns:
            GuestCommandResult: Output of the whole run, stopping at the first
            command that fails.
        """
        cwd = self._start_directory
        stdout: list[str] = []
        result = GuestCommandResult(exit_code=0, stdout="", stderr="")
        for line in lines:
            for command in _split_chain(line, self._words(line)):
                result, cwd = self._run_command(cwd, command)
                stdout.append(result.stdout)
                if result.exit_code != 0:
                    return GuestCommandResult(exit_code=result.exit_code, stdout="".join(stdout), stderr=result.stderr)
        return GuestCommandResult(exit_code=result.exit_code, stdout="".join(stdout), stderr=result.stderr)

    @staticmethod
    def _words(text: str) -> list[str]:
        """Split text into words under the shell's quoting rules.

        Args:
            text: Command text to split.

        Returns:
            list[str]: Words with their quotes removed, or the raw text as one
            word when the quoting is unbalanced.
        """
        try:
            return shlex.split(text)
        except ValueError:
            return [text]

    def _run_command(self, cwd: str, command: str) -> tuple[GuestCommandResult, str]:
        """Run one command of a chain.

        Args:
            cwd: Directory the command resolves relative paths against.
            command: Raw text of the command.

        Returns:
            tuple[GuestCommandResult, str]: Outcome and the working directory
            the next command inherits.
        """
        words = self._words(command)
        if not words:
            return GuestCommandResult(exit_code=0, stdout="", stderr=""), cwd
        if words[0] == _CHANGE_DIRECTORY:
            return self._run_change_directory(cwd, words[1:])
        if words[0] == "cat":
            return self._run_cat(cwd, words[1:]), cwd
        return (
            GuestCommandResult(exit_code=_COMMAND_NOT_FOUND_EXIT, stdout="", stderr=f"bash: {words[0]}: command not found"),
            cwd,
        )

    def _run_change_directory(self, cwd: str, operands: Sequence[str]) -> tuple[GuestCommandResult, str]:
        """Change directory the way ``bash``'s ``cd`` builtin does.

        Args:
            cwd: Current working directory.
            operands: Words following ``cd``.

        Returns:
            tuple[GuestCommandResult, str]: Outcome and the resulting working
            directory.
        """
        self.change_directory_operands.append(tuple(operands))
        if len(operands) > 1:
            return GuestCommandResult(exit_code=_BASH_USAGE_EXIT, stdout="", stderr="bash: cd: too many arguments"), cwd
        target = self._resolve(cwd, operands[0]) if operands else _LINUX_START_DIRECTORY
        host_directory = self._host_path(target)
        if not host_directory.is_dir():
            return (
                GuestCommandResult(exit_code=_BASH_USAGE_EXIT, stdout="", stderr=f"bash: cd: {operands[0]}: No such file or directory"),
                cwd,
            )
        return GuestCommandResult(exit_code=0, stdout="", stderr=""), target

    def _run_cat(self, cwd: str, operands: Sequence[str]) -> GuestCommandResult:
        """Print one file, resolved against the current working directory.

        Args:
            cwd: Current working directory.
            operands: Words following ``cat``.

        Returns:
            GuestCommandResult: Exit 0 with the file's contents.
        """
        if not operands:
            return GuestCommandResult(exit_code=_BASH_USAGE_EXIT, stdout="", stderr="cat: missing operand")
        host_file = self._host_path(self._resolve(cwd, operands[0]))
        if not host_file.is_file():
            return GuestCommandResult(
                exit_code=_NOT_FOUND_EXIT,
                stdout="",
                stderr=f"cat: {operands[0]}: No such file or directory",
            )
        return GuestCommandResult(exit_code=0, stdout=host_file.read_text(encoding="utf-8"), stderr="")

    @staticmethod
    def _resolve(cwd: str, target: str) -> str:
        """Resolve one operand against the current working directory.

        Args:
            cwd: Current working directory.
            target: Operand as the command received it.

        Returns:
            str: Absolute in-guest path.
        """
        if target.startswith("/"):
            return target
        return f"{cwd.rstrip('/')}/{target}"

    def _host_path(self, guest_path: str) -> Path:
        """Translate an absolute in-guest path to the host path backing it.

        Args:
            guest_path: Absolute in-guest path.

        Returns:
            Path: Backing host path.
        """
        parts = [part for part in guest_path.split("/") if part]
        return self._root.joinpath(*parts) if parts else self._root


class _CommandTestSandbox(QEMUSandbox):
    """``QEMUSandbox`` subclass wired to a real in-guest agent by the test.

    Only the connection is arranged here; ``run_command`` and the execution
    script generator are the production implementations.
    """

    async def connect_agent(self) -> None:
        """Connect the real guest-agent client to the modelled in-guest agent."""
        agent = GuestAgentClient(port=self._qemu_config.agent_port)
        await self._ensure_agent_connected(agent, _AGENT_CONNECT_TIMEOUT)
        self._agent = agent

    async def close_agent(self) -> None:
        """Disconnect the guest-agent client the test opened."""
        if self._agent is not None:
            await self._agent.disconnect()
            self._agent = None

    def mark_running(self) -> None:
        """Put the sandbox in the state its data-plane methods require."""
        self.state.status = "running"

    def execution_script(self, command: str, working_directory: str) -> str:
        """Return the real generated in-guest execution script.

        Args:
            command: Command the script is to run in the guest.
            working_directory: Directory the script must run it from.

        Returns:
            str: Body of the script the shared-folder fallback writes.
        """
        _name, content = self._generate_execution_script(
            command=command,
            working_directory=working_directory,
            script_id="s17d23",
            result_name="result_s17d23.txt",
            stdout_name="s17d23.stdout",
            stderr_name="s17d23.stderr",
        )
        return content


def _script_change_directory_line(script: str) -> str:
    """Return the ``cd`` line a generated execution script carries.

    Args:
        script: Body of the generated script.

    Returns:
        str: The script's directory-changing line.

    Raises:
        AssertionError: If the script changes directory nowhere.
    """
    for raw_line in script.splitlines():
        line = raw_line.strip()
        if line.lower().startswith(f"{_CHANGE_DIRECTORY} "):
            return line
    msg = f"the generated execution script never changes directory: {script!r}"
    raise AssertionError(msg)


@asynccontextmanager
async def _guest_session(
    responder: _WindowsGuestShell | _LinuxGuestShell,
    guest_os: GuestOS,
) -> AsyncGenerator[_CommandTestSandbox]:
    """Run a sandbox against a real in-guest agent backed by a guest model.

    Args:
        responder: Guest model executing every dispatched command line.
        guest_os: Guest OS family to configure on the sandbox.

    Yields:
        _CommandTestSandbox: Started sandbox whose agent is connected.
    """
    server = IntellicrackAgentServer(responder)
    await server.start()
    sandbox = _CommandTestSandbox(
        config=SandboxConfig(),
        qemu_config=QEMUConfig(guest_os=guest_os, agent_port=server.port, agent_connect_timeout=_AGENT_CONNECT_TIMEOUT),
    )
    try:
        await sandbox.connect_agent()
        sandbox.mark_running()
        yield sandbox
    finally:
        await sandbox.close_agent()
        await server.stop()


def _windows_volumes(tmp_path: Path) -> dict[str, Path]:
    """Create the host directories backing the modelled guest's volumes.

    The volume the shell starts on carries a file with the same name as the one
    in the working directory, so a command that never left it succeeds while
    reading the wrong file.

    Args:
        tmp_path: Directory the volumes are created under.

    Returns:
        dict[str, Path]: Host directory backing each volume.
    """
    system = tmp_path / "system"
    share = tmp_path / "share"
    start = system.joinpath(*_WINDOWS_START_DIRECTORY[len(_SYSTEM_DRIVE) :].strip(_SEPARATOR).split(_SEPARATOR))
    start.mkdir(parents=True)
    (start / _PAYLOAD_NAME).write_text(_DECOY_PAYLOAD, encoding="utf-8")
    for directory in (_WINDOWS_WORK_DIRECTORY, _WINDOWS_SPACED_WORK_DIRECTORY):
        work = share.joinpath(*directory[len(_SHARE_DRIVE) :].strip(_SEPARATOR).split(_SEPARATOR))
        work.mkdir(parents=True)
        (work / _PAYLOAD_NAME).write_text(_WORK_PAYLOAD, encoding="utf-8")
    return {_SYSTEM_DRIVE: system, _SHARE_DRIVE: share}


def _linux_root(tmp_path: Path) -> Path:
    """Create the host directory tree backing the modelled guest's filesystem.

    Args:
        tmp_path: Directory the tree is created under.

    Returns:
        Path: Host directory backing the guest's root.
    """
    root = tmp_path / "guestfs"
    root.mkdir()
    (root / _PAYLOAD_NAME).write_text(_DECOY_PAYLOAD, encoding="utf-8")
    for directory in (_LINUX_WORK_DIRECTORY, _LINUX_SPACED_WORK_DIRECTORY):
        work = root.joinpath(*[part for part in directory.split("/") if part])
        work.mkdir(parents=True)
        (work / _PAYLOAD_NAME).write_text(_WORK_PAYLOAD, encoding="utf-8")
    return root


class TestWorkingDirectoryReachesAnotherVolume:
    """A Windows working directory off the shell's volume must take effect."""

    @pytest.mark.asyncio
    async def test_command_runs_on_the_volume_the_working_directory_names(
        self,
        tmp_path: Path,
    ) -> None:
        r"""The command must read the share's file, not the boot volume's.

        The in-guest agent's shells start on ``D:``; the working directory is
        on the share, which landed on ``E:``. A ``cd`` without ``/d`` updates
        ``E:``'s remembered directory, exits 0, and leaves the shell on ``D:``,
        where a file of the same name is waiting - so the command succeeds and
        returns the wrong bytes, which is the failure the exit status alone
        cannot show.

        Args:
            tmp_path: Directory the guest's volumes are created under.
        """
        guest = _WindowsGuestShell(_windows_volumes(tmp_path))
        async with _guest_session(guest, GuestOS.WINDOWS) as sandbox:
            exit_code, stdout, stderr = await sandbox.run_command(
                _READ_COMMAND_WINDOWS,
                time_limit=_COMMAND_TIME_LIMIT,
                working_directory=_WINDOWS_WORK_DIRECTORY,
            )

            assert exit_code == 0, f"the guest could not run the composed command line: {stderr!r} ({guest.command_lines})"
            assert stdout != _DECOY_PAYLOAD, (
                f"the command ran in {_WINDOWS_START_DIRECTORY} instead of {_WINDOWS_WORK_DIRECTORY} "
                f"and still reported success: {guest.command_lines}"
            )
            assert stdout == _WORK_PAYLOAD, f"the command did not run in {_WINDOWS_WORK_DIRECTORY}: {stdout!r}"

    @pytest.mark.asyncio
    async def test_a_working_directory_that_does_not_exist_is_reported(
        self,
        tmp_path: Path,
    ) -> None:
        r"""A directory the guest does not have must fail instead of running.

        The ``&&`` is what makes that hold: the ``cd`` fails, and the command
        after it never runs in whatever directory the shell was left in.

        Args:
            tmp_path: Directory the guest's volumes are created under.
        """
        guest = _WindowsGuestShell(_windows_volumes(tmp_path))
        async with _guest_session(guest, GuestOS.WINDOWS) as sandbox:
            exit_code, stdout, _stderr = await sandbox.run_command(
                _READ_COMMAND_WINDOWS,
                time_limit=_COMMAND_TIME_LIMIT,
                working_directory=f"{_SHARE_DRIVE}{_SEPARATOR}nowhere",
            )

            assert exit_code != 0, "a working directory the guest does not have was reported as a success"
            assert not stdout, f"the command ran even though its working directory does not exist: {stdout!r}"


class TestWorkingDirectorySurvivesItsSpaces:
    """A working directory carrying a space must reach ``cd`` as one operand."""

    @pytest.mark.asyncio
    async def test_linux_guest_enters_a_directory_whose_name_has_a_space(
        self,
        tmp_path: Path,
    ) -> None:
        """``/bin/bash`` splits an unquoted path and refuses the ``cd``.

        Two operands make ``cd`` answer ``too many arguments``, so the ``&&``
        chain stops and the command never runs at all.

        Args:
            tmp_path: Directory the guest's filesystem is created under.
        """
        guest = _LinuxGuestShell(_linux_root(tmp_path))
        async with _guest_session(guest, GuestOS.LINUX) as sandbox:
            exit_code, stdout, stderr = await sandbox.run_command(
                _READ_COMMAND_LINUX,
                time_limit=_COMMAND_TIME_LIMIT,
                working_directory=_LINUX_SPACED_WORK_DIRECTORY,
            )

            assert guest.change_directory_operands == [(_LINUX_SPACED_WORK_DIRECTORY,)], (
                f"the working directory reached the guest's cd as {guest.change_directory_operands}: {guest.command_lines}"
            )
            assert exit_code == 0, f"the guest could not enter {_LINUX_SPACED_WORK_DIRECTORY}: {stderr!r}"
            assert stdout == _WORK_PAYLOAD, f"the command did not run in {_LINUX_SPACED_WORK_DIRECTORY}: {stdout!r}"

    @pytest.mark.asyncio
    async def test_windows_guest_receives_the_spaced_directory_as_one_operand(
        self,
        tmp_path: Path,
    ) -> None:
        r"""``cmd.exe`` must be handed the directory whole, not word by word.

        ``CD`` with command extensions takes the whole remainder of the line as
        its path, so this guest - like a real one - still enters an unquoted
        spaced directory; the exit status cannot show the difference. The
        operand vector it parsed can: the contract is that the directory is one
        operand, which is what every other consumer of that line depends on and
        what a guest with extensions disabled requires outright.

        Args:
            tmp_path: Directory the guest's volumes are created under.
        """
        guest = _WindowsGuestShell(_windows_volumes(tmp_path))
        async with _guest_session(guest, GuestOS.WINDOWS) as sandbox:
            exit_code, stdout, stderr = await sandbox.run_command(
                _READ_COMMAND_WINDOWS,
                time_limit=_COMMAND_TIME_LIMIT,
                working_directory=_WINDOWS_SPACED_WORK_DIRECTORY,
            )

            assert guest.change_directory_operands == [(_DRIVE_SWITCH, _WINDOWS_SPACED_WORK_DIRECTORY)], (
                f"the working directory reached the guest's cd as {guest.change_directory_operands}: {guest.command_lines}"
            )
            assert exit_code == 0, f"the guest could not enter {_WINDOWS_SPACED_WORK_DIRECTORY}: {stderr!r}"
            assert stdout == _WORK_PAYLOAD, f"the command did not run in {_WINDOWS_SPACED_WORK_DIRECTORY}: {stdout!r}"


class TestGeneratedScriptChangesDirectoryTheSameWay:
    """The shared-folder fallback's own ``cd`` line must hold the same rules."""

    @pytest.mark.asyncio
    async def test_windows_script_line_crosses_volumes_and_keeps_its_spaces(
        self,
        tmp_path: Path,
    ) -> None:
        """The generated batch line must land the next line in the share.

        Args:
            tmp_path: Directory the guest's volumes are created under.
        """
        guest = _WindowsGuestShell(_windows_volumes(tmp_path))
        async with _guest_session(guest, GuestOS.WINDOWS) as sandbox:
            script = sandbox.execution_script(_READ_COMMAND_WINDOWS, _WINDOWS_SPACED_WORK_DIRECTORY)

            result = guest.run_lines([_script_change_directory_line(script), _READ_COMMAND_WINDOWS])

            assert guest.change_directory_operands == [(_DRIVE_SWITCH, _WINDOWS_SPACED_WORK_DIRECTORY)], (
                f"the script's cd line reached the guest as {guest.change_directory_operands}"
            )
            assert result.exit_code == 0, f"the generated script could not enter its working directory: {result.stderr!r}"
            assert result.stdout == _WORK_PAYLOAD, f"the generated script ran its command elsewhere: {result.stdout!r}"

    @pytest.mark.asyncio
    async def test_linux_script_line_keeps_its_spaces(
        self,
        tmp_path: Path,
    ) -> None:
        """The generated shell line must land the next line in the share.

        Args:
            tmp_path: Directory the guest's filesystem is created under.
        """
        guest = _LinuxGuestShell(_linux_root(tmp_path))
        async with _guest_session(guest, GuestOS.LINUX) as sandbox:
            script = sandbox.execution_script(_READ_COMMAND_LINUX, _LINUX_SPACED_WORK_DIRECTORY)

            result = guest.run_lines([_script_change_directory_line(script), _READ_COMMAND_LINUX])

            assert guest.change_directory_operands == [(_LINUX_SPACED_WORK_DIRECTORY,)], (
                f"the script's cd line reached the guest as {guest.change_directory_operands}"
            )
            assert result.exit_code == 0, f"the generated script could not enter its working directory: {result.stderr!r}"
            assert result.stdout == _WORK_PAYLOAD, f"the generated script ran its command elsewhere: {result.stdout!r}"


class TestCommandsWithoutAWorkingDirectoryAreUntouched:
    """A command given no working directory must reach the guest unchanged."""

    @pytest.mark.asyncio
    async def test_no_working_directory_composes_no_change_directory(
        self,
        tmp_path: Path,
    ) -> None:
        """Nothing is prefixed, so the command runs where the shell starts.

        Args:
            tmp_path: Directory the guest's volumes are created under.
        """
        guest = _WindowsGuestShell(_windows_volumes(tmp_path))
        async with _guest_session(guest, GuestOS.WINDOWS) as sandbox:
            exit_code, stdout, stderr = await sandbox.run_command(
                _READ_COMMAND_WINDOWS,
                time_limit=_COMMAND_TIME_LIMIT,
            )

            assert guest.command_lines == [_READ_COMMAND_WINDOWS], f"the command line was rewritten: {guest.command_lines}"
            assert guest.change_directory_operands == [], f"a directory change was composed from nothing: {guest.change_directory_operands}"
            assert exit_code == 0, f"the guest could not run the command line: {stderr!r}"
            assert stdout == _DECOY_PAYLOAD, f"the command did not run where the agent's shell starts: {stdout!r}"


class TestTheModelledGuestsEnforceTheirOwnShellRules:
    """The guests must refuse what a real interpreter refuses."""

    def test_windows_guest_keeps_a_current_directory_per_volume(
        self,
        tmp_path: Path,
    ) -> None:
        r"""``cd`` without ``/d`` must not move the shell to another volume.

        This pins the guest itself: a model that treats ``cd`` and ``cd /d``
        alike cannot fail when the host omits the switch, and the gate built on
        it would certify the defect as fixed.

        Args:
            tmp_path: Directory the guest's volumes are created under.
        """
        guest = _WindowsGuestShell(_windows_volumes(tmp_path))

        without_switch = guest.run_lines([f"{_CHANGE_DIRECTORY} {_WINDOWS_WORK_DIRECTORY}", _READ_COMMAND_WINDOWS])
        with_switch = guest.run_lines([f'{_CHANGE_DIRECTORY} {_DRIVE_SWITCH} "{_WINDOWS_WORK_DIRECTORY}"', _READ_COMMAND_WINDOWS])

        assert without_switch.exit_code == 0, f"cd to an existing directory must succeed: {without_switch.stderr!r}"
        assert without_switch.stdout == _DECOY_PAYLOAD, "cd without /d must leave the shell on the volume it was on"
        assert with_switch.stdout == _WORK_PAYLOAD, f"cd /d must move the shell to the other volume: {with_switch.stderr!r}"

    def test_linux_guest_refuses_a_cd_with_two_operands(
        self,
        tmp_path: Path,
    ) -> None:
        """``cd`` must answer ``too many arguments`` and stop the chain.

        Args:
            tmp_path: Directory the guest's filesystem is created under.
        """
        guest = _LinuxGuestShell(_linux_root(tmp_path))

        split = guest.run_lines([f"{_CHANGE_DIRECTORY} {_LINUX_SPACED_WORK_DIRECTORY} {_CHAIN} {_READ_COMMAND_LINUX}"])
        quoted = guest.run_lines([f"{_CHANGE_DIRECTORY} '{_LINUX_SPACED_WORK_DIRECTORY}' {_CHAIN} {_READ_COMMAND_LINUX}"])

        assert split.exit_code != 0, "bash must refuse a cd carrying two operands"
        assert "too many arguments" in split.stderr
        assert not split.stdout, f"the chained command ran after cd failed: {split.stdout!r}"
        assert quoted.exit_code == 0, f"a quoted directory must be entered: {quoted.stderr!r}"
        assert quoted.stdout == _WORK_PAYLOAD

    def test_windows_shells_do_not_inherit_one_another(
        self,
        tmp_path: Path,
    ) -> None:
        """Each dispatched command line starts in the agent's own directory.

        Args:
            tmp_path: Directory the guest's volumes are created under.
        """
        guest = _WindowsGuestShell(_windows_volumes(tmp_path))

        guest.run_lines([f'{_CHANGE_DIRECTORY} {_DRIVE_SWITCH} "{_WINDOWS_WORK_DIRECTORY}"'])
        second = guest.run_lines([_READ_COMMAND_WINDOWS])

        assert second.stdout == _DECOY_PAYLOAD, "a later command line inherited an earlier shell's directory"
