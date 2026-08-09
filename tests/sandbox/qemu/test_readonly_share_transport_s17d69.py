# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S17-D69: the guest must never write to a vvfat share.

QEMU exposed the host shared folder to the guest as ``fat:rw:`` and the in-guest
agent wrote everything it produced there - monitor logs appended line by line, a
mirror of every dropped file, and the write-then-rename that publishes a command
result. QEMU's ``vvfat`` driver commits those directory changes back to the host
directory, and its commit path does not fail a write, it calls ``abort()``:
``block/vvfat.c`` reaches ``abort()`` immediately after logging ``Error handling
renames (%d)``, and reports ``cluster %d used more than once`` on the way there.
Under MSVCRT an ``abort()`` leaves exit code 3, so the whole virtual machine
disappeared mid-run - the S17-D39 "not dependable across a long run" symptom, and
the reason a staged binary could run and still deliver nothing (S17-D54).

The transport is now read-only. ``-drive file=fat:...,readonly=on`` means QEMU's
commit path is never entered at all, which required moving everything the guest
writes onto the guest's own disk under a work root - ``%SystemDrive%\intellicrack``
or ``/var/lib/intellicrack`` - and collecting it back over the qemu-guest-agent
file commands instead of reading it off the share.

Four independent facts have to hold for that to be true, and each is gated here
against real code rather than a description of it:

* the argv the production builder emits exposes the share read-only;
* the real generated in-guest agent, executed, creates its directories on the
  work root and creates nothing under the share;
* the host collects a log out of the guest over a real guest-agent channel, in
  as many reads as the file needs, and parses it into real records;
* a read of a sandbox file prefers what is in the guest over what is on the
  host side of the share, which is the sharp discriminator between the two
  transports - the two carry deliberately different bytes here.

The guest-agent halves drive the real :class:`QemuGuestAgentClient` over a real
loopback socket against :class:`GuestAgentProtocolServer`, which models the
agent's file commands and keeps the bytes it was handed, so every assertion is
made on what actually crossed the channel.
"""

from __future__ import annotations

import ast
import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
import pytest_asyncio

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import AcceleratorType, GuestOS, QEMUConfig, QemuGuestAgentClient, QEMUSandbox
from tests.sandbox.qemu.guest_agent_server import GuestAgentProtocolServer, GuestCommandResult


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence


_AGENT_CONNECT_TIMEOUT: Final[float] = 10.0
_LINUX_WORK_ROOT: Final[str] = "/var/lib/intellicrack"
_LINUX_LOG_DIR: Final[str] = "/var/lib/intellicrack/logs"
_LINUX_SHARE_ROOT: Final[str] = "/mnt/shared"
_FILE_LOG_NAME: Final[str] = "file_changes.log"
_DROPPED_GUEST_PATH: Final[str] = "/home/analyst/payload.bin"

# The generated Windows agent's prologue ends where it starts launching
# monitors. Everything above that line only computes paths and creates the
# directories they name, which is exactly what this gate needs to observe.
_WINDOWS_PROLOGUE_MARKER: Final[str] = "$monitorScripts = @("
_ALLOWED_ROOTS_MARKER: Final[str] = "$allowedRoots = @("
_POWERSHELL_TIMEOUT_S: Final[float] = 120.0

# Two full read chunks plus a partial one, so a host that issues a single
# guest-file-read and stops - or that never advances its offset - is caught by
# the byte comparison rather than passing on a truncated prefix.
_LARGE_LOG_BYTES: Final[int] = 150_000
_MINIMUM_READS: Final[int] = 3

_SHARE_COPY_MARKER: Final[bytes] = b"stale bytes from the host side of the share\n"
_GUEST_COPY_MARKER: Final[bytes] = b"live bytes from inside the running guest\n"

_GUEST_ECHO_STDOUT: Final[str] = "ran inside the guest\n"
_GUEST_ECHO_EXIT_CODE: Final[int] = 0

# The Linux log-size probe walks its directory with ``find``. Only the operand
# is parsed out of it here; the command itself is production's to build.
_FIND_COMMAND_PREFIX: Final[str] = "find "
_QUOTED_OPERAND_PARTS: Final[int] = 3
_LOG_SUFFIX: Final[str] = ".log"
# Deliberately different sizes on the two sides of the same file name, so the
# reader cannot satisfy both. The host side is what vvfat froze at boot.
_GUEST_LOG_BODY: Final[bytes] = b"written by the monitor inside the guest\n"
_SHARE_LOG_BODY: Final[bytes] = b"frozen on the host side of the share when QEMU started, and never again\n"


class _TransportSandbox(QEMUSandbox):
    """``QEMUSandbox`` given only what a live virtual machine would provide.

    The working directory, the host side of the share, the guest-agent channel
    and the running state are arranged here. Everything under test - the argv
    builder, the collection paths, the guest-agent file transfers - is the
    production implementation.
    """

    def use_workspace(self, temp_dir: Path) -> None:
        """Point the sandbox at a working directory and its shared folder.

        Only the share root and the ``monitor`` directory the agent scripts are
        staged into are created. The ``logs`` and ``output`` directories the
        real start-up also makes are deliberately left out, so that a guest
        script which creates one of them on the share is visible here rather
        than hidden behind a directory that was there all along.

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

    def windows_agent_script(self) -> str:
        """Return the generated in-guest Windows agent source.

        Returns:
            str: The PowerShell the sandbox stages into the guest.
        """
        return self._windows_agent_script_content()

    async def write_guest_agent_scripts(self) -> None:
        """Generate the in-guest agent scripts into the shared folder."""
        await self._create_guest_agent_script()

    async def attach_agent(self, port: int) -> None:
        """Connect the real guest-agent client to the modelled agent.

        Args:
            port: Loopback port the modelled agent listens on.

        Raises:
            AssertionError: If the client cannot reach the modelled agent.
        """
        client = QemuGuestAgentClient(port=port)
        connected = await client.connect(time_limit=_AGENT_CONNECT_TIMEOUT)
        if not connected:
            msg = "the guest-agent client could not reach the modelled agent"
            raise AssertionError(msg)
        self._qga = client
        self.state.status = "running"

    async def release_agent(self) -> None:
        """Disconnect the guest-agent client this test opened."""
        if self._qga is not None:
            await self._qga.disconnect()
            self._qga = None

    async def collect_guest_logs(self) -> None:
        """Run the production log collection out of the guest."""
        await self._collect_guest_logs()

    def collected_root(self) -> Path | None:
        """Return the host directory the guest's output is collected into.

        Returns:
            Path | None: The collection root, or ``None`` when unset.
        """
        return self._collected_root()

    async def parse_collected_logs(self) -> list[str]:
        """Parse the collected monitor logs and return the changed paths.

        Returns:
            list[str]: ``path`` of every parsed file-change record, in order.
        """
        logs = await self._collect_monitoring_logs()
        return [change["path"] for change in logs.file_changes]

    async def current_log_sizes(self) -> dict[str, int]:
        """Read every monitor log's size through the production reader.

        Returns:
            dict[str, int]: Log file name to size in bytes.
        """
        return await self._current_log_sizes()


def _make_sandbox(tmp_path: Path, guest_os: GuestOS) -> _TransportSandbox:
    """Build a sandbox for one guest family with a real workspace.

    Args:
        tmp_path: Directory the sandbox treats as its own temp dir.
        guest_os: Guest family whose paths and shells apply.

    Returns:
        _TransportSandbox: Sandbox ready to be driven.
    """
    sandbox = _TransportSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=guest_os))
    sandbox.use_workspace(tmp_path)
    return sandbox


def _share_drive_argument(argv: list[str]) -> str:
    """Return the ``-drive`` value that exposes the shared folder.

    Args:
        argv: Full QEMU command line emitted by the production builder.

    Returns:
        str: The single ``-drive`` value naming a ``fat:`` file. A command line
        carrying no such drive, or more than one, fails the calling test.
    """
    values = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "-drive" and "fat:" in argv[index + 1]]
    assert len(values) == 1, f"expected exactly one fat: -drive in the launch argv, found {values!r} (S17-D69)"
    return values[0]


@pytest_asyncio.fixture
async def agent_server() -> AsyncIterator[GuestAgentProtocolServer]:
    """Run a modelled qemu-guest-agent on loopback for one test.

    Yields:
        GuestAgentProtocolServer: The started server.
    """
    server = GuestAgentProtocolServer()
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


class _LinuxFindGuest:
    """Guest model answering ``find`` out of the agent's own filesystem.

    The listing is produced from the same :attr:`GuestAgentProtocolServer.guest_files`
    mapping the agent's file commands read and write, so the sizes reported here
    are the sizes of bytes that really exist inside the modelled guest rather
    than a table written out beside the test.

    Attributes:
        listed_directories: Directory operand of every ``find`` executed, so a
            caller that walks somewhere other than the guest's work root is
            visible.
    """

    listed_directories: list[str]

    def __init__(self, guest_files: dict[str, bytearray]) -> None:
        """Adopt the modelled guest's filesystem.

        Args:
            guest_files: In-guest path to bytes, owned by the agent server.
        """
        self._guest_files = guest_files
        self.listed_directories = []

    def __call__(self, path: str, args: Sequence[str]) -> GuestCommandResult:
        """Execute one command against the modelled guest.

        Args:
            path: Executable the host dispatched.
            args: Argument list passed with it.

        Returns:
            GuestCommandResult: ``name size`` lines for a ``find`` of a
            directory the guest has files under, and an empty success for
            anything else.
        """
        del path
        payload = args[-1] if args else ""
        if not payload.startswith(_FIND_COMMAND_PREFIX):
            return GuestCommandResult()
        quoted = payload.split('"')
        if len(quoted) < _QUOTED_OPERAND_PARTS:
            return GuestCommandResult()
        directory = quoted[1]
        self.listed_directories.append(directory)
        prefix = f"{directory}/"
        lines = [
            f"{guest_path[len(prefix) :]} {len(payload_bytes)}"
            for guest_path, payload_bytes in sorted(self._guest_files.items())
            if guest_path.startswith(prefix) and "/" not in guest_path[len(prefix) :] and guest_path.endswith(_LOG_SUFFIX)
        ]
        return GuestCommandResult(exit_code=0, stdout="".join(f"{line}\n" for line in lines), stderr="")


@pytest_asyncio.fixture
async def find_agent_server() -> AsyncIterator[tuple[GuestAgentProtocolServer, _LinuxFindGuest]]:
    """Run a modelled agent whose ``find`` answers from its own filesystem.

    Yields:
        tuple[GuestAgentProtocolServer, _LinuxFindGuest]: The started server and
        the guest model answering its executed commands.
    """
    guest_files: dict[str, bytearray] = {}
    guest = _LinuxFindGuest(guest_files)
    server = GuestAgentProtocolServer(guest)
    server.guest_files = guest_files
    await server.start()
    try:
        yield (server, guest)
    finally:
        await server.stop()


class TestTheShareIsExposedReadOnly:
    """QEMU must never be asked to commit guest writes back to the share."""

    def test_the_share_drive_is_read_only(self, tmp_path: Path) -> None:
        """The production argv marks the FAT share drive read-only.

        ``readonly=on`` is what keeps vvfat out of the write-back path that
        calls ``abort()``. This drives the real command builder rather than
        restating the argument, so a builder that reverts to ``fat:rw:`` fails
        here regardless of how the string is assembled.

        Args:
            tmp_path: Per-test directory holding the image and the share.
        """
        image = tmp_path / "guest.qcow2"
        image.write_bytes(b"QFI\xfb" + bytes(64))
        sandbox = _make_sandbox(tmp_path, GuestOS.WINDOWS)
        sandbox.qemu_config.image_path = image
        sandbox.force_accelerator(AcceleratorType.TCG)
        sandbox.set_qemu_path(tmp_path / "qemu-system-x86_64.exe")

        drive = _share_drive_argument(sandbox.build_command())

        assert "readonly=on" in drive, f"the share drive {drive!r} is not read-only, so vvfat can still abort the VM (S17-D69)"

    def test_no_argument_asks_vvfat_to_write_back(self, tmp_path: Path) -> None:
        """No launch argument requests a writable FAT volume.

        ``fat:rw:`` is the exact spelling that enables the commit path, and
        ``snapshot=off`` was what directed those commits at the host directory.
        Neither may survive anywhere in the command line.

        Args:
            tmp_path: Per-test directory holding the image and the share.
        """
        image = tmp_path / "guest.qcow2"
        image.write_bytes(b"QFI\xfb" + bytes(64))
        sandbox = _make_sandbox(tmp_path, GuestOS.LINUX)
        sandbox.qemu_config.image_path = image
        sandbox.force_accelerator(AcceleratorType.TCG)
        sandbox.set_qemu_path(tmp_path / "qemu-system-x86_64")

        argv = sandbox.build_command()

        writable = [item for item in argv if "fat:rw:" in item]
        assert not writable, f"the launch argv still asks vvfat for write-back: {writable!r} (S17-D69)"


class TestTheGeneratedGuestAgentWritesToItsOwnDisk:
    """The in-guest agent must build every writable path on the work root."""

    @pytest.mark.skipif(sys.platform != "win32", reason="the generated Windows agent is PowerShell and needs Windows to run")
    def test_the_windows_agent_creates_its_directories_off_the_share(self, tmp_path: Path) -> None:
        r"""Running the real agent prologue creates nothing under the share.

        The prologue is lifted from the generated script rather than rewritten,
        and executed: it resolves ``$shareRoot`` from its own location exactly
        as it does inside a guest, and honours ``%SystemDrive%``, which is
        redirected here so the directories it really creates land under the
        test's own directory. What is asserted is the filesystem afterwards -
        ``<work root>\logs`` exists, ``<share>\logs`` does not.

        Args:
            tmp_path: Per-test directory standing in for the guest's disk.
        """
        sandbox = _make_sandbox(tmp_path, GuestOS.WINDOWS)
        script = sandbox.windows_agent_script()
        marker = script.find(_WINDOWS_PROLOGUE_MARKER)
        assert marker > 0, (
            f"the generated Windows agent no longer contains {_WINDOWS_PROLOGUE_MARKER!r}, so its prologue cannot be lifted (S17-D69)"
        )

        share = tmp_path / "shared"
        prologue = share / "monitor" / "agent_prologue.ps1"
        prologue.write_text(script[:marker], encoding="utf-8")

        guest_disk = tmp_path / "guestdisk"
        guest_disk.mkdir(parents=True, exist_ok=True)
        powershell = shutil.which("powershell") or shutil.which("pwsh")
        assert powershell is not None, "no PowerShell interpreter is available to run the generated guest agent (S17-D69)"

        # Only %SystemDrive% is redirected, so the directories the agent really
        # creates land under this test's own directory. %SystemRoot% is left
        # alone: PowerShell itself loads the CLR through it and cannot start at
        # all if it is pointed somewhere else.
        environment = dict(os.environ)
        environment["SystemDrive"] = str(guest_disk)
        completed = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(prologue)],
            capture_output=True,
            text=True,
            timeout=_POWERSHELL_TIMEOUT_S,
            check=False,
            env=environment,
        )

        assert completed.returncode == 0, f"the generated agent prologue failed: rc={completed.returncode} stderr={completed.stderr!r}"
        assert (guest_disk / "intellicrack" / "logs").is_dir(), (
            f"the agent did not build its log directory on the guest's own disk; stderr={completed.stderr!r} (S17-D69)"
        )
        assert (guest_disk / "intellicrack" / "output" / "dropped").is_dir(), (
            "the agent did not mirror dropped files onto the guest's own disk (S17-D69)"
        )
        assert not (share / "logs").exists(), (
            "the agent created a log directory on the read-only share, which is the write vvfat aborts on (S17-D69)"
        )
        assert not (share / "output").exists(), "the agent created an output directory on the read-only share (S17-D69)"

    def test_the_windows_agent_trusts_its_own_work_root(self, tmp_path: Path) -> None:
        """A binary staged into the work root stays executable in the guest.

        The in-guest allowlist is what decides whether the agent will run a
        staged executable at all. Moving staged files off the share is only
        safe if the allowlist moved with them, so the generated script's own
        ``$allowedRoots`` line is read back and checked for the work root.

        Args:
            tmp_path: Per-test directory the sandbox uses as its workspace.
        """
        sandbox = _make_sandbox(tmp_path, GuestOS.WINDOWS)
        script = sandbox.windows_agent_script()
        allowed = [line for line in script.splitlines() if line.startswith(_ALLOWED_ROOTS_MARKER)]
        assert len(allowed) == 1, (
            f"the generated Windows agent no longer has a single {_ALLOWED_ROOTS_MARKER!r} line: {allowed!r} (S17-D69)"
        )
        assert "$workRootPrefix" in allowed[0], (
            f"the in-guest allowlist {allowed[0]!r} does not accept the work root, so a staged binary cannot be run (S17-D69)"
        )

    @pytest.mark.asyncio
    async def test_the_linux_agent_builds_its_paths_on_the_work_root(self, tmp_path: Path) -> None:
        """The generated Linux agent's own path expressions resolve off the share.

        The three module-level assignments are lifted out of the generated
        source and evaluated, so what is asserted is the value production
        computes, not a copy of the source line.

        Args:
            tmp_path: Per-test directory the sandbox uses as its workspace.
        """
        sandbox = _make_sandbox(tmp_path, GuestOS.LINUX)
        await sandbox.write_guest_agent_scripts()
        source = (tmp_path / "shared" / "monitor" / "agent.py").read_text(encoding="utf-8")

        wanted = ("WORK_ROOT", "LOG_DIR", "DROPPED_MIRROR_DIR")
        module = ast.parse(source)
        assignments: dict[str, ast.expr] = {}
        for node in module.body:
            if not isinstance(node, ast.AnnAssign | ast.Assign):
                continue
            name = _assigned_name(node)
            if name in wanted and node.value is not None:
                assignments[name] = node.value
        assert set(assignments) == set(wanted), f"the generated Linux agent no longer assigns {wanted!r} at module level (S17-D69)"

        resolved_paths: dict[str, Path] = {}
        for name in wanted:
            resolved_paths[name] = _evaluate_path(assignments[name], resolved_paths)

        for name in wanted:
            resolved = resolved_paths[name].as_posix()
            assert resolved.startswith(_LINUX_WORK_ROOT), (
                f"the Linux agent writes {name} to {resolved!r}, which is not on the guest's own disk (S17-D69)"
            )
            assert not resolved.startswith(_LINUX_SHARE_ROOT), (
                f"the Linux agent still writes {name} onto the share at {resolved!r} (S17-D69)"
            )


def _evaluate_path(node: ast.expr, known: dict[str, Path]) -> Path:
    """Evaluate one path expression lifted from the generated agent source.

    Only the three shapes the generated agent uses are understood - a
    ``Path("...")`` call, a ``parent / "child"`` join, and a reference to a
    path assigned earlier in the same module. Anything else fails the calling
    test rather than being guessed at, because a shape this cannot read is a
    shape whose write target this gate cannot vouch for.

    Args:
        node: Expression node from the generated module.
        known: Paths already evaluated from earlier assignments.

    Returns:
        Path: The value the generated module would compute.

    Raises:
        AssertionError: If the expression is not one of those three shapes.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return Path(node.value)
    if isinstance(node, ast.Name) and node.id in known:
        return known[node.id]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Path" and len(node.args) == 1:
        return _evaluate_path(node.args[0], known)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _evaluate_path(node.left, known) / _evaluate_path(node.right, known)
    message = f"the generated Linux agent builds a path this gate cannot evaluate: {ast.unparse(node)!r} (S17-D69)"
    raise AssertionError(message)


def _assigned_name(node: ast.AnnAssign | ast.Assign) -> str:
    """Return the single name an assignment binds, if it binds exactly one.

    Args:
        node: Module-level assignment from the generated agent source.

    Returns:
        str: The bound name, or an empty string for any other shape.
    """
    targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
    if len(targets) != 1 or not isinstance(targets[0], ast.Name):
        return ""
    return targets[0].id


class TestTheHostCollectsTheGuestsLogsOverTheAgent:
    """With nothing on the share, the logs must come out through the agent."""

    @pytest.mark.asyncio
    async def test_a_guest_log_becomes_a_parsed_record(self, tmp_path: Path, agent_server: GuestAgentProtocolServer) -> None:
        """A monitor log written inside the guest reaches the report parsers.

        The log exists only inside the modelled guest, at the work-root path
        the real agent writes to. A host that still reads the share collects
        nothing and parses nothing, so the parsed record is the whole
        assertion.

        Args:
            tmp_path: Per-test directory the sandbox uses as its workspace.
            agent_server: Modelled qemu-guest-agent holding the guest's files.
        """
        sandbox = _make_sandbox(tmp_path, GuestOS.LINUX)
        agent_server.guest_files[f"{_LINUX_LOG_DIR}/{_FILE_LOG_NAME}"] = bytearray(
            f"2026-08-09T10:00:00|created|{_DROPPED_GUEST_PATH}||1024\n".encode(),
        )
        await sandbox.attach_agent(agent_server.port)
        try:
            await sandbox.collect_guest_logs()
            changed = await sandbox.parse_collected_logs()
        finally:
            await sandbox.release_agent()

        assert changed == [_DROPPED_GUEST_PATH], f"the guest's file-change log did not reach the parsers; got {changed!r} (S17-D69)"

    @pytest.mark.asyncio
    async def test_a_log_larger_than_one_read_arrives_whole(self, tmp_path: Path, agent_server: GuestAgentProtocolServer) -> None:
        """A log spanning several agent reads is collected byte for byte.

        The agent returns at most ``count`` bytes per read and flags the end of
        the file itself. A host that stops at the first buffer would collect a
        prefix and parse a truncated last line, so both the byte count and the
        number of reads are checked.

        Args:
            tmp_path: Per-test directory the sandbox uses as its workspace.
            agent_server: Modelled qemu-guest-agent holding the guest's files.
        """
        line = b"2026-08-09T10:00:00|created|/tmp/big.bin||7\n"
        payload = bytearray(line * (_LARGE_LOG_BYTES // len(line)))
        guest_path = f"{_LINUX_LOG_DIR}/{_FILE_LOG_NAME}"
        agent_server.guest_files[guest_path] = payload

        sandbox = _make_sandbox(tmp_path, GuestOS.LINUX)
        await sandbox.attach_agent(agent_server.port)
        try:
            await sandbox.collect_guest_logs()
        finally:
            await sandbox.release_agent()

        collected = sandbox.collected_root()
        assert collected is not None
        landed = collected / "logs" / _FILE_LOG_NAME
        assert landed.read_bytes() == bytes(payload), "the collected log does not match the bytes inside the guest (S17-D69)"
        reads = [size for path, size in agent_server.file_reads if path == guest_path]
        assert len(reads) >= _MINIMUM_READS, (
            f"the host read the guest log in {len(reads)} request(s), so it is not following the agent's eof flag (S17-D69)"
        )


class TestLogGrowthIsMeasuredWhereTheGuestWrites:
    """Readiness must watch the logs the guest is really appending to."""

    @pytest.mark.asyncio
    async def test_the_sizes_come_from_the_guest_not_the_host_side_of_the_share(
        self,
        tmp_path: Path,
        find_agent_server: tuple[GuestAgentProtocolServer, _LinuxFindGuest],
    ) -> None:
        """``_current_log_sizes`` reports the bytes inside the running guest.

        The same log name carries deliberately different content on each side.
        vvfat froze the host side of the share when QEMU started, so a reader
        that stats it sees a size that never changes and declares every monitor
        instantly stable - the readiness check would then return before a single
        line had been written. The size that comes back is therefore the whole
        assertion, and the directory the guest was asked to walk is checked as
        well so a reader that asks about the share's path cannot pass.

        Args:
            tmp_path: Per-test directory the sandbox uses as its workspace.
            find_agent_server: Modelled agent and the guest model behind it.
        """
        server, guest = find_agent_server
        server.guest_files[f"{_LINUX_LOG_DIR}/{_FILE_LOG_NAME}"] = bytearray(_GUEST_LOG_BODY)
        share_log = tmp_path / "shared" / "logs" / _FILE_LOG_NAME
        share_log.parent.mkdir(parents=True, exist_ok=True)
        share_log.write_bytes(_SHARE_LOG_BODY)

        sandbox = _make_sandbox(tmp_path, GuestOS.LINUX)
        await sandbox.attach_agent(server.port)
        try:
            sizes = await sandbox.current_log_sizes()
        finally:
            await sandbox.release_agent()

        assert sizes[_FILE_LOG_NAME] == len(_GUEST_LOG_BODY), (
            f"the readiness check measured {sizes[_FILE_LOG_NAME]} bytes, not the {len(_GUEST_LOG_BODY)} the guest holds (S17-D69)"
        )
        assert guest.listed_directories == [_LINUX_LOG_DIR], (
            f"the guest was asked to walk {guest.listed_directories!r} rather than its own log directory (S17-D69)"
        )


class TestASandboxReadPrefersTheGuestOverTheShare:
    """The running guest, not the stale host directory, is the source of truth."""

    @pytest.mark.asyncio
    async def test_the_guest_bytes_win_over_a_host_side_copy(self, tmp_path: Path, agent_server: GuestAgentProtocolServer) -> None:
        """``copy_from_sandbox`` returns what the guest holds, not the share.

        Both locations are populated with deliberately different bytes. vvfat
        froze the share at boot, so the host-side copy is exactly the stale
        content a read of the share would hand back - which makes the returned
        bytes a sharp discriminator between the two transports.

        Args:
            tmp_path: Per-test directory the sandbox uses as its workspace.
            agent_server: Modelled qemu-guest-agent holding the guest's files.
        """
        relative = "output/result.txt"
        share_copy = tmp_path / "shared" / "output" / "result.txt"
        share_copy.parent.mkdir(parents=True, exist_ok=True)
        share_copy.write_bytes(_SHARE_COPY_MARKER)
        agent_server.guest_files[f"{_LINUX_WORK_ROOT}/{relative}"] = bytearray(_GUEST_COPY_MARKER)

        sandbox = _make_sandbox(tmp_path, GuestOS.LINUX)
        destination = tmp_path / "pulled" / "result.txt"
        await sandbox.attach_agent(agent_server.port)
        try:
            await sandbox.copy_from_sandbox(relative, destination)
        finally:
            await sandbox.release_agent()

        assert destination.read_bytes() == _GUEST_COPY_MARKER, (
            "the sandbox read the host side of the share instead of the running guest (S17-D69)"
        )

    @pytest.mark.asyncio
    async def test_a_command_runs_through_the_agent(self, tmp_path: Path, agent_server: GuestAgentProtocolServer) -> None:
        """``run_command`` reaches the guest without writing a script to the share.

        The share cannot carry a script into a running guest and cannot carry a
        result back out, so the command has to go over the agent. The modelled
        guest records what it was asked to run, and the share is checked
        afterwards for the script the old path would have dropped there.

        Args:
            tmp_path: Per-test directory the sandbox uses as its workspace.
            agent_server: Modelled qemu-guest-agent recording executed commands.
        """
        sandbox = _make_sandbox(tmp_path, GuestOS.WINDOWS)
        await sandbox.attach_agent(agent_server.port)
        try:
            exit_code, _, _ = await sandbox.run_command("echo intellicrack")
        finally:
            await sandbox.release_agent()

        assert exit_code == _GUEST_ECHO_EXIT_CODE, (
            f"the guest reported {exit_code} for a command the modelled agent ran successfully (S17-D69)"
        )
        assert any("echo intellicrack" in line for line in agent_server.command_lines()), (
            f"the command never reached the guest; the agent saw {agent_server.command_lines()!r} (S17-D69)"
        )
        staged = list((tmp_path / "shared").rglob("*.cmd")) + list((tmp_path / "shared").rglob("*.sh"))
        assert not staged, f"a command script was written onto the read-only share: {staged!r} (S17-D69)"
