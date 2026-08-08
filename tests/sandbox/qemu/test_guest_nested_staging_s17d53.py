# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S17-D53: staging into a guest subdirectory that does not exist yet.

Measured live: ``copy_to_sandbox(Path('C:/Windows/System32/en-US/ipconfig.exe.mui'),
'input/en-US/ipconfig.exe.mui')`` raised ``SandboxError: qemu-guest-agent could
not open D:\\input\\en-US\\ipconfig.exe.mui inside the guest for writing:
failed to open file ... The system cannot find the path specified``.
``_stage_file_in_guest`` opened the destination through ``guest-file-open``
without ever asking the guest to create the directories above it, and nothing
on the host side created them either. Placing a target together with the files
it needs - a DLL beside it, a resource subtree, a config directory - is the
normal shape of real work, and every one of those failed.

:class:`GuestAgentProtocolServer` models ``guest-file-open`` as always
succeeding regardless of whether the parent directory exists, exactly like the
in-memory dict it keeps - so a bug that skips directory creation would not
show up as a file-open failure against this model. What it does record
faithfully is every ``guest-exec`` the client issued, so these gates assert on
that: a nested destination must produce a guest-exec that creates the parent
directory, using exactly the invocation
:meth:`intellicrack.sandbox.qemu.QEMUSandbox._guest_mkdir_command` builds,
before the file is opened for writing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig, QemuGuestAgentClient, QEMUSandbox
from tests.sandbox.qemu.guest_agent_server import GuestAgentProtocolServer, GuestCommandResult


if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

_WINDOWS_SHARED_ROOT: Final[str] = "D:\\"
_LINUX_SHARED_ROOT: Final[str] = "/mnt/shared"
_WINDOWS_NESTED_RELATIVE: Final[str] = "input/en-US/ipconfig.exe.mui"
_EXPECTED_WINDOWS_GUEST_PATH: Final[str] = "D:\\input\\en-US\\ipconfig.exe.mui"
_EXPECTED_WINDOWS_PARENT: Final[str] = "D:\\input\\en-US"
_LINUX_NESTED_RELATIVE: Final[str] = "input/sub/dir/payload.bin"
_EXPECTED_LINUX_GUEST_PATH: Final[str] = "/mnt/shared/input/sub/dir/payload.bin"
_EXPECTED_LINUX_PARENT: Final[str] = "/mnt/shared/input/sub/dir"

_AGENT_CONNECT_TIMEOUT: Final[float] = 10.0
_GUEST_EXEC: Final[str] = "guest-exec"
_GUEST_FILE_OPEN: Final[str] = "guest-file-open"


class _NestedStagingSandbox(QEMUSandbox):
    """``QEMUSandbox`` wired to a real guest-agent channel and a real share.

    Only the two things a running VM would otherwise provide are arranged
    here - the host-side shared directory and the in-guest root it is mounted
    at. ``copy_to_sandbox`` and the whole guest-file staging path underneath
    it, including directory creation, are the production implementations.
    """

    async def attach_agent(self, port: int, guest_root: str) -> None:
        """Connect the real qemu-guest-agent client to the modelled agent.

        Args:
            port: Loopback port the modelled agent listens on.
            guest_root: In-guest root the shared volume is mounted at.

        Raises:
            AssertionError: If the client cannot reach the modelled agent.
        """
        client = QemuGuestAgentClient(port=port)
        connected = await client.connect(time_limit=_AGENT_CONNECT_TIMEOUT)
        if not connected:
            msg = "the guest-agent client could not reach the modelled agent"
            raise AssertionError(msg)
        self._qga = client
        self._guest_shared_root = guest_root

    def use_share(self, share: Path) -> None:
        """Point the sandbox at a host-side shared folder.

        Args:
            share: Directory standing in for the host side of the share.
        """
        self._shared_folder = share

    def mkdir_command_line(self, guest_dir: str) -> str:
        """Return the production mkdir invocation for a guest directory.

        Args:
            guest_dir: Absolute in-guest path of the directory.

        Returns:
            str: Executable and arguments joined by spaces, taken from the
            real :meth:`QEMUSandbox._guest_mkdir_command` so the gate cannot
            drift from what production actually sends.
        """
        path, args = self._guest_mkdir_command(guest_dir)
        return " ".join([path, *args])

    async def release_agent(self) -> None:
        """Disconnect the guest-agent client this test opened."""
        if self._qga is not None:
            await self._qga.disconnect()
            self._qga = None


def _make_sandbox(share: Path, guest_os: GuestOS) -> _NestedStagingSandbox:
    """Build a sandbox for the given guest family pointed at a share.

    Args:
        share: Directory standing in for the host side of the share.
        guest_os: Guest family whose path separators apply.

    Returns:
        _NestedStagingSandbox: Sandbox ready to stage a file.
    """
    sandbox = _NestedStagingSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=guest_os))
    sandbox.use_share(share)
    return sandbox


@pytest.mark.asyncio
class TestNestedDestinationDirectoryIsCreated:
    """A destination whose parent does not exist yet must still be reachable."""

    async def test_a_windows_guest_gets_its_missing_subdirectory_created(self, tmp_path: Path) -> None:
        """The nested destination from the live defect must now stage cleanly.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        source = tmp_path / "ipconfig.exe.mui"
        source.write_bytes(b"MZ\x90\x00resource")
        share = tmp_path / "shared"
        share.mkdir()

        server = GuestAgentProtocolServer()
        await server.start()
        sandbox = _make_sandbox(share, GuestOS.WINDOWS)
        try:
            await sandbox.attach_agent(server.port, _WINDOWS_SHARED_ROOT)
            expected_mkdir = sandbox.mkdir_command_line(_EXPECTED_WINDOWS_PARENT)

            await sandbox.copy_to_sandbox(source, _WINDOWS_NESTED_RELATIVE)

            assert expected_mkdir in server.command_lines(), (
                f"no guest-exec created {_EXPECTED_WINDOWS_PARENT!r}; commands run: {server.command_lines()}"
            )
            mkdir_index = server.commands.index(_GUEST_EXEC)
            open_index = server.commands.index(_GUEST_FILE_OPEN)
            assert mkdir_index < open_index, "the directory was not created before the file was opened for writing"
            assert _EXPECTED_WINDOWS_GUEST_PATH in server.guest_files, (
                f"the file never reached the guest; files present: {sorted(server.guest_files)}"
            )
            assert bytes(server.guest_files[_EXPECTED_WINDOWS_GUEST_PATH]) == source.read_bytes()
        finally:
            await sandbox.release_agent()
            await server.stop()

    async def test_a_linux_guest_gets_every_missing_intermediate_directory(self, tmp_path: Path) -> None:
        """Several missing levels at once must still be created in one pass.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        source = tmp_path / "payload.bin"
        source.write_bytes(b"\x7fELF" + bytes(range(64)))
        share = tmp_path / "shared"
        share.mkdir()

        server = GuestAgentProtocolServer()
        await server.start()
        sandbox = _make_sandbox(share, GuestOS.LINUX)
        try:
            await sandbox.attach_agent(server.port, _LINUX_SHARED_ROOT)
            expected_mkdir = sandbox.mkdir_command_line(_EXPECTED_LINUX_PARENT)

            await sandbox.copy_to_sandbox(source, _LINUX_NESTED_RELATIVE)

            assert expected_mkdir in server.command_lines(), (
                f"no guest-exec created {_EXPECTED_LINUX_PARENT!r}; commands run: {server.command_lines()}"
            )
            assert _EXPECTED_LINUX_GUEST_PATH in server.guest_files, (
                f"the file never reached the guest; files present: {sorted(server.guest_files)}"
            )
            assert bytes(server.guest_files[_EXPECTED_LINUX_GUEST_PATH]) == source.read_bytes()
        finally:
            await sandbox.release_agent()
            await server.stop()

    async def test_a_directory_that_already_exists_is_not_fatal(self, tmp_path: Path) -> None:
        """A guest reporting the directory already exists must not abort staging.

        ``mkdir`` without ``-p``-style idempotency exits non-zero when the
        target already exists on Windows; that outcome must be tolerated
        rather than raised, since it means the destination is already usable.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        source = tmp_path / "ipconfig.exe.mui"
        source.write_bytes(b"already-there")
        share = tmp_path / "shared"
        share.mkdir()

        def _responder(path: str, args: Sequence[str]) -> GuestCommandResult:
            del args
            if path == "cmd.exe":
                return GuestCommandResult(exit_code=1, stdout="", stderr="A subdirectory or file already exists.\n")
            return GuestCommandResult()

        server = GuestAgentProtocolServer(responder=_responder)
        await server.start()
        sandbox = _make_sandbox(share, GuestOS.WINDOWS)
        try:
            await sandbox.attach_agent(server.port, _WINDOWS_SHARED_ROOT)

            await sandbox.copy_to_sandbox(source, _WINDOWS_NESTED_RELATIVE)

            assert _EXPECTED_WINDOWS_GUEST_PATH in server.guest_files, (
                "a nonzero mkdir exit code aborted staging instead of being tolerated"
            )
            assert bytes(server.guest_files[_EXPECTED_WINDOWS_GUEST_PATH]) == source.read_bytes()
        finally:
            await sandbox.release_agent()
            await server.stop()


@pytest.mark.asyncio
async def test_a_top_level_destination_issues_no_directory_command(tmp_path: Path) -> None:
    """A destination with no subdirectory must not send a spurious mkdir.

    The shared folder's own subdirectories (``input``, ``output``, ``logs``)
    already exist before the guest boots, so staging directly into one of
    them must not cost every copy an extra guest command.

    Args:
        tmp_path: pytest-provided temporary directory fixture.
    """
    source = tmp_path / "true_x86_64"
    source.write_bytes(b"\x7fELF")
    share = tmp_path / "shared"
    share.mkdir()

    server = GuestAgentProtocolServer()
    await server.start()
    sandbox = _make_sandbox(share, GuestOS.LINUX)
    try:
        await sandbox.attach_agent(server.port, _LINUX_SHARED_ROOT)

        await sandbox.copy_to_sandbox(source, "input/true_x86_64")

        assert _GUEST_EXEC not in server.commands, (
            f"a top-level destination triggered an unnecessary directory command: {server.command_lines()}"
        )
    finally:
        await sandbox.release_agent()
        await server.stop()
