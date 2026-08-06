# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D30: a file staged after boot must reach the running guest.

``QEMUSandbox.copy_to_sandbox`` wrote only into the host-side shared directory.
On a Windows host that directory reaches the guest as a QEMU **vvfat** block
device, because virtio-9p is compiled out of every Windows QEMU build (the
S17-D17 host-side fix). vvfat presents the directory as it was **when QEMU
started**, so nothing the host writes afterwards ever appears inside the guest.

Measured live on 2026-08-05 against a booted Debian 13 guest: the host staged
``input/true_x86_64`` and the run came back
``Command not found: /mnt/shared/input/true_x86_64``, while ``ls -la
/mnt/shared/input`` inside that guest returned ``total 24`` with only ``.`` and
``..`` on ``/dev/vdb1 on /mnt/shared type vfat``. Every ``run_binary`` on the
QEMU backend was therefore incapable of executing its target.

The staging now goes through the qemu-guest-agent file commands, which write
inside the guest itself. These tests drive the real
:class:`QemuGuestAgentClient` over a real loopback socket against the real
:class:`GuestAgentProtocolServer`, which models the agent's file commands and
keeps the bytes it was handed - so the assertions are made on what actually
arrived on the far side of the channel, not on what the host intended to send.
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig, QemuGuestAgentClient, QEMUSandbox
from tests.sandbox.qemu.guest_agent_server import GuestAgentProtocolServer


if TYPE_CHECKING:
    from pathlib import Path

_GUEST_SHARED_ROOT: Final[str] = "/mnt/shared"
_WINDOWS_SHARED_ROOT: Final[str] = "E:\\"
_STAGED_RELATIVE: Final[str] = "input/true_x86_64"
_EXPECTED_GUEST_PATH: Final[str] = "/mnt/shared/input/true_x86_64"
_EXPECTED_WINDOWS_GUEST_PATH: Final[str] = "E:\\input\\true_x86_64"

_AGENT_CONNECT_TIMEOUT: Final[float] = 10.0
# Larger than one guest-file-write buffer, so a client that sends the payload
# in a single frame - or drops everything past the first - is caught.
_LARGE_PAYLOAD_BYTES: Final[int] = 150_000
_MINIMUM_CHUNKS: Final[int] = 2


class _StagingSandbox(QEMUSandbox):
    """``QEMUSandbox`` wired to a real guest-agent channel and a real share.

    Only the two things a running VM would otherwise provide are arranged
    here - the host-side shared directory and the in-guest root it is mounted
    at. ``copy_to_sandbox`` and the whole guest-file staging path underneath it
    are the production implementations.
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

    async def release_agent(self) -> None:
        """Disconnect the guest-agent client this test opened."""
        if self._qga is not None:
            await self._qga.disconnect()
            self._qga = None


def _make_sandbox(share: Path, guest_os: GuestOS) -> _StagingSandbox:
    """Build a sandbox for the given guest family pointed at a share.

    Args:
        share: Directory standing in for the host side of the share.
        guest_os: Guest family whose path separators apply.

    Returns:
        _StagingSandbox: Sandbox ready to stage a file.
    """
    sandbox = _StagingSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=guest_os))
    sandbox.use_share(share)
    return sandbox


class TestStagedFileReachesTheRunningGuest:
    """What the host stages must exist inside the guest, byte for byte."""

    @pytest.mark.asyncio
    async def test_staged_bytes_arrive_at_the_in_guest_path(self, tmp_path: Path) -> None:
        """The staged file appears inside the guest with the source's bytes.

        The host-side copy is not the assertion: it was always written, and
        writing it is exactly what S17-D30 proved insufficient. What is gated
        is that the bytes crossed the agent channel into the guest.

        Args:
            tmp_path: Per-test temporary directory.
        """
        source = tmp_path / "true_x86_64"
        payload = bytes(range(256)) * 40
        source.write_bytes(payload)
        share = tmp_path / "shared"
        share.mkdir()

        server = GuestAgentProtocolServer()
        await server.start()
        sandbox = _make_sandbox(share, GuestOS.LINUX)
        try:
            await sandbox.attach_agent(server.port, _GUEST_SHARED_ROOT)

            await sandbox.copy_to_sandbox(source, _STAGED_RELATIVE)

            assert _EXPECTED_GUEST_PATH in server.guest_files, (
                f"nothing was written inside the guest; files present: {sorted(server.guest_files)}"
            )
            assert bytes(server.guest_files[_EXPECTED_GUEST_PATH]) == payload, (
                "the bytes that arrived inside the guest are not the bytes that left the host"
            )
            assert (share / _STAGED_RELATIVE).read_bytes() == payload, "the host-side copy was dropped"
        finally:
            await sandbox.release_agent()
            await server.stop()

    @pytest.mark.asyncio
    async def test_a_large_file_is_chunked_and_still_arrives_whole(self, tmp_path: Path) -> None:
        """A payload past one buffer crosses in several writes and reassembles.

        Args:
            tmp_path: Per-test temporary directory.
        """
        source = tmp_path / "big.bin"
        payload = bytes(range(251)) * (_LARGE_PAYLOAD_BYTES // 251 + 1)
        source.write_bytes(payload)
        share = tmp_path / "shared"
        share.mkdir()

        server = GuestAgentProtocolServer()
        await server.start()
        sandbox = _make_sandbox(share, GuestOS.LINUX)
        try:
            await sandbox.attach_agent(server.port, _GUEST_SHARED_ROOT)

            await sandbox.copy_to_sandbox(source, _STAGED_RELATIVE)

            writes = [size for path, size in server.file_writes if path == _EXPECTED_GUEST_PATH]
            assert len(writes) >= _MINIMUM_CHUNKS, f"a {len(payload)}-byte payload crossed in {len(writes)} write(s)"
            assert sum(writes) == len(payload)
            assert bytes(server.guest_files[_EXPECTED_GUEST_PATH]) == payload
        finally:
            await sandbox.release_agent()
            await server.stop()

    @pytest.mark.asyncio
    async def test_a_windows_guest_is_given_a_windows_path(self, tmp_path: Path) -> None:
        """The in-guest path follows the guest's own separators and drive root.

        A Windows guest mounts the share on a drive letter, and the in-guest
        agent's allowlist only accepts an executable under that root, so a
        POSIX-shaped path would be both unopenable and unrunnable.

        Args:
            tmp_path: Per-test temporary directory.
        """
        source = tmp_path / "target.exe"
        source.write_bytes(b"MZ\x90\x00")
        share = tmp_path / "shared"
        share.mkdir()

        server = GuestAgentProtocolServer()
        await server.start()
        sandbox = _make_sandbox(share, GuestOS.WINDOWS)
        try:
            await sandbox.attach_agent(server.port, _WINDOWS_SHARED_ROOT)

            await sandbox.copy_to_sandbox(source, _STAGED_RELATIVE)

            assert _EXPECTED_WINDOWS_GUEST_PATH in server.guest_files, (
                f"the guest was given the wrong path; files present: {sorted(server.guest_files)}"
            )
        finally:
            await sandbox.release_agent()
            await server.stop()


class TestStagingFailuresAreNotSilent:
    """A guest that refuses the file must fail the copy, not the later run."""

    @pytest.mark.asyncio
    async def test_an_agent_without_file_commands_fails_the_copy(self, tmp_path: Path) -> None:
        """An agent build lacking ``guest-file-open`` surfaces at staging time.

        Reporting success here is what produced the live symptom: the run only
        failed later, from inside the guest, with a misleading "not found".

        Args:
            tmp_path: Per-test temporary directory.
        """
        source = tmp_path / "true_x86_64"
        source.write_bytes(b"\x7fELF")
        share = tmp_path / "shared"
        share.mkdir()

        server = GuestAgentProtocolServer(unsupported_commands=frozenset({"guest-file-open"}))
        await server.start()
        sandbox = _make_sandbox(share, GuestOS.LINUX)
        try:
            await sandbox.attach_agent(server.port, _GUEST_SHARED_ROOT)

            with pytest.raises(SandboxError) as excinfo:
                await sandbox.copy_to_sandbox(source, _STAGED_RELATIVE)

            assert _EXPECTED_GUEST_PATH in str(excinfo.value), (
                f"the failure does not name the guest path it could not write: {excinfo.value}"
            )
        finally:
            await sandbox.release_agent()
            await server.stop()

    @pytest.mark.asyncio
    async def test_staging_before_the_guest_is_up_still_copies_host_side(self, tmp_path: Path) -> None:
        """With no agent yet, the host-side copy alone is the whole job.

        Files staged before QEMU starts are inside the vvfat snapshot the guest
        boots with, so this path must stay a plain copy rather than fail for
        want of a channel that does not exist yet.

        Args:
            tmp_path: Per-test temporary directory.
        """
        source = tmp_path / "seed.bin"
        source.write_bytes(b"seed")
        share = tmp_path / "shared"
        share.mkdir()
        sandbox = _make_sandbox(share, GuestOS.LINUX)

        await sandbox.copy_to_sandbox(source, _STAGED_RELATIVE)

        assert (share / _STAGED_RELATIVE).read_bytes() == b"seed"


def test_staging_is_reachable_without_a_running_event_loop() -> None:
    """The staging helper is a coroutine, not a blocking call in disguise.

    Guards the async contract the panel depends on: a blocking implementation
    would freeze the GUI thread for the length of a multi-megabyte transfer.
    """
    assert inspect.iscoroutinefunction(QEMUSandbox.copy_to_sandbox)
