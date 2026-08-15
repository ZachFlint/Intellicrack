# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S18-D15: the folder chosen in Sandbox Settings has to reach a QEMU guest.

Sandbox Settings offers a "Shared folder" and a "Read only" box beside it, the bridge
builds both into the sandbox configuration, and the QEMU backend then never mentioned
either: ``_build_qemu_command`` attached only the per-instance work share it creates for
itself under its own temp directory. Measured on a real Windows guest booted with a folder
configured and a marker file placed in it, the guest reported the marker on no drive it
could see, with the work share's ``D:`` present as the control - so an analyst staging a
sample beside its supporting files had no way to reach them.

The fix has two halves and this gate holds both to their own evidence:

* the configured folder is staged onto the work share's own volume, read-only, without
  displacing anything already there. It is emphatically **not** a second volume, and that
  is the correction the first attempt needed: attaching it as one produced a command line
  that looked right and a guest that still saw nothing. QEMU stamps every vvfat disk with
  one hardcoded MBR signature, so the second disk was a signature collision - measured on
  a real Windows guest, ``Get-Disk`` reported it ``Offline`` with ``OfflineReason=Resource
  Exhaustion``, its partition given no drive letter, while a phantom ``F:`` with no
  filesystem sat where the analyst's files should have been. Read-only is not a preference
  either: a writable vvfat share makes QEMU ``abort()`` when the guest commits a directory
  change.
* writes travel the other way. Whatever the guest leaves in its own ``output`` directory
  is copied into one named subdirectory of the configured folder, and that copy happens
  through the production method against real files on disk - byte-for-byte, nested tree
  and all - not against a description of it.

The staging assertions read the share the production provisioner actually built, rather
than the argv that describes it, because argv is exactly what the first attempt got right
while the guest got nothing.
"""

from __future__ import annotations

import asyncio
import shutil
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import AcceleratorType, GuestOS, QEMUConfig, QEMUSandbox


if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


_DRIVE_FLAG: Final[str] = "-drive"
_READONLY_CLAUSE: Final[str] = "readonly=on"
_FAT_CLAUSE: Final[str] = "file=fat:"
_GUEST_OUTPUT_DIR_NAME: Final[str] = QEMUSandbox.GUEST_OUTPUT_DIR_NAME
_MIRRORED_OUTPUT_DIR_NAME: Final[str] = QEMUSandbox.MIRRORED_OUTPUT_DIR_NAME
_CONFIGURED_SHARE_DIR_NAME: Final[str] = QEMUSandbox.CONFIGURED_SHARE_DIR_NAME


class _ShareSandbox(QEMUSandbox):
    """``QEMUSandbox`` given only what a live virtual machine would provide.

    The working directory and the accelerator are arranged here; the argv
    builder and the mirror under test are the production ones.
    """

    def use_workspace(self, temp_dir: Path) -> None:
        """Point the sandbox at a working directory and its shared folder.

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

    def collection_root(self) -> Path:
        """Return the host directory guest output is collected into.

        A sandbox with no collection root would mean the workspace was never
        arranged, so the assertion below fails the gate rather than letting it
        observe nothing.

        Returns:
            Path: The production collection root for this sandbox.
        """
        root = self._collected_root()
        assert root is not None, "the sandbox has no collection root, so this gate could not observe the mirror"
        return root

    def mirror_output(self) -> int:
        """Run the production mirror into the configured folder.

        Returns:
            int: Number of files the mirror copied.
        """
        return asyncio.run(self._mirror_output_to_configured_folder())

    def stop_sequence(self) -> None:
        """Run the production stop sequence end to end."""
        asyncio.run(self._stop_impl())

    def provision_shared_folders(self) -> Path:
        """Create the real per-instance share the way a start would.

        Returns:
            Path: The share the production code provisioned.
        """
        asyncio.run(self._prepare_qemu_shared_folders())
        assert self._shared_folder is not None, "provisioning produced no shared folder at all"
        return self._shared_folder


def _make_sandbox(
    tmp_path: Path,
    configured: Path | None,
    *,
    read_only: bool = False,
    workspace: Path | None = None,
    extra_folders: Sequence[Path] = (),
) -> _ShareSandbox:
    """Build a Windows-guest sandbox pointed at a configured folder.

    The folder is supplied the way the dialog supplies it: as a
    :attr:`SandboxConfig.shared_folders` entry carrying the host path, the
    in-guest path and the read-only flag.

    Args:
        tmp_path: Directory the guest image is written into.
        configured: Folder to configure as the shared folder, or ``None``.
        read_only: Whether the folder is marked read-only in the dialog.
        workspace: Directory used as the sandbox working directory, defaulting
            to ``tmp_path``. Worth separating when the test drives a real stop,
            which deletes that directory.
        extra_folders: Further folders configured alongside ``configured``, for
            the case where more than one is chosen.

    Returns:
        _ShareSandbox: A sandbox ready to build a command or mirror output.
    """
    image = tmp_path / "guest.qcow2"
    image.write_bytes(b"QFI\xfb")
    shared_folders: list[tuple[Path, str, bool]] = []
    if configured is not None:
        shared_folders.append((configured, "C:\\Shared", read_only))
    shared_folders.extend((folder, "C:\\Shared", read_only) for folder in extra_folders)
    sandbox = _ShareSandbox(
        config=SandboxConfig(shared_folders=shared_folders),
        qemu_config=QEMUConfig(
            guest_os=GuestOS.WINDOWS,
            image_path=image,
            display="none",
        ),
    )
    sandbox.use_workspace(workspace if workspace is not None else tmp_path)
    sandbox.force_accelerator(AcceleratorType.TCG)
    sandbox.set_qemu_path(tmp_path / "qemu-system-x86_64.exe")
    return sandbox


def _drive_values(argv: list[str]) -> list[str]:
    """Return every ``-drive`` argument the builder emitted.

    Args:
        argv: The QEMU command line under test.

    Returns:
        list[str]: The values that followed each ``-drive``.
    """
    return [argv[index + 1] for index, item in enumerate(argv) if item == _DRIVE_FLAG and index + 1 < len(argv)]


def _values_naming(argv: list[str], path: Path) -> list[str]:
    """Return the arguments that mention a host path.

    Args:
        argv: The QEMU command line under test.
        path: Host path to look for.

    Returns:
        list[str]: Every argument carrying that path.
    """
    return [item for item in argv if str(path) in item]


class TestTheConfiguredFolderIsOnTheGuestVolume:
    """A folder chosen in Sandbox Settings has to be readable from the guest's share."""

    def test_the_configured_folders_files_are_on_the_share_the_guest_mounts(self, tmp_path: Path) -> None:
        """The analyst's files are reachable through the volume QEMU builds its FAT over.

        Args:
            tmp_path: Per-test temporary directory.
        """
        configured = tmp_path / "analyst-folder"
        (configured / "support").mkdir(parents=True)
        payload = bytes(range(256))
        (configured / "support" / "licence.dat").write_bytes(payload)
        sandbox = _make_sandbox(tmp_path, configured)

        share = sandbox.provision_shared_folders()
        try:
            staged = share / _CONFIGURED_SHARE_DIR_NAME / configured.name / "support" / "licence.dat"
            assert staged.is_file(), (
                f"a shared folder was configured and nothing of it is on the guest's volume: "
                f"{sorted(str(item.relative_to(share)) for item in share.rglob('*'))}"
            )
            assert staged.read_bytes() == payload, "the file on the guest's volume is not the analyst's file"
        finally:
            shutil.rmtree(share.parent, ignore_errors=True)

    def test_it_travels_on_one_volume_and_not_a_second_one(self, tmp_path: Path) -> None:
        """A second vvfat disk collides on QEMU's fixed MBR signature and goes offline.

        This is the regression the live run caught: the previous fix attached a
        volume of its own, and the guest took it offline for
        ``Resource Exhaustion`` - Windows' name for two disks claiming one
        signature - so the analyst's folder was unreachable while the command
        line said it was mounted.

        Args:
            tmp_path: Per-test temporary directory.
        """
        configured = tmp_path / "analyst-folder"
        configured.mkdir()

        without = _make_sandbox(tmp_path, None).build_command()
        with_it = _make_sandbox(tmp_path, configured).build_command()

        fat_drives = [value for value in _drive_values(with_it) if _FAT_CLAUSE in value]
        assert len(fat_drives) == 1, f"the guest is given more than one vvfat disk, which collide on one MBR signature: {fat_drives}"
        assert len(_drive_values(with_it)) == len(_drive_values(without)), (
            f"configuring a folder added a volume: {_drive_values(without)} -> {_drive_values(with_it)}"
        )
        assert not _values_naming(with_it, configured), (
            f"the configured folder is still handed to QEMU as its own volume: {_values_naming(with_it, configured)}"
        )

    def test_it_does_not_displace_the_instance_work_share(self, tmp_path: Path) -> None:
        """The work share survives around it, since the guest agent lives there.

        Args:
            tmp_path: Per-test temporary directory.
        """
        configured = tmp_path / "analyst-folder"
        (configured / "support").mkdir(parents=True)
        sandbox = _make_sandbox(tmp_path, configured)

        share = sandbox.provision_shared_folders()
        try:
            present = {entry.name for entry in share.iterdir() if entry.is_dir()}
            assert {"input", "output", "logs", "monitor"} <= present, (
                f"staging the configured folder cost the work share its own directories: {present}"
            )
            argv = sandbox.build_command()
            assert _values_naming(argv, share), f"the work share is no longer attached at all: {argv}"
        finally:
            shutil.rmtree(share.parent, ignore_errors=True)

    def test_the_volume_carrying_it_is_read_only(self, tmp_path: Path) -> None:
        """A writable vvfat volume aborts QEMU outright, so this one is read-only.

        Args:
            tmp_path: Per-test temporary directory.
        """
        configured = tmp_path / "analyst-folder"
        configured.mkdir()
        sandbox = _make_sandbox(tmp_path, configured)

        share = sandbox.provision_shared_folders()
        try:
            carriers = _values_naming(sandbox.build_command(), share)
            assert carriers, f"nothing on the command line carries the share the folder was staged onto: {share}"
            for carrier in carriers:
                assert _READONLY_CLAUSE in carrier, f"the staged folder is writable, which aborts QEMU on a guest write: {carrier}"
        finally:
            shutil.rmtree(share.parent, ignore_errors=True)

    def test_two_folders_of_the_same_name_stay_apart(self, tmp_path: Path) -> None:
        """Both configured folders reach the guest, neither hiding the other.

        Args:
            tmp_path: Per-test temporary directory.
        """
        first = tmp_path / "one" / "samples"
        second = tmp_path / "two" / "samples"
        first.mkdir(parents=True)
        second.mkdir(parents=True)
        (first / "a.bin").write_bytes(b"first")
        (second / "b.bin").write_bytes(b"second")
        sandbox = _make_sandbox(tmp_path, None, extra_folders=[first, second])

        share = sandbox.provision_shared_folders()
        try:
            root = share / _CONFIGURED_SHARE_DIR_NAME
            found = sorted(path.name for path in root.rglob("*.bin"))
            assert found == ["a.bin", "b.bin"], (
                f"two folders sharing a basename did not both reach the guest: {sorted(str(item.relative_to(root)) for item in root.rglob('*'))}"
            )
        finally:
            shutil.rmtree(share.parent, ignore_errors=True)

    def test_a_configured_path_that_is_not_a_directory_is_refused(self, tmp_path: Path) -> None:
        """A stale or mistyped setting must not stop the sandbox launching.

        Args:
            tmp_path: Per-test temporary directory.
        """
        missing = tmp_path / "folder-that-was-deleted"
        sandbox = _make_sandbox(tmp_path, missing)

        share = sandbox.provision_shared_folders()
        try:
            staged = share / _CONFIGURED_SHARE_DIR_NAME
            assert not staged.exists() or not list(staged.iterdir()), (
                f"a non-existent folder was staged onto the guest's volume: {list(staged.iterdir())}"
            )
            assert not _values_naming(sandbox.build_command(), missing), "a non-existent folder was handed to QEMU as a volume"
        finally:
            shutil.rmtree(share.parent, ignore_errors=True)


class TestGuestOutputComesBack:
    """The read-only mount is only half a shared folder; writes travel the other way."""

    def test_guest_output_is_mirrored_into_the_configured_folder(self, tmp_path: Path) -> None:
        """Collected guest output lands in the analyst's folder, byte for byte.

        Args:
            tmp_path: Per-test temporary directory.
        """
        configured = tmp_path / "analyst-folder"
        configured.mkdir()
        sandbox = _make_sandbox(tmp_path, configured)

        collected = sandbox.collection_root() / _GUEST_OUTPUT_DIR_NAME
        (collected / "dropped").mkdir(parents=True)
        payload = bytes(range(256))
        (collected / "report.txt").write_bytes(b"unpacked at 0x401000\r\n")
        (collected / "dropped" / "stage2.bin").write_bytes(payload)

        copied = sandbox.mirror_output()

        mirrored = configured / _MIRRORED_OUTPUT_DIR_NAME
        assert copied == 2, f"the mirror reported {copied} files for the two the guest left"
        assert (mirrored / "report.txt").read_bytes() == b"unpacked at 0x401000\r\n", (
            "the mirrored file does not match what the guest wrote"
        )
        assert (mirrored / "dropped" / "stage2.bin").read_bytes() == payload, "the nested tree did not survive the mirror"

    def test_the_mirror_keeps_the_analysts_own_files_apart(self, tmp_path: Path) -> None:
        """Guest output is placed under one named subdirectory, not loose.

        Args:
            tmp_path: Per-test temporary directory.
        """
        configured = tmp_path / "analyst-folder"
        configured.mkdir()
        (configured / "report.txt").write_bytes(b"the analyst's own notes\r\n")
        sandbox = _make_sandbox(tmp_path, configured)

        collected = sandbox.collection_root() / _GUEST_OUTPUT_DIR_NAME
        collected.mkdir(parents=True)
        (collected / "report.txt").write_bytes(b"whatever the sample wrote\r\n")

        sandbox.mirror_output()

        assert (configured / "report.txt").read_bytes() == b"the analyst's own notes\r\n", (
            "the guest's output overwrote a file of the same name in the analyst's folder"
        )

    def test_no_configured_folder_mirrors_nothing(self, tmp_path: Path) -> None:
        """With no folder configured there is nowhere to mirror to, and nothing is written.

        Args:
            tmp_path: Per-test temporary directory.
        """
        sandbox = _make_sandbox(tmp_path, None)
        collected = sandbox.collection_root() / _GUEST_OUTPUT_DIR_NAME
        collected.mkdir(parents=True)
        (collected / "report.txt").write_bytes(b"whatever the sample wrote\r\n")

        assert sandbox.mirror_output() == 0, "the mirror claimed to copy files with no folder configured"

    def test_a_read_only_folder_is_left_alone(self, tmp_path: Path) -> None:
        """The dialog's "Read only" box has to mean something somewhere.

        The mount is read-only either way, because a writable vvfat volume
        aborts QEMU, so the box is honoured on the one direction that can
        carry writes at all.

        Args:
            tmp_path: Per-test temporary directory.
        """
        configured = tmp_path / "analyst-folder"
        configured.mkdir()
        sandbox = _make_sandbox(tmp_path, configured, read_only=True)

        collected = sandbox.collection_root() / _GUEST_OUTPUT_DIR_NAME
        collected.mkdir(parents=True)
        (collected / "report.txt").write_bytes(b"whatever the sample wrote\r\n")

        assert sandbox.mirror_output() == 0, "the guest wrote into a folder the analyst marked read-only"
        assert list(configured.iterdir()) == [], f"a read-only folder was written to: {list(configured.iterdir())}"

    def test_a_read_only_folder_is_still_readable_from_the_guest(self, tmp_path: Path) -> None:
        """Read-only means read-only, not absent - the guest still sees it.

        Args:
            tmp_path: Per-test temporary directory.
        """
        configured = tmp_path / "analyst-folder"
        configured.mkdir()
        (configured / "licence.dat").write_bytes(b"\x01\x02\x03\x04")
        sandbox = _make_sandbox(tmp_path, configured, read_only=True)

        share = sandbox.provision_shared_folders()
        try:
            staged = share / _CONFIGURED_SHARE_DIR_NAME / configured.name / "licence.dat"
            assert staged.read_bytes() == b"\x01\x02\x03\x04", (
                f"a folder marked read-only was not put on the guest's volume at all: {sorted(str(item) for item in share.rglob('*'))}"
            )
        finally:
            shutil.rmtree(share.parent, ignore_errors=True)

    def test_nothing_collected_mirrors_nothing(self, tmp_path: Path) -> None:
        """A run that produced no guest output leaves the configured folder alone.

        Args:
            tmp_path: Per-test temporary directory.
        """
        configured = tmp_path / "analyst-folder"
        configured.mkdir()
        sandbox = _make_sandbox(tmp_path, configured)

        assert sandbox.mirror_output() == 0, "the mirror claimed to copy files that were never collected"
        assert list(configured.iterdir()) == [], f"the mirror created something in an untouched folder: {list(configured.iterdir())}"


class TestTheMirrorIsWiredIntoTheStopSequence:
    """A mirror nothing calls is no shared folder at all."""

    def test_stopping_the_sandbox_mirrors_collected_output(self, tmp_path: Path) -> None:
        """The real stop sequence delivers guest output to the analyst's folder.

        The stop sequence also removes the instance work tree, and the mirror
        reads out of that tree, so this run pins the ordering too: a mirror
        placed after the cleanup would find nothing left to copy.

        Args:
            tmp_path: Per-test temporary directory.
        """
        configured = tmp_path / "analyst-folder"
        configured.mkdir()
        workspace = tmp_path / "work"
        workspace.mkdir()
        sandbox = _make_sandbox(tmp_path, configured, workspace=workspace)

        collected = sandbox.collection_root() / _GUEST_OUTPUT_DIR_NAME
        collected.mkdir(parents=True)
        payload = bytes(range(256))
        (collected / "stage2.bin").write_bytes(payload)

        sandbox.stop_sequence()

        mirrored = configured / _MIRRORED_OUTPUT_DIR_NAME / "stage2.bin"
        assert mirrored.is_file(), f"stopping the sandbox delivered nothing to the configured folder: {list(configured.rglob('*'))}"
        assert mirrored.read_bytes() == payload, "the mirrored file does not match what the guest left behind"
        assert not workspace.exists(), "the stop sequence never reached its cleanup, so this gate proved nothing about ordering"


class _OrderRecordingSandbox(_ShareSandbox):
    """Sandbox that records the order the production stop sequence works in.

    Neither seam is reimplemented: ``_collect_guest_output`` and
    ``_shut_down_guest`` still run, and all that is added is a note of when the
    real :meth:`_stop_impl` reached them. The method under test is the stop
    sequence itself, which is where the ordering defect was.
    """

    _steps: list[str] | None = None

    @property
    def steps(self) -> list[str]:
        """The steps the stop sequence has reached, in order.

        Returns:
            list[str]: The record, created on first use so no mutable default
            is ever shared between sandboxes.
        """
        if self._steps is None:
            self._steps = []
        return self._steps

    async def _collect_guest_output(self) -> int:
        """Note that the guest's output was fetched, then fetch it.

        Returns:
            int: Whatever the production collector reported.
        """
        self.steps.append("collect")
        return await super()._collect_guest_output()

    async def _shut_down_guest(self) -> bool:
        """Note that the guest was asked to power off, then ask it.

        Returns:
            bool: Whether the guest powered itself off.
        """
        self.steps.append("shutdown")
        return await super()._shut_down_guest()

    async def _cleanup(self) -> None:
        """Note that the work tree was removed, then remove it."""
        self.steps.append("cleanup")
        await super()._cleanup()


class TestGuestOutputIsFetchedWhileTheGuestIsStillThere:
    """Output collected only on the run path is thrown away with the machine."""

    def test_stopping_fetches_the_guest_output_before_the_guest_goes(self, tmp_path: Path) -> None:
        """The fetch runs over the guest agent, which dies with the guest.

        Measured live: a session driven through ``execute`` wrote its results
        into the guest's own output directory and nothing came back, because
        the only collection was on the ``run_binary`` path. Collecting after
        the shutdown would not fix it - there would be no agent left to read
        with - so the order is the fix and the order is what is asserted.

        Args:
            tmp_path: Per-test temporary directory.
        """
        configured = tmp_path / "analyst-folder"
        configured.mkdir()
        workspace = tmp_path / "work"
        workspace.mkdir()
        image = tmp_path / "guest.qcow2"
        image.write_bytes(b"QFI\xfb")
        sandbox = _OrderRecordingSandbox(
            config=SandboxConfig(shared_folders=[(configured, "C:\\Shared", False)]),
            qemu_config=QEMUConfig(guest_os=GuestOS.WINDOWS, image_path=image, display="none"),
        )
        sandbox.use_workspace(workspace)

        sandbox.stop_sequence()

        assert sandbox.steps == ["collect", "shutdown", "cleanup"], (
            f"the stop sequence did not fetch the guest's output while the guest was still running: {sandbox.steps}"
        )


class TestTheMirrorReadsWhatTheGuestActuallyWrites:
    """The directory pulled back has to be one the sandbox really provisions."""

    def test_the_mirrored_directory_is_provisioned_for_the_guest(self, tmp_path: Path) -> None:
        """``_GUEST_OUTPUT_DIR_NAME`` names a directory the real start creates.

        Args:
            tmp_path: Per-test temporary directory.
        """
        sandbox = _make_sandbox(tmp_path, None)
        share = sandbox.provision_shared_folders()
        try:
            provisioned = sorted(entry.name for entry in share.iterdir() if entry.is_dir())
            assert _GUEST_OUTPUT_DIR_NAME in provisioned, (
                f"the mirror pulls {_GUEST_OUTPUT_DIR_NAME!r}, which the sandbox never gives the guest: {provisioned}"
            )
        finally:
            assert share.parent.exists(), "provisioning produced no temp tree to clean up"
            shutil.rmtree(share.parent, ignore_errors=True)


@pytest.mark.parametrize("name", [_GUEST_OUTPUT_DIR_NAME, _MIRRORED_OUTPUT_DIR_NAME])
def test_the_share_names_are_usable_on_a_fat_volume(name: str) -> None:
    """Both names have to survive the FAT transport the Windows share uses.

    Args:
        name: Directory name under test.
    """
    assert name, "a share directory name is empty"
    assert not set(name) & set('<>:"/\\|?*'), f"{name!r} cannot be created on the FAT volume the guest mounts"
