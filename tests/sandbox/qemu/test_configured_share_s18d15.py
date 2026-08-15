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

* the configured folder is attached as a **second, read-only** volume beside the work
  share, never in place of it. Read-only is not a preference on the FAT transport: a
  writable vvfat share makes QEMU ``abort()`` when the guest commits a directory change.
  The assertions below are made on the argv the production builder emits, and the work
  share is asserted to have survived in the same command.
* writes travel the other way. Whatever the guest leaves in its own ``output`` directory
  is copied into one named subdirectory of the configured folder, and that copy happens
  through the production method against real files on disk - byte-for-byte, nested tree
  and all - not against a description of it.
"""

from __future__ import annotations

import asyncio
import shutil
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import AcceleratorType, GuestOS, QEMUConfig, QEMUSandbox


if TYPE_CHECKING:
    from pathlib import Path


_DRIVE_FLAG: Final[str] = "-drive"
_READONLY_CLAUSE: Final[str] = "readonly=on"
_GUEST_OUTPUT_DIR_NAME: Final[str] = QEMUSandbox.GUEST_OUTPUT_DIR_NAME
_MIRRORED_OUTPUT_DIR_NAME: Final[str] = QEMUSandbox.MIRRORED_OUTPUT_DIR_NAME


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

    Returns:
        _ShareSandbox: A sandbox ready to build a command or mirror output.
    """
    image = tmp_path / "guest.qcow2"
    image.write_bytes(b"QFI\xfb")
    shared_folders: list[tuple[Path, str, bool]] = []
    if configured is not None:
        shared_folders.append((configured, "C:\\Shared", read_only))
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


class TestTheConfiguredFolderIsAttached:
    """A folder chosen in Sandbox Settings has to become a volume the guest can see."""

    def test_the_configured_folder_reaches_the_command_line(self, tmp_path: Path) -> None:
        """The configured folder appears among the volumes QEMU is launched with.

        Args:
            tmp_path: Per-test temporary directory.
        """
        configured = tmp_path / "analyst-folder"
        (configured / "support").mkdir(parents=True)
        (configured / "support" / "licence.dat").write_bytes(b"\x01\x02\x03\x04")

        argv = _make_sandbox(tmp_path, configured).build_command()

        assert _values_naming(argv, configured), f"a shared folder was configured and no QEMU volume carries it: {argv}"

    def test_it_does_not_displace_the_instance_work_share(self, tmp_path: Path) -> None:
        """The work share survives beside it, since the guest agent lives there.

        Args:
            tmp_path: Per-test temporary directory.
        """
        configured = tmp_path / "analyst-folder"
        configured.mkdir()

        argv = _make_sandbox(tmp_path, configured).build_command()

        work_share = tmp_path / "shared"
        assert _values_naming(argv, work_share), f"the configured folder replaced the instance work share: {argv}"
        assert len(_drive_values(argv)) >= 2, f"the two shares collapsed into one volume: {_drive_values(argv)}"

    def test_the_configured_volume_is_read_only(self, tmp_path: Path) -> None:
        """A writable vvfat volume aborts QEMU outright, so this one is read-only.

        Args:
            tmp_path: Per-test temporary directory.
        """
        configured = tmp_path / "analyst-folder"
        configured.mkdir()

        argv = _make_sandbox(tmp_path, configured).build_command()

        carriers = _values_naming(argv, configured)
        assert carriers, f"nothing on the command line carries the configured folder: {argv}"
        for carrier in carriers:
            assert _READONLY_CLAUSE in carrier, f"the configured folder is writable, which aborts QEMU on a guest write: {carrier}"

    def test_no_configured_folder_attaches_nothing_extra(self, tmp_path: Path) -> None:
        """With no folder configured the command line is unchanged.

        Args:
            tmp_path: Per-test temporary directory.
        """
        with_folder = tmp_path / "analyst-folder"
        with_folder.mkdir()

        without = _make_sandbox(tmp_path, None).build_command()
        with_it = _make_sandbox(tmp_path, with_folder).build_command()

        assert len(_drive_values(with_it)) == len(_drive_values(without)) + 1, (
            f"configuring a folder did not add exactly one volume: {_drive_values(without)} -> {_drive_values(with_it)}"
        )

    def test_a_configured_path_that_is_not_a_directory_is_refused(self, tmp_path: Path) -> None:
        """A stale or mistyped setting must not stop the sandbox launching.

        Args:
            tmp_path: Per-test temporary directory.
        """
        missing = tmp_path / "folder-that-was-deleted"

        argv = _make_sandbox(tmp_path, missing).build_command()

        assert not _values_naming(argv, missing), f"a non-existent folder was handed to QEMU as a volume: {argv}"


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

    def test_a_read_only_folder_is_still_mounted(self, tmp_path: Path) -> None:
        """Read-only means read-only, not absent - the guest still sees it.

        Args:
            tmp_path: Per-test temporary directory.
        """
        configured = tmp_path / "analyst-folder"
        configured.mkdir()

        argv = _make_sandbox(tmp_path, configured, read_only=True).build_command()

        assert _values_naming(argv, configured), f"a read-only shared folder was not attached at all: {argv}"

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
