# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S17-D17 (guest side): the shared volume must be usable in the guest.

The host attaches the shared folder either as a FAT-formatted virtio block
device (every Windows QEMU build has virtio-9p compiled out) or as a virtio-9p
export. Neither is reachable from inside the guest until the guest acts on it:
a raw block device is mounted by nothing, and Windows assigns the FAT drive an
arbitrary letter. Before this gate the bootstrap simply exec'd
``/mnt/shared/monitor/start_agent.sh`` or ``Z:\\monitor\\start_agent.cmd`` and
the monitor never started.

The guest here is a *model*, driven through the real qemu-guest-agent wire
protocol over a real loopback socket
(:class:`tests.sandbox.qemu.guest_agent_server.GuestAgentProtocolServer`). It is
modelled on the image the sandbox actually targets rather than on a convenient
abstraction:

* the Linux guest is a Debian genericcloud layout, so its EFI System Partition
  is ``vfat`` too and is enumerated ahead of the share; its ``lsblk`` honours
  the ``--output`` columns it is handed and escapes them as ``--raw`` does, its
  ``mount`` records which source was attached, and the launcher is reachable
  only when the source that got mounted is the share;
* the Windows guest owns a filesystem backed by the host directory the sandbox
  staged its scripts into, and ``cmd.exe /c <launcher>`` really reads and
  interprets those bytes - ``%~dp0`` expansion included - so a script naming a
  drive letter nothing provides fails here as it does in a guest. This guest
  has no ``Z:``: QEMU's ``smb=`` needs an ``smbd`` the Windows host does not
  have, and the sandbox emits no ``-smb`` argument at all. It also boots from
  ``D:``, so code that assumes ``C:`` skips the wrong volume, addresses the
  wrong system directories, or scans a volume the guest never writes to.

The share root the guest resolved has to hold for everything built afterwards,
so the run-time data plane is driven here too: the in-guest monitor agent is a
second real loopback server, and ``run_binary`` and ``extract_dropped_files``
run against it exactly as they do against a booted guest.

Nothing is mocked - the client under test opens a socket, writes JSON and
parses replies.
"""

from __future__ import annotations

import re
import socket
import zipfile
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox import qemu as qemu_module
from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig, QEMUSandbox
from tests.sandbox.qemu.guest_agent_server import (
    GuestAgentProtocolServer,
    GuestCommandResult,
    IntellicrackAgentServer,
    QmpProtocolServer,
)
from tests.sandbox.qemu.powershell_script import PowerShellScript, evaluate_script, split_path_parent


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Sequence
    from pathlib import Path

    from intellicrack.sandbox.base import FileChange
    from tests.sandbox.qemu.guest_agent_server import GuestCommandResponder

_LINUX_MOUNT_POINT: Final[str] = "/mnt/shared"
_LINUX_LAUNCH_PATH: Final[str] = "/mnt/shared/monitor/start_agent.sh"
_LINUX_LAUNCH_COMMAND: Final[str] = "/bin/bash /mnt/shared/monitor/start_agent.sh"
_ROOT_DEVICE: Final[str] = "/dev/vda1"
_ESP_DEVICE: Final[str] = "/dev/vda15"
_SHARE_DEVICE: Final[str] = "/dev/vdb1"
_SHARE_MOUNT_TAG: Final[str] = "shared"
_VVFAT_LABEL: Final[str] = "QEMU VVFAT"
_ESP_LABEL: Final[str] = "UEFI"
_WINDOWS_SHARE_DRIVE: Final[str] = "E:"
_WINDOWS_SHARE_ROOT: Final[str] = "E:\\"
_WINDOWS_LAUNCH_PATH: Final[str] = "E:\\monitor\\start_agent.cmd"
_WINDOWS_AGENT_PATH: Final[str] = "E:\\monitor\\agent.ps1"
_WINDOWS_LAUNCH_RELATIVE: Final[str] = "monitor\\start_agent.cmd"
# The modelled guest deliberately does not boot from C:, so code that assumes
# the system drive instead of asking the guest probes the wrong volume.
_GUEST_SYSTEM_DRIVE: Final[str] = "D:"
_GUEST_SPARE_DRIVE: Final[str] = "C:"
_WINDOWS_DRIVES: Final[tuple[str, ...]] = (_GUEST_SPARE_DRIVE, _GUEST_SYSTEM_DRIVE, _WINDOWS_SHARE_DRIVE)
_BATCH_NOOPS: Final[frozenset[str]] = frozenset({"setlocal", "endlocal"})
_POWERSHELL_NAMES: Final[frozenset[str]] = frozenset({"powershell", "powershell.exe"})
_SHELL_NAMES: Final[frozenset[str]] = frozenset({"cmd", "cmd.exe"})
_DRIVE_REFERENCE = re.compile(r"([A-Za-z]:)\\")
_NET_USE = re.compile(r"net(?:\.exe)?\s+use\b", re.IGNORECASE)
_MOUNT_ARGV_LENGTH: Final[int] = 6
_TEST_ARGV_LENGTH: Final[int] = 2
_MOUNT_WRONG_FS_EXIT: Final[int] = 32
_NOT_FOUND_EXIT: Final[int] = 1
_COMMAND_NOT_FOUND_EXIT: Final[int] = 127
_XCOPY_NOT_FOUND_EXIT: Final[int] = 4
_WINDOWS_NOT_RECOGNIZED_EXIT: Final[int] = 9009
_PORT_PAIR_ATTEMPTS: Final[int] = 32
_AGENT_CONNECT_TIMEOUT: Final[float] = 0.05
_LIVE_AGENT_CONNECT_TIMEOUT: Final[float] = 5.0
_LSBLK_UNESCAPED: Final[str] = "#+-.:=@_/"
_LSBLK_COLUMNS: Final[str] = "PATH,FSTYPE,LABEL,MOUNTPOINT"
_LSBLK_ARGV: Final[tuple[str, ...]] = ("--noheadings", "--raw", "--output", _LSBLK_COLUMNS)
_XCOPY_OPERAND_COUNT: Final[int] = 2

# Where the guest's own Windows installation lives. The modelled guest boots
# from D:, so every directory the in-guest monitor mirrors dropped files from
# hangs off D: too - a host that scans C: scans a volume nothing writes to.
# Windows is installed in WinNT rather than Windows, which an in-place upgrade
# from a pre-2000 release leaves behind and a manual install can choose: a host
# that derives the directory from the system drive instead of asking the guest
# for %SystemRoot% names one that is not there.
_GUEST_SYSTEM_ROOT: Final[str] = "D:\\WinNT"
_GUEST_DROP_ROOTS: Final[tuple[str, ...]] = (
    "D:\\Users\\Public\\Downloads",
    "D:\\Users\\Default\\AppData\\Local\\Temp",
    "D:\\WinNT\\Temp",
)
# What the guest reports when neither variable is set, which is the case the
# host and the agent script both have to fall back for.
_UNSET_ENVIRONMENT: Final[str] = ""
_FALLBACK_SYSTEM_DRIVE: Final[str] = "C:"
_FALLBACK_SYSTEM_ROOT: Final[str] = "C:\\Windows"
_SYSTEM_DRIVE_REFERENCE: Final[str] = "%SystemDrive%"
_SYSTEM_ROOT_REFERENCE: Final[str] = "%SystemRoot%"
_SYSTEM_DRIVE_VARIABLE: Final[str] = "SystemDrive"
_SYSTEM_ROOT_VARIABLE: Final[str] = "SystemRoot"
_AGENT_SCRIPT_NAME: Final[str] = "agent.ps1"
_MONITOR_DIRECTORY: Final[str] = "monitor"
_DROP_ROOTS_VARIABLE: Final[str] = "_IC_DropWatchedRoots"
_ALLOWED_NAMES_VARIABLE: Final[str] = "allowedNames"
_ALLOWED_ROOTS_VARIABLE: Final[str] = "allowedRoots"
_EXECUTABLE_SUFFIX: Final[str] = ".exe"
_ALLOWLIST_REJECT_EXIT: Final[int] = -1
_SHELL_COMMAND_FLAG: Final[str] = "/c"
_GUEST_DROP_FILE_NAME: Final[str] = "dropped_payload.bin"
_GUEST_DROP_PAYLOAD: Final[bytes] = b"written by the sample under analysis\n"
_GUEST_BINARY_NAME: Final[str] = "sample.exe"
_GUEST_BINARY_PATH: Final[str] = "E:\\input\\sample.exe"
# A sample whose own name carries spaces. The in-guest agent takes the
# executable as one field and its arguments as another, so the path needs no
# quoting - and a caller that quotes it anyway names a file that is not there.
_SPACED_BINARY_NAME: Final[str] = "sample with space.exe"
_SPACED_BINARY_PATH: Final[str] = "E:\\input\\sample with space.exe"
_SPACED_BINARY_ARGS: Final[tuple[str, str]] = ("--report", "C:\\out dir\\report.txt")
_MZ_HEADER: Final[bytes] = b"MZ" + b"\x00" * 62
_HOST_LOG_LINE: Final[str] = "2026-07-30 11:22:33|created|D:\\Users\\Public\\Downloads\\dropped_payload.bin"
_HOST_LOG_PATH: Final[str] = "D:\\Users\\Public\\Downloads\\dropped_payload.bin"
_FILE_CHANGES_LOG: Final[str] = "file_changes.log"
_HOST_DROPPED_MIRROR_FILE: Final[str] = "mirrored_by_the_guest.bin"
_EXPECTED_LOG_DIR: Final[str] = "E:\\logs"
_EXPECTED_DROPPED_MIRROR: Final[str] = "E:\\output\\dropped"
_RUN_BINARY_TIMEOUT_S: Final[int] = 5


@dataclass(frozen=True)
class _GuestDevice:
    """One block device the modelled guest's ``lsblk`` reports.

    Attributes:
        path: Device node path such as ``/dev/vdb1``.
        fs_type: Filesystem type ``blkid`` detected, empty when there is none.
        label: Filesystem volume label, empty when the volume is unlabelled.
        mountpoint: Where the device is mounted, empty when it is not mounted.
    """

    path: str
    fs_type: str = ""
    label: str = ""
    mountpoint: str = ""


# The layout of the actual target image: a Debian genericcloud qcow2 whose
# partition 15 is an EFI System Partition - vfat, like the share, and
# enumerated before it - plus the FAT virtio drive QEMU synthesises from the
# host shared folder. vvfat labels that drive "QEMU VVFAT" and nothing else on
# the bus carries that label.
_DEBIAN_CLOUD_DEVICES: Final[tuple[_GuestDevice, ...]] = (
    _GuestDevice("/dev/vda"),
    _GuestDevice(_ROOT_DEVICE, "ext4", "", "/"),
    _GuestDevice("/dev/vda14"),
    _GuestDevice(_ESP_DEVICE, "vfat", _ESP_LABEL, "/boot/efi"),
    _GuestDevice("/dev/vdb"),
    _GuestDevice(_SHARE_DEVICE, "vfat", _VVFAT_LABEL),
)
_NO_SHARE_DEVICES: Final[tuple[_GuestDevice, ...]] = _DEBIAN_CLOUD_DEVICES[:4]

# A guest that owns a spare FAT data partition. It is unmounted, exactly as
# the share is, and is enumerated ahead of it; only its label says it is not
# the share. Nothing about a guest having one is unusual.
_FOREIGN_VFAT_DEVICE: Final[str] = "/dev/vda2"
_FOREIGN_VFAT_LABEL: Final[str] = "DATA"
_FOREIGN_LABEL_DEVICES: Final[tuple[_GuestDevice, ...]] = (
    _GuestDevice("/dev/vda"),
    _GuestDevice(_ROOT_DEVICE, "ext4", "", "/"),
    _GuestDevice(_FOREIGN_VFAT_DEVICE, "vfat", _FOREIGN_VFAT_LABEL),
    _GuestDevice("/dev/vda14"),
    _GuestDevice(_ESP_DEVICE, "vfat", _ESP_LABEL, "/boot/efi"),
    _GuestDevice("/dev/vdb"),
    _GuestDevice(_SHARE_DEVICE, "vfat", _VVFAT_LABEL),
)

# A guest that already has a second ``file=fat:`` drive mounted. vvfat stamps
# the same "QEMU VVFAT" label into every drive it synthesises, so this volume
# is indistinguishable from the share by label; only its mount point is.
_SECOND_VVFAT_DEVICE: Final[str] = "/dev/vdb1"
_SECOND_VVFAT_MOUNTPOINT: Final[str] = "/mnt/tools"
_THIRD_DISK_SHARE_DEVICE: Final[str] = "/dev/vdc1"
_MOUNTED_VVFAT_DEVICES: Final[tuple[_GuestDevice, ...]] = (
    _GuestDevice("/dev/vda"),
    _GuestDevice(_ROOT_DEVICE, "ext4", "", "/"),
    _GuestDevice("/dev/vda14"),
    _GuestDevice(_ESP_DEVICE, "vfat", _ESP_LABEL, "/boot/efi"),
    _GuestDevice("/dev/vdb"),
    _GuestDevice(_SECOND_VVFAT_DEVICE, "vfat", _VVFAT_LABEL, _SECOND_VVFAT_MOUNTPOINT),
    _GuestDevice("/dev/vdc"),
    _GuestDevice(_THIRD_DISK_SHARE_DEVICE, "vfat", _VVFAT_LABEL),
)

# A guest whose EFI System Partition carries no label - ``mkfs.vfat`` without
# ``-n`` leaves it empty, which is ordinary - while still being mounted. That
# is the one row shape where an empty column has a non-empty column after it.
_UNLABELLED_ESP_DEVICES: Final[tuple[_GuestDevice, ...]] = (
    _GuestDevice("/dev/vda"),
    _GuestDevice(_ROOT_DEVICE, "ext4", "", "/"),
    _GuestDevice("/dev/vda14"),
    _GuestDevice(_ESP_DEVICE, "vfat", "", "/boot/efi"),
    _GuestDevice("/dev/vdb"),
    _GuestDevice(_SHARE_DEVICE, "vfat", _VVFAT_LABEL),
)


def _escape_lsblk_value(value: str) -> str:
    r"""Escape one column value the way ``lsblk --raw`` writes it.

    Raw output separates columns with a single space, so any character that
    could be mistaken for a separator is written as ``\xNN``.

    Args:
        value: Unescaped column value.

    Returns:
        str: Value with unsafe characters hex-escaped.
    """
    return "".join(char if char.isalnum() or char in _LSBLK_UNESCAPED else f"\\x{ord(char):02x}" for char in value)


class _LinuxGuestModel:
    """Model of a Linux guest answering the mount sequence over guest-exec.

    The model owns real state. ``lsblk`` honours the ``--output`` column list
    it is given and escapes values as ``--raw`` does, ``mount`` records which
    source was attached, and the launcher becomes visible only when the source
    that got mounted is the share itself. Mounting the guest's own EFI System
    Partition therefore succeeds - it really is ``vfat`` - and still leaves the
    launcher absent, which is exactly what happens on the target image.

    Attributes:
        mounted: Whether anything is currently mounted at the mount point.
        mounted_source: Source the successful ``mount`` named, empty when
            nothing is mounted.
        launched: Launcher paths the guest was asked to run.
        mount_argv: Argument list of every ``mount`` invocation received.
    """

    mounted: bool
    mounted_source: str
    launched: list[str]
    mount_argv: list[tuple[str, ...]]

    def __init__(
        self,
        devices: Sequence[_GuestDevice] = _DEBIAN_CLOUD_DEVICES,
        *,
        mount_exit_code: int = 0,
        launcher_present: bool = True,
        listing_exit_code: int = 0,
        share_device: str = _SHARE_DEVICE,
    ) -> None:
        """Configure the modelled guest.

        Args:
            devices: Block devices the guest's ``lsblk`` reports.
            mount_exit_code: Exit status the ``mount`` command returns even
                when its arguments are correct; non-zero models a kernel that
                refuses the mount.
            launcher_present: Whether the shared volume actually carries the
                monitor launch script.
            listing_exit_code: Exit status of the block-device enumeration.
            share_device: Device node that really carries the host shared
                folder; every other volume the guest owns is something else,
                whatever its filesystem type or label.
        """
        self._devices = tuple(devices)
        self._mount_exit_code = mount_exit_code
        self._launcher_present = launcher_present
        self._listing_exit_code = listing_exit_code
        self._share_device = share_device
        self.mounted = False
        self.mounted_source = ""
        self.launched = []
        self.mount_argv = []

    def block_device_listing(self) -> str:
        """Return the guest's own ``lsblk --raw`` output.

        Returns:
            str: Standard output the guest produces for the column list the
            production code asks for.
        """
        return self._run_lsblk(list(_LSBLK_ARGV)).stdout

    def __call__(self, path: str, args: Sequence[str]) -> GuestCommandResult:
        """Execute one command against the modelled guest.

        Args:
            path: Executable the production code asked the guest to run.
            args: Argument list passed with the executable.

        Returns:
            GuestCommandResult: Exit status and captured output.
        """
        argv = list(args)
        if path == "test":
            return self._run_test(argv)
        if path == "mkdir":
            return GuestCommandResult(exit_code=0, stdout="", stderr="")
        if path == "lsblk":
            return self._run_lsblk(argv)
        if path == "mount":
            return self._run_mount(argv)
        if path == "/bin/bash":
            return self._run_launcher(argv)
        return GuestCommandResult(
            exit_code=_COMMAND_NOT_FOUND_EXIT,
            stdout="",
            stderr=f"{path}: command not found",
        )

    def _launcher_visible(self) -> bool:
        """Report whether the launcher is reachable at the mount point.

        Returns:
            bool: True only when the share - not some other ``vfat`` volume -
            is what got mounted and it carries the launcher.
        """
        return self._launcher_present and self.mounted_source in {self._share_device, _SHARE_MOUNT_TAG}

    def _run_test(self, argv: list[str]) -> GuestCommandResult:
        """Answer ``test -f <path>`` from the modelled filesystem state.

        Args:
            argv: Arguments passed to ``test``.

        Returns:
            GuestCommandResult: Exit 0 when the path exists in the model.
        """
        exists = len(argv) == _TEST_ARGV_LENGTH and argv[0] == "-f" and argv[1] == _LINUX_LAUNCH_PATH and self._launcher_visible()
        return GuestCommandResult(exit_code=0 if exists else _NOT_FOUND_EXIT, stdout="", stderr="")

    def _run_lsblk(self, argv: list[str]) -> GuestCommandResult:
        """Report the guest's block devices in the requested columns.

        Args:
            argv: Arguments passed to ``lsblk``.

        Returns:
            GuestCommandResult: One row per device carrying exactly the
            requested columns, or a usage error for an unknown column.
        """
        if "--output" not in argv:
            return GuestCommandResult(
                exit_code=_NOT_FOUND_EXIT,
                stdout="",
                stderr="lsblk: no output columns requested",
            )
        columns = argv[argv.index("--output") + 1].split(",")
        unknown = [column for column in columns if column not in {"PATH", "FSTYPE", "LABEL", "MOUNTPOINT"}]
        if unknown:
            return GuestCommandResult(
                exit_code=_NOT_FOUND_EXIT,
                stdout="",
                stderr=f"lsblk: unknown column: {unknown[0]}",
            )
        raw = "--raw" in argv
        rows: list[str] = []
        for device in self._devices:
            values = [self._column_value(device, column) for column in columns]
            rows.append(" ".join(_escape_lsblk_value(value) if raw else value for value in values))
        return GuestCommandResult(
            exit_code=self._listing_exit_code,
            stdout="".join(f"{row}\n" for row in rows),
            stderr="",
        )

    def _column_value(self, device: _GuestDevice, column: str) -> str:
        """Return one ``lsblk`` column value for a device.

        Args:
            device: Device whose column is being rendered.
            column: Column name requested through ``--output``.

        Returns:
            str: The column value, empty when the device has none.
        """
        if column == "PATH":
            return device.path
        if column == "FSTYPE":
            return device.fs_type
        if column == "LABEL":
            return device.label
        return self._live_mountpoint(device)

    def _live_mountpoint(self, device: _GuestDevice) -> str:
        """Return where a device is mounted right now.

        Args:
            device: Device whose mount state is being reported.

        Returns:
            str: The mount point, including one this test session created.
        """
        if self.mounted and device.path == self.mounted_source:
            return _LINUX_MOUNT_POINT
        return device.mountpoint

    def _run_mount(self, argv: list[str]) -> GuestCommandResult:
        """Attempt a mount, honouring the modelled filesystem types.

        Args:
            argv: Arguments passed to ``mount``.

        Returns:
            GuestCommandResult: Exit 0 only when the source really carries the
            requested filesystem and the configured exit code allows it.
        """
        self.mount_argv.append(tuple(argv))
        if len(argv) != _MOUNT_ARGV_LENGTH or argv[0] != "-t" or argv[2] != "-o":
            return GuestCommandResult(
                exit_code=_MOUNT_WRONG_FS_EXIT,
                stdout="",
                stderr=f"mount: unsupported invocation: {' '.join(argv)}",
            )

        fs_type, source, target = argv[1], argv[4], argv[5]
        if target != _LINUX_MOUNT_POINT:
            return GuestCommandResult(
                exit_code=_MOUNT_WRONG_FS_EXIT,
                stdout="",
                stderr=f"mount: {target}: mount point does not exist",
            )
        if not self._source_matches(fs_type, source):
            return GuestCommandResult(
                exit_code=_MOUNT_WRONG_FS_EXIT,
                stdout="",
                stderr=f"mount: {target}: wrong fs type, bad option, bad superblock on {source}",
            )
        if self._mount_exit_code != 0:
            return GuestCommandResult(
                exit_code=self._mount_exit_code,
                stdout="",
                stderr=f"mount: {target}: permission denied",
            )

        self.mounted = True
        self.mounted_source = source
        return GuestCommandResult(exit_code=0, stdout="", stderr="")

    def _source_matches(self, fs_type: str, source: str) -> bool:
        """Report whether ``source`` really holds ``fs_type`` in this guest.

        Args:
            fs_type: Filesystem type named by the ``mount -t`` argument.
            source: Device node or 9p mount tag named by the caller.

        Returns:
            bool: True when the pairing is one the guest kernel would accept.
        """
        if fs_type == "9p":
            return source == _SHARE_MOUNT_TAG
        return any(device.path == source and device.fs_type == fs_type for device in self._devices)

    def _run_launcher(self, argv: list[str]) -> GuestCommandResult:
        """Record a monitor-launcher invocation.

        Args:
            argv: Arguments passed to ``/bin/bash``.

        Returns:
            GuestCommandResult: Exit 0 when the script exists, 127 otherwise.
        """
        script = argv[0] if argv else ""
        if not (self._launcher_visible() and script == _LINUX_LAUNCH_PATH):
            return GuestCommandResult(
                exit_code=_COMMAND_NOT_FOUND_EXIT,
                stdout="",
                stderr=f"/bin/bash: {script}: No such file or directory",
            )
        self.launched.append(script)
        return GuestCommandResult(exit_code=0, stdout="", stderr="")


def _split_command_line(line: str) -> list[str]:
    """Split one command line into tokens the way ``cmd.exe`` does.

    Args:
        line: Command line with double quotes grouping arguments.

    Returns:
        list[str]: Tokens with the grouping quotes removed.
    """
    tokens: list[str] = []
    current: list[str] = []
    quoted = False
    for char in line:
        if char == '"':
            quoted = not quoted
            continue
        if char.isspace() and not quoted:
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(char)
    if current:
        tokens.append("".join(current))
    return tokens


def _guest_to_host(guest_path: str, share_drive: str | None, share_host_root: Path) -> Path | None:
    """Translate an in-guest path to the host file backing it.

    Only the share drive is backed by anything: every other drive the modelled
    guest owns is empty, which is what makes a path built on the wrong root
    resolve to nothing.

    Args:
        guest_path: Absolute path as the guest sees it.
        share_drive: Designator of the drive carrying the shared folder, or
            None when no drive carries it.
        share_host_root: Host directory whose contents that drive exposes.

    Returns:
        Path | None: Backing host path, or None when the path is not on the
        share drive.
    """
    if share_drive is None:
        return None
    prefix = f"{share_drive}\\"
    if not guest_path.upper().startswith(prefix.upper()):
        return None
    relative = guest_path[len(prefix) :].replace("\\", "/").strip("/")
    if not relative:
        return None
    return share_host_root.joinpath(*relative.split("/"))


def _guest_environment(system_drive: str, system_root: str) -> dict[str, str]:
    """Build the environment block a modelled Windows guest exports.

    A variable the guest does not set is absent rather than empty, which is
    what makes the agent script's own substitution run.

    Args:
        system_drive: Value of ``%SystemDrive%``, empty when it is not set.
        system_root: Value of ``%SystemRoot%``, empty when it is not set.

    Returns:
        dict[str, str]: Variables the guest exports, without the unset ones.
    """
    exported = ((_SYSTEM_DRIVE_VARIABLE, system_drive), (_SYSTEM_ROOT_VARIABLE, system_root))
    return {name: value for name, value in exported if value}


def _read_agent_script(share_host_root: Path) -> str:
    """Read the agent script the sandbox really staged into the share.

    Args:
        share_host_root: Host directory the share drive exposes.

    Returns:
        str: Full text of the staged ``agent.ps1``.
    """
    return (share_host_root / _MONITOR_DIRECTORY / _AGENT_SCRIPT_NAME).read_text(encoding="utf-8")


class _WindowsGuestModel:
    """Model of a Windows guest that really runs what it is handed.

    The guest owns a filesystem: the share drive is backed by the host
    directory the sandbox staged its scripts into, and every other drive is
    empty. ``cmd.exe /c <launcher>`` therefore reads the launcher's real bytes
    and interprets them - ``%~dp0`` expands to the launcher's own directory,
    every drive-qualified path the line names must be on a drive the guest
    actually has, and a ``powershell.exe -File`` line goes on to read that
    script and apply the same rule to its contents.

    That is what makes a hardcoded drive letter visible: this guest has no
    ``Z:``, because nothing maps one. QEMU's ``smb=`` netdev option would need
    an ``smbd`` on the host, a Windows host has none, and the sandbox emits no
    ``-smb`` argument at all - so the FAT virtio volume is the only share that
    exists, and a launcher naming ``Z:`` fails here exactly as it does in a
    real guest.

    Attributes:
        launched: Launcher paths that ran to completion.
        probed: Paths the production code probed with ``dir``.
        scripts_run: PowerShell scripts a launcher actually started.
        missing_drives: Drive designators a script referenced that this guest
            does not have.
        net_use_attempts: Lines that tried to map a network drive.
        script: Declarations the last PowerShell script the guest ran resolved
            from its own location and this guest's environment.
    """

    launched: list[str]
    probed: list[str]
    scripts_run: list[str]
    missing_drives: list[str]
    net_use_attempts: list[str]
    script: PowerShellScript

    def __init__(
        self,
        share_host_root: Path,
        drives: Sequence[str] = _WINDOWS_DRIVES,
        share_drive: str | None = _WINDOWS_SHARE_DRIVE,
        system_drive: str = _GUEST_SYSTEM_DRIVE,
        system_root: str = _GUEST_SYSTEM_ROOT,
    ) -> None:
        """Configure the modelled guest.

        Args:
            share_host_root: Host directory whose contents the share drive
                exposes to the guest.
            drives: Drive designators ``fsutil fsinfo drives`` reports.
            share_drive: Designator of the drive carrying the shared folder, or
                None when no drive carries it.
            system_drive: Drive this guest booted from, as ``%SystemDrive%``
                reports it, or empty when the variable is not set.
            system_root: Directory this guest's Windows lives in, as
                ``%SystemRoot%`` reports it, or empty when the variable is not
                set.
        """
        self._share_host_root = share_host_root
        self._drives = tuple(drives)
        self._share_drive = share_drive
        self._system_drive = system_drive
        self._system_root = system_root
        self.launched = []
        self.probed = []
        self.scripts_run = []
        self.missing_drives = []
        self.net_use_attempts = []
        self.script = PowerShellScript(variables={}, arrays={})

    def __call__(self, path: str, args: Sequence[str]) -> GuestCommandResult:
        """Execute one command against the modelled guest.

        Args:
            path: Executable the production code asked the guest to run.
            args: Argument list passed with the executable.

        Returns:
            GuestCommandResult: Exit status and captured output.
        """
        argv = list(args)
        if path != "cmd.exe" or argv[:1] != ["/c"]:
            return GuestCommandResult(
                exit_code=_COMMAND_NOT_FOUND_EXIT,
                stdout="",
                stderr=f"'{path}' is not recognized as an internal or external command",
            )

        rest = argv[1:]
        if rest[:3] == ["fsutil", "fsinfo", "drives"]:
            listing = "Drives: " + " ".join(f"{drive}\\" for drive in self._drives)
            return GuestCommandResult(exit_code=0, stdout=f"{listing}\n", stderr="")
        if rest[:2] == ["echo", _SYSTEM_DRIVE_REFERENCE]:
            return self._echo_environment(_SYSTEM_DRIVE_REFERENCE, self._system_drive)
        if rest[:2] == ["echo", _SYSTEM_ROOT_REFERENCE]:
            return self._echo_environment(_SYSTEM_ROOT_REFERENCE, self._system_root)
        if rest[:2] == ["dir", "/b"]:
            return self._run_probe(rest[2:])
        return self._run_launcher(rest)

    @staticmethod
    def _echo_environment(reference: str, value: str) -> GuestCommandResult:
        """Answer ``echo %VAR%`` the way ``cmd.exe`` answers it.

        A variable that is not set is left unexpanded rather than echoed as an
        empty line, which is the only signal the host gets that the guest
        cannot answer.

        Args:
            reference: The ``%VAR%`` reference as it was written.
            value: Value the guest exports, empty when it exports none.

        Returns:
            GuestCommandResult: Exit 0 carrying the expanded value or the
            unexpanded reference.
        """
        return GuestCommandResult(exit_code=0, stdout=f"{value or reference}\n", stderr="")

    def _host_path(self, guest_path: str) -> Path | None:
        """Translate an in-guest path to the host file backing it.

        Args:
            guest_path: Absolute path as the guest sees it.

        Returns:
            Path | None: Backing host path, or None when the path is not on
            the share drive (every other drive is empty in this guest).
        """
        return _guest_to_host(guest_path, self._share_drive, self._share_host_root)

    def _run_probe(self, operands: list[str]) -> GuestCommandResult:
        """Answer a ``dir /b <path>`` existence probe.

        Args:
            operands: Operands following ``dir /b``.

        Returns:
            GuestCommandResult: Exit 0 when the probed path exists.
        """
        probe = operands[0] if operands else ""
        self.probed.append(probe)
        host_file = self._host_path(probe) if probe else None
        if host_file is not None and host_file.is_file():
            return GuestCommandResult(exit_code=0, stdout=f"{probe}\n", stderr="")
        return GuestCommandResult(
            exit_code=_NOT_FOUND_EXIT,
            stdout="",
            stderr="File Not Found",
        )

    def _run_launcher(self, operands: list[str]) -> GuestCommandResult:
        """Read the launcher out of the guest filesystem and interpret it.

        Args:
            operands: Operands following ``cmd.exe /c``.

        Returns:
            GuestCommandResult: Exit 0 only when every command in the launcher
            resolved inside this guest.
        """
        script = operands[0] if operands else ""
        host_file = self._host_path(script) if script else None
        if host_file is None or not host_file.is_file():
            return GuestCommandResult(
                exit_code=_NOT_FOUND_EXIT,
                stdout="",
                stderr=f"The system cannot find the path specified: {script}",
            )
        result = self._interpret_batch(script, host_file.read_text(encoding="utf-8"))
        if result.exit_code == 0:
            self.launched.append(script)
        return result

    def _interpret_batch(self, script_path: str, body: str) -> GuestCommandResult:
        """Run every command line of a batch file against this guest.

        Args:
            script_path: In-guest path the batch file was started from.
            body: Full text of the batch file.

        Returns:
            GuestCommandResult: Outcome of the first failing line, or exit 0.
        """
        separator = "\\"
        script_dir = script_path.rsplit(separator, 1)[0] + separator
        for raw_line in body.splitlines():
            line = raw_line.strip()
            lowered = line.lower()
            if not line or lowered.startswith(("@echo", "echo ", "rem ")) or lowered in _BATCH_NOOPS:
                continue
            expanded = line.replace("%~dp0", script_dir)
            absent = self._reject_absent_drives(expanded)
            if absent is not None:
                return absent
            result = self._run_batch_command(_split_command_line(expanded))
            if result.exit_code != 0:
                return result
        return GuestCommandResult(exit_code=0, stdout="", stderr="")

    def _reject_absent_drives(self, text: str) -> GuestCommandResult | None:
        """Fail when a script names a drive this guest does not have.

        Args:
            text: Script text whose drive-qualified paths are checked.

        Returns:
            GuestCommandResult | None: Failure for the first absent drive, or
            None when every referenced drive exists.
        """
        for reference in _DRIVE_REFERENCE.findall(text):
            drive = str(reference).upper()
            if drive in self._drives:
                continue
            if drive not in self.missing_drives:
                self.missing_drives.append(drive)
            return GuestCommandResult(
                exit_code=_NOT_FOUND_EXIT,
                stdout="",
                stderr=f"The system cannot find the drive specified: {drive}",
            )
        return None

    def _run_batch_command(self, tokens: list[str]) -> GuestCommandResult:
        """Execute one resolved command line from a batch file.

        Args:
            tokens: Command line already split and de-quoted.

        Returns:
            GuestCommandResult: Outcome of the command.
        """
        if not tokens:
            return GuestCommandResult(exit_code=0, stdout="", stderr="")
        if tokens[0].lower() not in _POWERSHELL_NAMES:
            return GuestCommandResult(
                exit_code=_COMMAND_NOT_FOUND_EXIT,
                stdout="",
                stderr=f"'{tokens[0]}' is not recognized as an internal or external command",
            )
        if "-File" not in tokens or tokens.index("-File") == len(tokens) - 1:
            return GuestCommandResult(
                exit_code=_NOT_FOUND_EXIT,
                stdout="",
                stderr="powershell.exe: -File requires a script path",
            )
        return self._run_powershell(tokens[tokens.index("-File") + 1])

    def _run_powershell(self, script_path: str) -> GuestCommandResult:
        """Read a PowerShell script and check it can run in this guest.

        Args:
            script_path: In-guest path of the script ``-File`` named.

        Returns:
            GuestCommandResult: Exit 0 when the script exists and references
            only drives and shares this guest provides.
        """
        host_file = self._host_path(script_path)
        if host_file is None or not host_file.is_file():
            return GuestCommandResult(
                exit_code=_NOT_FOUND_EXIT,
                stdout="",
                stderr=f"The argument '{script_path}' to the -File parameter does not exist",
            )
        self.scripts_run.append(script_path)
        body = host_file.read_text(encoding="utf-8")
        self.script = evaluate_script(
            body,
            script_root=split_path_parent(script_path),
            environment=_guest_environment(self._system_drive, self._system_root),
        )
        attempts = [line.strip() for line in body.splitlines() if _NET_USE.search(line)]
        self.net_use_attempts.extend(attempts)
        if attempts:
            return GuestCommandResult(
                exit_code=_NOT_FOUND_EXIT,
                stdout="",
                stderr="System error 53 has occurred. The network path was not found.",
            )
        absent = self._reject_absent_drives(body)
        if absent is not None:
            return absent
        return GuestCommandResult(exit_code=0, stdout="", stderr="")


class _WindowsAgentGuest:
    """Model of the in-guest monitor agent executing what the host dispatches.

    Every request is first put through the allowlist the *real* generated
    ``agent.ps1`` declares: its ``$allowedNames`` and ``$allowedRoots`` are
    evaluated out of the staged script text and applied by the same three rules
    ``Test-AllowedCommand`` applies, so a command the live agent would answer
    with ``command not in allowlist`` is answered that way here too. What
    survives is launched the way ``& $cmd @cmdArgs`` launches it: the command
    field is one executable name, never a command line to be split, and the
    arguments travel beside it.

    It shares the modelled guest's filesystem: the share drive is backed by the
    staged host directory, and the only directories that exist below the boot
    volume are the ones the agent's own file watcher mirrors from. An ``xcopy``
    whose source is one of those copies a file into its destination; a source
    anywhere else finds nothing, which is what a host scanning a volume the
    guest never wrote to gets back. A program is only runnable when it really
    is on the share, so a command built on the wrong share root is not.

    Attributes:
        commands: Every ``(command, args)`` pair the agent was asked to run.
        rejected: Every command the script's allowlist refused.
        copied: Every ``(source, destination)`` pair an ``xcopy`` really moved.
    """

    commands: list[tuple[str, tuple[str, ...]]]
    rejected: list[str]
    copied: list[tuple[str, str]]

    def __init__(
        self,
        share_host_root: Path,
        share_drive: str = _WINDOWS_SHARE_DRIVE,
        populated_directories: Sequence[str] = _GUEST_DROP_ROOTS,
        system_drive: str = _GUEST_SYSTEM_DRIVE,
        system_root: str = _GUEST_SYSTEM_ROOT,
    ) -> None:
        """Configure the modelled in-guest agent.

        Args:
            share_host_root: Host directory whose contents the share drive
                exposes to the guest.
            share_drive: Designator of the drive carrying the shared folder.
            populated_directories: Guest directories that exist and hold a file
                the sample dropped.
            system_drive: Drive this guest booted from, as ``%SystemDrive%``
                reports it.
            system_root: Directory this guest's Windows lives in, as
                ``%SystemRoot%`` reports it.
        """
        self._share_host_root = share_host_root
        self._share_drive = share_drive
        self._populated = {directory.upper() for directory in populated_directories}
        self._environment = _guest_environment(system_drive, system_root)
        self.commands = []
        self.rejected = []
        self.copied = []

    def __call__(self, path: str, args: Sequence[str]) -> GuestCommandResult:
        """Execute one dispatched command against the modelled guest.

        Args:
            path: Executable the host dispatched.
            args: Argument list passed with it.

        Returns:
            GuestCommandResult: Exit status and captured output.
        """
        argv = list(args)
        self.commands.append((path, tuple(argv)))
        if not self._command_allowed(path):
            self.rejected.append(path)
            return GuestCommandResult(
                exit_code=_ALLOWLIST_REJECT_EXIT,
                stdout="",
                stderr=f"command not in allowlist: {path}",
            )
        if path.lower() in _SHELL_NAMES and argv[:1] == [_SHELL_COMMAND_FLAG]:
            return self._run_shell(" ".join(argv[1:]))
        return self._run_program(path, argv)

    def _allowlist(self) -> tuple[frozenset[str], tuple[str, ...]]:
        """Read the allowlist out of the agent script the sandbox staged.

        A script that no longer declares either array in a form this guest can
        evaluate raises ``KeyError`` here, which is the loud failure such a
        script deserves: the live agent would have nothing to check against.

        Returns:
            tuple[frozenset[str], tuple[str, ...]]: Lower-cased ``$allowedNames``
            and ``$allowedRoots`` as the script declares them for this guest.
        """
        script = evaluate_script(
            _read_agent_script(self._share_host_root),
            script_root=f"{self._share_drive}\\{_MONITOR_DIRECTORY}",
            environment=self._environment,
        )
        names = script.arrays[_ALLOWED_NAMES_VARIABLE]
        roots = script.arrays[_ALLOWED_ROOTS_VARIABLE]
        return frozenset(name.lower() for name in names), tuple(root.lower() for root in roots)

    def _command_allowed(self, command: str) -> bool:
        """Apply the generated script's own ``Test-AllowedCommand`` rules.

        Args:
            command: Value of the request's ``command`` field.

        Returns:
            bool: True when the live agent would run it.
        """
        if not command:
            return False
        names, roots = self._allowlist()
        lowered = command.lower()
        if lowered in names:
            return True
        if not lowered.endswith(_EXECUTABLE_SUFFIX):
            return False
        return any(lowered.startswith(root) for root in roots)

    def _run_shell(self, line: str) -> GuestCommandResult:
        """Interpret one ``cmd.exe /c`` payload.

        Args:
            line: The payload following ``/c``.

        Returns:
            GuestCommandResult: Outcome of the interpreted command.
        """
        tokens = _split_command_line(line)
        name = tokens[0].lower() if tokens else ""
        operands = [token for token in tokens[1:] if not token.startswith("/")]
        if name == "xcopy":
            return self._run_xcopy(operands)
        if name == "dir":
            return self._run_dir(operands)
        return GuestCommandResult(
            exit_code=_COMMAND_NOT_FOUND_EXIT,
            stdout="",
            stderr=f"'{tokens[0] if tokens else ''}' is not recognized as an internal or external command",
        )

    def _run_dir(self, operands: list[str]) -> GuestCommandResult:
        """List one guest directory the share drive really backs.

        Args:
            operands: Non-switch operands of the ``dir`` invocation.

        Returns:
            GuestCommandResult: Exit 0 with one file name per line, or the
            not-found status for a path this guest does not have.
        """
        target = _guest_to_host(operands[0], self._share_drive, self._share_host_root) if operands else None
        if target is None or not target.is_dir():
            return GuestCommandResult(
                exit_code=_NOT_FOUND_EXIT,
                stdout="",
                stderr="The system cannot find the path specified.",
            )
        names = sorted(entry.name for entry in target.iterdir())
        return GuestCommandResult(exit_code=0, stdout="".join(f"{name}\n" for name in names), stderr="")

    def _run_xcopy(self, operands: list[str]) -> GuestCommandResult:
        """Copy one guest directory into the share, when it exists.

        Args:
            operands: Non-switch operands of the ``xcopy`` invocation.

        Returns:
            GuestCommandResult: Exit 0 with one file copied, or xcopy's
            not-found status.
        """
        if len(operands) != _XCOPY_OPERAND_COUNT:
            return GuestCommandResult(exit_code=_XCOPY_NOT_FOUND_EXIT, stdout="", stderr="Invalid number of parameters")
        source, destination = operands
        if source.upper() not in self._populated:
            return GuestCommandResult(
                exit_code=_XCOPY_NOT_FOUND_EXIT,
                stdout="0 File(s) copied\n",
                stderr=f"File not found - {source}",
            )
        host_destination = _guest_to_host(destination, self._share_drive, self._share_host_root)
        if host_destination is None:
            return GuestCommandResult(exit_code=_XCOPY_NOT_FOUND_EXIT, stdout="", stderr=f"Invalid drive specification: {destination}")
        host_destination.mkdir(parents=True, exist_ok=True)
        (host_destination / _GUEST_DROP_FILE_NAME).write_bytes(_GUEST_DROP_PAYLOAD)
        self.copied.append((source, destination))
        return GuestCommandResult(exit_code=0, stdout="1 File(s) copied\n", stderr="")

    def _run_program(self, executable: str, argv: list[str]) -> GuestCommandResult:
        """Run a program the host addressed by its in-guest path.

        ``& $cmd @cmdArgs`` hands the command field to the process launcher as
        one name, so it is resolved verbatim: nothing splits it on spaces and
        nothing strips quotes from it.

        Args:
            executable: In-guest path of the program to run.
            argv: Argument list passed to the program.

        Returns:
            GuestCommandResult: Exit 0 when the executable is really there.
        """
        host_file = _guest_to_host(executable, self._share_drive, self._share_host_root)
        if host_file is None or not host_file.is_file():
            return GuestCommandResult(
                exit_code=_WINDOWS_NOT_RECOGNIZED_EXIT,
                stdout="",
                stderr=f"'{executable}' is not recognized as an internal or external command",
            )
        invocation = " ".join([host_file.name, *argv])
        return GuestCommandResult(exit_code=0, stdout=f"ran {invocation}\n", stderr="")


class _MountTestSandbox(QEMUSandbox):
    """``QEMUSandbox`` subclass exposing the mount helpers to test code.

    Only public wrappers are added; every wrapped method is the real
    production implementation.
    """

    def use_shared_folder(self, path: Path) -> None:
        """Point the sandbox at a host shared folder without starting QEMU.

        Args:
            path: Host directory standing in for the prepared shared folder.
        """
        self._shared_folder = path

    async def create_agent_scripts(self) -> None:
        """Drive the real :meth:`QEMUSandbox._create_guest_agent_script`."""
        await self._create_guest_agent_script()

    @classmethod
    def windows_agent_script(cls) -> str:
        """Return the real Windows guest agent PowerShell body.

        Returns:
            str: Script source the sandbox stages into the share.
        """
        return cls._windows_agent_script_content()

    def generate_execution_script(self, script_id: str) -> str:
        """Return the real in-guest execution script body for one invocation.

        Args:
            script_id: Unique identifier for the generated script.

        Returns:
            str: Script body carrying the in-guest paths the host will poll.
        """
        _name, content = self._generate_execution_script(
            command="target.exe",
            working_directory=None,
            script_id=script_id,
            result_name=f"result_{script_id}.txt",
            stdout_name=f"{script_id}.stdout",
            stderr_name=f"{script_id}.stderr",
        )
        return content

    async def mount_shared_volume(self) -> None:
        """Drive the real :meth:`QEMUSandbox._mount_guest_shared_volume`."""
        await self._mount_guest_shared_volume()

    async def bootstrap(self) -> None:
        """Drive the real :meth:`QEMUSandbox._bootstrap_guest_agent`."""
        await self._bootstrap_guest_agent()

    async def attach_agents(self) -> None:
        """Drive the real :meth:`QEMUSandbox._attach_qemu_agents`."""
        await self._attach_qemu_agents()

    def shared_folder_args(self) -> list[str]:
        """Return the real shared-folder argv for the current host and guest.

        Returns:
            list[str]: The ``-drive`` or ``-fsdev``/``-device`` arguments.
        """
        return self._shared_folder_args()

    def uses_fat_transport(self) -> bool:
        """Return the real transport predicate used to build the argv.

        Returns:
            bool: True when the share is a FAT virtio drive.
        """
        return self._uses_fat_shared_transport()

    def drop_watch_roots(self) -> list[str]:
        """Return the guest directories the real host-side scan reads.

        Returns:
            list[str]: Absolute in-guest directories
            :meth:`QEMUSandbox._windows_drop_watch_roots` produces from the
            values probed out of the guest.
        """
        return self._windows_drop_watch_roots()

    def guest_shared_root(self) -> str | None:
        """Return the guest-side share root resolved by the mount.

        Returns:
            str | None: Resolved root, or None when the mount has not run.
        """
        return self._guest_shared_root

    @classmethod
    def parse_block_devices(cls, listing: str) -> list[tuple[str, str, str, str]]:
        """Return the real parse of one ``lsblk --raw`` listing.

        Args:
            listing: Standard output of the guest's ``lsblk`` invocation.

        Returns:
            list[tuple[str, str, str, str]]: One
            ``(path, fs_type, label, mountpoint)`` tuple per parsed row.
        """
        return [(row.path, row.fs_type, row.label, row.mountpoint) for row in cls._parse_guest_block_devices(listing)]

    def mark_running(self) -> None:
        """Put the sandbox in the state its data-plane methods require."""
        self.state.status = "running"

    async def collected_file_changes(self) -> list[FileChange]:
        """Return the file-change records the real log collection produced.

        Returns:
            list[FileChange]: Records parsed out of the host-side log folder
            the sandbox reads.
        """
        logs = await self._collect_monitoring_logs()
        return logs.file_changes

    async def collect_dropped_mirror(self, staging_dir: Path) -> None:
        """Drive the real :meth:`QEMUSandbox._host_collect_dropped_files`.

        Args:
            staging_dir: Destination directory for the collected files.
        """
        await self._host_collect_dropped_files(staging_dir=staging_dir)

    async def close_clients(self) -> None:
        """Disconnect every protocol client the test opened."""
        if self._qga is not None:
            await self._qga.disconnect()
            self._qga = None
        if self._qmp is not None:
            await self._qmp.disconnect()
            self._qmp = None
        if self._agent is not None:
            await self._agent.disconnect()
            self._agent = None


class _ChannelNeighbour:
    """The loopback port one below the guest-agent channel.

    The sandbox derives the guest-agent channel port as ``agent_port + 1``, so
    the port below the agent server is the one the Intellicrack in-guest agent
    listens on. A test that drives the agent data plane has a real
    :class:`IntellicrackAgentServer` there; every other test only needs that
    connection to be deterministically refused rather than to reach whatever
    else the host happens to be running, so the port is bound and never
    listened on.

    Attributes:
        guard: Socket holding an unserved port, or None when one is served.
        server: Listening in-guest agent server, or None when the port is only
            held.
    """

    guard: socket.socket | None
    server: IntellicrackAgentServer | None

    def __init__(self, guard: socket.socket | None, server: IntellicrackAgentServer | None) -> None:
        """Record whichever way the port is being held.

        Args:
            guard: Socket holding an unserved port.
            server: Listening in-guest agent server.
        """
        self.guard = guard
        self.server = server

    async def release(self) -> None:
        """Give the port back."""
        if self.guard is not None:
            self.guard.close()
        if self.server is not None:
            await self.server.stop()


async def _claim_neighbour(port: int, agent_responder: GuestCommandResponder | None) -> _ChannelNeighbour:
    """Take the port below the guest-agent channel.

    Args:
        port: Port to claim.
        agent_responder: Guest model answering in-guest agent requests, or None
            to leave the port unserved.

    Returns:
        _ChannelNeighbour: Holder for the claimed port.

    Raises:
        OSError: If the port is already in use.
    """
    if agent_responder is not None:
        server = IntellicrackAgentServer(agent_responder, port=port)
        await server.start()
        return _ChannelNeighbour(None, server)

    guard = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        guard.bind(("127.0.0.1", port))
    except OSError:
        guard.close()
        raise
    return _ChannelNeighbour(guard, None)


async def _start_agent_channel(
    responder: GuestCommandResponder,
    agent_responder: GuestCommandResponder | None,
) -> tuple[GuestAgentProtocolServer, _ChannelNeighbour]:
    """Start the agent server on a port whose predecessor can be claimed.

    Args:
        responder: Guest model answering ``guest-exec`` requests.
        agent_responder: Guest model answering in-guest agent requests, or None
            to leave the Intellicrack agent port unserved.

    Returns:
        tuple[GuestAgentProtocolServer, _ChannelNeighbour]: The listening
        guest-agent server and the holder of ``port - 1``.

    Raises:
        RuntimeError: If no adjacent port pair could be claimed.
    """
    for _attempt in range(_PORT_PAIR_ATTEMPTS):
        server = GuestAgentProtocolServer(responder)
        await server.start()
        try:
            neighbour = await _claim_neighbour(server.port - 1, agent_responder)
        except OSError:
            await server.stop()
            continue
        return server, neighbour

    msg = "could not reserve an adjacent loopback port pair for the guest-agent channel"
    raise RuntimeError(msg)


@asynccontextmanager
async def _guest_session(
    responder: GuestCommandResponder,
    guest_os: GuestOS,
    shared_folder: Path,
    agent_responder: GuestCommandResponder | None = None,
) -> AsyncGenerator[tuple[_MountTestSandbox, GuestAgentProtocolServer]]:
    """Wire a sandbox to a real QMP server and a real modelled guest agent.

    Args:
        responder: Guest model answering ``guest-exec`` requests.
        guest_os: Guest OS family to configure on the sandbox.
        shared_folder: Host directory standing in for the shared folder.
        agent_responder: Guest model answering the in-guest Intellicrack
            agent's requests. When given, that agent really listens and the
            sandbox's data plane runs against it; the model records what it
            was asked to do.

    Yields:
        tuple[_MountTestSandbox, GuestAgentProtocolServer]: The sandbox under
        test and the agent server recording its commands.
    """
    ga_server, neighbour = await _start_agent_channel(responder, agent_responder)
    qmp_server = QmpProtocolServer()
    await qmp_server.start()
    connect_timeout = _AGENT_CONNECT_TIMEOUT if agent_responder is None else _LIVE_AGENT_CONNECT_TIMEOUT
    sandbox = _MountTestSandbox(
        config=SandboxConfig(),
        qemu_config=QEMUConfig(
            guest_os=guest_os,
            monitor_port=qmp_server.port,
            agent_port=ga_server.port - 1,
            agent_connect_timeout=connect_timeout,
        ),
    )
    sandbox.use_shared_folder(shared_folder)
    try:
        yield sandbox, ga_server
    finally:
        await sandbox.close_clients()
        await qmp_server.stop()
        await ga_server.stop()
        await neighbour.release()


def _index_of(command_lines: list[str], needle: str) -> int:
    """Return the position of the first command containing ``needle``.

    Args:
        command_lines: Commands the guest received, in arrival order.
        needle: Substring identifying the command of interest.

    Returns:
        int: Index of the first match, or -1 when there is none.
    """
    for index, line in enumerate(command_lines):
        if needle in line:
            return index
    return -1


class TestLinuxFatShareIsMountedInTheGuest:
    """A FAT-backed share must be discovered and mounted before bootstrap."""

    @pytest.mark.asyncio
    async def test_mount_discovers_the_vfat_device_instead_of_assuming_vdb(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The share is found by filesystem type, not by device ordering.

        The modelled guest is the real target layout: the EFI System Partition
        on ``/dev/vda15`` is ``vfat`` too and is enumerated before the share, so
        taking the first ``vfat`` row remounts the boot partition instead.

        Args:
            tmp_path: Host directory standing in for the shared folder.
            monkeypatch: Fixture used to pin the host platform.
        """
        monkeypatch.setattr(qemu_module, "_IS_WINDOWS", True)
        guest = _LinuxGuestModel()
        async with _guest_session(guest, GuestOS.LINUX, tmp_path) as (sandbox, ga_server):
            await sandbox.mount_shared_volume()
            await sandbox.bootstrap()

            assert guest.mounted is True
            assert guest.mount_argv == [("-t", "vfat", "-o", "rw", _SHARE_DEVICE, _LINUX_MOUNT_POINT)]
            assert guest.launched == [_LINUX_LAUNCH_PATH]
            assert sandbox.guest_shared_root() == _LINUX_MOUNT_POINT

            command_lines = ga_server.command_lines()
            assert _index_of(command_lines, "lsblk") >= 0, f"the guest was never asked for its block devices: {command_lines}"
            assert _index_of(command_lines, "mount -t vfat") < _index_of(command_lines, _LINUX_LAUNCH_COMMAND), (
                f"the share must be mounted before the launcher runs: {command_lines}"
            )
            assert _ESP_DEVICE not in " ".join(guest.mount_argv[0]), (
                f"the guest's EFI System Partition was mounted over the share: {guest.mount_argv}"
            )

    @pytest.mark.asyncio
    async def test_attach_mounts_the_share_before_launching_the_monitor(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The real start sequence mounts first and bootstraps afterwards.

        ``_attach_qemu_agents`` runs to its final step, where the Intellicrack
        in-guest agent socket is deliberately refused; reaching that error
        proves the mount and the bootstrap both completed before it.

        Args:
            tmp_path: Host directory standing in for the shared folder.
            monkeypatch: Fixture used to pin the host platform.
        """
        monkeypatch.setattr(qemu_module, "_IS_WINDOWS", True)
        guest = _LinuxGuestModel()
        async with _guest_session(guest, GuestOS.LINUX, tmp_path) as (sandbox, ga_server):
            with pytest.raises(SandboxError, match="guest agent failed to connect"):
                await sandbox.attach_agents()

            command_lines = ga_server.command_lines()
            mount_index = _index_of(command_lines, "mount -t vfat")
            launch_index = _index_of(command_lines, _LINUX_LAUNCH_COMMAND)
            assert mount_index >= 0, f"the start sequence never mounted the share: {command_lines}"
            assert launch_index > mount_index, f"the monitor was launched before the share was mounted: {command_lines}"
            assert guest.launched == [_LINUX_LAUNCH_PATH]

    @pytest.mark.asyncio
    async def test_missing_vfat_volume_aborts_before_the_launcher(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A guest with no vfat volume raises and never launches the monitor.

        Args:
            tmp_path: Host directory standing in for the shared folder.
            monkeypatch: Fixture used to pin the host platform.
        """
        monkeypatch.setattr(qemu_module, "_IS_WINDOWS", True)
        guest = _LinuxGuestModel(_NO_SHARE_DEVICES)
        async with _guest_session(guest, GuestOS.LINUX, tmp_path) as (sandbox, ga_server):
            with pytest.raises(SandboxError, match="no unmounted vfat block device labelled"):
                await sandbox.attach_agents()

            assert guest.mounted is False
            assert guest.launched == []
            assert _index_of(ga_server.command_lines(), _LINUX_LAUNCH_COMMAND) == -1

    @pytest.mark.asyncio
    async def test_failed_mount_exit_status_aborts_before_the_launcher(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A non-zero ``mount`` exit status is detected and raises.

        Args:
            tmp_path: Host directory standing in for the shared folder.
            monkeypatch: Fixture used to pin the host platform.
        """
        monkeypatch.setattr(qemu_module, "_IS_WINDOWS", True)
        guest = _LinuxGuestModel(mount_exit_code=_MOUNT_WRONG_FS_EXIT)
        async with _guest_session(guest, GuestOS.LINUX, tmp_path) as (sandbox, ga_server):
            with pytest.raises(SandboxError, match="mounting the shared volume"):
                await sandbox.attach_agents()

            assert guest.mounted is False
            assert guest.launched == []
            assert _index_of(ga_server.command_lines(), _LINUX_LAUNCH_COMMAND) == -1

    @pytest.mark.asyncio
    async def test_unmounted_volume_with_a_foreign_label_is_not_the_share(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A spare unmounted FAT partition must not be taken for the share.

        It is unmounted exactly as the share is and is enumerated ahead of it,
        so mount state alone cannot tell the two apart; only vvfat's label can.
        Mounting the wrong one succeeds - it really is ``vfat`` - and leaves the
        monitor launcher nowhere to be found.

        Args:
            tmp_path: Host directory standing in for the shared folder.
            monkeypatch: Fixture used to pin the host platform.
        """
        monkeypatch.setattr(qemu_module, "_IS_WINDOWS", True)
        guest = _LinuxGuestModel(_FOREIGN_LABEL_DEVICES)
        async with _guest_session(guest, GuestOS.LINUX, tmp_path) as (sandbox, ga_server):
            await sandbox.mount_shared_volume()

            assert guest.mount_argv == [("-t", "vfat", "-o", "rw", _SHARE_DEVICE, _LINUX_MOUNT_POINT)], (
                f"the spare {_FOREIGN_VFAT_LABEL} partition was mounted instead of the share: {guest.mount_argv}"
            )
            assert guest.mounted_source == _SHARE_DEVICE
            assert sandbox.guest_shared_root() == _LINUX_MOUNT_POINT
            assert _index_of(ga_server.command_lines(), _FOREIGN_VFAT_DEVICE) == -1

    @pytest.mark.asyncio
    async def test_mounted_volume_with_the_vvfat_label_is_not_the_share(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A second ``file=fat:`` drive already mounted must not be the share.

        vvfat stamps the same label into every drive it synthesises, so this
        volume is indistinguishable from the share by label and is enumerated
        first; only the fact that the guest already mounted it says it is not
        the volume that is waiting to be mounted.

        Args:
            tmp_path: Host directory standing in for the shared folder.
            monkeypatch: Fixture used to pin the host platform.
        """
        monkeypatch.setattr(qemu_module, "_IS_WINDOWS", True)
        guest = _LinuxGuestModel(_MOUNTED_VVFAT_DEVICES, share_device=_THIRD_DISK_SHARE_DEVICE)
        async with _guest_session(guest, GuestOS.LINUX, tmp_path) as (sandbox, ga_server):
            await sandbox.mount_shared_volume()

            assert guest.mount_argv == [("-t", "vfat", "-o", "rw", _THIRD_DISK_SHARE_DEVICE, _LINUX_MOUNT_POINT)], (
                f"the already-mounted vvfat drive was remounted over the share: {guest.mount_argv}"
            )
            assert guest.mounted_source == _THIRD_DISK_SHARE_DEVICE
            assert sandbox.guest_shared_root() == _LINUX_MOUNT_POINT
            assert _index_of(ga_server.command_lines(), _SECOND_VVFAT_DEVICE) == -1

    @pytest.mark.asyncio
    async def test_unlabelled_mounted_volume_still_leaves_the_share_findable(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unlabelled mounted vfat volume must not shift the parsed columns.

        Args:
            tmp_path: Host directory standing in for the shared folder.
            monkeypatch: Fixture used to pin the host platform.
        """
        monkeypatch.setattr(qemu_module, "_IS_WINDOWS", True)
        guest = _LinuxGuestModel(_UNLABELLED_ESP_DEVICES)
        async with _guest_session(guest, GuestOS.LINUX, tmp_path) as (sandbox, _ga_server):
            await sandbox.mount_shared_volume()

            assert guest.mount_argv == [("-t", "vfat", "-o", "rw", _SHARE_DEVICE, _LINUX_MOUNT_POINT)]
            assert sandbox.guest_shared_root() == _LINUX_MOUNT_POINT

    def test_empty_label_column_does_not_swallow_the_mountpoint(self) -> None:
        """An empty column stays empty instead of shifting the row leftwards.

        ``lsblk --raw`` writes one space per column boundary and escapes any
        space inside a value, so an unlabelled volume produces two adjacent
        separators. Splitting on runs of whitespace instead collapses them and
        reads the mount point as the label, which turns a mounted volume into
        an unmounted one carrying a path for a name.
        """
        guest = _LinuxGuestModel(_UNLABELLED_ESP_DEVICES)

        rows = {row[0]: row for row in _MountTestSandbox.parse_block_devices(guest.block_device_listing())}

        assert rows[_ESP_DEVICE] == (_ESP_DEVICE, "vfat", "", "/boot/efi"), (
            f"the unlabelled mounted volume lost its column alignment: {rows[_ESP_DEVICE]}"
        )
        assert rows[_SHARE_DEVICE] == (_SHARE_DEVICE, "vfat", _VVFAT_LABEL, "")

    @pytest.mark.asyncio
    async def test_mounted_volume_without_the_launcher_aborts(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A mount that succeeds but exposes no launcher is still a failure.

        Args:
            tmp_path: Host directory standing in for the shared folder.
            monkeypatch: Fixture used to pin the host platform.
        """
        monkeypatch.setattr(qemu_module, "_IS_WINDOWS", True)
        guest = _LinuxGuestModel(launcher_present=False)
        async with _guest_session(guest, GuestOS.LINUX, tmp_path) as (sandbox, ga_server):
            with pytest.raises(SandboxError, match="monitor launch script"):
                await sandbox.attach_agents()

            assert guest.mounted is True
            assert guest.launched == []
            assert _index_of(ga_server.command_lines(), _LINUX_LAUNCH_COMMAND) == -1


class TestMountTransportFollowsTheLaunchArguments:
    """The in-guest mount and the QEMU argv must pick the same transport."""

    @pytest.mark.asyncio
    async def test_non_windows_host_uses_the_9p_export(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A 9p host attaches ``-fsdev`` and the guest mounts ``-t 9p shared``.

        Args:
            tmp_path: Host directory standing in for the shared folder.
            monkeypatch: Fixture used to pin the host platform.
        """
        monkeypatch.setattr(qemu_module, "_IS_WINDOWS", False)
        guest = _LinuxGuestModel(_NO_SHARE_DEVICES)
        async with _guest_session(guest, GuestOS.LINUX, tmp_path) as (sandbox, ga_server):
            launch_args = " ".join(sandbox.shared_folder_args())
            assert sandbox.uses_fat_transport() is False
            assert "-fsdev" in launch_args
            assert "mount_tag=shared" in launch_args

            await sandbox.mount_shared_volume()

            assert guest.mount_argv == [
                ("-t", "9p", "-o", "trans=virtio,version=9p2000.L,rw", "shared", _LINUX_MOUNT_POINT),
            ]
            assert guest.mounted is True
            assert _index_of(ga_server.command_lines(), "lsblk") == -1, "a 9p export has no block device to enumerate"

    @pytest.mark.asyncio
    async def test_windows_host_uses_the_fat_block_device(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A FAT host attaches ``-drive fat:rw:`` and the guest mounts vfat.

        Args:
            tmp_path: Host directory standing in for the shared folder.
            monkeypatch: Fixture used to pin the host platform.
        """
        monkeypatch.setattr(qemu_module, "_IS_WINDOWS", True)
        guest = _LinuxGuestModel()
        async with _guest_session(guest, GuestOS.LINUX, tmp_path) as (sandbox, ga_server):
            launch_args = " ".join(sandbox.shared_folder_args())
            assert sandbox.uses_fat_transport() is True
            assert "fat:rw:" in launch_args

            await sandbox.mount_shared_volume()

            assert guest.mount_argv == [("-t", "vfat", "-o", "rw", _SHARE_DEVICE, _LINUX_MOUNT_POINT)]
            assert _index_of(ga_server.command_lines(), "lsblk") >= 0


def _staged_share(root: Path) -> Path:
    """Create the host-side shared folder skeleton the sandbox writes into.

    Args:
        root: Directory to build the share under.

    Returns:
        Path: The shared folder root.
    """
    shared = root / "shared"
    for name in ("input", "output", "logs", "monitor"):
        (shared / name).mkdir(parents=True, exist_ok=True)
    return shared


class TestWindowsGuestResolvesTheDriveLetter:
    """The Windows launcher must run from the drive the guest actually used."""

    @pytest.mark.asyncio
    async def test_bootstrap_runs_the_launcher_the_host_generated(
        self,
        tmp_path: Path,
    ) -> None:
        """The launcher the host wrote must actually run on the probed drive.

        The guest executes the real ``start_agent.cmd`` bytes and the
        ``agent.ps1`` it starts, so a script that names a drive letter this
        guest does not have - the FAT volume landed on ``E:`` and nothing maps
        ``Z:`` - fails here the way it fails in a real guest.

        Args:
            tmp_path: Host directory the shared folder is staged under.
        """
        shared = _staged_share(tmp_path)
        guest = _WindowsGuestModel(shared)
        async with _guest_session(guest, GuestOS.WINDOWS, shared) as (sandbox, ga_server):
            await sandbox.create_agent_scripts()
            await sandbox.mount_shared_volume()
            await sandbox.bootstrap()

            assert sandbox.guest_shared_root() == _WINDOWS_SHARE_ROOT
            assert guest.missing_drives == [], f"the generated scripts named drives this guest has no: {guest.missing_drives}"
            assert guest.launched == [_WINDOWS_LAUNCH_PATH]
            assert guest.scripts_run == [_WINDOWS_AGENT_PATH], (
                f"the launcher must start the agent from its own share root: {guest.scripts_run}"
            )
            assert guest.net_use_attempts == [], f"the guest scripts still map a network drive nothing exports: {guest.net_use_attempts}"

            launch_command = ga_server.command_lines()[-1]
            assert launch_command == f"cmd.exe /c {_WINDOWS_LAUNCH_PATH}"

    @pytest.mark.asyncio
    async def test_drive_probe_skips_the_drive_the_guest_booted_from(
        self,
        tmp_path: Path,
    ) -> None:
        """The system drive to skip comes from the guest, not from a constant.

        This guest boots from ``D:``; code that assumes ``C:`` skips the wrong
        volume and probes the boot drive instead of the spare one.

        Args:
            tmp_path: Host directory the shared folder is staged under.
        """
        shared = _staged_share(tmp_path)
        guest = _WindowsGuestModel(shared)
        async with _guest_session(guest, GuestOS.WINDOWS, shared) as (sandbox, ga_server):
            await sandbox.create_agent_scripts()
            await sandbox.mount_shared_volume()

            assert f"{_GUEST_SPARE_DRIVE}\\{_WINDOWS_LAUNCH_RELATIVE}" in guest.probed, (
                f"the drive that is not the guest's system drive was never probed: {guest.probed}"
            )
            assert not [path for path in guest.probed if path.startswith(_GUEST_SYSTEM_DRIVE)], (
                f"the guest's own system drive {_GUEST_SYSTEM_DRIVE} must not be probed for the share: {guest.probed}"
            )
            assert _index_of(ga_server.command_lines(), "echo %SystemDrive%") >= 0, "the guest was never asked which drive it booted from"

    @pytest.mark.asyncio
    async def test_in_guest_execution_paths_follow_the_probed_root(
        self,
        tmp_path: Path,
    ) -> None:
        """Run-time in-guest paths use the resolved root, not the default.

        Args:
            tmp_path: Host directory the shared folder is staged under.
        """
        shared = _staged_share(tmp_path)
        guest = _WindowsGuestModel(shared)
        async with _guest_session(guest, GuestOS.WINDOWS, shared) as (sandbox, _ga_server):
            await sandbox.create_agent_scripts()
            await sandbox.mount_shared_volume()

            script = sandbox.generate_execution_script("abcdef")

            assert f"{_WINDOWS_SHARE_ROOT}output\\result_abcdef.txt" in script, (
                f"the execution script polls a path outside the probed share root: {script!r}"
            )
            assert f"{_WINDOWS_SHARE_ROOT}output\\abcdef.stdout" in script
            assert "Z:\\" not in script, f"the default share root is still hardcoded into the data plane: {script!r}"

    @pytest.mark.asyncio
    async def test_no_drive_carrying_the_share_aborts_before_the_launcher(
        self,
        tmp_path: Path,
    ) -> None:
        """A guest where no drive carries the monitor directory raises.

        Args:
            tmp_path: Host directory the shared folder is staged under.
        """
        shared = _staged_share(tmp_path)
        guest = _WindowsGuestModel(shared, share_drive=None)
        async with _guest_session(guest, GuestOS.WINDOWS, shared) as (sandbox, ga_server):
            await sandbox.create_agent_scripts()
            with pytest.raises(SandboxError, match="no guest drive letter carries"):
                await sandbox.attach_agents()

            assert guest.launched == []
            assert sandbox.guest_shared_root() is None
            command_lines = ga_server.command_lines()
            for probe in (f"echo {_SYSTEM_DRIVE_REFERENCE}", f"echo {_SYSTEM_ROOT_REFERENCE}"):
                assert _index_of(command_lines, probe) >= 0, f"the guest was never asked for {probe}: {command_lines}"
            allowed = ("fsutil", "dir /b", f"echo {_SYSTEM_DRIVE_REFERENCE}", f"echo {_SYSTEM_ROOT_REFERENCE}")
            unexpected = [line for line in command_lines if not any(token in line for token in allowed)]
            assert not unexpected, f"only drive enumeration and existence probes may run: {unexpected}"


class TestWindowsDataPlaneFollowsTheProbedRoot:
    """Every in-guest path built after the probe must use the probed root."""

    @pytest.mark.asyncio
    async def test_run_binary_launches_the_sample_from_the_probed_share_root(
        self,
        tmp_path: Path,
    ) -> None:
        """``run_binary`` addresses the sample on the drive the guest gave it.

        The modelled guest only has files on the share drive it really
        assigned, so a command built on the compiled-in default names a path
        nothing backs and the sample never runs.

        Args:
            tmp_path: Host directory the shared folder is staged under.
        """
        shared = _staged_share(tmp_path)
        guest = _WindowsGuestModel(shared)
        agent_guest = _WindowsAgentGuest(shared)
        binary = tmp_path / _GUEST_BINARY_NAME
        binary.write_bytes(_MZ_HEADER)
        async with _guest_session(guest, GuestOS.WINDOWS, shared, agent_responder=agent_guest) as (sandbox, _ga_server):
            await sandbox.create_agent_scripts()
            await sandbox.attach_agents()
            sandbox.mark_running()

            report = await sandbox.run_binary(binary, time_limit=_RUN_BINARY_TIMEOUT_S, monitor=False)

            assert sandbox.guest_shared_root() == _WINDOWS_SHARE_ROOT
            dispatched = [command for command, _args in agent_guest.commands if _GUEST_BINARY_NAME in command]
            assert dispatched, f"run_binary never dispatched the sample: {agent_guest.commands}"
            assert _GUEST_BINARY_PATH in dispatched[0], f"the sample was addressed outside the probed share root: {dispatched[0]!r}"
            assert agent_guest.rejected == [], f"the in-guest agent refused what the host dispatched: {agent_guest.rejected}"
            assert report.result == "success", f"the guest could not run the path the host built: {report.stderr!r}"

    @pytest.mark.asyncio
    async def test_run_binary_runs_a_sample_whose_path_carries_spaces(
        self,
        tmp_path: Path,
    ) -> None:
        """A path with spaces reaches the guest whole, and so do the arguments.

        The in-guest agent takes the executable as one field and launches it
        without a shell, so the path must arrive unquoted: quotes wrapped
        around it are part of the name it then looks for, and the allowlist
        sees a value that neither ends in ``.exe`` nor starts at the share
        root. Splitting the invocation into a command line instead would break
        it at the first space.

        Args:
            tmp_path: Host directory the shared folder is staged under.
        """
        shared = _staged_share(tmp_path)
        guest = _WindowsGuestModel(shared)
        agent_guest = _WindowsAgentGuest(shared)
        binary = tmp_path / _SPACED_BINARY_NAME
        binary.write_bytes(_MZ_HEADER)
        async with _guest_session(guest, GuestOS.WINDOWS, shared, agent_responder=agent_guest) as (sandbox, _ga_server):
            await sandbox.create_agent_scripts()
            await sandbox.attach_agents()
            sandbox.mark_running()

            report = await sandbox.run_binary(
                binary,
                args=list(_SPACED_BINARY_ARGS),
                time_limit=_RUN_BINARY_TIMEOUT_S,
                monitor=False,
            )

            assert agent_guest.rejected == [], f"the in-guest agent refused what the host dispatched: {agent_guest.rejected}"
            assert (_SPACED_BINARY_PATH, _SPACED_BINARY_ARGS) in agent_guest.commands, (
                f"the sample and its arguments did not reach the guest intact: {agent_guest.commands}"
            )
            assert report.result == "success", f"the guest could not run the path the host built: {report.stderr!r}"
            assert _SPACED_BINARY_NAME in report.stdout

    @pytest.mark.asyncio
    async def test_run_command_is_interpreted_by_the_guests_own_shell(
        self,
        tmp_path: Path,
    ) -> None:
        """A shell command line must be handed to the guest's shell.

        ``run_command`` takes a command line, not a program name: the in-guest
        agent validates whatever it is given against its allowlist and then
        launches it directly, so a line sent as if it were an executable is
        refused before anything runs.

        Args:
            tmp_path: Host directory the shared folder is staged under.
        """
        shared = _staged_share(tmp_path)
        guest = _WindowsGuestModel(shared)
        agent_guest = _WindowsAgentGuest(shared)
        (shared / "input" / _GUEST_BINARY_NAME).write_bytes(_MZ_HEADER)
        async with _guest_session(guest, GuestOS.WINDOWS, shared, agent_responder=agent_guest) as (sandbox, _ga_server):
            await sandbox.create_agent_scripts()
            await sandbox.attach_agents()
            sandbox.mark_running()

            exit_code, stdout, stderr = await sandbox.run_command(
                f'dir "{_WINDOWS_SHARE_ROOT}input"',
                time_limit=_RUN_BINARY_TIMEOUT_S,
            )

            assert agent_guest.rejected == [], f"the in-guest agent refused the command line: {agent_guest.rejected}"
            assert exit_code == 0, f"the guest could not interpret the command line: {stderr!r}"
            assert _GUEST_BINARY_NAME in stdout, f"the guest shell did not list the share's input directory: {stdout!r}"

    @pytest.mark.asyncio
    async def test_extract_scans_the_volume_the_guest_mirrors_from(
        self,
        tmp_path: Path,
    ) -> None:
        """Dropped-file collection reads the guest's own system volume.

        The in-guest monitor derives the directories it mirrors from
        ``%SystemDrive%`` and ``%SystemRoot%``; this guest booted from ``D:``,
        so a host that scans ``C:`` scans a volume the guest never writes to.
        The staging destination has to be on the probed share root for the same
        reason: the guest cannot write to a drive it does not have.

        Args:
            tmp_path: Host directory the shared folder is staged under.
        """
        shared = _staged_share(tmp_path)
        guest = _WindowsGuestModel(shared)
        agent_guest = _WindowsAgentGuest(shared)
        async with _guest_session(guest, GuestOS.WINDOWS, shared, agent_responder=agent_guest) as (sandbox, _ga_server):
            await sandbox.create_agent_scripts()
            await sandbox.attach_agents()
            sandbox.mark_running()

            archive = await sandbox.extract_dropped_files()

            copied_sources = sorted(source for source, _destination in agent_guest.copied)
            assert copied_sources == sorted(_GUEST_DROP_ROOTS), (
                f"the host asked the guest for directories it does not mirror from: {agent_guest.commands}"
            )
            outside = [destination for _source, destination in agent_guest.copied if not destination.startswith(_WINDOWS_SHARE_ROOT)]
            assert not outside, f"dropped files were staged outside the probed share root: {outside}"
            with zipfile.ZipFile(archive) as archive_file:
                names = archive_file.namelist()
            assert [name for name in names if _GUEST_DROP_FILE_NAME in name], f"the archive carries none of the dropped files: {names}"


class TestGeneratedAgentScriptResolvesItsOwnShareRoot:
    """The staged agent must write where the host reads, on any drive letter."""

    @pytest.mark.asyncio
    async def test_agent_output_directories_land_where_the_host_reads_them(
        self,
        tmp_path: Path,
    ) -> None:
        """``$PSScriptRoot`` resolution must put the logs and mirror on the share root.

        The generated ``agent.ps1`` is written before the guest has assigned
        the FAT volume a letter, so it derives everything from its own
        location. Both constructs it uses for that - ``$PSScriptRoot`` and
        ``Split-Path -Parent`` - are evaluated here against the real script
        text, and the directories they produce are handed to the host readers
        that really consume them.

        Args:
            tmp_path: Host directory the shared folder is staged under.
        """
        shared = _staged_share(tmp_path)
        guest = _WindowsGuestModel(shared)
        async with _guest_session(guest, GuestOS.WINDOWS, shared) as (sandbox, _ga_server):
            await sandbox.create_agent_scripts()
            await sandbox.mount_shared_volume()
            await sandbox.bootstrap()

            variables = guest.script.variables
            assert variables["PSScriptRoot"] == f"{_WINDOWS_SHARE_ROOT}monitor"
            assert variables["logDir"] == _EXPECTED_LOG_DIR, f"the agent writes its logs outside the share root: {variables}"
            assert variables["droppedMirror"] == _EXPECTED_DROPPED_MIRROR, (
                f"the agent mirrors dropped files outside the share root: {variables}"
            )

            log_dir = _guest_to_host(variables["logDir"], _WINDOWS_SHARE_DRIVE, shared)
            mirror_dir = _guest_to_host(variables["droppedMirror"], _WINDOWS_SHARE_DRIVE, shared)
            assert log_dir is not None
            assert mirror_dir is not None
            log_dir.mkdir(parents=True, exist_ok=True)
            mirror_dir.mkdir(parents=True, exist_ok=True)
            (log_dir / _FILE_CHANGES_LOG).write_text(f"{_HOST_LOG_LINE}\n", encoding="utf-8")
            (mirror_dir / _HOST_DROPPED_MIRROR_FILE).write_bytes(_GUEST_DROP_PAYLOAD)

            changes = await sandbox.collected_file_changes()
            assert [change["path"] for change in changes] == [_HOST_LOG_PATH], (
                f"the host reads its monitor logs from somewhere the agent does not write: {changes}"
            )

            staging = tmp_path / "staging"
            staging.mkdir()
            await sandbox.collect_dropped_mirror(staging)
            assert (staging / _HOST_DROPPED_MIRROR_FILE).read_bytes() == _GUEST_DROP_PAYLOAD, (
                "the host reads its dropped-file mirror from somewhere the agent does not write"
            )


class TestTheModelledAgentEnforcesTheScriptsAllowlist:
    """The guest model must refuse what the real agent script refuses."""

    @pytest.mark.asyncio
    async def test_allowlist_decisions_come_from_the_staged_script(
        self,
        tmp_path: Path,
    ) -> None:
        r"""``Test-AllowedCommand``'s three rules decide, not the model's opinion.

        This pins the guest model itself: a peer that waves everything through
        cannot fail when the host dispatches something the live agent would
        answer with ``command not in allowlist``, and every gate built on that
        peer would certify a dead code path as working. The rules come out of
        the script the sandbox really staged - which is why the ``System32``
        below this guest's own ``%SystemRoot%`` is accepted even though the
        model has no file there, while the same executable one directory up is
        not.

        Args:
            tmp_path: Host directory the shared folder is staged under.
        """
        shared = _staged_share(tmp_path)
        sandbox = _MountTestSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=GuestOS.WINDOWS))
        sandbox.use_shared_folder(shared)
        await sandbox.create_agent_scripts()
        (shared / "input" / _GUEST_BINARY_NAME).write_bytes(_MZ_HEADER)
        agent_guest = _WindowsAgentGuest(shared)

        accepted = agent_guest(_GUEST_BINARY_PATH, [])
        quoted = agent_guest(f'"{_GUEST_BINARY_PATH}" ', [])
        elsewhere = agent_guest(f"{_GUEST_SYSTEM_DRIVE}\\Users\\Public\\tool.exe", [])
        system32 = agent_guest(f"{_GUEST_SYSTEM_ROOT}\\System32\\reg.exe", ["query", "HKLM"])

        assert accepted.exit_code == 0, f"an executable on the share root must run: {accepted.stderr!r}"
        assert quoted.exit_code == _ALLOWLIST_REJECT_EXIT, "a quoted path is not a name the allowlist accepts"
        assert elsewhere.exit_code == _ALLOWLIST_REJECT_EXIT, "an executable outside every allowed root must be refused"
        assert agent_guest.rejected == [f'"{_GUEST_BINARY_PATH}" ', f"{_GUEST_SYSTEM_DRIVE}\\Users\\Public\\tool.exe"]
        assert system32.exit_code != _ALLOWLIST_REJECT_EXIT, (
            f"the allowed roots must follow this guest's own %SystemRoot%: {system32.stderr!r}"
        )


class TestHostAndGuestWatchOneSetOfDirectories:
    """The dropped-file scan and the in-guest mirror must name one set."""

    @pytest.mark.parametrize(
        ("system_drive", "system_root"),
        [
            (_GUEST_SYSTEM_DRIVE, _GUEST_SYSTEM_ROOT),
            (_UNSET_ENVIRONMENT, _UNSET_ENVIRONMENT),
        ],
        ids=["guest_answers", "guest_answers_nothing"],
    )
    @pytest.mark.asyncio
    async def test_watched_roots_are_the_same_on_both_sides(
        self,
        tmp_path: Path,
        system_drive: str,
        system_root: str,
    ) -> None:
        r"""The script's watched roots must equal the host's scanned roots.

        Both sides are derived, neither is written down here: the guest side
        comes out of ``$Global:_IC_DropWatchedRoots`` in the script the sandbox
        really staged, evaluated against the environment this guest exports,
        and the host side out of :meth:`QEMUSandbox._windows_drop_watch_roots`
        after the probe. A guest that exports neither variable is covered too,
        because that is the case where the host's fallback and the script's own
        substitution have to agree - if the script simply joined an unset
        ``$env:SystemRoot``, its ``Temp`` would not even be an absolute path.

        Args:
            tmp_path: Host directory the shared folder is staged under.
            system_drive: Value this guest exports for ``%SystemDrive%``.
            system_root: Value this guest exports for ``%SystemRoot%``.
        """
        shared = _staged_share(tmp_path)
        guest = _WindowsGuestModel(shared, system_drive=system_drive, system_root=system_root)
        async with _guest_session(guest, GuestOS.WINDOWS, shared) as (sandbox, _ga_server):
            await sandbox.create_agent_scripts()
            await sandbox.mount_shared_volume()
            await sandbox.bootstrap()

            assert _DROP_ROOTS_VARIABLE in guest.script.arrays, (
                f"the agent script's watched roots do not resolve to absolute paths in this guest: {guest.script.arrays}"
            )
            guest_roots = guest.script.arrays[_DROP_ROOTS_VARIABLE]
            host_roots = sandbox.drop_watch_roots()

            assert guest_roots, "the agent script declares no watched roots at all"
            assert sorted(guest_roots) == sorted(host_roots), (
                f"the guest mirrors from {sorted(guest_roots)} while the host scans {sorted(host_roots)}"
            )
            expected_root = system_root or _FALLBACK_SYSTEM_ROOT
            expected_drive = system_drive or _FALLBACK_SYSTEM_DRIVE
            assert all(root.startswith((expected_root, expected_drive)) for root in guest_roots), (
                f"the watched roots left this guest's own volume: {guest_roots}"
            )
            assert any(root.startswith(expected_root) for root in guest_roots), (
                f"no watched root is below the guest's Windows directory {expected_root}: {guest_roots}"
            )


class TestGeneratedGuestScriptsNeedNoSmbExport:
    """The Windows guest scripts must not depend on a share nothing provides."""

    def test_agent_script_does_not_map_a_network_drive(self) -> None:
        r"""``agent.ps1`` must not reach for QEMU's built-in SMB server.

        ``smb=`` needs an ``smbd`` on the host, a Windows host has none, and
        the sandbox emits no ``-smb`` argument - so a ``net use`` of
        ``\\10.0.2.4\qemu`` maps nothing and every path under the mapped letter
        dangles.
        """
        script = _MountTestSandbox.windows_agent_script()

        assert not _NET_USE.search(script), "the agent still maps a network drive over an SMB export that does not exist"
        assert "10.0.2.4" not in script, "the agent still references QEMU's built-in SMB server address"
