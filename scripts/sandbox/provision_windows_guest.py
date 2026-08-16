# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Host-side provisioner for Intellicrack's Windows QEMU sandbox guest.

Intellicrack's QEMU backend ships a Linux guest image only, so the six Sandbox
report tabs fed by the in-guest Windows PowerShell monitors (Registry Changes,
API Calls, DLL Loads, Services, Kernel Objects, Injections) can never be
exercised. This module builds everything a Windows guest needs and emits the
exact ``qemu-system-x86_64`` command line that performs the unattended install.

It deliberately stops short of launching QEMU. The caller runs the emitted
command; this module only produces artifacts and the argv.

The produced guest must be bootable by
:meth:`intellicrack.sandbox.qemu.QEMUSandbox._build_qemu_command`, which pins
three properties the install has to match exactly:

* **Firmware** - that method passes neither ``-bios`` nor ``-drive if=pflash``,
  so the guest boots the SeaBIOS default. The install is therefore legacy BIOS
  with an MBR disk layout; UEFI and Secure Boot are not in play at all, which
  is also why the absent ``edk2-x86_64-vars.fd`` varstore does not matter here.
* **System disk** - ``-drive file=...,format=qcow2,if=virtio`` is virtio-blk,
  which Windows Setup cannot see without the ``viostor`` driver.
* **NIC** - ``-device virtio-net-pci`` needs ``NetKVM``, and the
  ``org.qemu.guest_agent.0`` channel rides a ``virtio-serial-pci`` device that
  needs ``vioserial``.

Those three drivers exist only in the Red Hat virtio-win ISO, which this
module never downloads: it locates one, or reports it as a prerequisite.

The qemu-guest-agent binary itself is not taken from virtio-win. QEMU's own
Windows build bundles ``qemu-ga.exe`` beside ``qemu-system-x86_64.exe``, and
that binary registers the ``qemu-ga`` service with ``-s install`` and defaults
to the ``\\.\Global\org.qemu.guest_agent.0`` path the sandbox opens. Staging
the bundled binary keeps guest and host agent versions identical.

That bundle is not self-sufficient, though. ``guest-exec`` spawns through
GLib, and GLib on Windows never spawns directly: it re-launches through
``gspawn-win64-helper.exe``, which it looks for beside its own
``libglib-2.0-0.dll``. QEMU's Windows build ships no ``gspawn`` helper at all,
so an agent staged from it answers every single ``guest-exec`` with
``Failed to execute helper program (No such file or directory)``. The virtio-win
medium's ``guest-agent`` MSI does carry the helpers, so they are taken from
there and staged alongside the bundled agent.

Invoke via ``pixi run python -m scripts.sandbox.provision_windows_guest --help``.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final, cast

from intellicrack.core.config import get_project_root
from intellicrack.core.logging import get_logger
from intellicrack.core.xml_gen import Element, SubElement, indent, tostring


_LOGGER = get_logger("sandbox.provision.windows")

_SECTOR_SIZE: Final[int] = 2048
_DESCRIPTOR_FIRST_LBA: Final[int] = 16
_DESCRIPTOR_LAST_LBA: Final[int] = 64
_ISO9660_STANDARD_ID: Final[bytes] = b"CD001"
_UDF_NSR_IDENTIFIERS: Final[frozenset[str]] = frozenset({"NSR02", "NSR03"})
_UDF_RECOGNITION_IDENTIFIERS: Final[frozenset[bytes]] = frozenset({b"BEA01", b"NSR02", b"NSR03", b"TEA01", b"BOOT2"})
_DESCRIPTOR_TYPE_BOOT_RECORD: Final[int] = 0
_DESCRIPTOR_TYPE_PRIMARY: Final[int] = 1
_BOOT_SYSTEM_ID_START: Final[int] = 7
_BOOT_SYSTEM_ID_END: Final[int] = 39
_EL_TORITO_SYSTEM_ID: Final[str] = "EL TORITO SPECIFICATION"
_BOOT_CATALOG_POINTER_OFFSET: Final[int] = 71
_SYSTEM_ID_START: Final[int] = 8
_SYSTEM_ID_END: Final[int] = 40
_VOLUME_ID_START: Final[int] = 40
_VOLUME_ID_END: Final[int] = 72

_CATALOG_ENTRY_SIZE: Final[int] = 32
_CATALOG_MAX_ENTRIES: Final[int] = 64
_CATALOG_VALIDATION_HEADER: Final[int] = 0x01
_CATALOG_SECTION_HEADERS: Final[frozenset[int]] = frozenset({0x90, 0x91})
_CATALOG_ENTRY_BOOTABLE: Final[int] = 0x88
_CATALOG_ENTRY_NON_BOOTABLE: Final[int] = 0x00
_CATALOG_VALIDATION_ID_START: Final[int] = 4
_CATALOG_VALIDATION_ID_END: Final[int] = 28
_CATALOG_VALIDATION_KEY_START: Final[int] = 30
_CATALOG_VALIDATION_KEY: Final[bytes] = b"\x55\xaa"
_CATALOG_LOAD_LBA_OFFSET: Final[int] = 8
_PLATFORM_ID_X86: Final[int] = 0x00
_PLATFORM_ID_UEFI: Final[int] = 0xEF

# Both Microsoft ISOs measured on this host - the untouched retail image and
# the prompt-free rebuild - carry this string in the El Torito validation
# entry, while the Debian and Fedora images measured alongside them leave the
# field empty. It is the cheapest positive identifier for Microsoft-authored
# media that needs no mount and no elevation, and it survives the fact that a
# Microsoft ISO's ISO9660 filesystem may hold nothing but a stub because the
# real sources tree lives in UDF.
_MICROSOFT_EL_TORITO_ID: Final[str] = "Microsoft Corporation"
_MINIMUM_INSTALL_MEDIA_BYTES: Final[int] = 2 * 1024 * 1024 * 1024

_INSTALL_IMAGE_NAMES: Final[tuple[str, ...]] = ("install.wim", "install.esd")
_BOOT_IMAGE_NAME: Final[str] = "boot.wim"
_SOURCES_DIRECTORY: Final[str] = "sources"
_BIOS_BOOT_DIRECTORY: Final[str] = "boot"
_SETUP_EXECUTABLE: Final[str] = "setup.exe"

_SCAN_SKIP_DIRECTORY_NAMES: Final[frozenset[str]] = frozenset({
    "$recycle.bin",
    "$winreagent",
    ".git",
    "appdata",
    "node_modules",
    "perflogs",
    "program files",
    "program files (x86)",
    "programdata",
    "system volume information",
    "windows",
    "windows.old",
    "winsxs",
})

_QEMU_EXECUTABLE_NAME: Final[str] = "qemu-system-x86_64.exe"
_QEMU_IMG_EXECUTABLE_NAME: Final[str] = "qemu-img.exe"
_QEMU_GUEST_AGENT_EXECUTABLE: Final[str] = "qemu-ga.exe"
QEMU_GUEST_AGENT_LIBRARIES: Final[tuple[str, ...]] = (
    "libglib-2.0-0.dll",
    "libintl-8.dll",
    "libiconv-2.dll",
    "libpcre2-8-0.dll",
    "libwinpthread-1.dll",
    "libssp-0.dll",
    "libgcc_s_seh-1.dll",
)
QEMU_GUEST_AGENT_SPAWN_HELPERS: Final[tuple[str, ...]] = (
    "gspawn-win64-helper.exe",
    "gspawn-win64-helper-console.exe",
)
"""GLib's Windows re-launch helpers, without which every ``guest-exec`` fails."""

_GUEST_AGENT_MEDIA_DIRECTORY: Final[str] = "guest-agent"
_GUEST_AGENT_PACKAGE_SUFFIX: Final[str] = ".msi"
_GUEST_AGENT_PACKAGE_ARCHITECTURES: Final[tuple[str, ...]] = ("x86_64", "amd64", "x64")
_MSI_EXECUTABLE: Final[str] = "msiexec.exe"
_QEMU_GUEST_AGENT_SERVICE: Final[str] = "qemu-ga"
_QEMU_GUEST_AGENT_INSTALL_DIR: Final[str] = "qemu-ga"
_QEMU_GUEST_AGENT_LOG: Final[str] = "C:\\ProgramData\\qemu-ga\\qemu-ga.log"

_ANSWER_ISO_LABEL: Final[str] = "IC_ANSWER"
_ANSWER_SCRIPT_RELATIVE: Final[str] = "scripts\\install-guest-agent.cmd"
_DRIVER_SCRIPT_RELATIVE: Final[str] = "scripts\\install-virtio-drivers.ps1"
_DRIVER_INSTALL_LOG: Final[str] = "C:\\ProgramData\\intellicrack\\virtio-drivers.log"
_GUEST_DRIVE_LETTERS: Final[str] = "C D E F G H I J K L M N O P Q R S T U V W X Y Z"

_BOOT_CRITICAL_DRIVER: Final[str] = "viostor"
VIRTIO_MARKER_DIRECTORIES: Final[tuple[str, ...]] = (_BOOT_CRITICAL_DRIVER, "vioserial", "NetKVM")
WINPE_DRIVER_DIRECTORIES: Final[tuple[str, ...]] = (*VIRTIO_MARKER_DIRECTORIES, "Balloon")
"""Driver directories whose packages the WinPE answer file points Setup at.

The three markers are the devices the sandbox launcher actually builds:
``viostor`` backs ``if=virtio`` and is boot critical, ``NetKVM`` backs
``-device virtio-net-pci``, and ``vioserial`` backs the ``virtio-serial-pci``
guest agent channel. ``Balloon`` completes the set the medium's memory device
needs. Every other package on the medium is left to the in-guest installer,
which runs once and installs from a directory it resolves itself, whereas each
entry here is multiplied by every candidate WinPE drive letter.
"""
UNTRUSTED_CHAIN_STATUSES: Final[tuple[str, ...]] = ("UntrustedRoot", "PartialChain")
"""``X509ChainStatusFlags`` names that mean the guest cannot validate a catalog's chain."""

DRIVER_ALREADY_CURRENT_EXIT: Final[int] = 259
"""``ERROR_NO_MORE_ITEMS`` from ``pnputil``: the package is staged and no device needed it."""

_DRIVER_INF_SUFFIX: Final[str] = ".inf"
WINPE_DRIVER_LETTERS: Final[tuple[str, ...]] = ("C", "D", "E", "F", "G", "H")
"""Drive letters the answer file searches, because WinPE assigns them itself."""

WINPE_DRIVER_STAGE_DIRECTORY: Final[str] = "drivers"
"""Folder on the answer medium the boot-critical driver files are staged into.

Setup is given one search path per candidate drive letter and nothing else.
Measured on Windows 11 26100 with the real installer: an answer file naming
sixty existing driver directories on the one drive letter that really exists
aborts the whole installation at ``ExecuteUnattendDriverInstall`` with
``0xD000A000``, before any disk is touched, while four paths install cleanly.
Every path in both runs held an INF and unreachable letters were tolerated, so
what Setup will not accept is the number of entries.
"""

WINPE_DRIVER_FAMILY_PREFERENCE: Final[tuple[str, ...]] = (
    "w11",
    "w10",
    "2k25",
    "2k22",
    "2k19",
    "2k16",
    "w8.1",
    "w8",
    "2k12R2",
    "2k12",
    "w7",
    "2k8R2",
    "2k8",
    "2k3",
    "xp",
)
"""Which family of a driver to stage, newest first, for a Windows 11 guest.

The medium carries a genuinely different set of families per driver, so the
choice is made per driver against what is really there rather than hardwired:
whichever of these the medium has for the guest's architecture is taken, and
anything unrecognised sorts after all of them.
"""

_VIRTIO_WIN_URL: Final[str] = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
_VIRTIO_WIN_APPROXIMATE_MB: Final[int] = 676

_UNATTEND_NAMESPACE: Final[str] = "urn:schemas-microsoft-com:unattend"
_WCM_NAMESPACE: Final[str] = "http://schemas.microsoft.com/WMIConfig/2002/State"
_XSI_NAMESPACE: Final[str] = "http://www.w3.org/2001/XMLSchema-instance"
_COMPONENT_PUBLIC_KEY: Final[str] = "31bf3856ad364e35"
_COMPONENT_ARCHITECTURE: Final[str] = "amd64"

# HKLM\SYSTEM\Setup\LabConfig values Windows Setup honours to skip the
# hardware gates this QEMU build cannot satisfy: it exposes no TPM device
# (-tpmdev is rejected outright and swtpm is not installed) and boots SeaBIOS,
# which has no Secure Boot at all.
_LAB_CONFIG_KEY: Final[str] = "HKLM\\SYSTEM\\Setup\\LabConfig"
_LAB_CONFIG_BYPASSES: Final[tuple[str, ...]] = (
    "BypassTPMCheck",
    "BypassSecureBootCheck",
    "BypassRAMCheck",
    "BypassCPUCheck",
    "BypassStorageCheck",
)
_OOBE_KEY: Final[str] = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OOBE"
_OOBE_BYPASS_NRO: Final[str] = "BypassNRO"

_SYSTEM_PARTITION_MB: Final[int] = 500
_SYSTEM_PARTITION_LABEL: Final[str] = "System Reserved"
_WINDOWS_PARTITION_LABEL: Final[str] = "Windows"
_WINDOWS_PARTITION_LETTER: Final[str] = "C"
_WINDOWS_PARTITION_ID: Final[int] = 2
_INSTALL_DISK_ID: Final[int] = 0
_AUTOLOGON_COUNT: Final[int] = 999_999_999

_DEFAULT_DISK_NAME: Final[str] = "windows11-intellicrack.qcow2"
_DEFAULT_ANSWER_ISO_NAME: Final[str] = "windows11-autounattend.iso"
_DEFAULT_DISK_SIZE_GB: Final[int] = 40
_DEFAULT_MEMORY_MB: Final[int] = 8192
_DEFAULT_CPU_CORES: Final[int] = 4
_DEFAULT_IMAGE_NAME: Final[str] = "Windows 11 Pro"
DEFAULT_ADMIN_USER: Final[str] = "analyst"
DEFAULT_ADMIN_CREDENTIAL: Final[str] = "Intellicrack1!"
_DEFAULT_COMPUTER_NAME: Final[str] = "IC-SANDBOX"
_DEFAULT_LOCALE: Final[str] = "en-US"
_DEFAULT_TIMEZONE: Final[str] = "UTC"
_DEFAULT_SCAN_DEPTH: Final[int] = 3
_DEFAULT_SCAN_BUDGET: Final[int] = 20_000

_VNC_PORT_BASE: Final[int] = 5900
_VNC_PORT_MAX: Final[int] = 5999
_DEFAULT_AGENT_PORT: Final[int] = 4445
_QGA_CHANNEL_PORT_OFFSET: Final[int] = 1
_USB_CONTROLLER_ID: Final[str] = "icusb"

_BOOT_ARGUMENT: Final[str] = "-boot"
_BOOT_ONCE_PREFIX: Final[str] = "once="
_CHARDEV_ARGUMENT: Final[str] = "-chardev"
_CHARDEV_PORT_PREFIX: Final[str] = "port="

_DEFAULT_INSTALL_TIMEOUT_SECONDS: Final[float] = 5400.0
_DEFAULT_INSTALL_RESTART_LIMIT: Final[int] = 8
_INSTALL_POLL_SECONDS: Final[float] = 10.0
_AGENT_PROBE_TIMEOUT_SECONDS: Final[float] = 4.0
_AGENT_READ_SIZE: Final[int] = 4096
_AGENT_SYNC_TOKEN_LIMIT: Final[int] = 2**31
_QGA_SYNC_DELIMITER: Final[bytes] = b"\xff"
_GUEST_SHUTDOWN_GRACE_SECONDS: Final[float] = 240.0
_INSTALL_FAILURE_EXIT_CODE: Final[int] = 4

_ISO_AUTHORING_TOOLS: Final[tuple[str, ...]] = ("oscdimg", "xorriso", "mkisofs", "genisoimage", "pycdlib")
_PYCDLIB_TOOL: Final[str] = "pycdlib"
_OSCDIMG_TOOL: Final[str] = "oscdimg"
_OSCDIMG_SEARCH_ROOTS: Final[tuple[Path, ...]] = (
    Path("C:/Program Files (x86)/Windows Kits/10/Assessment and Deployment Kit/Deployment Tools/amd64/Oscdimg"),
    Path("C:/Program Files/Windows Kits/10/Assessment and Deployment Kit/Deployment Tools/amd64/Oscdimg"),
)

_SUBPROCESS_TIMEOUT_SECONDS: Final[float] = 900.0
_MOUNT_TIMEOUT_SECONDS: Final[float] = 180.0
_POWERSHELL_EXECUTABLE: Final[str] = "pwsh"
_POWERSHELL_FALLBACK: Final[str] = "powershell"
_DRIVE_LETTER_LENGTH: Final[int] = 1
_WINDOWS_PLATFORM: Final[str] = "win32"


class ProvisioningError(RuntimeError):
    """Raised when the Windows guest cannot be provisioned.

    Distinguishes operator-facing provisioning failures - absent install
    media, a missing virtio-win ISO, no ISO authoring tool - from unexpected
    programming errors.
    """


@dataclass(frozen=True)
class BootCatalogEntry:
    """One 32-byte record decoded from an El Torito boot catalog.

    Attributes:
        platform_id: El Torito platform identifier the record belongs to.
            ``0x00`` is x86 BIOS and ``0xEF`` is UEFI.
        bootable: Whether the record marks a bootable image.
        load_lba: Absolute ISO logical block address of the boot image.
    """

    platform_id: int
    bootable: bool
    load_lba: int


@dataclass(frozen=True)
class IsoStructure:
    """Structural facts read from an ISO image without mounting it.

    Every field is derived from plain file reads of the volume descriptor set
    and the El Torito boot catalog, so probing needs neither elevation nor a
    filesystem driver.

    Attributes:
        path: Absolute path of the probed image.
        size_bytes: Size of the image file in bytes.
        volume_id: ISO9660 primary volume identifier, empty when absent.
        system_id: ISO9660 primary system identifier, empty when absent.
        has_primary_descriptor: Whether a CD001 primary volume descriptor was
            found.
        udf_identifiers: Volume recognition sequence identifiers found in the
            descriptor set, in the order encountered.
        el_torito_identifier: Identifier string from the boot catalog
            validation entry, empty when there is no catalog.
        boot_catalog_lba: Logical block address of the boot catalog, or None.
        bios_boot_lba: Load address of the first bootable x86 BIOS entry, or
            None.
        uefi_boot_lba: Load address of the first bootable UEFI entry, or None.
    """

    path: Path
    size_bytes: int
    volume_id: str
    system_id: str
    has_primary_descriptor: bool
    udf_identifiers: tuple[str, ...]
    el_torito_identifier: str
    boot_catalog_lba: int | None
    bios_boot_lba: int | None
    uefi_boot_lba: int | None

    @property
    def is_udf_bridged(self) -> bool:
        """Whether the image carries a UDF filesystem alongside ISO9660.

        Microsoft install media is always UDF-bridged because ``install.wim``
        exceeds the 4 GiB ISO9660 file size limit, so its real ``sources``
        tree lives only in the UDF filesystem.

        Returns:
            bool: True when an NSR02 or NSR03 descriptor is present.
        """
        return any(identifier in _UDF_NSR_IDENTIFIERS for identifier in self.udf_identifiers)

    @property
    def is_microsoft_media(self) -> bool:
        """Whether the boot catalog identifies Microsoft as the author.

        Returns:
            bool: True when the El Torito validation entry names Microsoft.
        """
        return self.el_torito_identifier == _MICROSOFT_EL_TORITO_ID

    @property
    def is_bios_bootable(self) -> bool:
        """Whether the image offers an x86 BIOS boot image.

        The sandbox runs SeaBIOS, so media without a BIOS entry cannot start
        the install at all.

        Returns:
            bool: True when a bootable x86 BIOS catalog entry exists.
        """
        return self.bios_boot_lba is not None

    @property
    def is_windows_install_candidate(self) -> bool:
        """Whether the image looks like bootable Windows installation media.

        Returns:
            bool: True when the image is Microsoft-authored, UDF-bridged,
            BIOS bootable, and large enough to hold a Windows image.
        """
        return (
            self.has_primary_descriptor
            and self.is_microsoft_media
            and self.is_udf_bridged
            and self.is_bios_bootable
            and self.size_bytes >= _MINIMUM_INSTALL_MEDIA_BYTES
        )

    def to_dict(self) -> dict[str, object]:
        """Render the structure as JSON-serialisable data.

        Returns:
            dict[str, object]: Mapping of every field and derived predicate.
        """
        return {
            "path": str(self.path),
            "size_bytes": self.size_bytes,
            "volume_id": self.volume_id,
            "system_id": self.system_id,
            "udf_identifiers": list(self.udf_identifiers),
            "el_torito_identifier": self.el_torito_identifier,
            "boot_catalog_lba": self.boot_catalog_lba,
            "bios_boot_lba": self.bios_boot_lba,
            "uefi_boot_lba": self.uefi_boot_lba,
            "is_udf_bridged": self.is_udf_bridged,
            "is_microsoft_media": self.is_microsoft_media,
            "is_bios_bootable": self.is_bios_bootable,
            "is_windows_install_candidate": self.is_windows_install_candidate,
        }


@dataclass(frozen=True)
class MediaContent:
    r"""Result of inspecting a mounted install medium's directory tree.

    Attributes:
        root: Directory the medium was inspected at.
        install_image: Path to ``sources\install.wim`` or ``install.esd``, or
            None when neither is present.
        has_boot_image: Whether ``sources\boot.wim`` is present.
        has_bios_boot_directory: Whether the legacy ``boot`` directory that
            holds ``etfsboot.com`` is present.
        has_setup_executable: Whether ``setup.exe`` is present at the root.
    """

    root: Path
    install_image: Path | None
    has_boot_image: bool
    has_bios_boot_directory: bool
    has_setup_executable: bool

    @property
    def is_windows_install_media(self) -> bool:
        """Whether the tree is a complete BIOS-bootable Windows medium.

        Returns:
            bool: True when a deployable image, its WinPE boot image, the
            legacy boot directory, and ``setup.exe`` are all present.
        """
        return self.install_image is not None and self.has_boot_image and self.has_bios_boot_directory and self.has_setup_executable

    def to_dict(self) -> dict[str, object]:
        """Render the content inspection as JSON-serialisable data.

        Returns:
            dict[str, object]: Mapping of every field and derived predicate.
        """
        return {
            "root": str(self.root),
            "install_image": str(self.install_image) if self.install_image is not None else None,
            "has_boot_image": self.has_boot_image,
            "has_bios_boot_directory": self.has_bios_boot_directory,
            "has_setup_executable": self.has_setup_executable,
            "is_windows_install_media": self.is_windows_install_media,
        }


@dataclass(frozen=True)
class VirtioMedium:
    r"""A located virtio-win medium and the driver layout read off it.

    Attributes:
        path: The virtio-win ISO itself.
        driver_subpaths: ``<driver>\\<family>\\<arch>`` directories the medium
            really carries for the guest's architecture, in sorted order.
    """

    path: Path
    driver_subpaths: tuple[str, ...]


@dataclass(frozen=True)
class UnattendSettings:
    """Inputs that shape the generated ``autounattend.xml``.

    Attributes:
        image_name: Windows edition name selected from the install image, for
            example ``Windows 11 Pro``.
        product_key: Product key to inject, or None to emit an empty key
            element so Setup skips the product key page.
        admin_user: Local account created and auto-logged on.
        admin_password: Plain-text password for that account.
        computer_name: NetBIOS name assigned to the guest.
        locale: Locale applied to input, system, UI, and user settings.
        timezone: Windows time zone identifier. ``UTC`` keeps the guest clock
            aligned with the emulated RTC, which QEMU leaves at UTC because
            the sandbox launcher passes no ``-rtc base=localtime``.
        driver_letters: Candidate WinPE drive letters searched for virtio
            drivers, because WinPE assigns CD-ROM letters unpredictably.
        driver_directory: Folder on the answer medium holding the staged
            driver files, appended to each candidate letter. One entry per
            letter is all Setup is given, because it aborts the installation
            outright when the answer file names many driver paths.
        disable_guest_firewall: Whether to turn the guest firewall off so the
            forwarded agent port is reachable from the host.
        answer_script: Path of the guest agent installer relative to the
            answer volume root.
    """

    image_name: str
    product_key: str | None
    admin_user: str
    admin_password: str
    computer_name: str
    locale: str
    timezone: str
    driver_letters: tuple[str, ...]
    driver_directory: str
    disable_guest_firewall: bool
    answer_script: str


@dataclass(frozen=True)
class InstallCommandSpec:
    """Everything needed to render the unattended install command line.

    Attributes:
        qemu_executable: Path to ``qemu-system-x86_64.exe``.
        accelerator: QEMU accelerator name, ``whpx`` or ``tcg``.
        cpu_cores: Cores handed to ``-smp cores=``.
        memory_mb: Guest memory in megabytes.
        disk_image: qcow2 system disk the guest is installed onto.
        install_iso: Windows installation medium.
        answer_iso: Generated answer file medium.
        virtio_iso: virtio-win driver medium.
        display: Display mode, one of ``vnc``, ``sdl``, or ``none``.
        vnc_port: TCP port the VNC server binds when ``display`` is ``vnc``.
        agent_port: Base agent port; the guest agent channel binds
            ``agent_port + 1``, matching the sandbox launcher.
    """

    qemu_executable: Path
    accelerator: str
    cpu_cores: int
    memory_mb: int
    disk_image: Path
    install_iso: Path
    answer_iso: Path
    virtio_iso: Path
    display: str
    vnc_port: int
    agent_port: int


@dataclass(frozen=True)
class InstallOutcome:
    """Result of supervising an unattended install to completion.

    Attributes:
        completed: True when the guest agent answered on its channel, which
            is the first moment the installed system is provably running.
        restarts: Number of times QEMU was relaunched after the guest power
            cycled. Windows Setup power cycles at least once.
        elapsed_seconds: Wall clock time the supervised run took.
        detail: Human-readable reason for the verdict.
    """

    completed: bool
    restarts: int
    elapsed_seconds: float
    detail: str


@dataclass(frozen=True)
class ProvisionPlan:
    """Complete outcome of a provisioning run.

    Attributes:
        install_media: Structural probe of the selected install medium.
        media_content: Directory inspection of the mounted medium, or None
            when content verification was skipped.
        virtio_iso: Located virtio-win medium.
        disk_image: Created qcow2 system disk.
        answer_iso: Generated answer file medium.
        authoring_tool: Name of the ISO authoring tool that built it.
        autounattend_xml: Full text of the generated answer file.
        install_command: Argv of the unattended install command.
    """

    install_media: IsoStructure
    media_content: MediaContent | None
    virtio_iso: Path
    disk_image: Path
    answer_iso: Path
    authoring_tool: str
    autounattend_xml: str
    install_command: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Render the plan as JSON-serialisable data.

        Returns:
            dict[str, object]: Mapping suitable for ``json.dumps``.
        """
        return {
            "install_media": self.install_media.to_dict(),
            "media_content": self.media_content.to_dict() if self.media_content is not None else None,
            "virtio_iso": str(self.virtio_iso),
            "disk_image": str(self.disk_image),
            "answer_iso": str(self.answer_iso),
            "authoring_tool": self.authoring_tool,
            "install_command": list(self.install_command),
        }


def _read_sector(handle: IO[bytes], lba: int) -> bytes:
    """Read one 2048-byte logical sector from an open binary file.

    Args:
        handle: Binary file object; it is seeked before reading.
        lba: Logical block address to read.

    Returns:
        bytes: Sector contents, shorter than a full sector at end of file.
    """
    handle.seek(lba * _SECTOR_SIZE)
    return handle.read(_SECTOR_SIZE)


def _decode_identifier(raw: bytes) -> str:
    """Decode a fixed-width ISO identifier field to a trimmed string.

    Args:
        raw: Raw field bytes.

    Returns:
        str: ASCII text with NUL and space padding removed.
    """
    return raw.rstrip(b"\x00").decode("ascii", errors="replace").strip()


def parse_boot_catalog(catalog: bytes) -> tuple[str, tuple[BootCatalogEntry, ...]]:
    """Decode an El Torito boot catalog sector.

    Walks the 32-byte records, tracking which platform the current section
    applies to so a bootable entry can be attributed to BIOS or UEFI. Parsing
    stops at the first record whose header identifier is neither a section
    header nor a boot entry.

    Args:
        catalog: Raw bytes of the sector holding the boot catalog.

    Returns:
        tuple[str, tuple[BootCatalogEntry, ...]]: The validation entry's
        identifier string (empty when the validation entry is absent or its
        ``0x55 0xAA`` key is wrong) and every decoded boot entry.
    """
    if len(catalog) < _CATALOG_ENTRY_SIZE:
        return ("", ())

    validation = catalog[:_CATALOG_ENTRY_SIZE]
    key = validation[_CATALOG_VALIDATION_KEY_START : _CATALOG_VALIDATION_KEY_START + len(_CATALOG_VALIDATION_KEY)]
    if validation[0] != _CATALOG_VALIDATION_HEADER or key != _CATALOG_VALIDATION_KEY:
        return ("", ())

    identifier = _decode_identifier(validation[_CATALOG_VALIDATION_ID_START:_CATALOG_VALIDATION_ID_END])
    current_platform = validation[1]

    entries: list[BootCatalogEntry] = []
    offset = _CATALOG_ENTRY_SIZE
    while offset + _CATALOG_ENTRY_SIZE <= len(catalog) and len(entries) < _CATALOG_MAX_ENTRIES:
        record = catalog[offset : offset + _CATALOG_ENTRY_SIZE]
        header = record[0]
        if header in _CATALOG_SECTION_HEADERS:
            current_platform = record[1]
        elif header in {_CATALOG_ENTRY_BOOTABLE, _CATALOG_ENTRY_NON_BOOTABLE}:
            load_lba = struct.unpack_from("<I", record, _CATALOG_LOAD_LBA_OFFSET)[0]
            entries.append(
                BootCatalogEntry(
                    platform_id=current_platform,
                    bootable=header == _CATALOG_ENTRY_BOOTABLE,
                    load_lba=int(load_lba),
                ),
            )
        else:
            break
        offset += _CATALOG_ENTRY_SIZE

    return (identifier, tuple(entries))


@dataclass(frozen=True)
class VolumeDescriptorSet:
    """What the ISO9660/UDF volume descriptor set at LBA 16 onwards contains.

    Attributes:
        volume_id: Primary volume identifier, empty when absent.
        system_id: Primary system identifier, empty when absent.
        has_primary_descriptor: Whether a CD001 primary descriptor was found.
        udf_identifiers: Volume recognition identifiers, in order.
        boot_catalog_lba: El Torito boot catalog address, or None.
    """

    volume_id: str
    system_id: str
    has_primary_descriptor: bool
    udf_identifiers: tuple[str, ...]
    boot_catalog_lba: int | None


def _scan_volume_descriptors(handle: IO[bytes]) -> VolumeDescriptorSet:
    """Walk an ISO's volume descriptor set and summarise it.

    Args:
        handle: Binary file object opened on the ISO image.

    Returns:
        VolumeDescriptorSet: Decoded descriptor summary.
    """
    volume_id = ""
    system_id = ""
    has_primary = False
    udf_identifiers: list[str] = []
    boot_catalog_lba: int | None = None

    for lba in range(_DESCRIPTOR_FIRST_LBA, _DESCRIPTOR_LAST_LBA + 1):
        sector = _read_sector(handle, lba)
        if len(sector) < _SECTOR_SIZE:
            break
        standard_id = sector[1:6]
        if standard_id == _ISO9660_STANDARD_ID:
            descriptor_type = sector[0]
            if descriptor_type == _DESCRIPTOR_TYPE_PRIMARY and not has_primary:
                has_primary = True
                system_id = _decode_identifier(sector[_SYSTEM_ID_START:_SYSTEM_ID_END])
                volume_id = _decode_identifier(sector[_VOLUME_ID_START:_VOLUME_ID_END])
            elif descriptor_type == _DESCRIPTOR_TYPE_BOOT_RECORD and boot_catalog_lba is None:
                boot_system = _decode_identifier(sector[_BOOT_SYSTEM_ID_START:_BOOT_SYSTEM_ID_END])
                if boot_system.startswith(_EL_TORITO_SYSTEM_ID):
                    boot_catalog_lba = int(struct.unpack_from("<I", sector, _BOOT_CATALOG_POINTER_OFFSET)[0])
        elif standard_id in _UDF_RECOGNITION_IDENTIFIERS:
            udf_identifiers.append(standard_id.decode("ascii"))

    return VolumeDescriptorSet(
        volume_id=volume_id,
        system_id=system_id,
        has_primary_descriptor=has_primary,
        udf_identifiers=tuple(udf_identifiers),
        boot_catalog_lba=boot_catalog_lba,
    )


def _read_boot_catalog(handle: IO[bytes], boot_catalog_lba: int | None) -> tuple[str, tuple[BootCatalogEntry, ...]]:
    """Read and decode the boot catalog a descriptor set pointed at.

    Args:
        handle: Binary file object opened on the ISO image.
        boot_catalog_lba: Catalog address, or None when there is no catalog.

    Returns:
        tuple[str, tuple[BootCatalogEntry, ...]]: Validation identifier and
        decoded boot entries; both empty when there is no catalog.
    """
    if boot_catalog_lba is None:
        return ("", ())
    return parse_boot_catalog(_read_sector(handle, boot_catalog_lba))


def probe_iso_structure(path: Path) -> IsoStructure:
    """Read an ISO image's volume descriptors and boot catalog.

    Nothing is mounted and no elevation is needed; the descriptor set at LBA
    16 onwards and the boot catalog are read directly out of the file. This
    is the only validation that works on Microsoft media whose ISO9660
    filesystem holds a stub while the real ``sources`` tree lives in UDF.

    Args:
        path: ISO image to probe.

    Returns:
        IsoStructure: Decoded structural facts.

    Raises:
        ProvisioningError: If the image cannot be opened or read.
    """
    try:
        size_bytes = path.stat().st_size
        with path.open("rb") as handle:
            descriptors = _scan_volume_descriptors(handle)
            el_torito_identifier, entries = _read_boot_catalog(handle, descriptors.boot_catalog_lba)
    except OSError as error:
        message = f"cannot read ISO image {path}: {error}"
        raise ProvisioningError(message) from error

    bios_boot_lba = next((entry.load_lba for entry in entries if entry.bootable and entry.platform_id == _PLATFORM_ID_X86), None)
    uefi_boot_lba = next((entry.load_lba for entry in entries if entry.bootable and entry.platform_id == _PLATFORM_ID_UEFI), None)

    return IsoStructure(
        path=path,
        size_bytes=size_bytes,
        volume_id=descriptors.volume_id,
        system_id=descriptors.system_id,
        has_primary_descriptor=descriptors.has_primary_descriptor,
        udf_identifiers=descriptors.udf_identifiers,
        el_torito_identifier=el_torito_identifier,
        boot_catalog_lba=descriptors.boot_catalog_lba,
        bios_boot_lba=bios_boot_lba,
        uefi_boot_lba=uefi_boot_lba,
    )


def classify_media_root(root: Path) -> MediaContent:
    """Inspect a mounted install medium's directory tree.

    Args:
        root: Directory the medium is mounted or extracted at.

    Returns:
        MediaContent: Which Windows Setup artifacts were found.
    """
    sources = root / _SOURCES_DIRECTORY
    install_image = next((sources / name for name in _INSTALL_IMAGE_NAMES if (sources / name).is_file()), None)
    return MediaContent(
        root=root,
        install_image=install_image,
        has_boot_image=(sources / _BOOT_IMAGE_NAME).is_file(),
        has_bios_boot_directory=(root / _BIOS_BOOT_DIRECTORY).is_dir(),
        has_setup_executable=(root / _SETUP_EXECUTABLE).is_file(),
    )


def available_drive_roots() -> tuple[Path, ...]:
    """Enumerate filesystem roots that can hold installation media.

    On Windows every ready logical drive is returned. Elsewhere the
    filesystem root is returned so the scanner still has somewhere to look.

    Returns:
        tuple[Path, ...]: Roots to scan, in ascending drive-letter order.
    """
    if sys.platform != _WINDOWS_PLATFORM:
        return (Path("/"),)
    roots: list[Path] = []
    for code in range(ord("A"), ord("Z") + 1):
        root = Path(f"{chr(code)}:/")
        try:
            ready = root.is_dir()
        except OSError:
            ready = False
        if ready:
            roots.append(root)
    return tuple(roots)


def _directory_size(candidate: Path) -> int:
    """Return a file's size, treating an unreadable file as empty.

    Args:
        candidate: File to measure.

    Returns:
        int: Size in bytes, or 0 when the file cannot be stat'ed.
    """
    try:
        return candidate.stat().st_size
    except OSError:
        return 0


def iter_candidate_isos(roots: tuple[Path, ...], max_depth: int, budget: int) -> list[Path]:
    """Collect ``.iso`` files under the given roots without a full-tree walk.

    A breadth-limited scan is deliberate: a whole-drive recursive glob over a
    multi-terabyte volume runs for minutes and competes for disk bandwidth
    with everything else on the host. Directories that never hold install
    media are skipped by name and the number of directories visited is
    capped.

    Args:
        roots: Filesystem roots to scan.
        max_depth: Maximum directory depth below each root, where depth 1
            means files directly inside the root.
        budget: Maximum number of directories to enumerate across all roots.

    Returns:
        list[Path]: Discovered ISO paths, largest file first.
    """
    found: list[Path] = []
    visited = 0
    for root in roots:
        frontier: deque[tuple[Path, int]] = deque([(root, 1)])
        while frontier:
            if visited >= budget:
                _LOGGER.warning("iso_scan_budget_exhausted", budget=budget, root=str(root))
                break
            directory, depth = frontier.popleft()
            visited += 1
            try:
                children = sorted(directory.iterdir())
            except OSError:
                continue
            for child in children:
                try:
                    is_dir = child.is_dir()
                except OSError:
                    continue
                if is_dir:
                    if depth < max_depth and child.name.lower() not in _SCAN_SKIP_DIRECTORY_NAMES:
                        frontier.append((child, depth + 1))
                elif child.suffix.lower() == ".iso":
                    found.append(child)

    found.sort(key=_directory_size, reverse=True)
    _LOGGER.info("iso_scan_complete", directories_visited=visited, iso_count=len(found))
    return found


def discover_install_media(
    roots: tuple[Path, ...],
    priority_roots: tuple[Path, ...] = (),
    max_depth: int = _DEFAULT_SCAN_DEPTH,
    budget: int = _DEFAULT_SCAN_BUDGET,
) -> list[IsoStructure]:
    """Find every Windows installation medium reachable from the given roots.

    Priority roots are scanned first, so a medium already staged in the
    Intellicrack images directory is found without touching the rest of the
    host.

    Args:
        roots: General filesystem roots to scan.
        priority_roots: Directories searched before ``roots``.
        max_depth: Maximum directory depth below each root.
        budget: Maximum number of directories to enumerate.

    Returns:
        list[IsoStructure]: Probes of every image that passes
        :attr:`IsoStructure.is_windows_install_candidate`, largest first.
    """
    seen: list[Path] = []
    for candidate in iter_candidate_isos(priority_roots, max_depth, budget):
        if candidate not in seen:
            seen.append(candidate)
    matches = [probe for probe in (probe_iso_structure(path) for path in seen) if probe.is_windows_install_candidate]
    if matches:
        return matches

    for candidate in iter_candidate_isos(roots, max_depth, budget):
        if candidate not in seen:
            seen.append(candidate)
    return [probe for probe in (probe_iso_structure(path) for path in seen) if probe.is_windows_install_candidate]


def _powershell_executable() -> str:
    """Resolve the PowerShell interpreter used for disk image mounting.

    Returns:
        str: ``pwsh`` when PowerShell 7 is installed, otherwise
        ``powershell``.
    """
    return _POWERSHELL_EXECUTABLE if shutil.which(_POWERSHELL_EXECUTABLE) else _POWERSHELL_FALLBACK


def _run_process(argv: list[str], timeout: float = _SUBPROCESS_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
    """Run a child process and capture both of its streams as text.

    Args:
        argv: Full argument vector, executable first.
        timeout: Seconds to wait before terminating the child.

    Returns:
        subprocess.CompletedProcess[str]: Completed process with captured
        output.

    Raises:
        ProvisioningError: If the executable is missing or the child exceeds
            ``timeout``.
    """
    _LOGGER.info("subprocess_spawning", argv=argv, executable=argv[0] if argv else None)
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as error:
        message = f"executable not found: {argv[0] if argv else '<empty>'}"
        raise ProvisioningError(message) from error
    except subprocess.TimeoutExpired as error:
        message = f"command timed out after {timeout}s: {' '.join(argv)}"
        raise ProvisioningError(message) from error


def mount_disk_image(path: Path) -> Path:
    """Mount an ISO read-only and return the directory it appears at.

    Uses the Windows storage stack, whose UDF driver is the only thing on
    this host that can read the ``sources`` tree of Microsoft media.

    Args:
        path: ISO image to mount.

    Returns:
        Path: Root directory of the mounted volume.

    Raises:
        ProvisioningError: If mounting is unsupported on this platform, the
            command fails, or no drive letter is assigned.
    """
    if sys.platform != _WINDOWS_PLATFORM:
        message = "mounting install media requires Windows"
        raise ProvisioningError(message)

    script = (
        f"$image = Mount-DiskImage -ImagePath '{path}' -PassThru -ErrorAction Stop; "
        "Start-Sleep -Milliseconds 750; "
        "($image | Get-Volume).DriveLetter"
    )
    argv = [_powershell_executable(), "-NoProfile", "-NonInteractive", "-Command", script]
    result = _run_process(argv, timeout=_MOUNT_TIMEOUT_SECONDS)
    letter = result.stdout.strip()
    if result.returncode != 0 or len(letter) != _DRIVE_LETTER_LENGTH or not letter.isalpha():
        detail = result.stderr.strip() or result.stdout.strip() or "no drive letter assigned"
        message = f"failed to mount {path}: {detail}"
        raise ProvisioningError(message)
    _LOGGER.info("install_media_mounted", image=str(path), drive_letter=letter)
    return Path(f"{letter}:/")


def dismount_disk_image(path: Path) -> None:
    """Dismount a previously mounted ISO, tolerating an already-gone volume.

    Args:
        path: ISO image to dismount.
    """
    if sys.platform != _WINDOWS_PLATFORM:
        return
    script = f"Dismount-DiskImage -ImagePath '{path}' | Out-Null"
    argv = [_powershell_executable(), "-NoProfile", "-NonInteractive", "-Command", script]
    result = _run_process(argv, timeout=_MOUNT_TIMEOUT_SECONDS)
    if result.returncode == 0:
        _LOGGER.info("install_media_dismounted", image=str(path))
    else:
        _LOGGER.warning("install_media_dismount_failed", image=str(path), stderr=result.stderr.strip())


def verify_media_contents(path: Path) -> MediaContent:
    """Mount an install medium, classify its tree, and dismount it again.

    Args:
        path: ISO image to verify.

    Returns:
        MediaContent: Directory inspection of the mounted medium.

    Raises:
        ProvisioningError: If the medium mounts but is not Windows install
            media.
    """
    root = mount_disk_image(path)
    try:
        content = classify_media_root(root)
    finally:
        dismount_disk_image(path)
    if not content.is_windows_install_media:
        message = (
            f"{path} mounted but is not Windows install media: "
            f"install_image={content.install_image}, boot_wim={content.has_boot_image}, "
            f"boot_dir={content.has_bios_boot_directory}, setup_exe={content.has_setup_executable}"
        )
        raise ProvisioningError(message)
    _LOGGER.info("install_media_verified", image=str(path), install_image=str(content.install_image))
    return content


def looks_like_virtio_media(root: Path) -> bool:
    """Report whether a directory tree is a virtio-win driver medium.

    Args:
        root: Directory to inspect.

    Returns:
        bool: True when the marker driver directories are all present.
    """
    return all((root / name).is_dir() for name in VIRTIO_MARKER_DIRECTORIES)


def discover_virtio_media(
    roots: tuple[Path, ...],
    max_depth: int,
    budget: int,
    *,
    priority_roots: tuple[Path, ...] = (),
) -> Path | None:
    """Locate a virtio-win driver ISO on the host.

    Priority roots are scanned first and on their own terms, exactly as
    :func:`discover_install_media` does: the Intellicrack images directory
    sits deeper than the breadth-limited scan of a drive root ever reaches,
    so a medium staged there is invisible to the general scan.

    Args:
        roots: Filesystem roots to scan.
        max_depth: Maximum directory depth below each root.
        budget: Maximum number of directories to enumerate.
        priority_roots: Directories searched before ``roots``.

    Returns:
        Path | None: First ISO whose name identifies it as virtio-win, or
        None when none is present.
    """
    for scan_roots in (priority_roots, roots):
        if not scan_roots:
            continue
        for candidate in iter_candidate_isos(scan_roots, max_depth, budget):
            if "virtio" in candidate.name.lower():
                _LOGGER.info("virtio_media_found", path=str(candidate))
                return candidate
    return None


def enumerate_virtio_driver_subpaths(medium_root: Path, architecture: str) -> tuple[str, ...]:
    r"""Enumerate the driver package directories WinPE can really be pointed at.

    The medium lays its packages out as ``<driver>\\<family>\\<arch>``, and the
    families genuinely differ per driver: on virtio-win 0.1.285 ``viostor``
    ships fifteen families, ``w11`` has no ``x86`` at all, and most server
    families are ``amd64`` only. Naming one fixed family therefore emits paths
    that exist on no medium for most guests, and WinPE loads no ``viostor`` at
    all, so Setup sees no disk. Every directory that does exist for the guest's
    architecture is emitted instead: an extra family costs one INF that matches
    no hardware, a missing one costs the system disk.

    Args:
        medium_root: Root of the mounted virtio-win medium.
        architecture: Architecture directory name to keep, matched without
            regard to case, for example ``amd64``.

    Returns:
        tuple[str, ...]: Sorted ``<driver>\\<family>\\<arch>`` subpaths that
        exist on the medium and carry at least one INF.
    """
    subpaths: list[str] = []
    for driver in WINPE_DRIVER_DIRECTORIES:
        driver_root = medium_root / driver
        if not driver_root.is_dir():
            continue
        for family in driver_root.iterdir():
            if not family.is_dir():
                continue
            subpaths.extend(
                f"{driver}\\{family.name}\\{package.name}"
                for package in family.iterdir()
                if package.is_dir() and package.name.casefold() == architecture.casefold() and _holds_driver_package(package)
            )
    return tuple(sorted(subpaths))


def select_winpe_driver_packages(subpaths: tuple[str, ...], drivers: tuple[str, ...] = WINPE_DRIVER_DIRECTORIES) -> tuple[str, ...]:
    r"""Pick the one package per driver that WinPE is given.

    Setup rejects an answer file that names many driver paths, so breadth has
    to be spent where it matters: the enumeration knows every family the
    medium carries, and this reduces that to a single package per driver,
    newest family first. A driver the medium has no package for is skipped
    rather than guessed at.

    Args:
        subpaths: ``<driver>\\<family>\\<arch>`` directories enumerated off
            the medium for the guest's architecture.
        drivers: Driver directories to pick packages for.

    Returns:
        tuple[str, ...]: One subpath per driver that has a package, in the
        order ``drivers`` declares.
    """
    selected: list[str] = []
    for driver in drivers:
        prefix = f"{driver}\\"
        candidates = [subpath for subpath in subpaths if subpath.casefold().startswith(prefix.casefold())]
        if not candidates:
            continue
        selected.append(min(candidates, key=_family_rank))
    return tuple(selected)


def _family_rank(subpath: str) -> tuple[int, str]:
    r"""Order a ``<driver>\\<family>\\<arch>`` subpath by how new its family is.

    Args:
        subpath: Driver package subpath.

    Returns:
        tuple[int, str]: Sort key placing preferred families first and any
        family the preference list does not name after all of them.
    """
    parts = subpath.split("\\")
    family = parts[1] if len(parts) > 1 else ""
    folded = [name.casefold() for name in WINPE_DRIVER_FAMILY_PREFERENCE]
    position = folded.index(family.casefold()) if family.casefold() in folded else len(folded)
    return (position, subpath.casefold())


def require_boot_critical_package(packages: tuple[str, ...], source: str, architecture: str) -> None:
    """Refuse a driver set WinPE could not boot the guest's system disk from.

    Args:
        packages: Packages selected for staging.
        source: Medium the packages were selected from, for the message.
        architecture: Architecture directory name the guest needs.

    Raises:
        ProvisioningError: If no boot-critical storage package is present.
    """
    if any(package.casefold().startswith(_BOOT_CRITICAL_DRIVER.casefold()) for package in packages):
        return
    message = (
        f"{source} carries no {_BOOT_CRITICAL_DRIVER} package for {architecture}. Windows Setup installs onto a "
        f"virtio-blk disk WinPE cannot see without it, so the install would find no disk at all."
    )
    raise ProvisioningError(message)


def stage_winpe_drivers(
    virtio_iso: Path,
    staging: Path,
    architecture: str,
    directory: str = WINPE_DRIVER_STAGE_DIRECTORY,
) -> tuple[str, ...]:
    r"""Copy the boot-critical driver files onto the answer medium.

    The files are laid down flat in one directory so Setup needs neither a
    recursive search nor more than one path per drive letter, and so the
    package set is the provisioner's own rather than whatever the virtio
    medium happens to be mounted as in WinPE.

    Args:
        virtio_iso: virtio-win medium to copy from.
        staging: Answer medium staging directory.
        architecture: Architecture directory name the guest needs.
        directory: Folder under ``staging`` to stage into, which must be the
            one the answer file names.

    Returns:
        tuple[str, ...]: Names of the files staged, sorted.

    Raises:
        ProvisioningError: If the medium carries no ``viostor`` package for
            the architecture, or two packages would overwrite each other.
    """
    destination = staging / directory
    destination.mkdir(parents=True, exist_ok=True)

    medium_root = mount_disk_image(virtio_iso)
    try:
        packages = select_winpe_driver_packages(enumerate_virtio_driver_subpaths(medium_root, architecture))
        require_boot_critical_package(packages, str(virtio_iso), architecture)

        origins: dict[str, str] = {}
        for package in packages:
            for source in sorted((medium_root / package).iterdir()):
                if not source.is_file():
                    continue
                previous = origins.get(source.name.casefold())
                if previous is not None:
                    message = f"{package} and {previous} both carry {source.name}; staging one would hide the other"
                    raise ProvisioningError(message)
                origins[source.name.casefold()] = package
                shutil.copy2(source, destination / source.name)
    finally:
        dismount_disk_image(virtio_iso)

    staged = tuple(sorted(path.name for path in destination.iterdir() if path.is_file()))
    _LOGGER.info(
        "winpe_drivers_staged",
        packages=list(packages),
        files=len(staged),
        directory=directory,
    )
    return staged


def _holds_driver_package(directory: Path) -> bool:
    r"""Report whether a directory carries an installable driver package.

    Args:
        directory: Candidate ``<driver>\\<family>\\<arch>`` directory.

    Returns:
        bool: True when at least one INF file sits directly inside it.
    """
    return any(entry.is_file() and entry.suffix.casefold() == _DRIVER_INF_SUFFIX for entry in directory.iterdir())


def verify_virtio_contents(path: Path, architecture: str = _COMPONENT_ARCHITECTURE) -> tuple[str, ...]:
    """Mount a virtio-win medium, confirm its drivers, and map its packages.

    Args:
        path: Driver ISO to verify.
        architecture: Architecture directory name the guest needs.

    Returns:
        tuple[str, ...]: WinPE driver subpaths the medium really carries for
        ``architecture``.

    Raises:
        ProvisioningError: If the medium lacks the marker driver directories,
            or carries no package for ``architecture``.
    """
    root = mount_disk_image(path)
    try:
        recognised = looks_like_virtio_media(root)
        subpaths = enumerate_virtio_driver_subpaths(root, architecture) if recognised else ()
    finally:
        dismount_disk_image(path)
    if not recognised:
        message = f"{path} mounted but carries none of the expected virtio driver directories: {', '.join(VIRTIO_MARKER_DIRECTORIES)}"
        raise ProvisioningError(message)
    if not subpaths:
        message = (
            f"{path} carries no {architecture} driver package under any of "
            f"{', '.join(WINPE_DRIVER_DIRECTORIES)}, so WinPE would have nothing to load"
        )
        raise ProvisioningError(message)
    _LOGGER.info("virtio_media_verified", image=str(path), driver_subpaths=len(subpaths))
    return subpaths


def require_virtio_media(
    explicit: Path | None,
    roots: tuple[Path, ...],
    max_depth: int,
    budget: int,
    *,
    priority_roots: tuple[Path, ...] = (),
    verify_contents: bool = False,
) -> Path:
    """Resolve the virtio-win medium or explain why provisioning cannot go on.

    The sandbox boots the guest from a virtio-blk disk over a virtio-net NIC
    with a virtio-serial agent channel, so Windows Setup cannot even see the
    system disk without ``viostor``. There is no fallback: an install done
    against some other controller produces an image the sandbox cannot boot.

    Args:
        explicit: Operator-supplied path, or None to search.
        roots: Filesystem roots to scan when searching.
        max_depth: Maximum directory depth below each root.
        budget: Maximum number of directories to enumerate.
        priority_roots: Directories searched before ``roots``.
        verify_contents: Whether to mount the resolved medium and confirm it
            really carries the virtio driver directories.

    Returns:
        Path: Located virtio-win ISO.

    Raises:
        ProvisioningError: If no virtio-win medium is available.
    """
    if explicit is not None:
        if not explicit.is_file():
            message = f"virtio-win ISO not found at {explicit}"
            raise ProvisioningError(message)
        if verify_contents:
            verify_virtio_contents(explicit)
        return explicit

    found = discover_virtio_media(roots, max_depth, budget, priority_roots=priority_roots)
    if found is not None:
        if verify_contents:
            verify_virtio_contents(found)
        return found

    message = (
        "virtio-win driver ISO not found on this host, and it is a hard prerequisite: the sandbox launcher "
        "builds '-drive ...,if=virtio' and '-device virtio-net-pci', so Windows Setup cannot see the system "
        "disk without the viostor driver, and the org.qemu.guest_agent.0 channel needs vioserial. Download "
        f"{_VIRTIO_WIN_URL} (approximately {_VIRTIO_WIN_APPROXIMATE_MB} MB) and re-run with --virtio-iso "
        "pointing at it."
    )
    raise ProvisioningError(message)


def resolve_virtio_medium(
    explicit: Path | None,
    roots: tuple[Path, ...],
    max_depth: int,
    budget: int,
    architecture: str,
    *,
    priority_roots: tuple[Path, ...] = (),
) -> VirtioMedium:
    """Locate the virtio-win medium and read its driver layout in one mount.

    Propagates the ``ProvisioningError`` raised when no virtio-win medium is
    available, when the located medium is not one, or when it carries no
    package for ``architecture``.

    Args:
        explicit: Operator-supplied path, or None to search.
        roots: Filesystem roots to scan when searching.
        max_depth: Maximum directory depth below each root.
        budget: Maximum number of directories to enumerate.
        architecture: Architecture directory name the guest needs.
        priority_roots: Directories searched before ``roots``.

    Returns:
        VirtioMedium: The located medium and the driver subpaths it carries.
    """
    path = require_virtio_media(
        explicit,
        roots,
        max_depth,
        budget,
        priority_roots=priority_roots,
        verify_contents=False,
    )
    return VirtioMedium(path=path, driver_subpaths=verify_virtio_contents(path, architecture))


def resolve_qemu_tools(tools_path: Path) -> tuple[Path, Path, Path]:
    """Resolve the bundled QEMU executables this provisioner depends on.

    Args:
        tools_path: Directory holding the bundled QEMU installation.

    Returns:
        tuple[Path, Path, Path]: ``(qemu-system-x86_64, qemu-img, qemu-ga)``.

    Raises:
        ProvisioningError: If any of the three is missing.
    """
    system = tools_path / _QEMU_EXECUTABLE_NAME
    image = tools_path / _QEMU_IMG_EXECUTABLE_NAME
    agent = tools_path / _QEMU_GUEST_AGENT_EXECUTABLE
    missing = [str(candidate) for candidate in (system, image, agent) if not candidate.is_file()]
    if missing:
        message = f"bundled QEMU tooling incomplete, missing: {', '.join(missing)}"
        raise ProvisioningError(message)
    return (system, image, agent)


def detect_accelerator(qemu_executable: Path, preferred: str | None = None) -> str:
    """Determine which QEMU accelerator to use for the install.

    Reads ``-accel help``, which enumerates the accelerators compiled into
    the binary without starting any guest.

    Args:
        qemu_executable: Path to ``qemu-system-x86_64.exe``.
        preferred: Accelerator the operator asked for, or None to autodetect.

    Returns:
        str: Accelerator name to pass to ``-machine accel=``.

    Raises:
        ProvisioningError: If ``preferred`` is not supported by this binary.
    """
    result = _run_process([str(qemu_executable), "-accel", "help"], timeout=_MOUNT_TIMEOUT_SECONDS)
    supported = {line.strip() for line in result.stdout.splitlines() if line.strip() and " " not in line.strip()}
    if preferred is not None:
        if preferred not in supported:
            message = f"accelerator {preferred!r} is not supported by {qemu_executable}; available: {sorted(supported)}"
            raise ProvisioningError(message)
        return preferred
    for candidate in ("whpx", "kvm", "hvf"):
        if candidate in supported:
            return candidate
    return "tcg"


def create_guest_disk(qemu_img: Path, disk_image: Path, size_gb: int, *, force: bool) -> None:
    """Create the qcow2 system disk the guest is installed onto.

    Args:
        qemu_img: Path to ``qemu-img.exe``.
        disk_image: Destination qcow2 path.
        size_gb: Virtual size in gibibytes.
        force: Whether to replace an existing image.

    Raises:
        ProvisioningError: If the image exists and ``force`` is False, or if
            ``qemu-img`` fails.
    """
    if disk_image.exists():
        if not force:
            message = f"guest disk already exists at {disk_image}; pass --force to replace it"
            raise ProvisioningError(message)
        disk_image.unlink()
        _LOGGER.warning("guest_disk_replaced", path=str(disk_image))

    disk_image.parent.mkdir(parents=True, exist_ok=True)
    result = _run_process([str(qemu_img), "create", "-f", "qcow2", str(disk_image), f"{size_gb}G"])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        message = f"qemu-img create failed ({result.returncode}): {detail}"
        raise ProvisioningError(message)
    _LOGGER.info("guest_disk_created", path=str(disk_image), size_gb=size_gb)


def _component(parent: Element, name: str) -> Element:
    """Append an unattend ``component`` element with the standard attributes.

    Args:
        parent: Element to append to.
        name: Component name such as ``Microsoft-Windows-Setup``.

    Returns:
        Element: The created element.
    """
    return SubElement(
        parent,
        "component",
        {
            "name": name,
            "processorArchitecture": _COMPONENT_ARCHITECTURE,
            "publicKeyToken": _COMPONENT_PUBLIC_KEY,
            "language": "neutral",
            "versionScope": "nonSxS",
        },
    )


def _text_element(parent: Element, tag: str, text: str) -> Element:
    """Append a child element carrying only text.

    Args:
        parent: Element to append to.
        tag: Child element name.
        text: Text content.

    Returns:
        Element: The created element.
    """
    child = SubElement(parent, tag)
    child.text = text
    return child


def _run_synchronous_commands(parent: Element, commands: tuple[str, ...]) -> None:
    """Append an ordered ``RunSynchronous`` block.

    Args:
        parent: Component element to append the block to.
        commands: Command lines in execution order.
    """
    block = SubElement(parent, "RunSynchronous")
    for order, command in enumerate(commands, start=1):
        entry = SubElement(block, "RunSynchronousCommand", {"wcm:action": "add"})
        _text_element(entry, "Order", str(order))
        _text_element(entry, "Path", command)


def lab_config_commands() -> tuple[str, ...]:
    """Build the registry commands that bypass the Windows 11 hardware gates.

    Returns:
        tuple[str, ...]: One ``reg add`` command per LabConfig value.
    """
    return tuple(f'reg add "{_LAB_CONFIG_KEY}" /v {name} /t REG_DWORD /d 1 /f' for name in _LAB_CONFIG_BYPASSES)


def _disk_configuration(parent: Element) -> None:
    """Append the MBR disk layout Windows Setup applies to the virtio disk.

    Two primary partitions are created because the sandbox boots SeaBIOS: a
    small active NTFS system partition holding the boot manager and an
    extended NTFS partition holding Windows. A GPT layout with an EFI system
    partition would produce a disk the firmware-free launcher cannot boot.

    Args:
        parent: ``Microsoft-Windows-Setup`` component element.
    """
    configuration = SubElement(parent, "DiskConfiguration")
    _text_element(configuration, "WillShowUI", "OnError")
    disk = SubElement(configuration, "Disk", {"wcm:action": "add"})
    _text_element(disk, "DiskID", str(_INSTALL_DISK_ID))
    _text_element(disk, "WillWipeDisk", "true")

    creations = SubElement(disk, "CreatePartitions")
    system_partition = SubElement(creations, "CreatePartition", {"wcm:action": "add"})
    _text_element(system_partition, "Order", "1")
    _text_element(system_partition, "Type", "Primary")
    _text_element(system_partition, "Size", str(_SYSTEM_PARTITION_MB))
    windows_partition = SubElement(creations, "CreatePartition", {"wcm:action": "add"})
    _text_element(windows_partition, "Order", "2")
    _text_element(windows_partition, "Type", "Primary")
    _text_element(windows_partition, "Extend", "true")

    modifications = SubElement(disk, "ModifyPartitions")
    system_modification = SubElement(modifications, "ModifyPartition", {"wcm:action": "add"})
    _text_element(system_modification, "Order", "1")
    _text_element(system_modification, "PartitionID", "1")
    _text_element(system_modification, "Label", _SYSTEM_PARTITION_LABEL)
    _text_element(system_modification, "Format", "NTFS")
    _text_element(system_modification, "Active", "true")
    windows_modification = SubElement(modifications, "ModifyPartition", {"wcm:action": "add"})
    _text_element(windows_modification, "Order", "2")
    _text_element(windows_modification, "PartitionID", str(_WINDOWS_PARTITION_ID))
    _text_element(windows_modification, "Label", _WINDOWS_PARTITION_LABEL)
    _text_element(windows_modification, "Format", "NTFS")
    _text_element(windows_modification, "Letter", _WINDOWS_PARTITION_LETTER)


def _driver_paths(parent: Element, settings: UnattendSettings) -> None:
    """Append the WinPE driver search paths for the staged driver folder.

    WinPE assigns CD-ROM drive letters in an order the answer file cannot
    know, so one entry per plausible letter is emitted for the single folder
    the drivers were staged into. Letters that do not resolve are recorded in
    ``setuperr.log`` and skipped; more entries than this and Setup abandons
    the installation instead.

    Args:
        parent: ``Microsoft-Windows-PnpCustomizationsWinPE`` element.
        settings: Answer file settings supplying letters and the folder.
    """
    paths = SubElement(parent, "DriverPaths")
    for key, letter in enumerate(settings.driver_letters, start=1):
        entry = SubElement(paths, "PathAndCredentials", {"wcm:action": "add", "wcm:keyValue": str(key)})
        _text_element(entry, "Path", f"{letter}:\\{settings.driver_directory}")


def computer_name_enforcement_command(computer_name: str) -> str:
    """Build the guest command that asserts the declared computer name.

    Setup applies the ``specialize`` pass ``ComputerName`` and then requires a
    reboot before OOBE to realise it; the name in force after that reboot is a
    Windows-generated one, so the declared name has to be re-asserted from
    inside the finished guest. ``Rename-Computer`` is deliberately run without
    ``-Restart``: it writes the pending name immediately and the provisioner
    keeps control of when the guest shuts down.

    Args:
        computer_name: NetBIOS name the guest is meant to answer to.

    Returns:
        str: Command line to run as a first-logon command.
    """
    quoted = computer_name.replace("'", "''")
    return (
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "
        f"\"if ($env:COMPUTERNAME -ne '{quoted}') {{ Rename-Computer -NewName '{quoted}' -Force }}\""
    )


def first_logon_commands(settings: UnattendSettings) -> tuple[tuple[str, str], ...]:
    """Build the ordered first-logon commands run inside the new guest.

    Args:
        settings: Answer file settings.

    Returns:
        tuple[tuple[str, str], ...]: ``(command_line, description)`` pairs.
    """
    letters = _GUEST_DRIVE_LETTERS
    commands: list[tuple[str, str]] = [
        ("powercfg.exe /change standby-timeout-ac 0", "Never suspend the guest"),
        ("powercfg.exe /change monitor-timeout-ac 0", "Never blank the guest console"),
        ("powercfg.exe /change hibernate-timeout-ac 0", "Never hibernate the guest"),
        (
            (
                f'cmd.exe /c for %d in ({letters}) do @if exist "%d:\\{_DRIVER_SCRIPT_RELATIVE}" '
                f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%d:\\{_DRIVER_SCRIPT_RELATIVE}"'
            ),
            "Trust the driver publisher, then install this guest's virtio-win packages",
        ),
        (
            f'cmd.exe /c for %d in ({letters}) do @if exist "%d:\\{settings.answer_script}" call "%d:\\{settings.answer_script}"',
            "Install and start the QEMU guest agent service",
        ),
        (
            computer_name_enforcement_command(settings.computer_name),
            "Assert the declared computer name, which Setup does not keep past the pre-OOBE reboot",
        ),
    ]
    if settings.disable_guest_firewall:
        commands.insert(
            0,
            ("netsh.exe advfirewall set allprofiles state off", "Allow the host to reach the forwarded guest agent port"),
        )
    return tuple(commands)


def _render_image_install(setup: Element, settings: UnattendSettings) -> None:
    """Append the ``ImageInstall`` and ``UserData`` blocks.

    Args:
        setup: ``Microsoft-Windows-Setup`` component element.
        settings: Answer file settings.
    """
    image_install = SubElement(setup, "ImageInstall")
    os_image = SubElement(image_install, "OSImage")
    install_from = SubElement(os_image, "InstallFrom")
    metadata = SubElement(install_from, "MetaData", {"wcm:action": "add"})
    _text_element(metadata, "Key", "/IMAGE/NAME")
    _text_element(metadata, "Value", settings.image_name)
    install_to = SubElement(os_image, "InstallTo")
    _text_element(install_to, "DiskID", str(_INSTALL_DISK_ID))
    _text_element(install_to, "PartitionID", str(_WINDOWS_PARTITION_ID))
    _text_element(os_image, "WillShowUI", "OnError")

    user_data = SubElement(setup, "UserData")
    _text_element(user_data, "AcceptEula", "true")
    _text_element(user_data, "FullName", settings.admin_user)
    _text_element(user_data, "Organization", "Intellicrack")
    product_key = SubElement(user_data, "ProductKey")
    _text_element(product_key, "Key", settings.product_key or "")
    _text_element(product_key, "WillShowUI", "OnError")


def _render_windows_pe_pass(root: Element, settings: UnattendSettings) -> None:
    """Append the ``windowsPE`` pass.

    Args:
        root: ``unattend`` root element.
        settings: Answer file settings.
    """
    windows_pe = SubElement(root, "settings", {"pass": "windowsPE"})

    international = _component(windows_pe, "Microsoft-Windows-International-Core-WinPE")
    setup_language = SubElement(international, "SetupUILanguage")
    _text_element(setup_language, "UILanguage", settings.locale)
    for tag in ("InputLocale", "SystemLocale", "UILanguage", "UserLocale"):
        _text_element(international, tag, settings.locale)

    _driver_paths(_component(windows_pe, "Microsoft-Windows-PnpCustomizationsWinPE"), settings)

    setup = _component(windows_pe, "Microsoft-Windows-Setup")
    _run_synchronous_commands(setup, lab_config_commands())
    _disk_configuration(setup)
    _render_image_install(setup, settings)


def _render_specialize_pass(root: Element, settings: UnattendSettings) -> None:
    """Append the ``specialize`` pass.

    Args:
        root: ``unattend`` root element.
        settings: Answer file settings.
    """
    specialize = SubElement(root, "settings", {"pass": "specialize"})
    shell_specialize = _component(specialize, "Microsoft-Windows-Shell-Setup")
    _text_element(shell_specialize, "ComputerName", settings.computer_name)
    _text_element(shell_specialize, "TimeZone", settings.timezone)
    deployment = _component(specialize, "Microsoft-Windows-Deployment")
    _run_synchronous_commands(deployment, (f'reg add "{_OOBE_KEY}" /v {_OOBE_BYPASS_NRO} /t REG_DWORD /d 1 /f',))


def _render_accounts(shell_oobe: Element, settings: UnattendSettings) -> None:
    """Append the local account and auto-logon blocks.

    Args:
        shell_oobe: ``Microsoft-Windows-Shell-Setup`` element in oobeSystem.
        settings: Answer file settings.
    """
    accounts = SubElement(shell_oobe, "UserAccounts")
    local_accounts = SubElement(accounts, "LocalAccounts")
    local_account = SubElement(local_accounts, "LocalAccount", {"wcm:action": "add"})
    account_secret = SubElement(local_account, "Password")
    _text_element(account_secret, "Value", settings.admin_password)
    _text_element(account_secret, "PlainText", "true")
    _text_element(local_account, "Description", "Intellicrack sandbox analyst")
    _text_element(local_account, "DisplayName", settings.admin_user)
    _text_element(local_account, "Group", "Administrators")
    _text_element(local_account, "Name", settings.admin_user)

    auto_logon = SubElement(shell_oobe, "AutoLogon")
    logon_secret = SubElement(auto_logon, "Password")
    _text_element(logon_secret, "Value", settings.admin_password)
    _text_element(logon_secret, "PlainText", "true")
    _text_element(auto_logon, "Enabled", "true")
    _text_element(auto_logon, "LogonCount", str(_AUTOLOGON_COUNT))
    _text_element(auto_logon, "Username", settings.admin_user)


def _render_oobe_pass(root: Element, settings: UnattendSettings) -> None:
    """Append the ``oobeSystem`` pass.

    Args:
        root: ``unattend`` root element.
        settings: Answer file settings.
    """
    oobe_system = SubElement(root, "settings", {"pass": "oobeSystem"})

    # The locale component in windowsPE only settles Setup's own UI. OOBE reads
    # this one, and without it Windows 11 24H2 stops on "Is this the right
    # country or region?" and "Is this the right keyboard layout?" no matter
    # what the Hide* flags below say, because those cover different pages. A
    # guest parked there needs a human with a mouse, which is exactly what an
    # unattended install exists to avoid.
    international = _component(oobe_system, "Microsoft-Windows-International-Core")
    for tag in ("InputLocale", "SystemLocale", "UILanguage", "UserLocale"):
        _text_element(international, tag, settings.locale)

    shell_oobe = _component(oobe_system, "Microsoft-Windows-Shell-Setup")
    _text_element(shell_oobe, "TimeZone", settings.timezone)

    oobe = SubElement(shell_oobe, "OOBE")
    for tag in (
        "HideEULAPage",
        "HideLocalAccountScreen",
        "HideOEMRegistrationScreen",
        "HideOnlineAccountScreens",
        "HideWirelessSetupInOOBE",
    ):
        _text_element(oobe, tag, "true")
    _text_element(oobe, "ProtectYourPC", "3")
    _text_element(oobe, "NetworkLocation", "Work")

    _render_accounts(shell_oobe, settings)

    first_logon = SubElement(shell_oobe, "FirstLogonCommands")
    for order, (command, description) in enumerate(first_logon_commands(settings), start=1):
        entry = SubElement(first_logon, "SynchronousCommand", {"wcm:action": "add"})
        _text_element(entry, "Order", str(order))
        _text_element(entry, "CommandLine", command)
        _text_element(entry, "Description", description)
        _text_element(entry, "RequiresUserInput", "false")


def render_autounattend(settings: UnattendSettings) -> str:
    """Generate the ``autounattend.xml`` that drives the unattended install.

    Args:
        settings: Inputs shaping the answer file.

    Returns:
        str: Complete XML document text, UTF-8 declared and indented.
    """
    root = Element(
        "unattend",
        {"xmlns": _UNATTEND_NAMESPACE, "xmlns:wcm": _WCM_NAMESPACE, "xmlns:xsi": _XSI_NAMESPACE},
    )
    _render_windows_pe_pass(root, settings)
    _render_specialize_pass(root, settings)
    _render_oobe_pass(root, settings)

    indent(root, space="    ")
    body = tostring(root, encoding="unicode")
    return f'<?xml version="1.0" encoding="utf-8"?>\r\n{body}\r\n'


def render_guest_agent_installer() -> str:
    """Generate the batch file that installs the QEMU guest agent in-guest.

    The script resolves its own location with ``%~dp0`` because the answer
    medium's drive letter is unknown until the guest assigns one. It copies
    the staged agent next to its runtime libraries, registers the service
    with ``qemu-ga.exe -s install``, and makes the service restart on failure
    so a guest whose virtio-serial port appears late still ends up with a
    live agent.

    Returns:
        str: Batch file source with CRLF line endings.
    """
    lines = (
        "@echo off",
        "setlocal",
        f'set "TARGET=%ProgramFiles%\\{_QEMU_GUEST_AGENT_INSTALL_DIR}"',
        'if not exist "%TARGET%" mkdir "%TARGET%"',
        f'copy /Y "%~dp0..\\{_QEMU_GUEST_AGENT_INSTALL_DIR}\\*" "%TARGET%\\" >nul',
        f'"%TARGET%\\{_QEMU_GUEST_AGENT_EXECUTABLE}" -s install -l "{_QEMU_GUEST_AGENT_LOG}"',
        f"sc.exe config {_QEMU_GUEST_AGENT_SERVICE} start= auto",
        f"sc.exe failure {_QEMU_GUEST_AGENT_SERVICE} reset= 0 actions= restart/5000/restart/5000/restart/5000",
        f"sc.exe start {_QEMU_GUEST_AGENT_SERVICE}",
        "endlocal",
        "exit /b 0",
    )
    return "\r\n".join(lines) + "\r\n"


def render_driver_installer() -> str:
    """Generate the PowerShell script that installs the virtio drivers in-guest.

    Two things this script does that a bare ``pnputil /add-driver *.inf
    /subdirs`` sweep cannot.

    First it establishes trust for each catalog's whole certificate chain, not
    just its signer. A stock Windows guest has no Red Hat certificate in its
    ``TrustedPublisher`` store, so ``pnputil`` either fails outright with "The
    publisher of an Authenticode(tm) signed catalog was not established as
    trusted" or raises the interactive "Would you like to install this device
    software?" dialog - once per package, blocking an unattended install behind
    a modal window that no one is there to click. Trusting the signer alone is
    not enough, because it says nothing about the root: most virtio-win
    catalogs are signed by the Microsoft Windows Hardware Compatibility
    Publisher and chain to a root the guest already trusts, but at least one
    (``smbus.cat`` on 0.1.285) is signed by a self-signed ``CN=Red Hat Inc.``
    development certificate, and that package fails ``0x800B0109``
    ``CERT_E_UNTRUSTEDROOT`` however trusted its publisher is. So each signer's
    chain is built and, only when it does not validate, its terminal element is
    added to ``Root`` and any intermediates to ``CA``. A catalog whose chain
    already validates causes no write to the machine root store at all.

    ``pnputil`` exit 259 is ``ERROR_NO_MORE_ITEMS``: the package is staged and
    no present device needed it. That is the expected result for the drivers
    WinPE already injected to make the installer's own disk visible, so it
    counts as success rather than failure.

    Second it installs only the packages that belong to this guest. The medium
    carries every driver for every Windows edition and all three architectures;
    handing an ARM64 or Server 2012 package to a Windows 11 amd64 guest fails
    with a catalog mismatch that reads alarmingly like corruption. The guest
    resolves its own virtio-win directory name from its product type and build
    number rather than being told at authoring time, so the same medium works
    for any guest the provisioner is later pointed at.

    Returns:
        str: PowerShell source with CRLF line endings.
    """
    markers = ", ".join(f"'{marker}'" for marker in VIRTIO_MARKER_DIRECTORIES)
    broken_statuses = ", ".join(f"'{status}'" for status in UNTRUSTED_CHAIN_STATUSES)
    lines = (
        "[CmdletBinding()]",
        "param(",
        "    [string]$Medium,",
        f"    [string]$LogPath = '{_DRIVER_INSTALL_LOG}'",
        ")",
        "$ErrorActionPreference = 'Stop'",
        "$logDirectory = Split-Path -Parent $LogPath",
        "if (-not (Test-Path $logDirectory)) { New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null }",
        "function Write-Step([string]$message) {",
        "    Add-Content -Path $LogPath -Value \"$([DateTimeOffset]::UtcNow.ToString('o')) $message\"",
        "}",
        "function Test-DriverExit([int]$code) {",
        "    if ($code -eq 0) { return $true }",
        f"    if ($code -eq {DRIVER_ALREADY_CURRENT_EXIT}) {{ return $true }}",
        "    return $false",
        "}",
        "function Get-TrustPlacement([System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate) {",
        "    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()",
        "    $chain.ChainPolicy.RevocationMode = 'NoCheck'",
        "    [void]$chain.Build($certificate)",
        "    $elements = @($chain.ChainElements | ForEach-Object { $_.Certificate })",
        f"    $broken = @($chain.ChainStatus | Where-Object {{ @({broken_statuses}) -contains $_.Status.ToString() }})",
        "    $decided = @()",
        "    if ($broken.Count -gt 0 -and $elements.Count -gt 0) {",
        "        $reason = $broken.Status -join ', '",
        "        $decided += [pscustomobject]@{ Certificate = $elements[$elements.Count - 1]; Store = 'Root'; Reason = $reason }",
        "        for ($index = 1; $index -lt $elements.Count - 1; $index++) {",
        "            $decided += [pscustomobject]@{ Certificate = $elements[$index]; Store = 'CA'; Reason = '' }",
        "        }",
        "    }",
        "    $decided += [pscustomobject]@{ Certificate = $certificate; Store = 'TrustedPublisher'; Reason = '' }",
        "    return $decided",
        "}",
        "",
        f"$markers = @({markers})",
        "function Test-Medium([string]$root) {",
        "    $present = @($markers | Where-Object { Test-Path (Join-Path $root $_) })",
        "    return $present.Count -eq $markers.Count",
        "}",
        "$mediumRoot = $null",
        "if ($Medium) {",
        "    if (-not (Test-Medium $Medium)) {",
        "        Write-Step \"$Medium carries none of $($markers -join ', '); refusing to guess\"",
        "        exit 1",
        "    }",
        "    $mediumRoot = $Medium",
        "} else {",
        "    foreach ($volume in [System.IO.DriveInfo]::GetDrives()) {",
        "        if (-not $volume.IsReady) { continue }",
        "        $root = $volume.RootDirectory.FullName",
        "        if (Test-Medium $root) { $mediumRoot = $root; break }",
        "    }",
        "}",
        "if ($null -eq $mediumRoot) {",
        "    Write-Step 'no virtio-win medium found; nothing to install'",
        "    exit 0",
        "}",
        'Write-Step "virtio-win medium at $mediumRoot"',
        "",
        "switch ($env:PROCESSOR_ARCHITECTURE) {",
        "    'AMD64' { $architecture = 'amd64' }",
        "    'ARM64' { $architecture = 'ARM64' }",
        "    default { $architecture = 'x86' }",
        "}",
        "$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem",
        "$build = [int]($osInfo.BuildNumber)",
        "if ($osInfo.ProductType -eq 1) {",
        "    $family = if ($build -ge 22000) { 'w11' } else { 'w10' }",
        "} elseif ($build -ge 26100) { $family = '2k25' }",
        "elseif ($build -ge 20348) { $family = '2k22' }",
        "elseif ($build -ge 17763) { $family = '2k19' }",
        "else { $family = '2k16' }",
        'Write-Step "guest is build $build product type $($osInfo.ProductType): $family\\$architecture"',
        "",
        "$packages = @()",
        "foreach ($driver in Get-ChildItem -Path $mediumRoot -Directory) {",
        "    $candidate = Join-Path $driver.FullName (Join-Path $family $architecture)",
        "    if (-not (Test-Path $candidate)) { continue }",
        "    if (-not (Get-ChildItem -Path $candidate -Filter *.inf -File)) { continue }",
        "    $packages += $candidate",
        "}",
        "if ($packages.Count -eq 0) {",
        '    Write-Step "medium carries no $family\\$architecture packages"',
        "    exit 0",
        "}",
        "Write-Step \"selected $($packages.Count) packages: $($packages -join '; ')\"",
        "",
        "$certificates = @{}",
        "foreach ($package in $packages) {",
        "    foreach ($catalog in Get-ChildItem -Path $package -Filter *.cat -File) {",
        "        $signature = Get-AuthenticodeSignature -FilePath $catalog.FullName",
        "        if ($null -eq $signature.SignerCertificate) { continue }",
        "        $certificate = $signature.SignerCertificate",
        "        if ($certificates.ContainsKey($certificate.Thumbprint)) { continue }",
        "        $certificates[$certificate.Thumbprint] = $certificate",
        '        Write-Step "publisher $($certificate.Subject) signs $($catalog.Name)"',
        "    }",
        "}",
        "if ($certificates.Count -eq 0) {",
        "    Write-Step 'no signed catalog yielded a publisher certificate; the install may raise a trust prompt'",
        "}",
        "",
        "$placements = @()",
        "foreach ($certificate in $certificates.Values) {",
        "    $placements += @(Get-TrustPlacement $certificate)",
        "}",
        "foreach ($placement in $placements) {",
        "    if ($placement.Reason) {",
        '        Write-Step "the chain for $($placement.Certificate.Subject) is $($placement.Reason)"',
        "    }",
        '    Write-Step "placing $($placement.Certificate.Subject) in $($placement.Store)"',
        "    try {",
        "        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($placement.Store, 'LocalMachine')",
        "        $store.Open('ReadWrite')",
        "        $store.Add($placement.Certificate)",
        "        $store.Close()",
        "    } catch {",
        '        Write-Step "could not add $($placement.Certificate.Subject) to $($placement.Store): $($_.Exception.Message)"',
        "    }",
        "}",
        "",
        "$failures = 0",
        "foreach ($package in $packages) {",
        '    $output = & pnputil.exe /add-driver "$package\\*.inf" /install 2>&1 | Out-String',
        "    $status = $LASTEXITCODE",
        '    Write-Step "pnputil $package exit $status`r`n$output"',
        "    if (-not (Test-DriverExit $status)) { $failures++ }",
        "}",
        'Write-Step "installed $($packages.Count - $failures) of $($packages.Count) packages"',
        "exit $(if ($failures -eq $packages.Count) { 1 } else { 0 })",
    )
    return "\r\n".join(lines) + "\r\n"


def _resolve_single_tool(name: str) -> tuple[str, Path | None] | None:
    """Resolve one ISO authoring tool by name.

    Args:
        name: Tool name from :data:`_ISO_AUTHORING_TOOLS`.

    Returns:
        tuple[str, Path | None] | None: Tool name and executable (None for
        the in-process ``pycdlib`` backend), or None when unavailable.
    """
    if name == _PYCDLIB_TOOL:
        return (name, None) if importlib.util.find_spec(_PYCDLIB_TOOL) is not None else None
    resolved = shutil.which(name)
    if resolved is not None:
        return (name, Path(resolved))
    if name == _OSCDIMG_TOOL:
        for root in _OSCDIMG_SEARCH_ROOTS:
            executable = root / "oscdimg.exe"
            if executable.is_file():
                return (name, executable)
    return None


def resolve_iso_authoring_tool(preferred: str | None = None) -> tuple[str, Path | None]:
    """Find an ISO authoring tool that actually exists on this host.

    Args:
        preferred: Tool name the operator asked for, or None to autodetect.

    Returns:
        tuple[str, Path | None]: Tool name and its executable, or None for
        the in-process ``pycdlib`` backend.

    Raises:
        ProvisioningError: If no supported tool is available, or if
            ``preferred`` is unknown or missing.
    """
    if preferred is not None:
        if preferred not in _ISO_AUTHORING_TOOLS:
            message = f"unknown ISO authoring tool {preferred!r}; supported: {list(_ISO_AUTHORING_TOOLS)}"
            raise ProvisioningError(message)
        resolved = _resolve_single_tool(preferred)
        if resolved is None:
            message = f"requested ISO authoring tool {preferred!r} is not installed"
            raise ProvisioningError(message)
        return resolved

    for name in _ISO_AUTHORING_TOOLS:
        resolved = _resolve_single_tool(name)
        if resolved is not None:
            return resolved

    message = (
        "no ISO authoring tool found; install one of the Windows ADK Deployment Tools (oscdimg), xorriso, "
        f"mkisofs, genisoimage, or the pycdlib Python package. Searched: {list(_ISO_AUTHORING_TOOLS)}"
    )
    raise ProvisioningError(message)


def iso_authoring_argv(tool: str, executable: Path, source: Path, output: Path, label: str) -> list[str]:
    """Build the argument vector for an external ISO authoring tool.

    Args:
        tool: Tool name returned by :func:`resolve_iso_authoring_tool`.
        executable: Resolved tool executable.
        source: Directory whose contents become the ISO root.
        output: Destination ISO path.
        label: Volume label to stamp on the image.

    Returns:
        list[str]: Argument vector, executable first.

    Raises:
        ProvisioningError: If the tool name has no external invocation.
    """
    if tool == _OSCDIMG_TOOL:
        return [str(executable), "-n", "-m", f"-l{label}", str(source), str(output)]
    if tool == "xorriso":
        return [str(executable), "-as", "mkisofs", "-J", "-r", "-V", label, "-o", str(output), str(source)]
    if tool in {"mkisofs", "genisoimage"}:
        return [str(executable), "-J", "-r", "-V", label, "-o", str(output), str(source)]
    message = f"tool {tool!r} is not an external ISO authoring command"
    raise ProvisioningError(message)


def _author_iso_with_pycdlib(source: Path, output: Path, label: str) -> None:
    """Author an ISO9660/Joliet image in-process with ``pycdlib``.

    Args:
        source: Directory whose contents become the ISO root.
        output: Destination ISO path.
        label: Volume label to stamp on the image.

    Raises:
        ProvisioningError: If ``pycdlib`` is not importable.
    """
    try:
        pycdlib = importlib.import_module(_PYCDLIB_TOOL)
    except ImportError as error:
        message = "pycdlib is not installed"
        raise ProvisioningError(message) from error

    iso = pycdlib.PyCdlib()
    iso.new(joliet=3, vol_ident=label)
    for entry in sorted(source.rglob("*")):
        relative = entry.relative_to(source)
        iso_path = "/" + "/".join(part.upper() for part in relative.parts)
        joliet_path = "/" + "/".join(relative.parts)
        if entry.is_dir():
            iso.add_directory(iso_path, joliet_path=joliet_path)
        else:
            iso.add_file(str(entry), f"{iso_path};1", joliet_path=joliet_path)
    iso.write(str(output))
    iso.close()


def author_iso(tool: str, executable: Path | None, source: Path, output: Path, label: str) -> None:
    """Build a data ISO from a staging directory.

    Args:
        tool: Tool name returned by :func:`resolve_iso_authoring_tool`.
        executable: Resolved tool executable, or None for ``pycdlib``.
        source: Directory whose contents become the ISO root.
        output: Destination ISO path.
        label: Volume label to stamp on the image.

    Raises:
        ProvisioningError: If the tool fails or produces no image.
    """
    if output.exists():
        output.unlink()
    if tool == _PYCDLIB_TOOL or executable is None:
        _author_iso_with_pycdlib(source, output, label)
    else:
        result = _run_process(iso_authoring_argv(tool, executable, source, output, label))
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            message = f"{tool} failed ({result.returncode}): {detail}"
            raise ProvisioningError(message)
    if not output.is_file():
        message = f"{tool} reported success but produced no image at {output}"
        raise ProvisioningError(message)
    _LOGGER.info("answer_iso_created", path=str(output), tool=tool, size_bytes=output.stat().st_size)


def select_guest_agent_package(media_root: Path) -> Path:
    """Pick the 64-bit guest agent installer off a mounted virtio-win medium.

    Args:
        media_root: Root directory of the mounted virtio-win volume.

    Returns:
        Path: The installer package to extract.

    Raises:
        ProvisioningError: If the medium carries no 64-bit agent package.
    """
    directory = media_root / _GUEST_AGENT_MEDIA_DIRECTORY
    packages = sorted(directory.glob(f"*{_GUEST_AGENT_PACKAGE_SUFFIX}")) if directory.is_dir() else []
    for package in packages:
        name = package.name.lower()
        if any(token in name for token in _GUEST_AGENT_PACKAGE_ARCHITECTURES):
            return package
    found = ", ".join(package.name for package in packages) or "<none>"
    message = (
        f"{media_root} carries no 64-bit guest agent package under {_GUEST_AGENT_MEDIA_DIRECTORY}: found {found}. "
        f"The GLib spawn helpers {', '.join(QEMU_GUEST_AGENT_SPAWN_HELPERS)} come from that package, and qemu-ga "
        "cannot run a single guest command without them."
    )
    raise ProvisioningError(message)


def extract_msi_payload(package: Path, destination: Path) -> None:
    """Unpack an installer package's files without installing it.

    Args:
        package: Installer package to unpack.
        destination: Directory the payload is written to.

    Raises:
        ProvisioningError: If the administrative install fails.
    """
    destination.mkdir(parents=True, exist_ok=True)
    argv = [_MSI_EXECUTABLE, "/a", str(package), "/qn", f"TARGETDIR={destination}"]
    result = _run_process(argv, timeout=_MOUNT_TIMEOUT_SECONDS)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        message = f"unpacking {package} failed ({result.returncode}): {detail}"
        raise ProvisioningError(message)
    _LOGGER.info("guest_agent_package_extracted", package=str(package), destination=str(destination))


def collect_named_files(root: Path, names: tuple[str, ...]) -> dict[str, Path]:
    """Find each named file anywhere below a directory tree.

    Args:
        root: Directory to search.
        names: File names to look for.

    Returns:
        dict[str, Path]: The names that were found, mapped to their location.
    """
    located: dict[str, Path] = {}
    for name in names:
        for candidate in root.rglob(name):
            if candidate.is_file():
                located[name] = candidate
                break
    return located


def stage_spawn_helpers(tools_path: Path, virtio_iso: Path, destination: Path) -> tuple[Path, ...]:
    """Place GLib's Windows spawn helpers beside the staged guest agent.

    ``guest-exec`` is the only way Intellicrack runs anything inside a Windows
    guest, and GLib refuses to spawn without these helpers, so a guest built
    without them can never be driven. The bundled QEMU tree is preferred when
    it happens to carry them; otherwise they are unpacked from the virtio-win
    medium's guest agent package.

    Args:
        tools_path: Directory holding the bundled QEMU build.
        virtio_iso: virtio-win medium to fall back to.
        destination: Directory the helpers are copied into.

    Returns:
        tuple[Path, ...]: The staged helper paths, in declaration order.

    Raises:
        ProvisioningError: If a helper cannot be obtained from either source.
    """
    outstanding = [name for name in QEMU_GUEST_AGENT_SPAWN_HELPERS if not (tools_path / name).is_file()]
    for name in QEMU_GUEST_AGENT_SPAWN_HELPERS:
        if name not in outstanding:
            shutil.copy2(tools_path / name, destination / name)

    if outstanding:
        with tempfile.TemporaryDirectory(prefix="intellicrack_guest_agent_") as raw_payload:
            payload = Path(raw_payload)
            media_root = mount_disk_image(virtio_iso)
            try:
                package = select_guest_agent_package(media_root)
                extract_msi_payload(package, payload)
            finally:
                dismount_disk_image(virtio_iso)
            located = collect_named_files(payload, tuple(outstanding))
            missing = [name for name in outstanding if name not in located]
            if missing:
                message = (
                    f"{package.name} on {virtio_iso} does not contain {', '.join(missing)}, and the bundled QEMU "
                    f"tree at {tools_path} does not either. Without them qemu-ga answers every guest-exec with "
                    "'Failed to execute helper program'."
                )
                raise ProvisioningError(message)
            for name, source in located.items():
                shutil.copy2(source, destination / name)

    staged = tuple(destination / name for name in QEMU_GUEST_AGENT_SPAWN_HELPERS)
    _LOGGER.info("guest_agent_spawn_helpers_staged", helpers=[str(path) for path in staged], extracted=outstanding)
    return staged


def stage_answer_tree(staging: Path, settings: UnattendSettings, qemu_agent: Path, tools_path: Path, virtio_iso: Path) -> str:
    """Populate the staging directory that becomes the answer medium.

    Args:
        staging: Directory to populate.
        settings: Answer file settings.
        qemu_agent: Bundled ``qemu-ga.exe`` to stage into the guest.
        tools_path: Directory holding the agent's runtime libraries.
        virtio_iso: virtio-win medium carrying the boot-critical drivers and
            the GLib spawn helpers.

    Returns:
        str: The generated ``autounattend.xml`` text.

    Raises:
        ProvisioningError: If a required guest agent library is missing, or
            the virtio medium carries no boot-critical driver package.
    """
    stage_winpe_drivers(virtio_iso, staging, _COMPONENT_ARCHITECTURE, settings.driver_directory)

    autounattend = render_autounattend(settings)
    (staging / "autounattend.xml").write_bytes(autounattend.encode("utf-8"))

    scripts_dir = staging / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    (scripts_dir / "install-guest-agent.cmd").write_bytes(render_guest_agent_installer().encode("ascii"))
    (scripts_dir / "install-virtio-drivers.ps1").write_bytes(render_driver_installer().encode("ascii"))

    agent_dir = staging / _QEMU_GUEST_AGENT_INSTALL_DIR
    agent_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(qemu_agent, agent_dir / qemu_agent.name)
    missing: list[str] = []
    for library in QEMU_GUEST_AGENT_LIBRARIES:
        source = tools_path / library
        if source.is_file():
            shutil.copy2(source, agent_dir / library)
        else:
            missing.append(library)
    if missing:
        message = f"bundled qemu-ga runtime libraries missing from {tools_path}: {', '.join(missing)}"
        raise ProvisioningError(message)
    stage_spawn_helpers(tools_path, virtio_iso, agent_dir)

    _LOGGER.info("answer_tree_staged", staging=str(staging), agent=str(qemu_agent))
    return autounattend


def find_free_port(low: int, high: int) -> int:
    """Find a free localhost TCP port in an inclusive range.

    Args:
        low: Lowest port to try.
        high: Highest port to try.

    Returns:
        int: A port nothing is currently listening on.

    Raises:
        ProvisioningError: If every port in the range is taken.
    """
    for port in range(low, high + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    message = f"no free TCP port between {low} and {high}"
    raise ProvisioningError(message)


def runtime_machine_argument(accelerator: str) -> str:
    """Build the ``-machine`` value the sandbox launcher uses.

    Mirrors ``QEMUSandbox._build_qemu_command``: q35 with the requested
    accelerator, plus ``kernel-irqchip=on`` under WHPX, whose in-hypervisor
    local APIC is the only mode that delivers interrupts to a Windows guest.
    With the userspace IRQ chip the installer starts its kernel and then spins
    at ring 0 forever without ever advancing the boot spinner.

    Args:
        accelerator: Accelerator name.

    Returns:
        str: Value for ``-machine``.
    """
    machine = f"q35,accel={accelerator}"
    if accelerator == "whpx":
        machine += ",kernel-irqchip=on"
    return machine


def runtime_cpu_argument(accelerator: str) -> str:
    """Build the ``-cpu`` value the sandbox launcher uses.

    Mirrors ``QEMUSandbox._build_qemu_command``: WHPX cannot virtualize the
    feature set of ``host`` or ``max``, so the model is ``qemu64`` plus the
    two features Windows 11 24H2 refuses to boot without - it triple-faults
    into WHPX exit code 4 before its boot manager prints anything if either
    is missing, and bare ``qemu64`` advertises neither. The anti-evasion masks
    ride along on every model.

    Args:
        accelerator: Accelerator name.

    Returns:
        str: Value for ``-cpu``.
    """
    if accelerator == "whpx":
        return "qemu64,+sse4.2,+popcnt,hv-vendor-id=AuthenticAMD,kvm=off,hypervisor=off"
    if accelerator == "kvm":
        return "host,hv-vendor-id=AuthenticAMD,kvm=off,hypervisor=off"
    return "max,hv-vendor-id=AuthenticAMD,hypervisor=off"


def build_install_command(spec: InstallCommandSpec) -> list[str]:
    """Render the QEMU command line that performs the unattended install.

    The machine type, CPU model, system disk interface, NIC model, and guest
    agent channel all follow the rules ``QEMUSandbox._build_qemu_command``
    applies, so the disk this install produces is one the sandbox can boot
    afterwards. No firmware argument is passed for the same reason the
    launcher passes none: the guest runs on SeaBIOS with an MBR disk.

    The three media are attached as AHCI CD-ROMs on the q35 ``ide`` bus
    rather than as virtio disks, because WinPE has no virtio driver until the
    very drivers on the third medium are loaded. ``-boot once=d`` boots the
    installer once and then falls back to the system disk, which is what
    stops a prompt-free installation medium from reinstalling on every
    reboot.

    The xHCI controller and tablet mirror the launcher for the same reason it
    carries them: q35 offers no USB bus and no absolute pointing device, so
    without them the guest sees only a relative PS/2 mouse and pointer input
    lands wherever its cursor has drifted rather than where it was aimed.

    Args:
        spec: Install parameters.

    Returns:
        list[str]: Full argument vector, executable first.
    """
    channel_port = spec.agent_port + _QGA_CHANNEL_PORT_OFFSET
    command: list[str] = [
        str(spec.qemu_executable),
        *["-machine", runtime_machine_argument(spec.accelerator)],
        *["-cpu", runtime_cpu_argument(spec.accelerator)],
        *["-smp", f"cores={spec.cpu_cores}"],
        *["-m", str(spec.memory_mb)],
        *["-drive", f"file={spec.disk_image},format=qcow2,if=virtio"],
        *["-drive", f"id=icinstall,file={spec.install_iso},media=cdrom,if=none,format=raw,readonly=on"],
        *["-device", "ide-cd,drive=icinstall,bus=ide.0"],
        *["-drive", f"id=icanswer,file={spec.answer_iso},media=cdrom,if=none,format=raw,readonly=on"],
        *["-device", "ide-cd,drive=icanswer,bus=ide.1"],
        *["-drive", f"id=icvirtio,file={spec.virtio_iso},media=cdrom,if=none,format=raw,readonly=on"],
        *["-device", "ide-cd,drive=icvirtio,bus=ide.2"],
        *[_BOOT_ARGUMENT, f"order=c,{_BOOT_ONCE_PREFIX}d,menu=off"],
        *["-netdev", "user,id=net0"],
        *["-device", "virtio-net-pci,netdev=net0"],
        *["-device", "virtio-serial-pci"],
        *[_CHARDEV_ARGUMENT, f"socket,id=agent,host=127.0.0.1,{_CHARDEV_PORT_PREFIX}{channel_port},server,nowait"],
        *["-device", "virtserialport,chardev=agent,name=org.qemu.guest_agent.0"],
        *["-device", f"qemu-xhci,id={_USB_CONTROLLER_ID}"],
        *["-device", f"usb-tablet,bus={_USB_CONTROLLER_ID}.0"],
    ]
    if spec.display == "vnc":
        command.extend(["-vnc", f":{spec.vnc_port - _VNC_PORT_BASE}"])
    elif spec.display == "sdl":
        command.extend(["-display", "sdl"])
    else:
        command.extend(["-display", "none"])
    return command


def build_resume_command(install_command: tuple[str, ...]) -> tuple[str, ...]:
    r"""Derive the argv that resumes an install after the guest power cycles.

    Windows Setup power cycles the guest at least once, and QEMU exits when it
    does, so the install has to be relaunched to reach its later phases. The
    install argv boots the installation medium once via the ``-boot``
    ``once=`` element; replaying it verbatim would boot that medium again, and
    a prompt-free installation medium restarts the whole installation rather
    than continuing it. Dropping the element alone leaves every other device,
    accelerator and channel argument exactly as the install used them, so the
    resumed guest is the same machine.

    Args:
        install_command: Argv produced by :func:`build_install_command`.

    Returns:
        tuple[str, ...]: The same argv, booting only the system disk.
    """
    resumed = list(install_command)
    for index, argument in enumerate(resumed[:-1]):
        if argument != _BOOT_ARGUMENT:
            continue
        elements = [element for element in resumed[index + 1].split(",") if not element.startswith(_BOOT_ONCE_PREFIX)]
        resumed[index + 1] = ",".join(elements)
    return tuple(resumed)


def agent_channel_port(install_command: tuple[str, ...]) -> int:
    """Read the guest agent channel port out of an install argv.

    Taken from the argv that is actually launched rather than recomputed, so
    the port the supervisor waits on cannot drift from the port QEMU binds.

    Args:
        install_command: Argv produced by :func:`build_install_command`.

    Returns:
        int: TCP port the guest agent character device listens on.

    Raises:
        ProvisioningError: If the argv carries no such channel.
    """
    for index, argument in enumerate(install_command[:-1]):
        if argument != _CHARDEV_ARGUMENT:
            continue
        for element in install_command[index + 1].split(","):
            if element.startswith(_CHARDEV_PORT_PREFIX):
                return int(element[len(_CHARDEV_PORT_PREFIX) :])
    message = "the install command carries no guest agent channel"
    raise ProvisioningError(message)


def _carries_sync_token(buffer: bytes, token: int) -> bool:
    """Report whether a guest agent reply stream echoes a synchronisation id.

    Args:
        buffer: Bytes read from the agent channel so far.
        token: Identifier sent with ``guest-sync-delimited``.

    Returns:
        bool: True once the agent echoed that exact identifier.
    """
    for line in buffer.split(b"\n"):
        text = line.strip(_QGA_SYNC_DELIMITER).strip()
        if not text:
            continue
        try:
            decoded: object = json.loads(text)
        except ValueError:
            continue
        if isinstance(decoded, dict) and cast("dict[str, object]", decoded).get("return") == token:
            return True
    return False


def guest_agent_responds(port: int, timeout: float = _AGENT_PROBE_TIMEOUT_SECONDS) -> bool:
    """Probe whether a guest agent is serving the channel on a port.

    A successful connection proves only that QEMU bound the socket, so this
    requires a completed ``guest-sync-delimited`` round trip carrying an
    identifier this call chose. That is the earliest point at which the
    installed Windows system is provably running its own agent.

    Args:
        port: TCP port the agent character device listens on.
        timeout: Seconds allowed for the connection and the reply.

    Returns:
        bool: True when the agent echoed the identifier.
    """
    token = secrets.randbelow(_AGENT_SYNC_TOKEN_LIMIT)
    payload = json.dumps({"execute": "guest-sync-delimited", "arguments": {"id": token}}).encode("utf-8")
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as channel:
            channel.settimeout(timeout)
            channel.sendall(_QGA_SYNC_DELIMITER + payload + b"\n")
            return _awaits_sync_token(channel, token, timeout)
    except OSError:
        return False


def _awaits_sync_token(channel: socket.socket, token: int, timeout: float) -> bool:
    """Read an agent channel until it echoes an identifier or the time runs out.

    Args:
        channel: Connected agent channel.
        token: Identifier sent with ``guest-sync-delimited``.
        timeout: Seconds allowed for the reply.

    Returns:
        bool: True when the agent echoed the identifier.
    """
    buffer = b""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        chunk = channel.recv(_AGENT_READ_SIZE)
        if not chunk:
            return False
        buffer += chunk
        if _carries_sync_token(buffer, token):
            return True
    return False


def _request_guest_shutdown(port: int) -> None:
    """Ask a running guest agent to power its guest off.

    The agent sends no reply to ``guest-shutdown``; QEMU exiting is the only
    signal, which the caller waits for.

    Args:
        port: TCP port the agent character device listens on.
    """
    payload = json.dumps({"execute": "guest-shutdown", "arguments": {"mode": "powerdown"}}).encode("utf-8")
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=_AGENT_PROBE_TIMEOUT_SECONDS) as channel:
            channel.sendall(_QGA_SYNC_DELIMITER + payload + b"\n")
    except OSError as error:
        _LOGGER.debug("guest_shutdown_unreachable", port=port, error=str(error))


def _stop_guest(process: subprocess.Popen[bytes], port: int, grace_seconds: float) -> None:
    """Bring a running guest down, preferring its own orderly shutdown.

    Killing QEMU while a Windows guest has writes in flight leaves the qcow2
    inconsistent, so the agent is asked first and the process is only
    terminated if it outlives the grace period.

    Args:
        process: The QEMU process.
        port: TCP port the agent character device listens on.
        grace_seconds: Seconds to wait for the guest to power itself off.
    """
    if process.poll() is not None:
        return
    _request_guest_shutdown(port)
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        _LOGGER.warning("guest_shutdown_timed_out", grace_seconds=grace_seconds)
        process.terminate()
        try:
            process.wait(timeout=_AGENT_PROBE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()


def run_unattended_install(
    install_command: tuple[str, ...],
    *,
    timeout_seconds: float = _DEFAULT_INSTALL_TIMEOUT_SECONDS,
    restart_limit: int = _DEFAULT_INSTALL_RESTART_LIMIT,
    poll_seconds: float = _INSTALL_POLL_SECONDS,
    shutdown_grace_seconds: float = _GUEST_SHUTDOWN_GRACE_SECONDS,
) -> InstallOutcome:
    """Run an unattended install through every guest power cycle it needs.

    The install argv on its own cannot finish an installation: Windows Setup
    power cycles the guest between its phases and QEMU exits when it does,
    leaving the disk mid-install. This relaunches the guest off its system
    disk each time that happens and waits for its agent to answer, which is
    the first evidence that Setup finished and the installed system booted.
    The guest is then powered off through its own agent so the qcow2 is left
    consistent.

    Args:
        install_command: Argv produced by :func:`build_install_command`.
        timeout_seconds: Total wall clock budget for the whole sequence.
        restart_limit: Power cycles tolerated before the run is called failed.
        poll_seconds: Interval between agent probes.
        shutdown_grace_seconds: Seconds the guest is given to power itself off
            before QEMU is terminated.

    Returns:
        InstallOutcome: Verdict, power cycle count and elapsed time.
    """
    channel_port = agent_channel_port(install_command)
    resume_command = build_resume_command(install_command)
    working_directory = str(Path(install_command[0]).parent)
    started = time.monotonic()
    restarts = 0

    _LOGGER.info("install_started", channel_port=channel_port, timeout_seconds=timeout_seconds)
    process = subprocess.Popen(list(install_command), cwd=working_directory)
    try:
        while time.monotonic() - started < timeout_seconds:
            if process.poll() is not None:
                restarts += 1
                _LOGGER.info("install_power_cycle", exit_code=process.returncode, restarts=restarts)
                if restarts > restart_limit:
                    detail = f"the guest power cycled {restarts} times without its agent ever answering"
                    _LOGGER.warning("install_restart_limit", restarts=restarts)
                    return InstallOutcome(
                        completed=False,
                        restarts=restarts,
                        elapsed_seconds=time.monotonic() - started,
                        detail=detail,
                    )
                process = subprocess.Popen(list(resume_command), cwd=working_directory)
                continue
            if guest_agent_responds(channel_port):
                elapsed = time.monotonic() - started
                _LOGGER.info("install_completed", restarts=restarts, elapsed_seconds=round(elapsed))
                return InstallOutcome(
                    completed=True,
                    restarts=restarts,
                    elapsed_seconds=elapsed,
                    detail="the installed guest answered on its agent channel",
                )
            time.sleep(poll_seconds)
    finally:
        _stop_guest(process, channel_port, shutdown_grace_seconds)

    elapsed = time.monotonic() - started
    detail = f"the agent never answered within {round(timeout_seconds)}s across {restarts} power cycles"
    _LOGGER.warning("install_timed_out", restarts=restarts, elapsed_seconds=round(elapsed))
    return InstallOutcome(completed=False, restarts=restarts, elapsed_seconds=elapsed, detail=detail)


def select_install_media(explicit: Path | None, images_dir: Path, max_depth: int, budget: int) -> IsoStructure:
    """Resolve which medium the install runs from.

    Args:
        explicit: Operator-supplied ISO, or None to discover one.
        images_dir: Intellicrack images directory, searched first.
        max_depth: Maximum directory depth below each scan root.
        budget: Maximum number of directories to enumerate.

    Returns:
        IsoStructure: Probe of the chosen medium.

    Raises:
        ProvisioningError: If the explicit medium is absent or fails
            validation, or if discovery finds nothing.
    """
    if explicit is not None:
        if not explicit.is_file():
            message = f"install media not found at {explicit}"
            raise ProvisioningError(message)
        probe = probe_iso_structure(explicit)
        if not probe.is_windows_install_candidate:
            message = (
                f"{explicit} is not usable Windows install media: microsoft={probe.is_microsoft_media}, "
                f"udf={probe.is_udf_bridged}, bios_bootable={probe.is_bios_bootable}, size={probe.size_bytes}"
            )
            raise ProvisioningError(message)
        return probe

    candidates = discover_install_media(
        roots=available_drive_roots(),
        priority_roots=(images_dir,) if images_dir.is_dir() else (),
        max_depth=max_depth,
        budget=budget,
    )
    if not candidates:
        message = "no Windows installation media found on this host; pass --iso to name one explicitly"
        raise ProvisioningError(message)
    for candidate in candidates:
        _LOGGER.info(
            "install_media_candidate",
            path=str(candidate.path),
            volume_id=candidate.volume_id,
            size_bytes=candidate.size_bytes,
        )
    return candidates[0]


def stage_install_media(probe: IsoStructure, images_dir: Path) -> IsoStructure:
    """Copy the chosen medium into the Intellicrack images directory.

    A medium already inside ``images_dir`` is left where it is; nothing is
    copied over itself, and an identically sized file already present is
    reused rather than rewritten.

    Args:
        probe: Probe of the chosen medium.
        images_dir: Destination directory.

    Returns:
        IsoStructure: Probe of the staged medium.

    Raises:
        ProvisioningError: If the copy fails.
    """
    images_dir.mkdir(parents=True, exist_ok=True)
    destination = images_dir / probe.path.name
    if probe.path.resolve() == destination.resolve():
        _LOGGER.info("install_media_already_staged", path=str(destination))
        return probe
    if destination.is_file() and destination.stat().st_size == probe.size_bytes:
        _LOGGER.info("install_media_stage_skipped", path=str(destination), reason="identical size already present")
        return probe_iso_structure(destination)
    try:
        shutil.copy2(probe.path, destination)
    except OSError as error:
        message = f"failed to stage {probe.path} into {images_dir}: {error}"
        raise ProvisioningError(message) from error
    _LOGGER.info("install_media_staged", source=str(probe.path), destination=str(destination))
    return probe_iso_structure(destination)


def build_unattend_settings(args: argparse.Namespace, driver_directory: str = WINPE_DRIVER_STAGE_DIRECTORY) -> UnattendSettings:
    """Translate parsed arguments into answer file settings.

    Args:
        args: Parsed command line arguments.
        driver_directory: Folder on the answer medium the boot-critical
            drivers are staged into, searched under every candidate letter.

    Returns:
        UnattendSettings: Settings for :func:`render_autounattend`.
    """
    return UnattendSettings(
        image_name=args.image_name,
        product_key=args.product_key,
        admin_user=args.admin_user,
        admin_password=args.admin_password,
        computer_name=args.computer_name,
        locale=args.locale,
        timezone=args.timezone,
        driver_letters=WINPE_DRIVER_LETTERS,
        driver_directory=driver_directory,
        disable_guest_firewall=not args.keep_guest_firewall,
        answer_script=_ANSWER_SCRIPT_RELATIVE,
    )


def build_answer_medium(
    settings: UnattendSettings,
    qemu_agent: Path,
    tools_path: Path,
    virtio_iso: Path,
    answer_iso: Path,
    preferred_tool: str | None,
) -> tuple[str, str]:
    """Stage and author the answer medium the install boots alongside.

    Args:
        settings: Answer file settings.
        qemu_agent: Bundled ``qemu-ga.exe`` to stage into the guest.
        tools_path: Directory holding the agent's runtime libraries.
        virtio_iso: virtio-win medium carrying the GLib spawn helpers.
        answer_iso: Destination ISO path.
        preferred_tool: ISO authoring tool to force, or None to autodetect.

    Returns:
        tuple[str, str]: The generated answer file text and the name of the
        authoring tool that built the medium.
    """
    tool_name, tool_executable = resolve_iso_authoring_tool(preferred_tool)
    with tempfile.TemporaryDirectory(prefix="intellicrack_answer_") as raw_staging:
        staging = Path(raw_staging)
        autounattend = stage_answer_tree(staging, settings, qemu_agent, tools_path, virtio_iso)
        author_iso(tool_name, tool_executable, staging, answer_iso, _ANSWER_ISO_LABEL)
    return (autounattend, tool_name)


def resolve_install_media(args: argparse.Namespace, images_dir: Path) -> tuple[IsoStructure, MediaContent | None]:
    """Select, stage, and optionally content-verify the installation medium.

    Args:
        args: Parsed command line arguments.
        images_dir: Intellicrack images directory.

    Returns:
        tuple[IsoStructure, MediaContent | None]: Probe of the staged medium
        and its mounted-tree inspection, or None when verification was
        skipped.
    """
    explicit = Path(args.iso) if args.iso else None
    probe = stage_install_media(
        select_install_media(explicit, images_dir, args.scan_depth, args.scan_budget),
        images_dir,
    )
    content = None if args.skip_content_verify else verify_media_contents(probe.path)
    return (probe, content)


def provision(args: argparse.Namespace) -> ProvisionPlan:
    """Run the whole provisioning sequence and return the resulting plan.

    Propagates the ``ProvisioningError`` raised by any step that cannot
    complete: absent or unusable install media, a missing virtio-win medium,
    incomplete bundled QEMU tooling, a failed ``qemu-img create``, or the
    absence of any ISO authoring tool.

    Args:
        args: Parsed command line arguments.

    Returns:
        ProvisionPlan: Everything produced, including the install argv.
    """
    tools_path = Path(args.tools_path) if args.tools_path else get_project_root() / "tools" / "qemu"
    images_dir = Path(args.images_dir) if args.images_dir else tools_path / "images"

    qemu_system, qemu_img, qemu_agent = resolve_qemu_tools(tools_path)
    accelerator = detect_accelerator(qemu_system, args.accel)

    probe, content = resolve_install_media(args, images_dir)

    virtio = resolve_virtio_medium(
        Path(args.virtio_iso) if args.virtio_iso else None,
        available_drive_roots(),
        args.scan_depth,
        args.scan_budget,
        _COMPONENT_ARCHITECTURE,
        priority_roots=(images_dir,) if images_dir.is_dir() else (),
    )

    disk_image = images_dir / args.disk_name
    create_guest_disk(qemu_img, disk_image, args.disk_size_gb, force=args.force)

    answer_iso = images_dir / args.answer_iso_name
    autounattend, tool_name = build_answer_medium(
        build_unattend_settings(args),
        qemu_agent,
        tools_path,
        virtio.path,
        answer_iso,
        args.iso_tool,
    )

    spec = InstallCommandSpec(
        qemu_executable=qemu_system,
        accelerator=accelerator,
        cpu_cores=args.cpu_cores,
        memory_mb=args.memory_mb,
        disk_image=disk_image,
        install_iso=probe.path,
        answer_iso=answer_iso,
        virtio_iso=virtio.path,
        display=args.display,
        vnc_port=find_free_port(_VNC_PORT_BASE, _VNC_PORT_MAX),
        agent_port=_DEFAULT_AGENT_PORT,
    )

    plan = ProvisionPlan(
        install_media=probe,
        media_content=content,
        virtio_iso=virtio.path,
        disk_image=disk_image,
        answer_iso=answer_iso,
        authoring_tool=tool_name,
        autounattend_xml=autounattend,
        install_command=tuple(build_install_command(spec)),
    )
    _LOGGER.info("provisioning_complete", disk_image=str(disk_image), answer_iso=str(answer_iso), accelerator=accelerator)
    return plan


def format_command(command: tuple[str, ...]) -> str:
    """Render an argument vector as a copy-pasteable shell line.

    Args:
        command: Argument vector.

    Returns:
        str: Single line with whitespace-bearing arguments quoted.
    """
    return " ".join(f'"{part}"' if " " in part else part for part in command)


def print_plan(plan: ProvisionPlan) -> None:
    """Print the provisioning outcome and the install command for an operator.

    Args:
        plan: Plan produced by :func:`provision`.
    """
    print("Windows guest provisioning complete.")
    print()
    print(f"  install media   : {plan.install_media.path}")
    print(f"  volume id       : {plan.install_media.volume_id or '<none>'}")
    print(f"  el torito id    : {plan.install_media.el_torito_identifier or '<none>'}")
    print(f"  udf descriptors : {', '.join(plan.install_media.udf_identifiers) or '<none>'}")
    if plan.media_content is not None:
        print(f"  deployable image: {plan.media_content.install_image}")
    print(f"  virtio-win iso  : {plan.virtio_iso}")
    print(f"  guest disk      : {plan.disk_image}")
    print(f"  answer iso      : {plan.answer_iso} (built with {plan.authoring_tool})")
    print()
    print("First boot of the unattended install:")
    print()
    print(format_command(plan.install_command))
    print()
    print(
        "Windows Setup power cycles the guest between its phases and QEMU exits when it does, so that "
        "command alone leaves the disk mid-install. Re-run this script with --install to supervise the "
        "whole sequence, or relaunch QEMU without the boot 'once=' element after every exit until the "
        f"guest agent answers on port {agent_channel_port(plan.install_command)}.",
    )
    print()


def _build_parser() -> argparse.ArgumentParser:
    """Build the command line parser.

    Returns:
        argparse.ArgumentParser: Configured parser.
    """
    parser = argparse.ArgumentParser(
        prog="provision_windows_guest",
        description="Build a Windows QEMU guest image for Intellicrack's sandbox and emit its unattended install command.",
    )
    parser.add_argument("--iso", help="Explicit Windows installation ISO; skips discovery.")
    parser.add_argument("--virtio-iso", help="Explicit virtio-win driver ISO; skips discovery.")
    parser.add_argument("--tools-path", help="Bundled QEMU directory (default: <project root>/tools/qemu).")
    parser.add_argument("--images-dir", help="Guest image directory (default: <tools path>/images).")
    parser.add_argument("--disk-name", default=_DEFAULT_DISK_NAME, help="qcow2 file name for the guest system disk.")
    parser.add_argument("--answer-iso-name", default=_DEFAULT_ANSWER_ISO_NAME, help="File name for the generated answer medium.")
    parser.add_argument("--disk-size-gb", type=int, default=_DEFAULT_DISK_SIZE_GB, help="Virtual size of the guest system disk.")
    parser.add_argument("--memory-mb", type=int, default=_DEFAULT_MEMORY_MB, help="Guest memory during the install.")
    parser.add_argument("--cpu-cores", type=int, default=_DEFAULT_CPU_CORES, help="Guest cores during the install.")
    parser.add_argument("--image-name", default=_DEFAULT_IMAGE_NAME, help="Windows edition name to deploy from the install image.")
    parser.add_argument("--product-key", help="Product key to inject; omitted by default so Setup skips the key page.")
    parser.add_argument("--admin-user", default=DEFAULT_ADMIN_USER, help="Local administrator account created in the guest.")
    parser.add_argument("--admin-password", default=DEFAULT_ADMIN_CREDENTIAL, help="Password for that account.")
    parser.add_argument("--computer-name", default=_DEFAULT_COMPUTER_NAME, help="Guest computer name.")
    parser.add_argument("--locale", default=_DEFAULT_LOCALE, help="Locale applied throughout the guest.")
    parser.add_argument("--timezone", default=_DEFAULT_TIMEZONE, help="Windows time zone identifier for the guest.")
    parser.add_argument("--accel", choices=["whpx", "kvm", "tcg"], help="Force an accelerator instead of autodetecting.")
    parser.add_argument("--display", choices=["vnc", "sdl", "none"], default="vnc", help="Display mode for the install run.")
    parser.add_argument("--iso-tool", choices=list(_ISO_AUTHORING_TOOLS), help="Force an ISO authoring tool.")
    parser.add_argument("--scan-depth", type=int, default=_DEFAULT_SCAN_DEPTH, help="Maximum directory depth when scanning for media.")
    parser.add_argument("--scan-budget", type=int, default=_DEFAULT_SCAN_BUDGET, help="Maximum directories enumerated when scanning.")
    parser.add_argument("--force", action="store_true", help="Replace an existing guest system disk.")
    parser.add_argument(
        "--skip-content-verify",
        action="store_true",
        help=(
            "Do not mount the Windows install medium to inspect its tree. The virtio-win medium is mounted "
            "regardless, because the boot-critical driver files WinPE loads are copied off it onto the answer "
            "medium this provisioner authors."
        ),
    )
    parser.add_argument("--keep-guest-firewall", action="store_true", help="Leave the guest firewall enabled.")
    parser.add_argument(
        "--install",
        action="store_true",
        help=(
            "Run the unattended install to completion, relaunching the guest across the power cycles "
            "Windows Setup performs, and wait for its agent to answer."
        ),
    )
    parser.add_argument(
        "--install-timeout",
        type=float,
        default=_DEFAULT_INSTALL_TIMEOUT_SECONDS,
        help="Wall clock budget in seconds for a supervised install.",
    )
    parser.add_argument(
        "--install-restart-limit",
        type=int,
        default=_DEFAULT_INSTALL_RESTART_LIMIT,
        help="Guest power cycles tolerated during a supervised install before it is called failed.",
    )
    parser.add_argument("--json", action="store_true", help="Emit the plan as JSON instead of human-readable text.")
    parser.add_argument("--print-autounattend", action="store_true", help="Also print the generated answer file.")
    return parser


def main(raw_args: list[str] | None = None) -> int:
    """Entry point for the provisioning driver.

    Args:
        raw_args: Argument list to parse, or None to read ``sys.argv``.

    Returns:
        int: Process exit code; 0 on success, 3 on a provisioning failure, 4
        when a supervised install did not reach a running guest agent, 130 on
        interruption.
    """
    args = _build_parser().parse_args(raw_args)
    try:
        plan = provision(args)
    except ProvisioningError as error:
        print(f"provisioning error: {error}", file=sys.stderr)
        _LOGGER.warning("provisioning_failed", error=str(error))
        return 3
    except KeyboardInterrupt:
        _LOGGER.warning("provisioning_interrupted")
        return 130

    if args.json:
        print(json.dumps(plan.to_dict(), indent=2))
    else:
        print_plan(plan)
    if args.print_autounattend:
        print(plan.autounattend_xml)
    if not args.install:
        return 0

    try:
        outcome = run_unattended_install(
            plan.install_command,
            timeout_seconds=args.install_timeout,
            restart_limit=args.install_restart_limit,
        )
    except KeyboardInterrupt:
        _LOGGER.warning("install_interrupted")
        return 130
    print(
        f"install {'completed' if outcome.completed else 'failed'} after {round(outcome.elapsed_seconds)}s "
        f"and {outcome.restarts} guest power cycle(s): {outcome.detail}",
    )
    return 0 if outcome.completed else _INSTALL_FAILURE_EXIT_CODE


if __name__ == "__main__":
    sys.exit(main())
