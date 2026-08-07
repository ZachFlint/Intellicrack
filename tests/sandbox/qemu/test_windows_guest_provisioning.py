# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the Windows QEMU guest provisioner.

Everything here is exercised without booting a virtual machine.

* **Install media identification** runs the real
  :func:`probe_iso_structure` parser over ISO9660 volume descriptor sets and
  El Torito boot catalogs written byte-for-byte to disk. The layouts are the
  ones measured on this host's real media: a Microsoft image declares
  ``Microsoft Corporation`` in its boot catalog validation entry, carries an
  ``NSR02`` UDF descriptor, and publishes both an x86 BIOS and a ``0xEF``
  UEFI boot entry, while the Linux images beside it leave the validation
  identifier empty and publish no UDF descriptor at all.
* **Answer file generation** parses the produced ``autounattend.xml`` with a
  real XML parser and asserts on the LabConfig bypasses, the MBR partition
  layout, the virtio driver paths, and the guest agent bootstrap.
* **Launch contract** drives the real
  :meth:`intellicrack.sandbox.qemu.QEMUSandbox._build_qemu_command` and
  asserts that the firmware, system disk interface, NIC model and guest
  agent channel it emits are the same ones the install command line uses. An
  install performed against a controller the sandbox does not provide would
  produce an unbootable guest, so this is the provisioner's load-bearing
  correctness property.
"""

from __future__ import annotations

import asyncio
import struct
from typing import TYPE_CHECKING, Final

import defusedxml.ElementTree as DefusedET
import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import AcceleratorType, GuestOS, QEMUConfig, QEMUSandbox
from scripts.sandbox.provision_windows_guest import (
    DEFAULT_ADMIN_CREDENTIAL,
    DEFAULT_ADMIN_USER,
    InstallCommandSpec,
    ProvisioningError,
    UnattendSettings,
    build_install_command,
    classify_media_root,
    discover_install_media,
    first_logon_commands,
    lab_config_commands,
    looks_like_virtio_media,
    parse_boot_catalog,
    probe_iso_structure,
    render_autounattend,
    render_guest_agent_installer,
    runtime_cpu_argument,
    runtime_machine_argument,
    select_install_media,
)


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path
    from xml.etree.ElementTree import Element


_SECTOR: Final[int] = 2048
_UNATTEND_NS: Final[str] = "urn:schemas-microsoft-com:unattend"
_WCM_NS: Final[str] = "http://schemas.microsoft.com/WMIConfig/2002/State"
_MICROSOFT_ID: Final[str] = "Microsoft Corporation"

# Measured on this host: both the retail Windows 11 image and the prompt-free
# rebuild place the boot catalog at LBA 22 with the BIOS boot image at 534 and
# the UEFI boot image at 536.
_REAL_CATALOG_LBA: Final[int] = 22
_REAL_BIOS_BOOT_LBA: Final[int] = 534
_REAL_UEFI_BOOT_LBA: Final[int] = 536
_WINDOWS_MEDIA_BYTES: Final[int] = 3 * 1024 * 1024 * 1024
_UNDERSIZED_MEDIA_BYTES: Final[int] = 64 * 1024 * 1024

_LAB_CONFIG_REQUIRED: Final[frozenset[str]] = frozenset({
    "BypassTPMCheck",
    "BypassSecureBootCheck",
    "BypassRAMCheck",
})


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Execute ``coro`` on a dedicated event loop for test isolation.

    Args:
        coro: Awaitable to run to completion.

    Returns:
        T: The coroutine's return value.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _volume_descriptor(descriptor_type: int, volume_id: str = "", system_id: str = "") -> bytes:
    """Build one 2048-byte ISO9660 volume descriptor.

    Args:
        descriptor_type: Descriptor type byte; 1 is primary, 255 terminator.
        volume_id: Volume identifier written at offset 40.
        system_id: System identifier written at offset 8.

    Returns:
        bytes: One full sector.
    """
    sector = bytearray(_SECTOR)
    sector[0] = descriptor_type
    sector[1:6] = b"CD001"
    sector[6] = 1
    sector[8:40] = system_id.encode("ascii").ljust(32)
    sector[40:72] = volume_id.encode("ascii").ljust(32)
    return bytes(sector)


def _boot_record(catalog_lba: int) -> bytes:
    """Build the El Torito boot record volume descriptor.

    Args:
        catalog_lba: Logical block address of the boot catalog.

    Returns:
        bytes: One full sector.
    """
    sector = bytearray(_SECTOR)
    sector[0] = 0
    sector[1:6] = b"CD001"
    sector[6] = 1
    sector[7:39] = b"EL TORITO SPECIFICATION".ljust(32, b"\x00")
    struct.pack_into("<I", sector, 71, catalog_lba)
    return bytes(sector)


def _recognition_descriptor(identifier: bytes) -> bytes:
    """Build one UDF volume recognition sequence descriptor.

    Args:
        identifier: Five-byte standard identifier such as ``b"NSR02"``.

    Returns:
        bytes: One full sector.
    """
    sector = bytearray(_SECTOR)
    sector[0] = 0
    sector[1:6] = identifier
    sector[6] = 1
    return bytes(sector)


def _catalog_validation_entry(identifier: str) -> bytes:
    """Build an El Torito validation entry with a correct checksum.

    Args:
        identifier: Manufacturer string placed at offset 4.

    Returns:
        bytes: One 32-byte catalog record.
    """
    record = bytearray(32)
    record[0] = 0x01
    record[1] = 0x00
    record[4:28] = identifier.encode("ascii").ljust(24, b"\x00")
    record[30] = 0x55
    record[31] = 0xAA
    checksum = -sum(struct.unpack_from("<16H", record, 0)) & 0xFFFF
    struct.pack_into("<H", record, 28, checksum)
    return bytes(record)


def _catalog_boot_entry(load_lba: int, *, bootable: bool = True) -> bytes:
    """Build an El Torito default or section boot entry.

    Args:
        load_lba: Logical block address of the boot image.
        bootable: Whether to mark the entry bootable.

    Returns:
        bytes: One 32-byte catalog record.
    """
    record = bytearray(32)
    record[0] = 0x88 if bootable else 0x00
    struct.pack_into("<I", record, 8, load_lba)
    return bytes(record)


def _catalog_section_header(platform_id: int) -> bytes:
    """Build a final El Torito section header for one platform.

    Args:
        platform_id: Platform identifier; ``0xEF`` is UEFI.

    Returns:
        bytes: One 32-byte catalog record.
    """
    record = bytearray(32)
    record[0] = 0x91
    record[1] = platform_id
    struct.pack_into("<H", record, 2, 1)
    return bytes(record)


def _write_iso(
    path: Path,
    *,
    volume_id: str,
    el_torito_id: str | None,
    udf_identifiers: tuple[bytes, ...],
    bios_boot_lba: int | None,
    uefi_boot_lba: int | None,
    total_bytes: int,
) -> Path:
    """Write a real ISO9660 volume descriptor set and El Torito catalog.

    The result is a genuine ISO header layout: the parser under test reads it
    with no knowledge that the data area beyond the descriptors is zeroed.

    Args:
        path: Destination file.
        volume_id: Primary volume identifier.
        el_torito_id: Boot catalog validation identifier, or None to omit the
            boot record entirely.
        udf_identifiers: Volume recognition identifiers to emit after the
            descriptor terminator.
        bios_boot_lba: Load address for the x86 BIOS boot entry, or None.
        uefi_boot_lba: Load address for the UEFI boot entry, or None.
        total_bytes: Final file size. The data area past the descriptors is
            left as a hole so a multi-gibibyte fixture costs no real storage.

    Returns:
        Path: The written file.
    """
    sectors: dict[int, bytes] = {16: _volume_descriptor(1, volume_id=volume_id)}
    if el_torito_id is not None:
        sectors[17] = _boot_record(_REAL_CATALOG_LBA)
    sectors[18] = _volume_descriptor(255)
    for offset, identifier in enumerate(udf_identifiers):
        sectors[19 + offset] = _recognition_descriptor(identifier)

    if el_torito_id is not None:
        catalog = bytearray(_SECTOR)
        catalog[0:32] = _catalog_validation_entry(el_torito_id)
        cursor = 32
        if bios_boot_lba is not None:
            catalog[cursor : cursor + 32] = _catalog_boot_entry(bios_boot_lba)
            cursor += 32
        if uefi_boot_lba is not None:
            catalog[cursor : cursor + 32] = _catalog_section_header(0xEF)
            cursor += 32
            catalog[cursor : cursor + 32] = _catalog_boot_entry(uefi_boot_lba)
        sectors[_REAL_CATALOG_LBA] = bytes(catalog)

    with path.open("wb") as handle:
        for lba, data in sorted(sectors.items()):
            handle.seek(lba * _SECTOR)
            handle.write(data)
        handle.truncate(total_bytes)
    return path


def _windows_iso(path: Path, *, size_bytes: int = _WINDOWS_MEDIA_BYTES) -> Path:
    """Write an ISO whose headers match this host's real Windows media.

    Args:
        path: Destination file.
        size_bytes: Final file size.

    Returns:
        Path: The written file.
    """
    return _write_iso(
        path,
        volume_id="CD_ROM",
        el_torito_id=_MICROSOFT_ID,
        udf_identifiers=(b"BEA01", b"NSR02", b"TEA01"),
        bios_boot_lba=_REAL_BIOS_BOOT_LBA,
        uefi_boot_lba=_REAL_UEFI_BOOT_LBA,
        total_bytes=size_bytes,
    )


def _linux_iso(path: Path) -> Path:
    """Write an ISO whose headers match this host's real Linux media.

    Args:
        path: Destination file.

    Returns:
        Path: The written file.
    """
    return _write_iso(
        path,
        volume_id="Debian 13.2.0 amd64 1",
        el_torito_id="",
        udf_identifiers=(),
        bios_boot_lba=7270,
        uefi_boot_lba=5470,
        total_bytes=_WINDOWS_MEDIA_BYTES,
    )


class _LaunchSandbox(QEMUSandbox):
    """``QEMUSandbox`` subclass exposing the real launch command builder.

    The setters mutate single-underscore attributes from inside the class
    hierarchy so ``basedpyright``'s ``reportPrivateUsage`` rule stays
    satisfied without any inline suppression.
    """

    def set_accelerator(self, accelerator: AcceleratorType) -> None:
        """Record the accelerator the command builder should assume.

        Args:
            accelerator: Accelerator type to install.
        """
        self._accelerator = accelerator
        self._accelerator_cached = True

    def set_qemu_path(self, qemu_path: Path) -> None:
        """Record the resolved QEMU executable path.

        Args:
            qemu_path: Path used as ``argv[0]``.
        """
        self._qemu_path = qemu_path

    def launch_argv(self) -> list[str]:
        """Build the real launch command line.

        Returns:
            list[str]: The argv :meth:`_build_qemu_command` would run QEMU
            with.
        """
        return _run(self._build_qemu_command())


def _qcow2_stub(directory: Path) -> Path:
    """Write a real qcow2 v3 header so the command builder accepts the image.

    Args:
        directory: Directory to write into.

    Returns:
        Path: Path to the created image file.
    """
    image = directory / "guest.qcow2"
    image.write_bytes(b"QFI\xfb" + (3).to_bytes(4, "big") + bytes(64))
    return image


def _launch_argv(tmp_path: Path, accelerator: AcceleratorType) -> list[str]:
    """Build the sandbox's real launch argv for one accelerator.

    Args:
        tmp_path: Per-test temporary directory.
        accelerator: Accelerator the sandbox should assume.

    Returns:
        list[str]: Full launch argv.
    """
    config = QEMUConfig(guest_os=GuestOS.WINDOWS, image_path=_qcow2_stub(tmp_path), display="none")
    sandbox = _LaunchSandbox(config=SandboxConfig(), qemu_config=config)
    sandbox.set_accelerator(accelerator)
    sandbox.set_qemu_path(tmp_path / "qemu-system-x86_64.exe")
    return sandbox.launch_argv()


def _value_after(argv: list[str], flag: str) -> str:
    """Return the single value following ``flag`` in an argv.

    Args:
        argv: Argument vector.
        flag: Flag whose value is wanted.

    Returns:
        str: The value.
    """
    assert flag in argv, f"{flag} missing from argv {argv!r}"
    return argv[argv.index(flag) + 1]


def _values_for(argv: list[str], flag: str) -> list[str]:
    """Return every value following each occurrence of ``flag``.

    Args:
        argv: Argument vector.
        flag: Flag to collect values for.

    Returns:
        list[str]: Values in argv order.
    """
    return [argv[index + 1] for index, item in enumerate(argv) if item == flag and index + 1 < len(argv)]


def _system_disk_interface(argv: list[str]) -> str:
    """Return the ``if=`` value of the qcow2 system disk in an argv.

    Args:
        argv: Argument vector.

    Returns:
        str: Disk interface name such as ``virtio``.

    Raises:
        AssertionError: If the argv carries no qcow2 system disk.
    """
    for value in _values_for(argv, "-drive"):
        fields = dict(pair.split("=", 1) for pair in value.split(",") if "=" in pair)
        if fields.get("format") == "qcow2":
            interface = fields.get("if")
            assert interface is not None, f"qcow2 drive {value!r} declares no interface"
            return interface
    message = f"no qcow2 system disk in argv {argv!r}"
    raise AssertionError(message)


def _device_starting_with(argv: list[str], prefix: str) -> str:
    """Return the first ``-device`` value beginning with ``prefix``.

    Args:
        argv: Argument vector.
        prefix: Device model prefix to match.

    Returns:
        str: The matching device value, or an empty string when absent.
    """
    return next((value for value in _values_for(argv, "-device") if value.startswith(prefix)), "")


def _launch_facts(argv: list[str]) -> dict[str, str | bool]:
    """Reduce an argv to the properties an installed guest must agree on.

    Args:
        argv: Argument vector.

    Returns:
        dict[str, str | bool]: Machine, CPU, disk interface, NIC model, guest
        agent channel name, and whether any firmware argument is present.
    """
    return {
        "machine": _value_after(argv, "-machine"),
        "cpu": _value_after(argv, "-cpu"),
        "system_disk_interface": _system_disk_interface(argv),
        "nic": _device_starting_with(argv, "virtio-net-pci"),
        "serial_bus": _device_starting_with(argv, "virtio-serial-pci"),
        "agent_channel": _device_starting_with(argv, "virtserialport"),
        "has_firmware": "-bios" in argv or any("if=pflash" in value for value in _values_for(argv, "-drive")),
    }


def _install_argv(tmp_path: Path, accelerator: str) -> list[str]:
    """Build the provisioner's install argv for one accelerator.

    Args:
        tmp_path: Per-test temporary directory.
        accelerator: Accelerator name.

    Returns:
        list[str]: Full install argv.
    """
    spec = InstallCommandSpec(
        qemu_executable=tmp_path / "qemu-system-x86_64.exe",
        accelerator=accelerator,
        cpu_cores=4,
        memory_mb=8192,
        disk_image=tmp_path / "guest.qcow2",
        install_iso=tmp_path / "windows.iso",
        answer_iso=tmp_path / "answer.iso",
        virtio_iso=tmp_path / "virtio-win.iso",
        display="none",
        vnc_port=5900,
        agent_port=4445,
    )
    return build_install_command(spec)


def _settings() -> UnattendSettings:
    """Build the answer file settings the provisioner uses by default.

    Returns:
        UnattendSettings: Settings for :func:`render_autounattend`.
    """
    return UnattendSettings(
        image_name="Windows 11 Pro",
        product_key=None,
        admin_user=DEFAULT_ADMIN_USER,
        admin_password=DEFAULT_ADMIN_CREDENTIAL,
        computer_name="IC-SANDBOX",
        locale="en-US",
        timezone="UTC",
        driver_letters=("C", "D", "E", "F", "G", "H"),
        driver_subpaths=("viostor\\w11\\amd64", "vioserial\\w11\\amd64", "NetKVM\\w11\\amd64"),
        disable_guest_firewall=True,
        answer_script="scripts\\install-guest-agent.cmd",
    )


def _answer_tree() -> Element:
    """Render and parse the answer file with an independent parser.

    ``defusedxml`` is a different implementation from the one that wrote the
    document, so a round trip through it is a genuine well-formedness oracle.

    Returns:
        Element: Parsed ``unattend`` root element.
    """
    parsed: Element = DefusedET.fromstring(render_autounattend(_settings()))
    return parsed


def _component(root: Element, pass_name: str, component_name: str) -> Element:
    """Find one component element inside one configuration pass.

    Args:
        root: Parsed ``unattend`` root element.
        pass_name: Configuration pass such as ``windowsPE``.
        component_name: Component name to find.

    Returns:
        Element: The matching component.

    Raises:
        AssertionError: If the pass has no such component.
    """
    for settings in root.findall(f"{{{_UNATTEND_NS}}}settings"):
        if settings.get("pass") != pass_name:
            continue
        for component in settings.findall(f"{{{_UNATTEND_NS}}}component"):
            if component.get("name") == component_name:
                return component
    message = f"no {component_name} component in {pass_name} pass"
    raise AssertionError(message)


def _texts(parent: Element, path: str) -> list[str]:
    """Collect the text of every element matching a namespaced path.

    Args:
        parent: Element to search below.
        path: Slash-separated tag path without namespaces.

    Returns:
        list[str]: Text of each match, empty strings for empty elements.
    """
    namespaced = "/".join(f"{{{_UNATTEND_NS}}}{part}" for part in path.split("/"))
    return [(element.text or "") for element in parent.findall(namespaced)]


class TestInstallMediaIdentification:
    """The ISO probe must separate Windows media from everything else."""

    def test_windows_media_is_identified_as_a_candidate(self, tmp_path: Path) -> None:
        """A Microsoft-authored, UDF-bridged, BIOS-bootable ISO qualifies.

        Args:
            tmp_path: Per-test temporary directory.
        """
        probe = probe_iso_structure(_windows_iso(tmp_path / "windows.iso"))

        assert probe.el_torito_identifier == _MICROSOFT_ID
        assert probe.is_microsoft_media
        assert probe.is_udf_bridged
        assert probe.is_bios_bootable
        assert probe.boot_catalog_lba == _REAL_CATALOG_LBA
        assert probe.bios_boot_lba == _REAL_BIOS_BOOT_LBA
        assert probe.uefi_boot_lba == _REAL_UEFI_BOOT_LBA
        assert probe.volume_id == "CD_ROM"
        assert probe.is_windows_install_candidate

    def test_linux_media_is_rejected(self, tmp_path: Path) -> None:
        """A bootable Linux ISO must not be mistaken for Windows media.

        Args:
            tmp_path: Per-test temporary directory.
        """
        probe = probe_iso_structure(_linux_iso(tmp_path / "debian.iso"))

        assert probe.is_bios_bootable, "the fixture is genuinely BIOS bootable"
        assert not probe.is_microsoft_media
        assert not probe.is_udf_bridged
        assert not probe.is_windows_install_candidate

    def test_media_without_udf_is_rejected(self, tmp_path: Path) -> None:
        """Microsoft branding alone is not enough without a UDF filesystem.

        ``install.wim`` exceeds the ISO9660 four gibibyte file size limit, so
        media with no UDF filesystem cannot be carrying one.

        Args:
            tmp_path: Per-test temporary directory.
        """
        image = _write_iso(
            tmp_path / "no-udf.iso",
            volume_id="CD_ROM",
            el_torito_id=_MICROSOFT_ID,
            udf_identifiers=(),
            bios_boot_lba=_REAL_BIOS_BOOT_LBA,
            uefi_boot_lba=_REAL_UEFI_BOOT_LBA,
            total_bytes=_WINDOWS_MEDIA_BYTES,
        )
        probe = probe_iso_structure(image)

        assert probe.is_microsoft_media
        assert not probe.is_udf_bridged
        assert not probe.is_windows_install_candidate

    def test_uefi_only_media_is_rejected(self, tmp_path: Path) -> None:
        """Media with no x86 BIOS boot entry cannot start a SeaBIOS install.

        Args:
            tmp_path: Per-test temporary directory.
        """
        image = _write_iso(
            tmp_path / "uefi-only.iso",
            volume_id="CD_ROM",
            el_torito_id=_MICROSOFT_ID,
            udf_identifiers=(b"BEA01", b"NSR02", b"TEA01"),
            bios_boot_lba=None,
            uefi_boot_lba=_REAL_UEFI_BOOT_LBA,
            total_bytes=_WINDOWS_MEDIA_BYTES,
        )
        probe = probe_iso_structure(image)

        assert probe.uefi_boot_lba == _REAL_UEFI_BOOT_LBA
        assert probe.bios_boot_lba is None
        assert not probe.is_bios_bootable
        assert not probe.is_windows_install_candidate

    def test_undersized_media_is_rejected(self, tmp_path: Path) -> None:
        """An image too small to hold a Windows image is not install media.

        Args:
            tmp_path: Per-test temporary directory.
        """
        probe = probe_iso_structure(_windows_iso(tmp_path / "tiny.iso", size_bytes=_UNDERSIZED_MEDIA_BYTES))

        assert probe.is_microsoft_media
        assert not probe.is_windows_install_candidate

    def test_boot_catalog_with_a_wrong_key_is_not_decoded(self) -> None:
        """A catalog whose ``0x55 0xAA`` key is wrong yields no entries."""
        catalog = bytearray(_catalog_validation_entry(_MICROSOFT_ID) + _catalog_boot_entry(_REAL_BIOS_BOOT_LBA))
        catalog[31] = 0x00

        identifier, entries = parse_boot_catalog(bytes(catalog))

        assert not identifier
        assert entries == ()

    def test_discovery_selects_only_windows_media(self, tmp_path: Path) -> None:
        """Discovery over a directory of real ISOs returns just the Windows one.

        Args:
            tmp_path: Per-test temporary directory.
        """
        _linux_iso(tmp_path / "debian.iso")
        _linux_iso(tmp_path / "fedora.iso")
        windows = _windows_iso(tmp_path / "windows.iso")

        found = discover_install_media(roots=(), priority_roots=(tmp_path,))

        assert [probe.path for probe in found] == [windows]

    def test_explicit_media_that_fails_validation_is_refused(self, tmp_path: Path) -> None:
        """Naming a non-Windows ISO explicitly still fails loudly.

        Args:
            tmp_path: Per-test temporary directory.
        """
        linux = _linux_iso(tmp_path / "debian.iso")

        with pytest.raises(ProvisioningError, match="not usable Windows install media"):
            select_install_media(linux, tmp_path, 1, 10)


class TestMediaContentClassification:
    """The mounted-tree classifier must demand a complete BIOS-bootable tree."""

    def _tree(self, root: Path, *, install_name: str = "install.wim", with_boot_dir: bool = True) -> Path:
        """Build a Windows-media-shaped directory tree on disk.

        Args:
            root: Directory to populate.
            install_name: Deployable image file name.
            with_boot_dir: Whether to create the legacy ``boot`` directory.

        Returns:
            Path: The populated root.
        """
        sources = root / "sources"
        sources.mkdir(parents=True, exist_ok=True)
        (sources / install_name).write_bytes(b"MSWIM\x00\x00\x00")
        (sources / "boot.wim").write_bytes(b"MSWIM\x00\x00\x00")
        (root / "setup.exe").write_bytes(b"MZ")
        if with_boot_dir:
            (root / "boot").mkdir(exist_ok=True)
        return root

    def test_complete_tree_is_windows_install_media(self, tmp_path: Path) -> None:
        """A tree with the image, WinPE, boot directory and setup qualifies.

        Args:
            tmp_path: Per-test temporary directory.
        """
        content = classify_media_root(self._tree(tmp_path))

        assert content.install_image == tmp_path / "sources" / "install.wim"
        assert content.is_windows_install_media

    def test_esd_media_is_accepted(self, tmp_path: Path) -> None:
        """Media that ships ``install.esd`` instead of ``install.wim`` counts.

        Args:
            tmp_path: Per-test temporary directory.
        """
        content = classify_media_root(self._tree(tmp_path, install_name="install.esd"))

        assert content.install_image == tmp_path / "sources" / "install.esd"
        assert content.is_windows_install_media

    def test_tree_without_legacy_boot_directory_is_rejected(self, tmp_path: Path) -> None:
        """UEFI-only media cannot boot the SeaBIOS install.

        Args:
            tmp_path: Per-test temporary directory.
        """
        content = classify_media_root(self._tree(tmp_path, with_boot_dir=False))

        assert content.install_image is not None
        assert not content.has_bios_boot_directory
        assert not content.is_windows_install_media

    def test_empty_tree_is_rejected(self, tmp_path: Path) -> None:
        """A directory with nothing in it is not install media.

        Args:
            tmp_path: Per-test temporary directory.
        """
        content = classify_media_root(tmp_path)

        assert content.install_image is None
        assert not content.is_windows_install_media

    def test_virtio_tree_needs_every_marker_driver(self, tmp_path: Path) -> None:
        """A driver medium missing the serial driver is not usable.

        ``viostor`` alone gets Setup onto the disk but leaves the
        ``org.qemu.guest_agent.0`` channel with no driver, so the sandbox
        could never reach the guest.

        Args:
            tmp_path: Per-test temporary directory.
        """
        partial = tmp_path / "partial"
        (partial / "viostor").mkdir(parents=True)
        (partial / "NetKVM").mkdir()
        assert not looks_like_virtio_media(partial)

        (partial / "vioserial").mkdir()
        assert looks_like_virtio_media(partial)


class TestAnswerFileGeneration:
    """The answer file must drive a fully unattended BIOS/MBR install."""

    def test_document_is_well_formed_and_namespaced(self) -> None:
        """The generated XML parses and declares the unattend namespaces."""
        root = _answer_tree()

        assert root.tag == f"{{{_UNATTEND_NS}}}unattend"
        passes = [settings.get("pass") for settings in root.findall(f"{{{_UNATTEND_NS}}}settings")]
        assert passes == ["windowsPE", "specialize", "oobeSystem"]

        disk = _component(root, "windowsPE", "Microsoft-Windows-Setup").find(
            f"{{{_UNATTEND_NS}}}DiskConfiguration/{{{_UNATTEND_NS}}}Disk",
        )
        assert disk is not None
        assert disk.get(f"{{{_WCM_NS}}}action") == "add", "wcm:action must resolve to the WMIConfig namespace"

    def test_hardware_gate_bypasses_are_present(self) -> None:
        """Every LabConfig bypass this TPM-less SeaBIOS guest needs is emitted."""
        setup = _component(_answer_tree(), "windowsPE", "Microsoft-Windows-Setup")
        commands = _texts(setup, "RunSynchronous/RunSynchronousCommand/Path")

        for required in sorted(_LAB_CONFIG_REQUIRED):
            matching = [command for command in commands if required in command]
            assert matching, f"{required} missing from windowsPE RunSynchronous commands {commands!r}"
            assert "HKLM\\SYSTEM\\Setup\\LabConfig" in matching[0]
            assert "REG_DWORD" in matching[0]
            assert matching[0].rstrip().endswith("/d 1 /f")

    def test_oobe_network_requirement_is_bypassed(self) -> None:
        """``BypassNRO`` is written in specialize so OOBE needs no network."""
        deployment = _component(_answer_tree(), "specialize", "Microsoft-Windows-Deployment")
        commands = _texts(deployment, "RunSynchronous/RunSynchronousCommand/Path")

        assert any("BypassNRO" in command and "CurrentVersion\\OOBE" in command for command in commands), commands

    def test_partition_layout_is_bios_mbr(self) -> None:
        """Two primary partitions with an active system volume, no ESP.

        The sandbox launcher passes no firmware argument, so the guest boots
        SeaBIOS and a GPT layout with an EFI system partition would be
        unbootable.
        """
        setup = _component(_answer_tree(), "windowsPE", "Microsoft-Windows-Setup")
        disk = setup.find(f"{{{_UNATTEND_NS}}}DiskConfiguration/{{{_UNATTEND_NS}}}Disk")
        assert disk is not None

        assert _texts(disk, "WillWipeDisk") == ["true"]
        assert _texts(disk, "CreatePartitions/CreatePartition/Type") == ["Primary", "Primary"]
        assert _texts(disk, "CreatePartitions/CreatePartition/Extend") == ["true"]
        assert _texts(disk, "ModifyPartitions/ModifyPartition/Active") == ["true"]
        assert _texts(disk, "ModifyPartitions/ModifyPartition/Format") == ["NTFS", "NTFS"]
        assert _texts(disk, "ModifyPartitions/ModifyPartition/Letter") == ["C"]

        rendered = render_autounattend(_settings())
        assert "EFI" not in rendered
        assert "GPT" not in rendered

    def test_windows_is_installed_to_the_second_partition(self) -> None:
        """The deployable image lands on the extended data partition."""
        setup = _component(_answer_tree(), "windowsPE", "Microsoft-Windows-Setup")
        install_to = setup.find(f"{{{_UNATTEND_NS}}}ImageInstall/{{{_UNATTEND_NS}}}OSImage/{{{_UNATTEND_NS}}}InstallTo")
        assert install_to is not None

        assert _texts(install_to, "DiskID") == ["0"]
        assert _texts(install_to, "PartitionID") == ["2"]

    def test_virtio_driver_paths_cover_every_winpe_letter(self) -> None:
        """WinPE searches every plausible CD-ROM letter for the boot driver."""
        settings = _settings()
        pnp = _component(_answer_tree(), "windowsPE", "Microsoft-Windows-PnpCustomizationsWinPE")
        paths = _texts(pnp, "DriverPaths/PathAndCredentials/Path")

        assert len(paths) == len(settings.driver_letters) * len(settings.driver_subpaths)
        for letter in settings.driver_letters:
            assert f"{letter}:\\viostor\\w11\\amd64" in paths, f"no viostor path for drive {letter}"

    def test_auto_logon_reaches_a_desktop_unattended(self) -> None:
        """A local administrator is created and logged on without a prompt."""
        shell = _component(_answer_tree(), "oobeSystem", "Microsoft-Windows-Shell-Setup")
        auto_logon = shell.find(f"{{{_UNATTEND_NS}}}AutoLogon")
        accounts = shell.find(f"{{{_UNATTEND_NS}}}UserAccounts")
        assert auto_logon is not None
        assert accounts is not None

        assert _texts(auto_logon, "Enabled") == ["true"]
        assert _texts(auto_logon, "Username") == ["analyst"]
        assert _texts(accounts, "LocalAccounts/LocalAccount/Group") == ["Administrators"]
        assert _texts(accounts, "LocalAccounts/LocalAccount/Name") == ["analyst"]
        assert _texts(shell, "OOBE/HideOnlineAccountScreens") == ["true"]

    def test_oobe_pass_settles_the_locale_so_oobe_asks_nothing(self) -> None:
        """OOBE must get its own locale component, not just Setup's (S17-D40).

        ``Microsoft-Windows-International-Core-WinPE`` in the ``windowsPE`` pass
        only settles Setup's own UI. OOBE reads the non-WinPE component in the
        ``oobeSystem`` pass, and without it Windows 11 24H2 stops on the region
        and keyboard-layout pages regardless of the ``Hide*`` flags, which cover
        different pages entirely. Measured: a guest installed from an answer
        file without this sat at "Is this the right keyboard layout?" waiting
        for a mouse, which is precisely what an unattended install must avoid.
        """
        settings = _settings()
        international = _component(_answer_tree(), "oobeSystem", "Microsoft-Windows-International-Core")

        for tag in ("InputLocale", "SystemLocale", "UILanguage", "UserLocale"):
            assert _texts(international, tag) == [settings.locale], (
                f"the oobeSystem locale component must set {tag} to the configured locale "
                f"{settings.locale!r}, otherwise OOBE prompts for it (S17-D40)"
            )

    def test_the_winpe_locale_component_is_not_reused_for_oobe(self) -> None:
        """The WinPE-scoped component must not stand in for the OOBE one.

        This is the discriminator for the test above: the two components differ
        only by a ``-WinPE`` suffix, and putting the WinPE one in ``oobeSystem``
        would look right while leaving OOBE prompting. It also pins the WinPE
        component to the pass it belongs in, so neither can be moved silently.
        """
        root = _answer_tree()
        oobe_pass = next(settings for settings in root.findall(f"{{{_UNATTEND_NS}}}settings") if settings.get("pass") == "oobeSystem")
        names = [component.get("name") for component in oobe_pass.findall(f"{{{_UNATTEND_NS}}}component")]

        assert "Microsoft-Windows-International-Core-WinPE" not in names, (
            f"the WinPE locale component does not drive OOBE and must not appear in oobeSystem; got {names}"
        )
        assert _component(root, "windowsPE", "Microsoft-Windows-International-Core-WinPE") is not None

    def test_first_logon_installs_drivers_and_the_guest_agent(self) -> None:
        """First logon adds the virtio drivers and starts the guest agent."""
        settings = _settings()
        shell = _component(_answer_tree(), "oobeSystem", "Microsoft-Windows-Shell-Setup")
        commands = _texts(shell, "FirstLogonCommands/SynchronousCommand/CommandLine")

        assert any("pnputil.exe /add-driver" in command for command in commands), commands
        assert any(settings.answer_script in command for command in commands), commands
        orders = _texts(shell, "FirstLogonCommands/SynchronousCommand/Order")
        assert orders == [str(index) for index in range(1, len(commands) + 1)]

    def test_guest_firewall_command_is_opt_out(self) -> None:
        """The firewall is only touched when the operator leaves it enabled."""
        settings = _settings()
        disabled = [command for command, _ in first_logon_commands(settings)]
        kept = [
            command
            for command, _ in first_logon_commands(
                UnattendSettings(
                    image_name=settings.image_name,
                    product_key=settings.product_key,
                    admin_user=settings.admin_user,
                    admin_password=settings.admin_password,
                    computer_name=settings.computer_name,
                    locale=settings.locale,
                    timezone=settings.timezone,
                    driver_letters=settings.driver_letters,
                    driver_subpaths=settings.driver_subpaths,
                    disable_guest_firewall=False,
                    answer_script=settings.answer_script,
                ),
            )
        ]

        assert any("advfirewall" in command for command in disabled)
        assert not any("advfirewall" in command for command in kept)

    def test_lab_config_commands_are_registry_writes(self) -> None:
        """Each bypass is a real ``reg add`` of a DWORD one."""
        commands = lab_config_commands()

        assert commands
        for command in commands:
            assert command.startswith('reg add "HKLM\\SYSTEM\\Setup\\LabConfig"')
            assert "/t REG_DWORD /d 1 /f" in command


class TestGuestAgentBootstrap:
    """The staged installer must leave a live ``qemu-ga`` service behind."""

    def test_installer_registers_and_starts_the_service(self) -> None:
        """The batch file installs, auto-starts and launches the agent."""
        script = render_guest_agent_installer()

        assert 'qemu-ga.exe" -s install' in script
        assert "sc.exe config qemu-ga start= auto" in script
        assert "sc.exe start qemu-ga" in script
        assert "%~dp0" in script, "the answer volume letter is unknown at generation time"
        assert script.endswith("\r\n")
        assert "\n" not in script.replace("\r\n", ""), "batch files need CRLF line endings"


class TestLaunchContract:
    """The install argv must agree with the argv the sandbox later boots with."""

    @pytest.mark.parametrize(
        ("accelerator", "name"),
        [(AcceleratorType.WHPX, "whpx"), (AcceleratorType.TCG, "tcg")],
    )
    def test_install_matches_the_sandbox_launch_command(
        self,
        tmp_path: Path,
        accelerator: AcceleratorType,
        name: str,
    ) -> None:
        """Firmware, disk, NIC and agent channel agree with the real builder.

        Args:
            tmp_path: Per-test temporary directory.
            accelerator: Accelerator the sandbox assumes.
            name: The same accelerator as the provisioner names it.
        """
        launch = _launch_facts(_launch_argv(tmp_path, accelerator))
        install = _launch_facts(_install_argv(tmp_path, name))

        assert install == launch

    def test_neither_command_supplies_firmware(self, tmp_path: Path) -> None:
        """Both run SeaBIOS, so an MBR install is the only bootable choice.

        Args:
            tmp_path: Per-test temporary directory.
        """
        launch = _launch_argv(tmp_path, AcceleratorType.WHPX)
        install = _install_argv(tmp_path, "whpx")

        for argv in (launch, install):
            assert "-bios" not in argv
            assert "-pflash" not in argv
            assert not any("pflash" in value for value in _values_for(argv, "-drive"))

    def test_system_disk_is_virtio_in_both_commands(self, tmp_path: Path) -> None:
        """The install writes to the same controller the sandbox boots from.

        Args:
            tmp_path: Per-test temporary directory.
        """
        assert _system_disk_interface(_launch_argv(tmp_path, AcceleratorType.WHPX)) == "virtio"
        assert _system_disk_interface(_install_argv(tmp_path, "whpx")) == "virtio"

    def test_mirrored_machine_and_cpu_helpers_track_the_sandbox(self, tmp_path: Path) -> None:
        """The provisioner's machine and CPU helpers reproduce the real values.

        Args:
            tmp_path: Per-test temporary directory.
        """
        launch = _launch_argv(tmp_path, AcceleratorType.WHPX)

        assert runtime_machine_argument("whpx") == _value_after(launch, "-machine")
        assert runtime_cpu_argument("whpx") == _value_after(launch, "-cpu")

    def test_installer_media_is_attached_as_ide_cdroms(self, tmp_path: Path) -> None:
        """WinPE cannot read virtio, so all three media ride the AHCI bus.

        Args:
            tmp_path: Per-test temporary directory.
        """
        argv = _install_argv(tmp_path, "whpx")
        cdroms = [value for value in _values_for(argv, "-drive") if "media=cdrom" in value]
        buses = [value for value in _values_for(argv, "-device") if value.startswith("ide-cd")]

        assert len(cdroms) == 3, cdroms
        assert sorted(bus.rsplit("=", 1)[1] for bus in buses) == ["ide.0", "ide.1", "ide.2"]
        assert all("readonly=on" in value for value in cdroms)

    def test_install_boots_the_installer_only_once(self, tmp_path: Path) -> None:
        """``once=d`` stops prompt-free media reinstalling on every reboot.

        Args:
            tmp_path: Per-test temporary directory.
        """
        boot = _value_after(_install_argv(tmp_path, "whpx"), "-boot")

        assert "once=d" in boot
        assert "order=c" in boot

    def test_agent_channel_port_offset_matches_the_sandbox(self, tmp_path: Path) -> None:
        """Both commands offset the guest agent channel one past the agent port.

        Args:
            tmp_path: Per-test temporary directory.
        """
        install = _install_argv(tmp_path, "whpx")
        chardev = _value_after(install, "-chardev")

        assert "port=4446" in chardev, chardev
        assert "org.qemu.guest_agent.0" in _device_starting_with(install, "virtserialport")
