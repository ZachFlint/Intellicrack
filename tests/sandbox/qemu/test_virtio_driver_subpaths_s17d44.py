# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gates for S17-D44: WinPE was sent to driver paths the medium does not have.

The answer file's ``Microsoft-Windows-PnpCustomizationsWinPE`` component is the
only thing that gets ``viostor`` into WinPE, and WinPE searches exactly the
directories it names, before any in-guest script exists to correct it. The
provisioner used to name one hardwired family and architecture per driver -
``viostor\w11\amd64`` and three siblings - while a virtio-win medium lays its
packages out as ``<driver>\<family>\<arch>`` with a genuinely different set of
architectures per family: on 0.1.285 ``viostor`` carries fifteen families,
``w11`` has no ``x86`` at all, and most server families are ``amd64`` only. For
any guest that is not Windows 11 amd64 every emitted path therefore resolved to
nothing, WinPE loaded no storage driver, and Setup found no disk to install to.

These gates hold the enumeration to two properties at once: it must name every
package directory the medium really carries for the guest's architecture, and
it must name nothing else. The container class builds a real directory tree
whose family and architecture combinations are the ones measured on the real
0.1.285 medium - including families the old constant never mentioned and a
family that has no ``amd64`` at all - and drives the real enumeration over it.
The host-native class does the same against the real ISO in
``tools/qemu/images``, which only a real Windows host can mount.

What the answer file does with that enumeration is a separate matter, and the
first real installation to exercise it falsified the original answer: naming
every enumerated package made Setup abort. Measured on Windows 11 26100, three
real installs of the same media differing only in this block:

* 360 paths (60 packages across six candidate letters) - aborted.
* 60 paths, every one an existing directory on the letter WinPE really
  assigned - aborted, identically:
  ``CDlpActionDriverInstallation::ExecuteUnattendDriverInstall ... 0xD000A000``
  logged beside ``SetupManager: Drivers Path: []``, before any disk was
  touched.
* 4 paths - installed, and wrote 7.7 GB to the system disk.

Every path in all three carried an INF and unreachable letters were tolerated,
so what Setup will not accept is the number of entries. The provisioner
therefore stages one package per driver into a folder on its own answer medium
and names that folder once per candidate letter, and the answer file gates
below hold it to that bound rather than to the breadth that broke it.
"""

from __future__ import annotations

import shutil
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Final

import defusedxml.ElementTree as DefusedET

from intellicrack.core.config import get_project_root
from scripts.sandbox.provision_windows_guest import (
    WINPE_DRIVER_DIRECTORIES,
    WINPE_DRIVER_FAMILY_PREFERENCE,
    WINPE_DRIVER_LETTERS,
    WINPE_DRIVER_STAGE_DIRECTORY,
    dismount_disk_image,
    enumerate_virtio_driver_subpaths,
    mount_disk_image,
    render_autounattend,
    require_virtio_media,
    resolve_virtio_medium,
    select_winpe_driver_packages,
    stage_winpe_drivers,
)
from tests.sandbox.qemu.virtio_installer_harness import answer_settings


if TYPE_CHECKING:
    from xml.etree.ElementTree import Element


_GUEST_ARCHITECTURE: Final[str] = "amd64"
"""Architecture directory a Windows amd64 sandbox guest needs packages from."""

_FOREIGN_ARCHITECTURES: Final[tuple[str, ...]] = ("ARM64", "x86")
"""Architectures the medium also carries and this guest must never be sent to."""

_UNATTEND_NS: Final[str] = "urn:schemas-microsoft-com:unattend"
"""Namespace every element of a Windows answer file lives in."""

_MEASURED_LAYOUT: Final[dict[str, dict[str, tuple[str, ...]]]] = {
    "viostor": {
        "2k12": ("amd64",),
        "2k12R2": ("amd64",),
        "2k16": ("amd64",),
        "2k19": ("amd64",),
        "2k22": ("amd64",),
        "2k25": ("amd64", "ARM64"),
        "2k3": ("amd64", "x86"),
        "2k8": ("amd64", "x86"),
        "2k8R2": ("amd64",),
        "w10": ("amd64", "ARM64", "x86"),
        "w11": ("amd64", "ARM64"),
        "w7": ("amd64", "x86"),
        "w8": ("amd64", "x86"),
        "w8.1": ("amd64", "x86"),
        "xp": ("amd64", "x86"),
    },
    "vioserial": {
        "2k12": ("amd64",),
        "2k19": ("amd64",),
        "w10": ("amd64", "x86"),
        "w11": ("amd64", "ARM64"),
    },
    "NetKVM": {
        "2k22": ("amd64",),
        "2k25": ("ARM64",),
        "w11": ("amd64", "ARM64"),
    },
    "Balloon": {
        "w10": ("amd64", "x86"),
        "w11": ("amd64",),
    },
    "qxldod": {
        "w10": ("amd64", "x86"),
        "w11": ("amd64",),
    },
}
"""``<driver> -> <family> -> architectures`` as measured on virtio-win 0.1.285.

``NetKVM\\2k25`` is ARM64 only and ``qxldod`` is a package the sandbox's guest
never boots on, so neither may reach the WinPE search list.
"""

_PACKAGES_WITHOUT_INF: Final[frozenset[tuple[str, str, str]]] = frozenset(
    {("vioserial", "2k12", "amd64")},
)
"""Directories built with no INF, which give WinPE nothing to load."""

_INF_TEMPLATE: Final[str] = (
    "[Version]\r\n"
    'Signature="$WINDOWS NT$"\r\n'
    "Class={class_name}\r\n"
    "ClassGuid={{4d36e97b-e325-11ce-bfc1-08002be10318}}\r\n"
    "Provider=%RHEL%\r\n"
    "CatalogFile={driver}.cat\r\n"
    "DriverVer=04/22/2025,100.95.104.28500\r\n"
    "\r\n"
    "[Manufacturer]\r\n"
    "%RHEL%=Standard,NT{architecture}\r\n"
    "\r\n"
    "[Standard.NT{architecture}]\r\n"
    "%{driver}.DeviceDesc%={driver}_Inst,PCI\\VEN_1AF4&DEV_1001\r\n"
    "\r\n"
    "[Strings]\r\n"
    'RHEL="Red Hat, Inc."\r\n'
    '{driver}.DeviceDesc="Red Hat VirtIO device"\r\n'
)
"""A real INF: the sections and directives Windows requires of a driver package."""

_CATALOG_DER: Final[bytes] = bytes.fromhex("300b06092a864886f70d010702")
"""A DER ``ContentInfo`` announcing PKCS#7 ``signedData``, as a catalog does."""

_SCAN_DEPTH: Final[int] = 4
"""Directory depth the host-native medium search is allowed to reach."""

_SCAN_BUDGET: Final[int] = 20_000
"""Directories the host-native medium search may enumerate."""

_MINIMUM_REAL_VIOSTOR_FAMILIES: Final[int] = 5
"""Storage families the real medium is known to carry for amd64, less a margin."""

_SETUP_REJECTED_PATH_COUNT: Final[int] = 60
"""Driver paths a real Windows 11 26100 install refused, measured on this host.

Sixty existing packages on the one drive letter WinPE really assigned aborted
Setup at ``ExecuteUnattendDriverInstall`` with ``0xD000A000 - 0x40031`` before
any disk was touched; four installed to completion. Every path in both runs
held an INF, so the count is what Setup will not take.
"""

_BOOT_CRITICAL_DRIVER: Final[str] = "viostor"
"""The storage driver without which Setup sees no ``if=virtio`` system disk."""

_NEWEST_FAMILY: Final[str] = "w11"
"""The family every driver in the measured layout carries for amd64."""


def _staged_media_root() -> Path:
    """Locate the images directory the provisioner keeps its media in.

    Returns:
        Path: ``<project root>/tools/qemu/images``, the only root the
        host-native gates search, so they judge the medium this repository
        provisions from rather than any other copy on the host.
    """
    return get_project_root() / "tools" / "qemu" / "images"


def _build_medium(root: Path) -> Path:
    """Materialise the measured virtio-win layout as real directories.

    Args:
        root: Directory to build the medium under.

    Returns:
        Path: The medium root, with every package directory created.
    """
    for driver, families in _MEASURED_LAYOUT.items():
        for family, architectures in families.items():
            for architecture in architectures:
                package = root / driver / family / architecture
                package.mkdir(parents=True)
                if (driver, family, architecture) in _PACKAGES_WITHOUT_INF:
                    (package / "readme.txt").write_text("no driver package here\r\n", encoding="ascii")
                    continue
                (package / f"{driver}.inf").write_text(
                    _INF_TEMPLATE.format(driver=driver, class_name="System", architecture=architecture),
                    encoding="ascii",
                )
                (package / f"{driver}.cat").write_bytes(_CATALOG_DER)
    return root


def _expected_subpaths() -> tuple[str, ...]:
    r"""Derive the subpaths the measured layout really offers an amd64 guest.

    Returns:
        tuple[str, ...]: Sorted ``<driver>\\<family>\\<arch>`` strings.
    """
    return tuple(
        sorted(
            f"{driver}\\{family}\\{architecture}"
            for driver, families in _MEASURED_LAYOUT.items()
            if driver in WINPE_DRIVER_DIRECTORIES
            for family, architectures in families.items()
            for architecture in architectures
            if architecture == _GUEST_ARCHITECTURE and (driver, family, architecture) not in _PACKAGES_WITHOUT_INF
        ),
    )


def _driver_path_texts(rendered: str) -> list[str]:
    """Parse an answer file and return its WinPE driver search paths.

    Args:
        rendered: The generated ``autounattend.xml`` text.

    Returns:
        list[str]: Every ``PathAndCredentials/Path`` value, in document order.
    """
    root: Element = DefusedET.fromstring(rendered)
    component = f"{{{_UNATTEND_NS}}}settings/{{{_UNATTEND_NS}}}component"
    texts: list[str] = []
    for element in root.findall(component):
        if element.get("name") != "Microsoft-Windows-PnpCustomizationsWinPE":
            continue
        texts.extend(
            (path.text or "")
            for path in element.findall(f"{{{_UNATTEND_NS}}}DriverPaths/{{{_UNATTEND_NS}}}PathAndCredentials/{{{_UNATTEND_NS}}}Path")
        )
    return texts


class TestTheEnumerationFollowsTheMedium:
    """The enumeration reports the medium's real layout, and only that."""

    def test_it_names_exactly_the_packages_the_medium_carries(self, tmp_path: Path) -> None:
        """Every amd64 package is named and nothing outside that set is.

        Args:
            tmp_path: Per-test temporary directory.
        """
        medium = _build_medium(tmp_path / "virtio")

        subpaths = enumerate_virtio_driver_subpaths(medium, _GUEST_ARCHITECTURE)

        expected = _expected_subpaths()
        assert set(subpaths) == set(expected), (
            f"the enumeration missed {sorted(set(expected) - set(subpaths))} and invented "
            f"{sorted(set(subpaths) - set(expected))} on a medium laid out as {sorted(_MEASURED_LAYOUT)}"
        )

    def test_every_named_directory_is_really_on_the_medium(self, tmp_path: Path) -> None:
        """A named path that does not resolve is the whole defect.

        Args:
            tmp_path: Per-test temporary directory.
        """
        medium = _build_medium(tmp_path / "virtio")

        subpaths = enumerate_virtio_driver_subpaths(medium, _GUEST_ARCHITECTURE)

        assert subpaths, f"the enumeration returned nothing for a medium holding {sorted(_MEASURED_LAYOUT)}"
        for subpath in subpaths:
            package = medium / Path(subpath.replace("\\", "/"))
            assert package.is_dir(), f"{subpath} is not a directory on the medium, so WinPE would search nothing at {package}"
            infs = sorted(entry.name for entry in package.iterdir() if entry.suffix == ".inf")
            assert infs, (
                f"{subpath} holds no INF, so WinPE has nothing to install from it: {sorted(entry.name for entry in package.iterdir())}"
            )

    def test_a_family_without_this_architecture_is_never_named(self, tmp_path: Path) -> None:
        r"""``NetKVM\\2k25`` is ARM64 only, so no amd64 path may point into it.

        Args:
            tmp_path: Per-test temporary directory.
        """
        medium = _build_medium(tmp_path / "virtio")
        absent = medium / "NetKVM" / "2k25" / _GUEST_ARCHITECTURE
        assert not absent.exists(), f"the medium under test was built wrong: {absent} exists, so it cannot gate the omission"

        subpaths = enumerate_virtio_driver_subpaths(medium, _GUEST_ARCHITECTURE)

        assert f"NetKVM\\2k25\\{_GUEST_ARCHITECTURE}" not in subpaths, (
            f"the enumeration named a family that has no {_GUEST_ARCHITECTURE} directory at all: {subpaths}"
        )
        for foreign in _FOREIGN_ARCHITECTURES:
            named = [subpath for subpath in subpaths if subpath.endswith(f"\\{foreign}")]
            assert not named, f"an {_GUEST_ARCHITECTURE} guest was sent to {foreign} packages: {named}"

    def test_a_directory_without_a_driver_package_is_not_named(self, tmp_path: Path) -> None:
        """A family directory carrying no INF gives WinPE nothing to load.

        Args:
            tmp_path: Per-test temporary directory.
        """
        medium = _build_medium(tmp_path / "virtio")
        driver, family, architecture = next(iter(_PACKAGES_WITHOUT_INF))
        empty = medium / driver / family / architecture
        assert empty.is_dir(), f"the medium under test was built wrong: {empty} is missing, so it cannot gate the omission"

        subpaths = enumerate_virtio_driver_subpaths(medium, _GUEST_ARCHITECTURE)

        assert f"{driver}\\{family}\\{architecture}" not in subpaths, (
            f"an INF-less directory reached the WinPE search list; it holds only {sorted(entry.name for entry in empty.iterdir())}"
        )

    def test_a_driver_outside_the_winpe_set_is_not_named(self, tmp_path: Path) -> None:
        """Only the devices the sandbox actually builds are searched for.

        Args:
            tmp_path: Per-test temporary directory.
        """
        medium = _build_medium(tmp_path / "virtio")
        outsider = next(driver for driver in _MEASURED_LAYOUT if driver not in WINPE_DRIVER_DIRECTORIES)

        subpaths = enumerate_virtio_driver_subpaths(medium, _GUEST_ARCHITECTURE)

        named = [subpath for subpath in subpaths if subpath.startswith(f"{outsider}\\")]
        assert not named, f"{outsider} is not one of {WINPE_DRIVER_DIRECTORIES} yet WinPE would search {named}"

    def test_the_order_is_deterministic(self, tmp_path: Path) -> None:
        """Two answer files built from one medium must be byte-identical.

        Args:
            tmp_path: Per-test temporary directory.
        """
        medium = _build_medium(tmp_path / "virtio")

        first = enumerate_virtio_driver_subpaths(medium, _GUEST_ARCHITECTURE)
        second = enumerate_virtio_driver_subpaths(medium, _GUEST_ARCHITECTURE)

        assert list(first) == sorted(first), f"the enumeration is unsorted, so the answer file varies run to run: {first}"
        assert first == second, f"two enumerations of one medium disagreed: {first} then {second}"


class TestTheAnswerFileStaysWithinWhatSetupAccepts:
    """The rendered ``autounattend.xml`` names one staged folder per letter.

    Naming every enumerated package is what this file used to assert, and a
    real installation measured it wrong: see the module docstring.
    """

    def test_it_emits_one_path_per_letter_and_no_more(self) -> None:
        """The count is bounded by the letters, not by the medium's breadth."""
        settings = replace(answer_settings(), driver_letters=WINPE_DRIVER_LETTERS)

        paths = _driver_path_texts(render_autounattend(settings))

        assert len(paths) == len(WINPE_DRIVER_LETTERS), (
            f"the answer file emitted {len(paths)} driver paths for {len(WINPE_DRIVER_LETTERS)} candidate letters"
        )
        assert len(paths) < _SETUP_REJECTED_PATH_COUNT, (
            f"{len(paths)} driver paths is at or above the {_SETUP_REJECTED_PATH_COUNT} a real Windows 11 install "
            f"aborted on with 0xD000A000, before it touched a disk"
        )
        assert [path.partition(":\\")[0] for path in paths] == list(WINPE_DRIVER_LETTERS), (
            f"the emitted paths {paths} are not one per candidate letter in order"
        )
        assert {path.partition(":\\")[2] for path in paths} == {WINPE_DRIVER_STAGE_DIRECTORY}, (
            f"the emitted paths point somewhere other than the staged driver folder: {paths}"
        )

    def test_the_staged_folder_carries_the_boot_critical_driver(self, tmp_path: Path) -> None:
        """What WinPE is pointed at must hold a loadable ``viostor`` package.

        A bounded path list is worthless if the one folder it names is empty:
        WinPE would load no storage driver and Setup would find no disk.

        Args:
            tmp_path: Per-test temporary directory.
        """
        medium = _build_medium(tmp_path / "virtio")
        subpaths = enumerate_virtio_driver_subpaths(medium, _GUEST_ARCHITECTURE)

        packages = select_winpe_driver_packages(subpaths)

        assert [package.split("\\")[0] for package in packages] == list(WINPE_DRIVER_DIRECTORIES), (
            f"{packages} does not carry exactly one package per driver the sandbox builds devices for"
        )
        for package in packages:
            directory = medium / Path(package.replace("\\", "/"))
            infs = sorted(entry.name for entry in directory.iterdir() if entry.suffix.casefold() == ".inf")
            assert infs, f"the selected package {package} carries no INF, so WinPE has nothing to load from it"

    def test_it_selects_per_driver_rather_than_one_hardwired_family(self, tmp_path: Path) -> None:
        """A driver missing the newest family falls back on its own.

        The measured medium gives every driver a ``w11`` amd64 package, so a
        hardwired ``w11`` would look correct against it. This removes that one
        directory for a single driver and requires that driver alone to move,
        which no hardwired family can do.

        Args:
            tmp_path: Per-test temporary directory.
        """
        medium = _build_medium(tmp_path / "virtio")
        deprived = "NetKVM"
        before = select_winpe_driver_packages(enumerate_virtio_driver_subpaths(medium, _GUEST_ARCHITECTURE))
        shutil.rmtree(medium / deprived / _NEWEST_FAMILY / _GUEST_ARCHITECTURE)

        after = select_winpe_driver_packages(enumerate_virtio_driver_subpaths(medium, _GUEST_ARCHITECTURE))

        assert {package.split("\\")[1] for package in before} == {_NEWEST_FAMILY}, (
            f"the untouched medium already resolved to {before}, so this run cannot detect a hardwired family"
        )
        moved = {package.split("\\")[0]: package.split("\\")[1] for package in after}
        assert moved[deprived] != _NEWEST_FAMILY, (
            f"{deprived} still resolved to {_NEWEST_FAMILY} after that directory was removed, so selection is not reading the medium"
        )
        expected = [
            family
            for family, architectures in _MEASURED_LAYOUT[deprived].items()
            if _GUEST_ARCHITECTURE in architectures and family != _NEWEST_FAMILY
        ]
        assert moved[deprived] == min(expected, key=WINPE_DRIVER_FAMILY_PREFERENCE.index), (
            f"{deprived} fell back to {moved[deprived]} rather than the newest family still on the medium"
        )
        for driver, family in moved.items():
            if driver != deprived:
                assert family == _NEWEST_FAMILY, f"{driver} moved off {_NEWEST_FAMILY} although its package is untouched"


class TestTheRealMediumEnumeratesOnlyRealDirectories:
    """Run the enumeration against the real virtio-win ISO on this host."""

    def test_every_enumerated_path_exists_on_the_real_medium(self) -> None:
        """The real medium's real layout, read through the real mount helper."""
        iso = require_virtio_media(None, (_staged_media_root(),), _SCAN_DEPTH, _SCAN_BUDGET, verify_contents=False)
        root = mount_disk_image(iso)
        try:
            subpaths = enumerate_virtio_driver_subpaths(root, _GUEST_ARCHITECTURE)
            resolved = {subpath: (root / Path(subpath.replace("\\", "/"))).is_dir() for subpath in subpaths}
            families = sorted({subpath.split("\\")[1] for subpath in subpaths if subpath.startswith("viostor\\")})
            foreign_present = sorted(
                str(entry.relative_to(root))
                for architecture in _FOREIGN_ARCHITECTURES
                for entry in root.glob(f"viostor/*/{architecture}")
                if entry.is_dir()
            )
        finally:
            dismount_disk_image(iso)

        assert subpaths, f"{iso} yielded no {_GUEST_ARCHITECTURE} driver package at all"
        missing = sorted(subpath for subpath, exists in resolved.items() if not exists)
        assert not missing, f"{iso} was told to offer {missing}, but those are not directories on it"
        assert len(families) >= _MINIMUM_REAL_VIOSTOR_FAMILIES, (
            f"{iso} yielded only the viostor families {families}; a guest outside them would find no system disk"
        )
        assert foreign_present, (
            f"{iso} carries no {_FOREIGN_ARCHITECTURES} viostor directory, so this run cannot prove the architecture scoping"
        )
        wrong = sorted(subpath for subpath in subpaths if not subpath.endswith(f"\\{_GUEST_ARCHITECTURE}"))
        assert not wrong, f"{iso} offered an {_GUEST_ARCHITECTURE} guest these foreign packages: {wrong}"

    def test_the_real_medium_stages_a_bounded_loadable_driver_set(self, tmp_path: Path) -> None:
        """The production staging runs against the real ISO, end to end.

        What lands in the staged folder is what WinPE gets: the files are
        copied off the real medium and read back off disk, and the answer
        file that names that folder is rendered by the production renderer.

        Args:
            tmp_path: Per-test temporary directory.
        """
        medium = resolve_virtio_medium(None, (_staged_media_root(),), _SCAN_DEPTH, _SCAN_BUDGET, _GUEST_ARCHITECTURE)

        staged = stage_winpe_drivers(medium.path, tmp_path, _GUEST_ARCHITECTURE)
        landed = sorted(entry.name for entry in (tmp_path / WINPE_DRIVER_STAGE_DIRECTORY).iterdir() if entry.is_file())

        assert staged == tuple(landed), f"the staging reported {staged} but {landed} is what is on disk"
        assert f"{_BOOT_CRITICAL_DRIVER}.inf" in landed, (
            f"{medium.path} staged {landed}, which has no {_BOOT_CRITICAL_DRIVER}.inf; WinPE would load no storage "
            f"driver and Setup would find no disk on the virtio-blk system disk"
        )
        assert f"{_BOOT_CRITICAL_DRIVER}.sys" in landed, f"{landed} names an INF with no driver binary beside it"
        for driver in WINPE_DRIVER_DIRECTORIES:
            assert any(name.casefold().startswith(driver.casefold()) for name in landed), (
                f"{medium.path} staged nothing for {driver}, which the sandbox launcher builds a device for"
            )

        paths = _driver_path_texts(render_autounattend(replace(answer_settings(), driver_letters=WINPE_DRIVER_LETTERS)))
        assert len(paths) < _SETUP_REJECTED_PATH_COUNT, (
            f"the real medium produced {len(paths)} driver paths, at or above the {_SETUP_REJECTED_PATH_COUNT} that "
            f"aborted a real installation"
        )
