# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gates for S18-D26: the answer file named more driver paths than Setup takes.

Measured with real installations of the same Windows 11 26100 media, differing
only in the ``DriverPaths`` block:

* 360 paths - sixty enumerated packages across six candidate letters - aborted.
* 60 paths, every one an existing directory on the drive letter WinPE really
  assigned - aborted identically, logging
  ``CDlpActionDriverInstallation::ExecuteUnattendDriverInstall(1512): Result =
  0xD000A000`` beside ``SetupManager: Drivers Path: []``, before any disk was
  touched.
* 4 paths - installed, and wrote 7.7 GB to the system disk before it was
  stopped.

Every path in all three carried an INF and unreachable letters were tolerated,
so the count is what Setup refuses. The provisioner now stages one package per
driver into a folder on the answer medium it authors itself and names that
folder once per candidate letter, which keeps the block at six entries however
many packages the medium carries.

These gates drive the real staging over a real directory tree: files are
copied, then read back off disk, and the answer file is rendered by the
production renderer.
"""

from __future__ import annotations

import ast
import inspect
from dataclasses import replace
from pathlib import Path
from typing import Final

import defusedxml.ElementTree as DefusedET
import pytest

from scripts.sandbox.provision_windows_guest import (
    WINPE_DRIVER_DIRECTORIES,
    WINPE_DRIVER_LETTERS,
    WINPE_DRIVER_STAGE_DIRECTORY,
    ProvisioningError,
    render_autounattend,
    require_boot_critical_package,
    select_winpe_driver_packages,
    stage_answer_tree,
)
from tests.sandbox.qemu.virtio_installer_harness import answer_settings


_UNATTEND_NS: Final[str] = "urn:schemas-microsoft-com:unattend"

_SETUP_REJECTED_PATH_COUNT: Final[int] = 60
"""Driver paths a real Windows 11 install aborted on; four installed cleanly."""

_ARCHITECTURE: Final[str] = "amd64"

_STAGING_DIRECTORY_POSITION: Final[int] = 3
"""Position of the folder argument in the staging call the answer tree makes."""

_LAYOUT: Final[dict[str, dict[str, tuple[str, ...]]]] = {
    "viostor": {"w11": ("amd64",), "w10": ("amd64", "x86"), "2k19": ("amd64",), "xp": ("amd64", "x86")},
    "vioserial": {"w10": ("amd64",), "2k12": ("amd64",)},
    "NetKVM": {"2k22": ("amd64",), "2k25": ("ARM64",)},
    "Balloon": {"w10": ("amd64", "x86"), "w11": ("amd64",)},
}
"""A medium whose families differ per driver, as the real 0.1.285 medium's do."""

_DER_SEQUENCE: Final[int] = 0x30
_DER_OBJECT_IDENTIFIER: Final[int] = 0x06
_SIGNED_DATA_OID: Final[tuple[int, ...]] = (0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02)
"""DER encoding of 1.2.840.113549.1.7.2, the PKCS#7 signedData identifier."""

_INF_TEMPLATE: Final[str] = (
    "[Version]\r\n"
    'Signature="$WINDOWS NT$"\r\n'
    "Class=System\r\n"
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


def _signed_data_header() -> bytes:
    """Build the DER opening a Windows catalogue file really carries.

    A ``.cat`` is a PKCS#7 signedData structure, so it starts with a SEQUENCE
    wrapping the signedData object identifier. The staging copies whatever
    files a package directory holds, and a catalogue that does not look like
    one would make the staged tree less like the medium it stands for.

    Returns:
        bytes: SEQUENCE containing the ``1.2.840.113549.1.7.2`` identifier.
    """
    identifier = bytes([_DER_OBJECT_IDENTIFIER, len(_SIGNED_DATA_OID), *_SIGNED_DATA_OID])
    return bytes([_DER_SEQUENCE, len(identifier)]) + identifier


def _build_medium(root: Path, layout: dict[str, dict[str, tuple[str, ...]]] = _LAYOUT) -> Path:
    """Materialise a virtio-win layout as real directories carrying real files.

    Args:
        root: Directory to build the medium under.
        layout: ``<driver> -> <family> -> architectures`` to create.

    Returns:
        Path: The medium root.
    """
    for driver, families in layout.items():
        for family, architectures in families.items():
            for architecture in architectures:
                package = root / driver / family / architecture
                package.mkdir(parents=True)
                (package / f"{driver}.inf").write_text(
                    _INF_TEMPLATE.format(driver=driver, architecture=architecture),
                    encoding="ascii",
                )
                (package / f"{driver}.sys").write_bytes(f"{driver}/{family}/{architecture}".encode("ascii"))
                (package / f"{driver}.cat").write_bytes(_signed_data_header())
    return root


def _enumerate(medium: Path) -> tuple[str, ...]:
    r"""Return the ``<driver>\\<family>\\<arch>`` subpaths a medium offers amd64.

    Args:
        medium: Medium root built by :func:`_build_medium`.

    Returns:
        tuple[str, ...]: Sorted subpaths for :data:`_ARCHITECTURE`.
    """
    return tuple(
        sorted(
            f"{driver}\\{family}\\{architecture}"
            for driver, families in _LAYOUT.items()
            for family, architectures in families.items()
            for architecture in architectures
            if architecture == _ARCHITECTURE and (medium / driver / family / architecture).is_dir()
        ),
    )


def _driver_paths(rendered: str) -> list[str]:
    """Return the WinPE driver search paths of a rendered answer file.

    Args:
        rendered: The generated ``autounattend.xml`` text.

    Returns:
        list[str]: Every ``PathAndCredentials/Path`` value, in document order.
    """
    root = DefusedET.fromstring(rendered)
    query = f"{{{_UNATTEND_NS}}}DriverPaths/{{{_UNATTEND_NS}}}PathAndCredentials/{{{_UNATTEND_NS}}}Path"
    return [
        (path.text or "")
        for component in root.findall(f"{{{_UNATTEND_NS}}}settings/{{{_UNATTEND_NS}}}component")
        if component.get("name") == "Microsoft-Windows-PnpCustomizationsWinPE"
        for path in component.findall(query)
    ]


def test_the_selection_stays_far_below_what_setup_refused(tmp_path: Path) -> None:
    """One package per driver, however many families the medium carries.

    Args:
        tmp_path: Per-test temporary directory.
    """
    medium = _build_medium(tmp_path / "virtio")
    subpaths = _enumerate(medium)

    packages = select_winpe_driver_packages(subpaths)

    assert len(subpaths) > len(packages), (
        f"the medium offered only {len(subpaths)} packages, so this run cannot show the selection narrowing anything"
    )
    assert len(packages) * len(WINPE_DRIVER_LETTERS) < _SETUP_REJECTED_PATH_COUNT, (
        f"{len(packages)} packages across {len(WINPE_DRIVER_LETTERS)} letters would be "
        f"{len(packages) * len(WINPE_DRIVER_LETTERS)} paths, at or above the {_SETUP_REJECTED_PATH_COUNT} that "
        f"aborted a real installation"
    )
    assert [package.split("\\")[0] for package in packages] == list(WINPE_DRIVER_DIRECTORIES), (
        f"{packages} is not one package per driver the sandbox launcher builds a device for"
    )


def test_a_driver_the_medium_lacks_is_skipped_rather_than_invented(tmp_path: Path) -> None:
    """Selection never names a directory the medium does not have.

    Args:
        tmp_path: Per-test temporary directory.
    """
    reduced = {driver: families for driver, families in _LAYOUT.items() if driver != "Balloon"}
    medium = _build_medium(tmp_path / "virtio", reduced)
    subpaths = tuple(subpath for subpath in _enumerate(medium) if not subpath.startswith("Balloon\\"))

    packages = select_winpe_driver_packages(subpaths)

    assert not any(package.startswith("Balloon\\") for package in packages), (
        f"{packages} names a Balloon package, but this medium carries none"
    )
    for package in packages:
        assert (medium / Path(package.replace("\\", "/"))).is_dir(), f"{package} is no directory on {medium}"


def test_the_answer_file_names_the_staged_folder_once_per_letter() -> None:
    """The rendered block is bounded by the letters and nothing else."""
    settings = replace(answer_settings(), driver_letters=WINPE_DRIVER_LETTERS)

    paths = _driver_paths(render_autounattend(settings))

    assert paths == [f"{letter}:\\{WINPE_DRIVER_STAGE_DIRECTORY}" for letter in WINPE_DRIVER_LETTERS], (
        f"the answer file emitted {paths} rather than the staged folder once per candidate letter"
    )


def test_the_answer_file_and_the_staging_cannot_name_different_folders() -> None:
    """One name drives both, so a renamed folder cannot strand WinPE.

    The paths are rendered from the settings, and the staging is handed the
    same field rather than the module constant, so a bespoke folder name still
    puts the files where Setup is told to look.
    """
    renamed = replace(answer_settings(), driver_letters=WINPE_DRIVER_LETTERS, driver_directory="winpe-drivers")

    paths = _driver_paths(render_autounattend(renamed))

    assert {path.partition(":\\")[2] for path in paths} == {"winpe-drivers"}, (
        f"the answer file ignored the configured folder and emitted {paths}"
    )
    assert _staging_directory_argument() == "settings.driver_directory", (
        "the answer tree stages drivers into a folder the answer file does not necessarily name"
    )


def _staging_directory_argument() -> str:
    """Return the folder expression ``stage_answer_tree`` stages drivers into.

    Returns:
        str: The fourth argument of its :func:`stage_winpe_drivers` call.

    Raises:
        AssertionError: If it no longer stages WinPE drivers at all.
    """
    source = Path(inspect.getsourcefile(stage_answer_tree) or "")
    module = ast.parse(source.read_text(encoding="utf-8"))
    for definition in module.body:
        if not isinstance(definition, ast.FunctionDef) or definition.name != "stage_answer_tree":
            continue
        for node in ast.walk(definition):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "stage_winpe_drivers":
                return ast.unparse(node.args[3]) if len(node.args) > _STAGING_DIRECTORY_POSITION else ""
    message = "stage_answer_tree no longer stages any WinPE drivers"
    raise AssertionError(message)


def test_a_medium_without_the_boot_driver_is_refused_not_staged(tmp_path: Path) -> None:
    """Silently staging no storage driver would strand Setup with no disk.

    Args:
        tmp_path: Per-test temporary directory.
    """
    without_storage = {driver: families for driver, families in _LAYOUT.items() if driver != "viostor"}
    medium = _build_medium(tmp_path / "virtio", without_storage)
    subpaths = tuple(subpath for subpath in _enumerate(medium) if not subpath.startswith("viostor\\"))

    packages = select_winpe_driver_packages(subpaths)

    assert not any(package.startswith("viostor\\") for package in packages), (
        f"{packages} claims a viostor package on a medium built without one"
    )
    with pytest.raises(ProvisioningError, match="carries no viostor package"):
        require_boot_critical_package(packages, str(medium), _ARCHITECTURE)

    complete = select_winpe_driver_packages(_enumerate(_build_medium(tmp_path / "complete")))
    require_boot_critical_package(complete, str(medium), _ARCHITECTURE)
