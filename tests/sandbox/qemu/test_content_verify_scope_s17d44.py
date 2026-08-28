# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gates for S17-D44's Verify clause: what ``--skip-content-verify`` still skips.

S17-D44 replaced a hardwired ``w11\amd64`` driver tuple with an enumeration of
the virtio medium's real layout, and recorded two consequences as unproven. The
second was that ``--skip-content-verify`` had narrowed: it no longer skips the
*virtio* medium, only the Windows install medium. That narrowing was justified
in the flag's own help text with "the answer file's WinPE driver paths are
enumerated from its real layout".

S18-D26 then made that justification false. Setup aborts on an answer file that
names sixty driver paths, so the provisioner now stages one package per driver
onto the answer medium it authors and names that one folder once per candidate
drive letter. The rendered ``DriverPaths`` block is therefore a function of the
settings alone and of no medium at all; what the virtio medium supplies is the
staged driver *files*. The narrowing became structural rather than conditional -
``stage_winpe_drivers`` mounts the medium on every run - and the help text's
stated reason stopped describing the code.

Driven against the real provisioner on this host before these gates were
written, one flag apart and nothing else:

* with ``--skip-content-verify``: ``media_content`` is ``null`` and
  ``Windows11-NoPrompt.iso`` is never mounted; the virtio medium was mounted
  three times all the same.
* without it: ``install_media_verified image=...Windows11-NoPrompt.iso
  install_image=J:\sources\install.wim`` appears, and the virtio medium was
  still mounted three times.

The three mounts were :func:`verify_virtio_contents` checking the medium
before use, :func:`stage_winpe_drivers` mounting it again to copy the boot-
critical drivers, and :func:`stage_spawn_helpers` mounting it a third time
whenever the bundled QEMU tree lacked GLib's spawn helpers - roughly 14 of a
29 second run, each extra mount paying its own ``Mount-DiskImage`` round trip
plus the 750 ms settle the provisioner waits out. That is the regression
:class:`TestTheMediumIsMountedExactlyOnce` below gates: the medium is now
mounted exactly once per provisioning run, its one mount held across
verification and both staging steps, so the numbers above are what a run
against the pre-fix provisioner measured rather than what today's code does.

The gates here pin that scope, keep the help text tied to what the code really
does, and cover the offline half of the same Verify clause - that a medium
carrying no ``w11`` family still yields a bootable driver selection.
:mod:`tests.sandbox.qemu.test_winpe_driver_staging_s18d26` already gates one
package per driver, a driver the medium lacks being skipped, and the refusal of
a medium without ``viostor``; every medium it builds carries a ``w11`` family,
which is exactly the case S17-D44's Verify clause excludes.
"""

from __future__ import annotations

import argparse
import ast
import inspect
import struct
from pathlib import Path
from typing import Final

import defusedxml.ElementTree as DefusedET
import pytest

import scripts.sandbox.provision_windows_guest as provisioner
from scripts.sandbox.provision_windows_guest import (
    WINPE_DRIVER_DIRECTORIES,
    WINPE_DRIVER_FAMILY_PREFERENCE,
    WINPE_DRIVER_LETTERS,
    ProvisioningError,
    enumerate_virtio_driver_subpaths,
    probe_iso_structure,
    render_autounattend,
    require_boot_critical_package,
    resolve_install_media,
    select_winpe_driver_packages,
    stage_virtio_medium,
)
from tests.sandbox.qemu.virtio_installer_harness import answer_settings, build_bundled_tools


_FLAG: Final[str] = "--skip-content-verify"
"""The command line contract under test, as an operator types it."""

_VERIFICATION_CALL: Final[str] = "verify_media_contents"
"""The one inspection the flag is allowed to suppress."""

_ARCHITECTURE: Final[str] = "amd64"

_UNATTEND_NS: Final[str] = "urn:schemas-microsoft-com:unattend"

_UNREACHED_SCAN_LIMIT: Final[int] = 1
"""Discovery never runs when the medium is named, so these bounds go unread."""

_STALE_HELP_CLAIMS: Final[tuple[str, ...]] = ("driver paths", "enumerated")
"""Wording that would attribute the rendered ``DriverPaths`` to the medium."""

_LIVE_HELP_CLAIMS: Final[tuple[str, ...]] = ("virtio", "regardless")
"""Wording the caveat about the medium that is still read cannot lose."""

_SECTOR: Final[int] = 2048
_PRIMARY_DESCRIPTOR_LBA: Final[int] = 16
_BOOT_RECORD_LBA: Final[int] = 17
_TERMINATOR_LBA: Final[int] = 18
_RECOGNITION_FIRST_LBA: Final[int] = 19
_CATALOG_LBA: Final[int] = 22
_BIOS_BOOT_LBA: Final[int] = 534
_MEDIA_BYTES: Final[int] = 3 * 1024 * 1024 * 1024
"""Above the provisioner's two gibibyte floor for install media."""

_ISO9660_ID: Final[bytes] = b"CD001"
_EL_TORITO_SYSTEM_ID: Final[bytes] = b"EL TORITO SPECIFICATION"
_MICROSOFT_ID: Final[bytes] = b"Microsoft Corporation"
_UDF_IDENTIFIERS: Final[tuple[bytes, ...]] = (b"BEA01", b"NSR02", b"TEA01")
"""The recognition sequence that makes Microsoft media UDF-bridged."""

_INF_BODY: Final[str] = (
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
"""A real INF body, because the enumeration only counts directories holding one."""

_W11_MEDIUM: Final[dict[str, dict[str, tuple[str, ...]]]] = {
    "viostor": {"w11": ("amd64",), "w10": ("amd64", "x86")},
    "vioserial": {"w11": ("amd64",)},
    "NetKVM": {"w11": ("amd64",)},
    "Balloon": {"w11": ("amd64",)},
}
"""A medium of the shape this repository's guest is installed from today."""

_NO_W11_MEDIUM: Final[dict[str, dict[str, tuple[str, ...]]]] = {
    "viostor": {"w10": ("amd64", "x86"), "2k22": ("amd64",), "2k19": ("amd64",)},
    "vioserial": {"2k19": ("amd64",)},
    "NetKVM": {"w10": ("amd64",), "2k25": ("ARM64",)},
    "Balloon": {"2k22": ("amd64",)},
}
"""The medium S17-D44's Verify clause names: nothing under ``w11`` anywhere."""

_UNRANKED_MEDIUM: Final[dict[str, dict[str, tuple[str, ...]]]] = {
    "viostor": {"w12": ("amd64",)},
    "vioserial": {"w12": ("amd64",)},
    "NetKVM": {"2k27": ("amd64",)},
    "Balloon": {"w12": ("amd64",)},
}
"""A medium newer than the preference list, which must not select nothing."""

_NO_W11_SELECTION: Final[tuple[str, ...]] = (
    "viostor\\w10\\amd64",
    "vioserial\\2k19\\amd64",
    "NetKVM\\w10\\amd64",
    "Balloon\\2k22\\amd64",
)
"""Exactly what :data:`_NO_W11_MEDIUM` must yield: newest family present, per driver."""

_UNRANKED_SELECTION: Final[tuple[str, ...]] = (
    "viostor\\w12\\amd64",
    "vioserial\\w12\\amd64",
    "NetKVM\\2k27\\amd64",
    "Balloon\\w12\\amd64",
)
"""Exactly what :data:`_UNRANKED_MEDIUM` must yield, none of it ranked."""


def _descriptor(descriptor_type: int, volume_id: bytes = b"") -> bytes:
    """Build one ISO9660 volume descriptor sector.

    Args:
        descriptor_type: Descriptor type byte, 1 for primary and 255 for the
            set terminator.
        volume_id: Primary volume identifier, padded into its field.

    Returns:
        bytes: One 2048 byte sector.
    """
    sector = bytearray(_SECTOR)
    sector[0] = descriptor_type
    sector[1:6] = _ISO9660_ID
    sector[40:72] = volume_id.ljust(32)
    return bytes(sector)


def _boot_record(catalog_lba: int) -> bytes:
    """Build the El Torito boot record that points at the boot catalog.

    Args:
        catalog_lba: Sector the boot catalog is written at.

    Returns:
        bytes: One 2048 byte sector.
    """
    sector = bytearray(_SECTOR)
    sector[1:6] = _ISO9660_ID
    sector[7:39] = _EL_TORITO_SYSTEM_ID.ljust(32, b"\x00")
    struct.pack_into("<I", sector, 71, catalog_lba)
    return bytes(sector)


def _recognition(identifier: bytes) -> bytes:
    """Build one UDF volume recognition descriptor sector.

    Args:
        identifier: Recognition identifier such as ``NSR02``.

    Returns:
        bytes: One 2048 byte sector.
    """
    sector = bytearray(_SECTOR)
    sector[1:6] = identifier
    return bytes(sector)


def _boot_catalog(load_lba: int) -> bytes:
    """Build a boot catalog naming Microsoft with one bootable x86 entry.

    Args:
        load_lba: Sector the BIOS boot image would be loaded from.

    Returns:
        bytes: One 2048 byte sector.
    """
    sector = bytearray(_SECTOR)
    sector[0] = 0x01
    sector[4:28] = _MICROSOFT_ID.ljust(24, b"\x00")
    sector[30:32] = b"\x55\xaa"
    sector[32] = 0x88
    struct.pack_into("<I", sector, 32 + 8, load_lba)
    return bytes(sector)


def _windows_install_iso(path: Path) -> Path:
    """Write an ISO whose header set matches this host's real Windows media.

    The provisioner validates install media by reading the descriptor set and
    the boot catalog straight out of the file, so a genuine header layout is
    all that separates a medium it accepts from one it refuses. The data area
    past the descriptors is left as a hole, which is why a three gibibyte
    fixture costs no real storage.

    Args:
        path: Destination file.

    Returns:
        Path: The written file.
    """
    sectors: dict[int, bytes] = {
        _PRIMARY_DESCRIPTOR_LBA: _descriptor(1, b"CD_ROM"),
        _BOOT_RECORD_LBA: _boot_record(_CATALOG_LBA),
        _TERMINATOR_LBA: _descriptor(255),
        _CATALOG_LBA: _boot_catalog(_BIOS_BOOT_LBA),
    }
    for offset, identifier in enumerate(_UDF_IDENTIFIERS):
        sectors[_RECOGNITION_FIRST_LBA + offset] = _recognition(identifier)

    with path.open("wb") as handle:
        for lba, data in sorted(sectors.items()):
            handle.seek(lba * _SECTOR)
            handle.write(data)
        handle.truncate(_MEDIA_BYTES)
    return path


def _build_medium(root: Path, layout: dict[str, dict[str, tuple[str, ...]]]) -> Path:
    r"""Materialise a ``<driver>\\<family>\\<arch>`` layout as real files.

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
                    _INF_BODY.format(driver=driver, architecture=architecture),
                    encoding="ascii",
                )
                (package / f"{driver}.sys").write_bytes(f"{driver}/{family}/{architecture}".encode("ascii"))
    return root


def _select(root: Path) -> tuple[str, ...]:
    """Run the real enumeration and selection over a built medium.

    Args:
        root: Medium root built by :func:`_build_medium`.

    Returns:
        tuple[str, ...]: The packages the provisioner would stage.
    """
    return select_winpe_driver_packages(enumerate_virtio_driver_subpaths(root, _ARCHITECTURE))


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


def _provisioner_ast() -> ast.Module:
    """Parse the provisioner module these gates import from.

    Returns:
        ast.Module: Syntax tree of the real production source file.
    """
    source = Path(inspect.getsourcefile(resolve_install_media) or "")
    return ast.parse(source.read_text(encoding="utf-8"))


def _flag_declaration() -> ast.Call:
    """Find the call that declares the flag on the real command line.

    Returns:
        ast.Call: The ``add_argument`` call whose first argument is the flag.

    Raises:
        AssertionError: If the provisioner no longer offers the flag.
    """
    for node in ast.walk(_provisioner_ast()):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr != "add_argument":
            continue
        first = node.args[0] if node.args else None
        if isinstance(first, ast.Constant) and first.value == _FLAG:
            return node
    message = f"the provisioner's command line no longer offers {_FLAG}"
    raise AssertionError(message)


def _flag_keyword(name: str) -> object | None:
    """Read one keyword of the flag's declaration as a Python value.

    Args:
        name: Keyword argument name to read.

    Returns:
        object | None: Its literal value, or None when it is not supplied.
    """
    for keyword in _flag_declaration().keywords:
        if keyword.arg == name:
            return ast.literal_eval(keyword.value)
    return None


def _flag_destination() -> str:
    """Return the parsed setting the flag writes.

    Returns:
        str: The namespace attribute name, either declared outright or
        derived the way ``argparse`` derives it from a long option.
    """
    assert _flag_keyword("action") == "store_true", f"{_FLAG} is no longer a boolean switch, so these gates read the wrong thing"
    declared = _flag_keyword("dest")
    return str(declared) if declared is not None else _FLAG.removeprefix("--").replace("-", "_")


def _flag_help() -> str:
    """Return the help paragraph an operator reads for the flag.

    Returns:
        str: The declared help text, with its wrapping normalised away.
    """
    return " ".join(str(_flag_keyword("help") or "").split())


def _args(medium: Path, *, skip: bool) -> argparse.Namespace:
    """Build the parsed settings the install media step reads.

    Args:
        medium: Install medium to name explicitly, which bypasses discovery.
        skip: Whether the flag was given.

    Returns:
        argparse.Namespace: Settings for
        :func:`~scripts.sandbox.provision_windows_guest.resolve_install_media`.
    """
    settings = {
        "iso": str(medium),
        "scan_depth": _UNREACHED_SCAN_LIMIT,
        "scan_budget": _UNREACHED_SCAN_LIMIT,
        _flag_destination(): skip,
    }
    return argparse.Namespace(**settings)


def _mentions(node: ast.AST, destination: str) -> bool:
    """Report whether an expression reads the flag's namespace attribute.

    Args:
        node: Expression to inspect.
        destination: Namespace attribute name the flag writes.

    Returns:
        bool: True when the attribute is read anywhere inside ``node``.
    """
    return any(isinstance(child, ast.Attribute) and child.attr == destination for child in ast.walk(node))


def _branches(node: ast.If | ast.IfExp) -> list[ast.AST]:
    """Return the two arms of a conditional, statement or expression form.

    Args:
        node: Conditional whose arms are wanted.

    Returns:
        list[ast.AST]: Every node making up the taken and untaken arms.
    """
    if isinstance(node, ast.IfExp):
        return [node.body, node.orelse]
    return [*node.body, *node.orelse]


def _called_names(nodes: list[ast.AST]) -> set[str]:
    """Collect the names of every function called inside a set of nodes.

    Args:
        nodes: Nodes to walk.

    Returns:
        set[str]: Called function names, attribute calls by their final name.
    """
    called: set[str] = set()
    for node in nodes:
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            if isinstance(child.func, ast.Name):
                called.add(child.func.id)
            elif isinstance(child.func, ast.Attribute):
                called.add(child.func.attr)
    return called


def _functions_reading(module: ast.Module, destination: str) -> set[str]:
    """Find every function that reads the flag's namespace attribute.

    Args:
        module: Parsed provisioner module.
        destination: Namespace attribute name the flag writes.

    Returns:
        set[str]: Names of the functions containing a read of it.
    """
    return {
        definition.name for definition in ast.walk(module) if isinstance(definition, ast.FunctionDef) and _mentions(definition, destination)
    }


def test_the_flag_leaves_the_install_medium_unmounted(tmp_path: Path) -> None:
    """One flag apart, the same medium is either inspected or it is not.

    The medium is a real ISO header set staged where the provisioner already
    keeps its images, so selection accepts it and nothing is copied. Only
    verification mounts it, and mounting a header-only fixture cannot succeed -
    so the flag is the whole difference between a plan that comes back and a
    run that reaches the storage stack naming that file.

    Args:
        tmp_path: Per-test temporary directory.
    """
    images = tmp_path / "images"
    images.mkdir()
    medium = _windows_install_iso(images / "windows.iso")

    assert probe_iso_structure(medium).is_windows_install_candidate, (
        f"{medium} is not accepted as install media, so this run cannot reach the verification step at all"
    )

    probe, content = resolve_install_media(_args(medium, skip=True), images)

    assert probe.path == medium, f"the provisioner selected {probe.path} rather than the medium it was pointed at"
    assert content is None, f"{_FLAG} still inspected the install medium and reported {content}"

    with pytest.raises(ProvisioningError) as failure:
        resolve_install_media(_args(medium, skip=False), images)
    assert medium.name in str(failure.value), (
        f"without {_FLAG} the run failed with {failure.value!r}, which never names the install medium, "
        f"so this run does not show the verification being attempted"
    )


def test_nothing_but_the_install_medium_verification_hangs_off_the_flag() -> None:
    """The flag reaches one inspection, and the virtio medium is not it.

    S17-D44 narrowed the flag deliberately, and the narrowing is what makes
    the answer medium authorable at all. A change that re-widened it - letting
    an operator skip the virtio medium too - would author an answer medium
    carrying no boot-critical driver files, and Setup would find no disk. This
    reads the real production source rather than trusting the help text.

    Raises:
        AssertionError: If the flag no longer guards anything.
    """
    module = _provisioner_ast()
    destination = _flag_destination()

    guards = [node for node in ast.walk(module) if isinstance(node, ast.If | ast.IfExp) and _mentions(node.test, destination)]
    if not guards:
        message = f"nothing in the provisioner is conditional on {destination}, so {_FLAG} does nothing at all"
        raise AssertionError(message)

    guarded: set[str] = set()
    for guard in guards:
        guarded |= _called_names(_branches(guard))
    readers = _functions_reading(module, destination)

    assert guarded == {_VERIFICATION_CALL}, (
        f"{_FLAG} decides whether {sorted(guarded)} runs; it may only decide {_VERIFICATION_CALL}, "
        f"because the virtio medium's layout is what the answer medium is built from"
    )
    assert readers == {"resolve_install_media"}, (
        f"{destination} is read in {sorted(readers)}, so the flag has escaped the install media step it belongs to"
    )


def test_the_help_text_gives_a_reason_the_code_still_honours(tmp_path: Path) -> None:
    """The flag's help may not attribute the rendered paths to the medium.

    Measured here on two real media, one carrying ``w11`` and one not: the
    packages the provisioner stages differ, and the paths the answer file names
    do not differ at all. The medium therefore governs the staged files and
    nothing else, and a help text telling an operator that the driver paths are
    enumerated from the medium's layout describes code that no longer exists.

    Args:
        tmp_path: Per-test temporary directory.
    """
    with_w11 = _select(_build_medium(tmp_path / "with-w11", _W11_MEDIUM))
    without_w11 = _select(_build_medium(tmp_path / "without-w11", _NO_W11_MEDIUM))
    settings = answer_settings()
    expected = [f"{letter}:\\{settings.driver_directory}" for letter in WINPE_DRIVER_LETTERS]

    assert with_w11 != without_w11, f"both media selected {with_w11}, so this run cannot show the medium governing anything"
    assert _driver_paths(render_autounattend(settings)) == expected, (
        "the rendered driver paths are no longer the staged folder once per candidate letter"
    )

    help_text = _flag_help().casefold()
    for claim in _STALE_HELP_CLAIMS:
        assert claim not in help_text, (
            f"the help for {_FLAG} says {claim!r}, but two media that stage different packages render identical "
            f"driver paths, so the paths are enumerated from no medium at all: {help_text!r}"
        )
    for claim in _LIVE_HELP_CLAIMS:
        assert claim in help_text, (
            f"the help for {_FLAG} no longer says {claim!r}, so an operator is not told the virtio medium is "
            f"still mounted on every run: {help_text!r}"
        )


def test_a_medium_with_no_w11_family_still_yields_one_real_package_per_driver(tmp_path: Path) -> None:
    """The case S17-D44's Verify clause names, minus the guest that installs it.

    Every driver the sandbox builds a device for must be staged from the newest
    family the medium really carries, and the boot-critical check must accept
    the result. A selection that fell back to ``w11`` would name directories
    that do not exist on this medium, which is the defect S17-D44 was filed for.

    Args:
        tmp_path: Per-test temporary directory.
    """
    medium = _build_medium(tmp_path / "virtio", _NO_W11_MEDIUM)
    families = {family.casefold() for driver in _NO_W11_MEDIUM.values() for family in driver}

    packages = _select(medium)

    assert "w11" not in families, f"the fixture medium carries {sorted(families)}, so it is not the non-w11 case at all"
    assert packages == _NO_W11_SELECTION, f"a medium without any w11 family selected {packages}"
    for package in packages:
        assert (medium / Path(package.replace("\\", "/"))).is_dir(), f"{package} is no directory on {medium}"
    assert [package.split("\\")[0] for package in packages] == list(WINPE_DRIVER_DIRECTORIES), (
        f"{packages} is not one package per driver the sandbox launcher builds a device for"
    )
    require_boot_critical_package(packages, str(medium), _ARCHITECTURE)


def test_families_the_preference_list_never_heard_of_are_still_staged(tmp_path: Path) -> None:
    """An unrecognised family sorts last; it must not sort out of existence.

    Args:
        tmp_path: Per-test temporary directory.
    """
    medium = _build_medium(tmp_path / "virtio", _UNRANKED_MEDIUM)
    families = {family.casefold() for driver in _UNRANKED_MEDIUM.values() for family in driver}

    packages = _select(medium)

    assert not families & {name.casefold() for name in WINPE_DRIVER_FAMILY_PREFERENCE}, (
        f"{sorted(families)} overlaps the preference list, so this run cannot show unranked families surviving"
    )
    assert packages == _UNRANKED_SELECTION, f"a medium of unrecognised families selected {packages}"
    require_boot_critical_package(packages, str(medium), _ARCHITECTURE)


class TestTheMediumIsMountedExactlyOnce:
    """The S17-D44 follow-up regression: the medium mounted twice, then thrice.

    S17-D44 established that verification does not mount the medium twice by
    itself. It said nothing about staging, which mounted the same medium
    again to copy the boot-critical drivers, and a third time whenever the
    bundled QEMU tree lacked GLib's spawn helpers - the "mounted three times"
    measurement in this module's own docstring. These gates replace
    ``mount_disk_image``/``dismount_disk_image`` with counters and drive the
    real :func:`stage_virtio_medium`, the function ``build_answer_medium`` and
    therefore ``provision`` now use to verify and stage a virtio-win medium in
    one held mount, holding the count to exactly one on both the successful
    path and the path where staging itself raises.
    """

    def test_a_successful_run_mounts_the_medium_exactly_once(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verification and both staging steps share one mount, not three.

        Args:
            tmp_path: Per-test temporary directory.
            monkeypatch: Pytest fixture used to replace the real mount calls.
        """
        medium = _build_medium(tmp_path / "virtio", _W11_MEDIUM)
        tools = build_bundled_tools(tmp_path / "tools", spawn_helpers=True)
        staging = tmp_path / "staging"
        staging.mkdir()
        calls = {"mount": 0, "dismount": 0}

        def fake_mount(path: Path) -> Path:
            """Record a mount call and hand back the prebuilt medium tree.

            Args:
                path: ISO path the real provisioner would have mounted.

            Returns:
                Path: The prebuilt medium directory, standing in for the
                drive letter a real mount would return.
            """
            del path
            calls["mount"] += 1
            return medium

        def fake_dismount(path: Path) -> None:
            """Record a dismount call.

            Args:
                path: ISO path the real provisioner would have dismounted.
            """
            del path
            calls["dismount"] += 1

        monkeypatch.setattr(provisioner, "mount_disk_image", fake_mount)
        monkeypatch.setattr(provisioner, "dismount_disk_image", fake_dismount)

        autounattend, subpaths = stage_virtio_medium(staging, answer_settings(), tools / "qemu-ga.exe", tools, medium)

        assert calls == {"mount": 1, "dismount": 1}, (
            f"one provisioning run mounted the virtio medium {calls['mount']} time(s) and dismounted it "
            f"{calls['dismount']} time(s); S17-D44 established exactly one mount, not {calls['mount']}"
        )
        assert subpaths, "verification reported no driver subpaths, so staging cannot have reused them"
        assert autounattend, "no answer file text was produced"
        staged_dir = staging / answer_settings().driver_directory
        assert (staged_dir / "viostor.inf").is_file(), (
            f"{staged_dir} carries no viostor.inf, so staging never really ran on the one held mount"
        )

    def test_a_staging_failure_still_leaves_the_mount_balanced(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A ``ProvisioningError`` raised mid-staging must still dismount once.

        The medium carries a ``viostor`` directory - so verification accepts
        it - but no ``amd64`` package under it, so ``require_boot_critical_package``
        raises once staging tries to select a package for every driver. The
        held mount has to survive that exception intact: exactly one mount,
        exactly one dismount, never a mount stranded open.

        Args:
            tmp_path: Per-test temporary directory.
            monkeypatch: Pytest fixture used to replace the real mount calls.
        """
        medium = _build_medium(tmp_path / "virtio", {"vioserial": {"w11": ("amd64",)}, "NetKVM": {"w11": ("amd64",)}})
        (medium / "viostor").mkdir()
        tools = build_bundled_tools(tmp_path / "tools", spawn_helpers=True)
        staging = tmp_path / "staging"
        staging.mkdir()
        calls = {"mount": 0, "dismount": 0}

        def fake_mount(path: Path) -> Path:
            """Record a mount call and hand back the prebuilt medium tree.

            Args:
                path: ISO path the real provisioner would have mounted.

            Returns:
                Path: The prebuilt medium directory, standing in for the
                drive letter a real mount would return.
            """
            del path
            calls["mount"] += 1
            return medium

        def fake_dismount(path: Path) -> None:
            """Record a dismount call.

            Args:
                path: ISO path the real provisioner would have dismounted.
            """
            del path
            calls["dismount"] += 1

        monkeypatch.setattr(provisioner, "mount_disk_image", fake_mount)
        monkeypatch.setattr(provisioner, "dismount_disk_image", fake_dismount)

        with pytest.raises(ProvisioningError, match="carries no viostor package"):
            stage_virtio_medium(staging, answer_settings(), tools / "qemu-ga.exe", tools, medium)

        assert calls == {"mount": 1, "dismount": 1}, (
            f"a staging failure left mount calls={calls['mount']} dismount calls={calls['dismount']}; the medium "
            f"must be dismounted exactly once even when staging raises, never left mounted and never mounted twice"
        )
