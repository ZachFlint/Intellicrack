# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gates for S17-D47: the guest agent cannot spawn without GLib's helper.

``guest-exec`` is the only way Intellicrack runs anything inside a Windows
guest - :meth:`~intellicrack.sandbox.qemu.QEMUSandbox._mount_guest_shared_volume`
and :meth:`~intellicrack.sandbox.qemu.QEMUSandbox._bootstrap_guest_agent` both
run entirely through it - and qemu-ga implements it with GLib's
``g_spawn_async_with_pipes``. On Windows GLib never spawns directly: it
re-launches through ``gspawn-win64-helper.exe``, which it resolves beside its
own ``libglib-2.0-0.dll``. QEMU's Windows build ships no such helper, so a guest
staged from that build alone answers **every** command with
``Failed to execute helper program (No such file or directory)`` while still
advertising ``guest-exec`` as enabled.

That was measured on a live guest, and injecting the two helpers over the
agent's own file commands flipped the identical probe from refused to
``exitcode=0`` with nothing else changed. The helpers come from the virtio-win
medium's guest agent package, which the provisioner already locates and mounts.

These gates therefore judge the staged tree the way GLib does - by what sits
beside the library that performs the lookup - rather than by the presence of a
file name somewhere. The container gates work on real directory trees; the
host-native class unpacks the real package off the real medium and validates
that the files it produced are genuine executables.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Final

import pytest

from scripts.sandbox.provision_windows_guest import (
    QEMU_GUEST_AGENT_SPAWN_HELPERS,
    ProvisioningError,
    available_drive_roots,
    collect_named_files,
    render_guest_agent_installer,
    require_virtio_media,
    select_guest_agent_package,
    stage_answer_tree,
    stage_spawn_helpers,
)
from tests.sandbox.qemu.virtio_installer_harness import answer_settings, build_bundled_tools, bundled_payload


_GLIB_LIBRARY: Final[str] = "libglib-2.0-0.dll"
"""The library whose directory GLib searches for the spawn helper."""

_COPY_COMMAND: Final[str] = "copy"
"""The batch command that carries the staged agent tree into the guest."""

_SCRIPT_DIRECTORY_VARIABLE: Final[str] = "%~dp0"
"""Batch expansion for the directory the answer medium put the script in."""

_WILDCARD: Final[str] = "*"
"""The one glob character the installer's copy pattern is allowed to use."""

_PACKAGE_DIRECTORY: Final[str] = "guest-agent"
"""Directory a virtio-win medium keeps its agent packages in."""

_PAYLOAD_SUBDIRECTORY: Final[str] = "QEMU Guest Agent/Qemu-ga"
"""Where an unpacked agent package puts its files, relative to the target."""

_PE_SIGNATURE: Final[bytes] = b"PE\x00\x00"
"""Signature at the offset an MS-DOS stub points to in a real executable."""

_DOS_SIGNATURE: Final[bytes] = b"MZ"
"""First two bytes of any Windows executable."""

_PE_OFFSET_FIELD: Final[int] = 0x3C
"""Where the MS-DOS header stores the file offset of the PE signature."""

_SCAN_DEPTH: Final[int] = 4
"""Directory depth the host-native medium search is allowed to reach."""

_SCAN_BUDGET: Final[int] = 20_000
"""Directories the host-native medium search may enumerate."""


def _staged_agent_directory(staging: Path) -> Path:
    """Locate the staged agent directory by finding the GLib library in it.

    Args:
        staging: Root of the staged answer tree.

    Returns:
        Path: The directory holding the staged GLib library.
    """
    libraries = [path for path in staging.rglob(_GLIB_LIBRARY) if path.is_file()]
    assert len(libraries) == 1, (
        f"the answer medium carries {len(libraries)} copies of {_GLIB_LIBRARY}, so this gate cannot tell which one GLib would load"
    )
    return libraries[0].parent


def _copy_source(installer: str) -> str:
    """Extract the source pattern the guest-side installer copies from.

    Args:
        installer: The generated batch file.

    Returns:
        str: The first quoted argument of its copy command.

    Raises:
        AssertionError: If the installer copies nothing into the guest.
    """
    for line in installer.splitlines():
        if not line.strip().lower().startswith(_COPY_COMMAND):
            continue
        quoted = line.split('"')
        assert len(quoted) > 1, f"the copy command in the generated installer quotes nothing, so its source cannot be resolved: {line!r}"
        return quoted[1]
    message = f"the generated guest agent installer runs no {_COPY_COMMAND} command, so nothing staged reaches the guest"
    raise AssertionError(message)


def _is_executable(path: Path) -> bool:
    """Report whether a file is a real Windows executable image.

    Args:
        path: File to inspect.

    Returns:
        bool: True when the file carries an MS-DOS header pointing at a PE
        signature.
    """
    payload = path.read_bytes()
    if not payload.startswith(_DOS_SIGNATURE) or len(payload) < _PE_OFFSET_FIELD + struct.calcsize("<I"):
        return False
    (offset,) = struct.unpack_from("<I", payload, _PE_OFFSET_FIELD)
    return payload[offset : offset + len(_PE_SIGNATURE)] == _PE_SIGNATURE


class TestTheAnswerMediumCarriesTheSpawnHelpers:
    """A staged answer tree has to give the guest a runnable agent."""

    def test_the_staged_agent_directory_carries_both_helpers(self, tmp_path: Path) -> None:
        """Both helpers are copied onto the medium, byte for byte.

        Args:
            tmp_path: Per-test temporary directory.
        """
        staging = tmp_path / "staging"
        staging.mkdir()
        tools = build_bundled_tools(tmp_path / "tools")

        stage_answer_tree(staging, answer_settings(), tools / "qemu-ga.exe", tools, tmp_path / "virtio-win.iso")

        agent_dir = _staged_agent_directory(staging)
        missing = [name for name in QEMU_GUEST_AGENT_SPAWN_HELPERS if not (agent_dir / name).is_file()]
        assert not missing, (
            f"the answer medium carries no {missing} beside the staged agent, so qemu-ga answers every guest-exec with "
            f"'Failed to execute helper program' and the whole Windows bootstrap is dead (S17-D47): "
            f"{sorted(path.name for path in agent_dir.iterdir())}"
        )
        for name in QEMU_GUEST_AGENT_SPAWN_HELPERS:
            assert (agent_dir / name).read_bytes() == bundled_payload(name), (
                f"{name} on the answer medium is not the file that was staged from the bundled tree"
            )

    def test_the_helpers_sit_beside_the_library_that_looks_them_up(self, tmp_path: Path) -> None:
        """GLib resolves the helper next to its own DLL, so that is where it goes.

        Args:
            tmp_path: Per-test temporary directory.
        """
        staging = tmp_path / "staging"
        staging.mkdir()
        tools = build_bundled_tools(tmp_path / "tools")

        stage_answer_tree(staging, answer_settings(), tools / "qemu-ga.exe", tools, tmp_path / "virtio-win.iso")

        library = next(path for path in staging.rglob(_GLIB_LIBRARY) if path.is_file())
        for name in QEMU_GUEST_AGENT_SPAWN_HELPERS:
            staged = [path for path in staging.rglob(name) if path.is_file()]
            assert staged, f"{name} is nowhere on the answer medium (S17-D47)"
            assert staged[0].parent == library.parent, (
                f"{name} is staged in {staged[0].parent} while {_GLIB_LIBRARY} is in {library.parent}. "
                "GLib only searches its own directory, so a helper anywhere else is a helper that does not exist."
            )

    def test_the_guest_copy_command_actually_covers_the_helpers(self, tmp_path: Path) -> None:
        """Expanding the installer's own copy pattern reaches both helpers.

        The pattern is taken out of the generated batch file and expanded
        against the real staged tree, so a copy that stops covering the helpers
        fails here rather than at first boot.

        Args:
            tmp_path: Per-test temporary directory.
        """
        staging = tmp_path / "staging"
        staging.mkdir()
        tools = build_bundled_tools(tmp_path / "tools")
        stage_answer_tree(staging, answer_settings(), tools / "qemu-ga.exe", tools, tmp_path / "virtio-win.iso")
        script = next(path for path in staging.rglob("install-guest-agent.cmd") if path.is_file())

        pattern = Path(
            _copy_source(render_guest_agent_installer())
            .replace(_SCRIPT_DIRECTORY_VARIABLE, f"{script.parent}{os.sep}")
            .replace("\\", os.sep),
        )
        assert not any(_WILDCARD in part for part in pattern.parent.parts), (
            f"the copy pattern wildcards a directory component, which this expansion cannot reproduce: {pattern}"
        )
        copied = {os.path.normcase(os.path.realpath(match)) for match in pattern.parent.glob(pattern.name)}

        assert copied, f"the installer's copy pattern {pattern!r} matches nothing in the staged tree, so the guest receives no agent at all"
        for name in QEMU_GUEST_AGENT_SPAWN_HELPERS:
            staged = next(path for path in staging.rglob(name) if path.is_file())
            assert os.path.normcase(os.path.realpath(staged)) in copied, (
                f"the guest-side installer copies {sorted(copied)} and never picks up {staged}, so the helper is staged "
                "on the medium but never reaches the guest (S17-D47)"
            )


class TestTheHelperSourceIsFoundOnTheMedium:
    """The helpers are unpacked from the medium the provisioner already needs."""

    def test_the_64_bit_package_is_the_one_selected(self, tmp_path: Path) -> None:
        """A medium carrying both architectures yields the 64-bit package.

        Args:
            tmp_path: Per-test temporary directory.
        """
        medium = tmp_path / "medium"
        packages = medium / _PACKAGE_DIRECTORY
        packages.mkdir(parents=True)
        (packages / "qemu-ga-i386.msi").write_bytes(b"32-bit package")
        (packages / "qemu-ga-x86_64.msi").write_bytes(b"64-bit package")

        selected = select_guest_agent_package(medium)

        assert selected.read_bytes() == b"64-bit package", (
            f"the provisioner picked {selected.name} for an amd64 guest. A 32-bit helper cannot re-launch a 64-bit "
            "qemu-ga, so guest-exec would still fail."
        )

    def test_a_medium_without_a_64_bit_package_is_refused_by_name(self, tmp_path: Path) -> None:
        """Nothing usable on the medium is reported rather than passed over.

        Args:
            tmp_path: Per-test temporary directory.
        """
        medium = tmp_path / "medium"
        packages = medium / _PACKAGE_DIRECTORY
        packages.mkdir(parents=True)
        (packages / "qemu-ga-i386.msi").write_bytes(b"32-bit package")

        with pytest.raises(ProvisioningError) as failure:
            select_guest_agent_package(medium)

        message = str(failure.value)
        for name in QEMU_GUEST_AGENT_SPAWN_HELPERS:
            assert name in message, f"the failure never names {name}, so an operator cannot tell what the guest will be missing: {message}"

    def test_the_helpers_are_found_at_the_depth_the_package_unpacks_to(self, tmp_path: Path) -> None:
        """An unpacked package nests its files, so the search has to recurse.

        Args:
            tmp_path: Per-test temporary directory.
        """
        payload = tmp_path / "payload"
        nested = payload / _PAYLOAD_SUBDIRECTORY
        nested.mkdir(parents=True)
        for name in QEMU_GUEST_AGENT_SPAWN_HELPERS:
            (nested / name).write_bytes(bundled_payload(name))

        located = collect_named_files(payload, (*QEMU_GUEST_AGENT_SPAWN_HELPERS, "not-in-this-package.exe"))

        assert set(located) == set(QEMU_GUEST_AGENT_SPAWN_HELPERS), (
            f"the search did not reach {_PAYLOAD_SUBDIRECTORY}, where a real package puts its files: {sorted(located)}"
        )
        for name, found in located.items():
            assert found.read_bytes() == bundled_payload(name), f"{name} resolved to the wrong file: {found}"


class TestTheRealVirtioMediumYieldsTheSpawnHelpers:
    """Unpack the real medium and check what comes out is actually runnable."""

    def test_the_real_medium_produces_real_executables(self, tmp_path: Path) -> None:
        """The staged helpers are genuine PE images from the real package.

        The bundled tools tree is deliberately empty so the medium is the only
        possible source, which is exactly the situation on this host: QEMU's
        Windows build ships no ``gspawn`` helper at all.

        Args:
            tmp_path: Per-test temporary directory.
        """
        virtio_iso = require_virtio_media(None, available_drive_roots(), _SCAN_DEPTH, _SCAN_BUDGET, verify_contents=False)
        empty_tools = tmp_path / "tools"
        empty_tools.mkdir()
        destination = tmp_path / "agent"
        destination.mkdir()

        staged = stage_spawn_helpers(empty_tools, virtio_iso, destination)

        assert len(staged) == len(QEMU_GUEST_AGENT_SPAWN_HELPERS), (
            f"the provisioner staged {len(staged)} helpers from {virtio_iso} rather than {len(QEMU_GUEST_AGENT_SPAWN_HELPERS)}"
        )
        for path in staged:
            assert path.is_file(), f"{path.name} was reported as staged from {virtio_iso} but is not on disk (S17-D47)"
            assert _is_executable(path), (
                f"{path} is not a Windows executable, so GLib cannot re-launch through it: first bytes {path.read_bytes()[:16]!r}"
            )
