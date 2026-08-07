# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Regression tests for S17-D42 and S17-D43: the guest-side virtio install.

The provisioner used to install the virtio drivers with a single first-logon
command::

    pnputil /add-driver "%d:\*.inf" /subdirs /install

Measured against a real Windows 11 guest and a real virtio-win medium, that one
line fails two different ways at once.

**S17-D42 - the publisher is not trusted.** virtio-win catalogs are Authenticode
signed by Red Hat, and a stock Windows guest carries no Red Hat certificate in
``LocalMachine\TrustedPublisher``. ``pnputil`` therefore either refuses the
package outright ("The publisher of an Authenticode(tm) signed catalog was not
established as trusted") or raises the interactive "Would you like to install
this device software?" dialog. On an unattended install nobody is there to
answer it, and because ``FirstLogonCommands`` are strictly sequential the modal
window blocks every later command - including the one that installs and starts
the QEMU guest agent, which is the whole reason the guest exists.

**S17-D43 - every package on the medium is fed to the guest.** ``/subdirs``
sweeps the entire medium, so a Windows 11 amd64 guest is handed the ARM64, x86,
Server 2012 and Server 2019 packages as well. Each of those fails with "not
present in the specified catalog file. The file is likely corrupt or the victim
of tampering" - alarming, unrelated to the real problem, and buried under fifty
other lines of output.

:func:`~scripts.sandbox.provision_windows_guest.render_driver_installer`
replaces the sweep with a generated PowerShell script that resolves the guest's
own virtio-win family and architecture, lifts the signer out of a catalog on the
medium into the machine store, and installs only the matching packages.

**Why these gates are not assertions on a string.** The script is the deliverable,
so :class:`TestTheGeneratedInstallerScopesToThisGuest` *runs* it - against real
directory trees, with the real ``powershell`` interpreter, reading the log it
actually wrote. Which packages it chose is an observable of that run, not a
property of the source text. The single structural gate,
:meth:`TestTheGeneratedInstallerScopesToThisGuest.test_publisher_trust_is_established_before_pnputil_runs`,
goes through the real PowerShell parser and asserts on the syntax tree rather
than on substrings, so a comment or a log message mentioning ``pnputil`` cannot
satisfy it.

Running the script needs a PowerShell interpreter, which the Windows test
container provides; :func:`~tests.sandbox.qemu.virtio_installer_harness.resolve_powershell`
skips loudly rather than silently passing if one is ever absent.
:class:`TestTheAnswerMediumRunsTheDriverInstaller` is pure file and string work
and runs anywhere.

The chain-trust half of the same generated script is gated separately, in
:mod:`tests.sandbox.qemu.test_virtio_chain_trust_s17d45`.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Final

import pytest

from scripts.sandbox.provision_windows_guest import (
    VIRTIO_MARKER_DIRECTORIES,
    first_logon_commands,
    render_driver_installer,
    stage_answer_tree,
)
from tests.sandbox.qemu.virtio_installer_harness import (
    PNPUTIL_COMMAND,
    Node,
    answer_settings,
    build_bundled_tools,
    build_medium,
    combinations,
    dump_syntax_tree,
    guest_combination,
    resolve_powershell,
    run_installer,
    selected_packages,
    write_installer,
)


if TYPE_CHECKING:
    from pathlib import Path


_BLIND_SWEEP_SWITCH: Final[str] = "/subdirs"
"""The ``pnputil`` switch that made the old command install everything."""

_NOTHING_SELECTED_MARKER: Final[str] = "carries no "
"""Log text the installer writes when the medium holds nothing for this guest."""

_UNTRUSTED_MARKER: Final[str] = "publisher"
"""Log text every branch of the trust step contains."""

_SIGNATURE_COMMAND: Final[str] = "Get-AuthenticodeSignature"
"""Command that lifts the publisher certificate out of a catalog."""

_TRUSTED_PUBLISHER_STORE: Final[str] = "TrustedPublisher"
"""Certificate store a guest consults before accepting a signed catalog."""

_AUTOMATIC_VARIABLES: Final[frozenset[str]] = frozenset({
    "_",
    "args",
    "false",
    "lastexitcode",
    "null",
    "psitem",
    "psscriptroot",
    "true",
})
"""Variables PowerShell itself supplies, so the script never declares them."""


@pytest.fixture
def powershell() -> Path:
    """Resolve a PowerShell interpreter able to run the generated script.

    Returns:
        Path: The interpreter's path.
    """
    return resolve_powershell()


@pytest.fixture
def installer(tmp_path: Path) -> Path:
    """Write the generated installer out exactly as the answer medium carries it.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        Path: The written script.
    """
    return write_installer(tmp_path)


@pytest.fixture
def syntax_tree(powershell: Path, installer: Path, tmp_path: Path) -> tuple[Node, ...]:
    """Parse the generated installer with PowerShell's own parser.

    Args:
        powershell: Resolved PowerShell interpreter.
        installer: The generated installer script.
        tmp_path: Per-test temporary directory for the dumper.

    Returns:
        tuple[Node, ...]: Every syntax node the dumper reports.
    """
    return dump_syntax_tree(powershell, installer, tmp_path)


class TestTheGeneratedInstallerScopesToThisGuest:
    """Run the generated installer and judge it by what it actually installed."""

    def test_only_this_guests_family_and_architecture_is_installed(
        self,
        powershell: Path,
        installer: Path,
        tmp_path: Path,
    ) -> None:
        """A medium holding every package yields exactly one per driver.

        Args:
            powershell: Resolved PowerShell interpreter.
            installer: The generated installer script.
            tmp_path: Per-test temporary directory.
        """
        pairs = combinations()
        medium = build_medium(tmp_path / "medium", pairs)
        available = len(VIRTIO_MARKER_DIRECTORIES) * len(pairs)

        _status, lines = run_installer(powershell, installer, medium, tmp_path / "install.log")
        selected = selected_packages(lines)

        assert selected, f"the installer selected nothing from a medium carrying {available} packages:\n" + "\n".join(lines)
        assert len(selected) == len(VIRTIO_MARKER_DIRECTORIES), (
            f"the installer chose {len(selected)} of {available} packages rather than one per driver, so it is still "
            f"feeding this guest packages built for other editions (S17-D43): {selected}"
        )
        _family, architecture = guest_combination(selected)
        assert architecture.lower() == os.environ["PROCESSOR_ARCHITECTURE"].lower(), (
            f"the installer chose {architecture} packages on a {os.environ['PROCESSOR_ARCHITECTURE']} guest, which "
            f"pnputil rejects as a catalog mismatch (S17-D43): {selected}"
        )

    def test_the_trust_step_runs_before_any_package_is_installed(
        self,
        powershell: Path,
        installer: Path,
        tmp_path: Path,
    ) -> None:
        """The log proves publisher trust was settled before pnputil was called.

        Log lines are appended as the script executes, so their order is the real
        execution order rather than a property of the source text.

        Args:
            powershell: Resolved PowerShell interpreter.
            installer: The generated installer script.
            tmp_path: Per-test temporary directory.
        """
        medium = build_medium(tmp_path / "medium", combinations())

        _status, lines = run_installer(powershell, installer, medium, tmp_path / "install.log")

        trust = next((index for index, line in enumerate(lines) if _UNTRUSTED_MARKER in line), None)
        install = next((index for index, line in enumerate(lines) if PNPUTIL_COMMAND in line), None)
        report = "\n".join(lines)
        assert install is not None, f"the installer never reached pnputil, so nothing about ordering was observed:\n{report}"
        assert trust is not None, (
            f"the installer installed packages without ever reporting on publisher trust, so an untrusted catalog "
            f"still raises the modal dialog that blocks the rest of the unattended install (S17-D42):\n{report}"
        )
        assert trust < install, (
            f"the installer called pnputil at log line {install} before settling publisher trust at line {trust} "
            f"(S17-D42):\n" + "\n".join(lines)
        )

    def test_a_medium_without_this_guests_packages_installs_nothing(
        self,
        powershell: Path,
        installer: Path,
        tmp_path: Path,
    ) -> None:
        """Every other edition on the medium is left alone.

        This is the live discriminator behind the scoping gate. It first asks the
        installer which pair this guest needs, then rebuilds the medium with that
        pair and only that pair removed. A blind sweep would install the survivors;
        a correctly scoped installer must install none of them.

        Args:
            powershell: Resolved PowerShell interpreter.
            installer: The generated installer script.
            tmp_path: Per-test temporary directory.
        """
        full = build_medium(tmp_path / "full", combinations())
        _status, lines = run_installer(powershell, installer, full, tmp_path / "full.log")
        guest = guest_combination(selected_packages(lines))

        remaining = tuple(pair for pair in combinations() if pair != guest)
        assert remaining, "the medium layout offers no pair other than this guest's, so the discriminator is empty"
        decoys = build_medium(tmp_path / "decoys", remaining)
        assert any(decoys.rglob("*.inf")), f"the decoy medium holds no packages at all, so installing none of them proves nothing: {decoys}"

        status, decoy_lines = run_installer(powershell, installer, decoys, tmp_path / "decoys.log")

        assert not selected_packages(decoy_lines), (
            f"the installer selected packages from a medium that carries nothing for {guest[0]}\\{guest[1]}, so it is "
            f"still sweeping other editions into this guest (S17-D43):\n" + "\n".join(decoy_lines)
        )
        assert any(_NOTHING_SELECTED_MARKER in line for line in decoy_lines), (
            "the installer neither selected packages nor reported that the medium held none, so it is not clear it "
            "examined the medium at all:\n" + "\n".join(decoy_lines)
        )
        assert status == 0, f"a medium with nothing for this guest is not an error, but the installer exited {status}"

    def test_an_unrecognisable_medium_is_refused_rather_than_guessed_at(
        self,
        powershell: Path,
        installer: Path,
        tmp_path: Path,
    ) -> None:
        """A caller-supplied path that is not a virtio medium fails loudly.

        Args:
            powershell: Resolved PowerShell interpreter.
            installer: The generated installer script.
            tmp_path: Per-test temporary directory.
        """
        empty = tmp_path / "not-a-medium"
        empty.mkdir()

        status, lines = run_installer(powershell, installer, empty, tmp_path / "empty.log")

        assert status != 0, f"the installer accepted {empty} as a virtio-win medium and exited cleanly:\n" + "\n".join(lines)
        assert lines, "the installer refused the path without recording why, leaving an unattended install undiagnosable"

    def test_publisher_trust_is_established_before_pnputil_runs(self, syntax_tree: tuple[Node, ...]) -> None:
        """The script's syntax tree carries the trust machinery, ahead of the install.

        Args:
            syntax_tree: The generated installer's syntax nodes.
        """
        commands = [node for node in syntax_tree if node.kind == "command"]
        members = [node for node in syntax_tree if node.kind == "member"]

        installs = [node for node in commands if node.name.lower().startswith(PNPUTIL_COMMAND)]
        assert installs, f"the generated installer never invokes {PNPUTIL_COMMAND}, so it installs nothing at all"
        for node in installs:
            arguments = [argument.lower() for argument in node.arguments]
            assert _BLIND_SWEEP_SWITCH not in arguments, (
                f"the generated installer still passes {_BLIND_SWEEP_SWITCH} to {PNPUTIL_COMMAND}, which hands this "
                f"guest every package on the medium (S17-D43): {node}"
            )
        first_install = min(node.offset for node in installs)

        literals = [node for node in syntax_tree if node.kind == "literal"]
        stores = [node for node in literals if node.name == _TRUSTED_PUBLISHER_STORE]
        adds = [node for node in members if node.name == "Add"]
        signatures = [node for node in commands if node.name == _SIGNATURE_COMMAND]
        for label, found in (
            ("a TrustedPublisher store", stores),
            ("a certificate store Add", adds),
            (_SIGNATURE_COMMAND, signatures),
        ):
            assert found, (
                f"the generated installer contains no {label}, so a virtio-win catalog signed by a publisher the guest "
                f"does not trust still raises the modal dialog that blocks the unattended install (S17-D42)"
            )
            assert min(node.offset for node in found) < first_install, (
                f"the generated installer reaches {label} only after calling {PNPUTIL_COMMAND}, so the first package "
                f"is offered to an untrusted-publisher prompt (S17-D42)"
            )

    def test_every_variable_is_spelled_the_way_it_was_declared(self, syntax_tree: tuple[Node, ...]) -> None:
        """No variable is read under a name nothing ever assigns.

        PowerShell resolves variable names case-insensitively, so a script that
        reads ``$medium`` while its parameter is ``$Medium`` silently binds to
        the parameter. That hides a whole class of bug in a generated script: the
        two names agree for a caller who passes the parameter and diverge for one
        who does not, which is exactly the split between running this installer by
        hand and running it the way the guest does. Requiring an exact-case
        declaration for every read collapses that difference.

        Args:
            syntax_tree: The generated installer's syntax nodes.
        """
        declared = {node.name for node in syntax_tree if node.kind == "declared"}
        used = {node.name for node in syntax_tree if node.kind == "used"}
        assert declared, "the generated installer declares no variables at all, so this gate inspected nothing"
        assert used, "the generated installer reads no variables at all, so this gate inspected nothing"

        undeclared = sorted(name for name in used if name not in declared and name.lower() not in _AUTOMATIC_VARIABLES)
        collisions = {name: sorted(other for other in declared if other.lower() == name.lower()) for name in undeclared}
        assert not undeclared, (
            f"the generated installer reads {undeclared} without ever declaring those exact names. "
            f"Case-insensitive matches that would silently absorb them: {collisions}"
        )


class TestTheAnswerMediumRunsTheDriverInstaller:
    """The installer has to reach the guest and be invoked once it is there."""

    def test_the_installer_is_staged_on_the_answer_medium(self, tmp_path: Path) -> None:
        """The answer medium carries the generated script verbatim.

        Args:
            tmp_path: Per-test temporary directory.
        """
        staging = tmp_path / "staging"
        staging.mkdir()
        tools = build_bundled_tools(tmp_path / "tools")

        stage_answer_tree(staging, answer_settings(), tools / "qemu-ga.exe", tools, tmp_path / "virtio-win.iso")

        expected = render_driver_installer().encode("ascii")
        staged = [path for path in staging.rglob("*") if path.is_file() and path.read_bytes() == expected]
        assert len(staged) == 1, (
            f"the answer medium carries {len(staged)} copies of the driver installer rather than one, so the guest "
            f"either cannot run it or runs it twice (S17-D42): {[str(path) for path in staged]}"
        )

    def test_a_first_logon_command_runs_the_staged_installer(self, tmp_path: Path) -> None:
        """The guest is told to run the script the medium carries.

        The relative path is taken from the staged tree rather than restated, so
        moving the script without updating the command fails this gate.

        Args:
            tmp_path: Per-test temporary directory.
        """
        staging = tmp_path / "staging"
        staging.mkdir()
        tools = build_bundled_tools(tmp_path / "tools")
        settings = answer_settings()
        stage_answer_tree(staging, settings, tools / "qemu-ga.exe", tools, tmp_path / "virtio-win.iso")
        expected = render_driver_installer().encode("ascii")
        staged = next(path for path in staging.rglob("*") if path.is_file() and path.read_bytes() == expected)
        relative = str(staged.relative_to(staging)).replace("/", "\\")

        commands = [command for command, _description in first_logon_commands(settings)]

        assert any(relative in command for command in commands), (
            f"nothing in the guest's first-logon sequence runs {relative}, so the virtio drivers are never installed "
            f"and the medium carries a script no one executes (S17-D42): {commands}"
        )
        assert not any(_BLIND_SWEEP_SWITCH in command.lower() for command in commands), (
            f"a first-logon command still sweeps the whole medium with {_BLIND_SWEEP_SWITCH}, which blocks the rest "
            f"of the sequence behind an untrusted-publisher dialog (S17-D42, S17-D43): {commands}"
        )
