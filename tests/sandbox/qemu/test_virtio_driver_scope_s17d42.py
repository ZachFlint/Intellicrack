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

Running the script needs a Windows PowerShell interpreter and ``pnputil.exe``,
neither of which the test container is guaranteed to have, so that class is
registered in :mod:`tests._helpers.host_native`.
:class:`TestTheAnswerMediumRunsTheDriverInstaller` is pure file and string work
and runs anywhere.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import pytest

from scripts.sandbox.provision_windows_guest import (
    DEFAULT_ADMIN_CREDENTIAL,
    DEFAULT_ADMIN_USER,
    QEMU_GUEST_AGENT_LIBRARIES,
    VIRTIO_MARKER_DIRECTORIES,
    UnattendSettings,
    first_logon_commands,
    render_driver_installer,
    stage_answer_tree,
)


_MEDIUM_FAMILIES: Final[tuple[str, ...]] = ("2k12", "2k16", "2k19", "2k22", "2k25", "w10", "w11")
"""Guest families a real virtio-win medium carries, one directory each."""

_MEDIUM_ARCHITECTURES: Final[tuple[str, ...]] = ("amd64", "x86", "ARM64")
"""Architectures a real virtio-win medium carries under every family."""

_BLIND_SWEEP_SWITCH: Final[str] = "/subdirs"
"""The ``pnputil`` switch that made the old command install everything."""

_SELECTION_PREFIX: Final[str] = "selected "
"""Log prefix the installer writes before touching a single package."""

_SELECTION_SEPARATOR: Final[str] = "; "
"""How the installer joins the package paths it chose."""

_NOTHING_SELECTED_MARKER: Final[str] = "carries no "
"""Log text the installer writes when the medium holds nothing for this guest."""

_UNTRUSTED_MARKER: Final[str] = "publisher"
"""Log text every branch of the trust step contains."""

_PNPUTIL_COMMAND: Final[str] = "pnputil"
"""Command that performs the install, and the ordering anchor for the AST gate."""

_SIGNATURE_COMMAND: Final[str] = "Get-AuthenticodeSignature"
"""Command that lifts the publisher certificate out of a catalog."""

_TRUSTED_PUBLISHER_STORE: Final[str] = "TrustedPublisher"
"""Certificate store a guest consults before accepting a signed catalog."""

_INSTALLER_TIMEOUT_SECONDS: Final[float] = 300.0

_AST_DUMPER: Final[str] = """\
param([Parameter(Mandatory=$true)][string]$Path)
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
if ($errors -and $errors.Count -gt 0) { throw "the generated script does not parse: $($errors[0].Message)" }
foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $parts = @($node.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.Extent.Text -replace '\\s+', ' ' })
    "command`t$($node.Extent.StartOffset)`t$($node.GetCommandName())`t$($parts -join '|')"
}
foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
    "member`t$($node.Extent.StartOffset)`t$($node.Member.Extent.Text)`t$($node.Extent.Text -replace '\\s+', ' ')"
}
foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] }, $true)) {
    "declared`t$($node.Extent.StartOffset)`t$($node.Name.VariablePath.UserPath)`t"
}
foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
    if ($node.Left -is [System.Management.Automation.Language.VariableExpressionAst]) {
        "declared`t$($node.Extent.StartOffset)`t$($node.Left.VariablePath.UserPath)`t"
    }
}
foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)) {
    "declared`t$($node.Extent.StartOffset)`t$($node.Variable.VariablePath.UserPath)`t"
}
foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
    if ($node.VariablePath.IsDriveQualified) { continue }
    "used`t$($node.Extent.StartOffset)`t$($node.VariablePath.UserPath)`t"
}
"""
"""Emits one tab-separated line per syntax node, using PowerShell's own parser."""

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

_AST_FIELD_COUNT: Final[int] = 4
"""Kind, offset, name and detail - the fields :data:`_AST_DUMPER` emits per node."""

_ARGUMENT_SEPARATOR: Final[str] = "|"
"""How :data:`_AST_DUMPER` joins a command's arguments."""


@dataclass(frozen=True)
class _Node:
    """One syntax node lifted out of the generated installer.

    Attributes:
        kind: ``command`` or ``member``.
        offset: Character offset of the node in the script, for ordering.
        name: Command name, or the invoked member name.
        detail: Joined argument texts, or the member expression's own text.
    """

    kind: str
    offset: int
    name: str
    detail: str

    @property
    def arguments(self) -> tuple[str, ...]:
        """Split the detail field back into individual argument texts.

        Returns:
            tuple[str, ...]: The command's arguments, empty for a member node.
        """
        return tuple(part for part in self.detail.split(_ARGUMENT_SEPARATOR) if part)


def _parse_nodes(payload: str) -> tuple[_Node, ...]:
    """Turn the AST dumper's output back into typed nodes.

    Args:
        payload: The dumper's standard output.

    Returns:
        tuple[_Node, ...]: One entry per emitted syntax node.
    """
    nodes: list[_Node] = []
    for line in payload.splitlines():
        fields = line.split("\t")
        if len(fields) != _AST_FIELD_COUNT:
            continue
        kind, offset, name, detail = fields
        nodes.append(_Node(kind=kind, offset=int(offset), name=name, detail=detail))
    assert nodes, f"the AST dumper emitted no syntax nodes, so nothing about the generated installer was inspected: {payload!r}"
    return tuple(nodes)


def _combinations() -> tuple[tuple[str, str], ...]:
    """Enumerate every family and architecture pair a real medium carries.

    Returns:
        tuple[tuple[str, str], ...]: ``(family, architecture)`` pairs.
    """
    return tuple((family, architecture) for family in _MEDIUM_FAMILIES for architecture in _MEDIUM_ARCHITECTURES)


def _build_medium(root: Path, combinations: tuple[tuple[str, str], ...]) -> Path:
    """Lay out a virtio-win medium holding the given family and architecture pairs.

    The marker directories are the ones the installer uses to recognise a medium
    at all, so they are taken from the provisioner rather than restated here.

    Args:
        root: Directory to populate; created if absent.
        combinations: ``(family, architecture)`` pairs to create under every
            driver directory.

    Returns:
        Path: ``root``, populated.
    """
    for driver in VIRTIO_MARKER_DIRECTORIES:
        for family, architecture in combinations:
            package = root / driver / family / architecture
            package.mkdir(parents=True, exist_ok=True)
            (package / f"{driver}.inf").write_text("this is not a valid inf\r\n", encoding="ascii")
            (package / f"{driver}.cat").write_bytes(b"this is not a valid catalog\r\n")
    return root


def _run_installer(shell: Path, script: Path, medium: Path, log: Path) -> tuple[int, list[str]]:
    """Run the generated installer against a medium and read back its log.

    Args:
        shell: PowerShell interpreter to run the script with.
        script: The generated installer.
        medium: Root of the virtio-win medium to install from.
        log: Path the installer should write its log to.

    Returns:
        tuple[int, list[str]]: The installer's exit status and its log lines.
    """
    completed = subprocess.run(
        [
            str(shell),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-Medium",
            str(medium),
            "-LogPath",
            str(log),
        ],
        capture_output=True,
        text=True,
        timeout=_INSTALLER_TIMEOUT_SECONDS,
        check=False,
    )
    lines = log.read_text(encoding="utf-8").splitlines() if log.is_file() else []
    return completed.returncode, lines


def _selected_packages(lines: list[str]) -> list[str]:
    """Extract the package directories the installer reported choosing.

    Args:
        lines: The installer's log lines.

    Returns:
        list[str]: Absolute package paths, empty when it selected nothing.
    """
    for line in lines:
        marker = line.find(_SELECTION_PREFIX)
        if marker < 0 or ":" not in line[marker:]:
            continue
        payload = line[marker:].split(":", 1)[1].strip()
        return [entry.strip() for entry in payload.split(_SELECTION_SEPARATOR) if entry.strip()]
    return []


def _guest_combination(paths: list[str]) -> tuple[str, str]:
    """Read the one family and architecture the installer chose.

    Args:
        paths: Package directories the installer selected.

    Returns:
        tuple[str, str]: The shared ``(family, architecture)`` suffix.
    """
    suffixes = {tuple(path.replace("\\", "/").rsplit("/", 2)[-2:]) for path in paths}
    assert len(suffixes) == 1, f"the installer mixed families or architectures, which is exactly S17-D43: {paths}"
    family, architecture = next(iter(suffixes))
    return family, architecture


@pytest.fixture
def powershell() -> Path:
    """Resolve a PowerShell interpreter able to run the generated script.

    Returns:
        Path: The interpreter's path.
    """
    for candidate in ("pwsh", "powershell"):
        resolved = shutil.which(candidate)
        if resolved is not None:
            return Path(resolved)
    pytest.skip("no PowerShell interpreter on PATH, so the generated installer cannot be run")


@pytest.fixture
def syntax_tree(powershell: Path, installer: Path, tmp_path: Path) -> tuple[_Node, ...]:
    """Parse the generated installer with PowerShell's own parser.

    Args:
        powershell: Resolved PowerShell interpreter.
        installer: The generated installer script.
        tmp_path: Per-test temporary directory for the dumper.

    Returns:
        tuple[_Node, ...]: Every syntax node the dumper reports.
    """
    dumper = tmp_path / "dump-ast.ps1"
    dumper.write_text(_AST_DUMPER, encoding="ascii", newline="\r\n")
    completed = subprocess.run(
        [
            str(powershell),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(dumper),
            "-Path",
            str(installer),
        ],
        capture_output=True,
        text=True,
        timeout=_INSTALLER_TIMEOUT_SECONDS,
        check=False,
    )
    assert completed.returncode == 0, f"PowerShell could not parse the generated installer: {completed.stderr}"
    return _parse_nodes(completed.stdout)


@pytest.fixture
def installer(tmp_path: Path) -> Path:
    """Write the generated installer out exactly as the answer medium carries it.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        Path: The written script.
    """
    script = tmp_path / "install-virtio-drivers.ps1"
    script.write_bytes(render_driver_installer().encode("ascii"))
    return script


def _settings() -> UnattendSettings:
    """Build answer file settings equivalent to what the provisioner emits.

    Returns:
        UnattendSettings: Settings for a Windows 11 amd64 sandbox guest.
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
        combinations = _combinations()
        medium = _build_medium(tmp_path / "medium", combinations)
        available = len(VIRTIO_MARKER_DIRECTORIES) * len(combinations)

        _status, lines = _run_installer(powershell, installer, medium, tmp_path / "install.log")
        selected = _selected_packages(lines)

        assert selected, f"the installer selected nothing from a medium carrying {available} packages:\n" + "\n".join(lines)
        assert len(selected) == len(VIRTIO_MARKER_DIRECTORIES), (
            f"the installer chose {len(selected)} of {available} packages rather than one per driver, so it is still "
            f"feeding this guest packages built for other editions (S17-D43): {selected}"
        )
        _family, architecture = _guest_combination(selected)
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
        medium = _build_medium(tmp_path / "medium", _combinations())

        _status, lines = _run_installer(powershell, installer, medium, tmp_path / "install.log")

        trust = next((index for index, line in enumerate(lines) if _UNTRUSTED_MARKER in line), None)
        install = next((index for index, line in enumerate(lines) if _PNPUTIL_COMMAND in line), None)
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
        full = _build_medium(tmp_path / "full", _combinations())
        _status, lines = _run_installer(powershell, installer, full, tmp_path / "full.log")
        guest = _guest_combination(_selected_packages(lines))

        remaining = tuple(pair for pair in _combinations() if pair != guest)
        assert remaining, "the medium layout offers no pair other than this guest's, so the discriminator is empty"
        decoys = _build_medium(tmp_path / "decoys", remaining)
        assert any(decoys.rglob("*.inf")), f"the decoy medium holds no packages at all, so installing none of them proves nothing: {decoys}"

        status, decoy_lines = _run_installer(powershell, installer, decoys, tmp_path / "decoys.log")

        assert not _selected_packages(decoy_lines), (
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

        status, lines = _run_installer(powershell, installer, empty, tmp_path / "empty.log")

        assert status != 0, f"the installer accepted {empty} as a virtio-win medium and exited cleanly:\n" + "\n".join(lines)
        assert lines, "the installer refused the path without recording why, leaving an unattended install undiagnosable"

    def test_publisher_trust_is_established_before_pnputil_runs(self, syntax_tree: tuple[_Node, ...]) -> None:
        """The script's syntax tree carries the trust machinery, ahead of the install.

        Args:
            syntax_tree: The generated installer's syntax nodes.
        """
        commands = [node for node in syntax_tree if node.kind == "command"]
        members = [node for node in syntax_tree if node.kind == "member"]

        installs = [node for node in commands if node.name.lower().startswith(_PNPUTIL_COMMAND)]
        assert installs, f"the generated installer never invokes {_PNPUTIL_COMMAND}, so it installs nothing at all"
        for node in installs:
            arguments = [argument.lower() for argument in node.arguments]
            assert _BLIND_SWEEP_SWITCH not in arguments, (
                f"the generated installer still passes {_BLIND_SWEEP_SWITCH} to {_PNPUTIL_COMMAND}, which hands this "
                f"guest every package on the medium (S17-D43): {node}"
            )
        first_install = min(node.offset for node in installs)

        stores = [node for node in members if _TRUSTED_PUBLISHER_STORE in node.detail]
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
                f"the generated installer reaches {label} only after calling {_PNPUTIL_COMMAND}, so the first package "
                f"is offered to an untrusted-publisher prompt (S17-D42)"
            )

    def test_every_variable_is_spelled_the_way_it_was_declared(self, syntax_tree: tuple[_Node, ...]) -> None:
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
        tools = tmp_path / "tools"
        tools.mkdir()
        agent = tools / "qemu-ga.exe"
        agent.write_bytes(b"MZ")
        for library in QEMU_GUEST_AGENT_LIBRARIES:
            (tools / library).write_bytes(b"MZ")

        stage_answer_tree(staging, _settings(), agent, tools)

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
        tools = tmp_path / "tools"
        tools.mkdir()
        agent = tools / "qemu-ga.exe"
        agent.write_bytes(b"MZ")
        for library in QEMU_GUEST_AGENT_LIBRARIES:
            (tools / library).write_bytes(b"MZ")
        settings = _settings()
        stage_answer_tree(staging, settings, agent, tools)
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
