# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Shared harness for the tests that exercise the guest-side virtio installer.

:func:`~scripts.sandbox.provision_windows_guest.render_driver_installer`
generates a PowerShell script that a Windows guest runs at first logon. The
script is the deliverable, so the tests around it *run* it - against real
directory trees, with the real PowerShell interpreter, reading back the log it
actually wrote - and parse it with PowerShell's own parser rather than matching
substrings. Both of those need a fair amount of scaffolding, and two test
modules need the same scaffolding, so it lives here.

Everything in this module is real work against the real interpreter: nothing is
stubbed, and no function here decides whether a test passes.
"""

from __future__ import annotations

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
    QEMU_GUEST_AGENT_SPAWN_HELPERS,
    VIRTIO_MARKER_DIRECTORIES,
    WINPE_DRIVER_STAGE_DIRECTORY,
    UnattendSettings,
    render_driver_installer,
)


MEDIUM_FAMILIES: Final[tuple[str, ...]] = ("2k12", "2k16", "2k19", "2k22", "2k25", "w10", "w11")
"""Guest families a real virtio-win medium carries, one directory each."""

MEDIUM_ARCHITECTURES: Final[tuple[str, ...]] = ("amd64", "x86", "ARM64")
"""Architectures a real virtio-win medium carries under every family."""

SELECTION_PREFIX: Final[str] = "selected "
"""Log prefix the installer writes before touching a single package."""

SELECTION_SEPARATOR: Final[str] = "; "
"""How the installer joins the package paths it chose."""

PNPUTIL_COMMAND: Final[str] = "pnputil"
"""Command that performs the install, and the ordering anchor for the AST gates."""

INSTALLER_TIMEOUT_SECONDS: Final[float] = 300.0
"""Ceiling for one interpreter run; a real run finishes in seconds."""

AST_DUMPER: Final[str] = """\
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
foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)) {
    "literal`t$($node.Extent.StartOffset)`t$($node.Value -replace '\\s+', ' ')`t"
}
"""
"""Emits one tab-separated line per syntax node, using PowerShell's own parser."""

_AST_FIELD_COUNT: Final[int] = 4
"""Kind, offset, name and detail - the fields :data:`AST_DUMPER` emits per node."""

_ARGUMENT_SEPARATOR: Final[str] = "|"
"""How :data:`AST_DUMPER` joins a command's arguments."""

_PLACEHOLDER_CATALOG: Final[bytes] = b"this is not a valid catalog\r\n"
"""Stand-in catalog bytes for the gates that never look at a signature."""


@dataclass(frozen=True)
class Node:
    """One syntax node lifted out of the generated installer.

    Attributes:
        kind: ``command``, ``member``, ``declared``, ``used`` or ``literal``.
        offset: Character offset of the node in the script, for ordering.
        name: Command name, variable name, or the invoked member name.
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


def parse_nodes(payload: str) -> tuple[Node, ...]:
    """Turn the AST dumper's output back into typed nodes.

    Args:
        payload: The dumper's standard output.

    Returns:
        tuple[Node, ...]: One entry per emitted syntax node.
    """
    nodes: list[Node] = []
    for line in payload.splitlines():
        fields = line.split("\t")
        if len(fields) != _AST_FIELD_COUNT:
            continue
        kind, offset, name, detail = fields
        nodes.append(Node(kind=kind, offset=int(offset), name=name, detail=detail))
    assert nodes, f"the AST dumper emitted no syntax nodes, so nothing about the generated installer was inspected: {payload!r}"
    return tuple(nodes)


def resolve_powershell() -> Path:
    """Find a PowerShell interpreter able to run the generated script.

    Returns:
        Path: The interpreter's path.
    """
    for candidate in ("pwsh", "powershell"):
        resolved = shutil.which(candidate)
        if resolved is not None:
            return Path(resolved)
    pytest.skip("no PowerShell interpreter on PATH, so the generated installer cannot be run")


def write_installer(directory: Path) -> Path:
    """Write the generated installer out exactly as the answer medium carries it.

    Args:
        directory: Directory to write the script into.

    Returns:
        Path: The written script.
    """
    script = directory / "install-virtio-drivers.ps1"
    script.write_bytes(render_driver_installer().encode("ascii"))
    return script


def run_powershell(shell: Path, script: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    """Run one PowerShell script file and capture both of its streams.

    Args:
        shell: PowerShell interpreter to run the script with.
        script: Script file to run.
        *arguments: Arguments to pass through to the script.

    Returns:
        subprocess.CompletedProcess[str]: The finished process.
    """
    return subprocess.run(
        [str(shell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script), *arguments],
        capture_output=True,
        text=True,
        timeout=INSTALLER_TIMEOUT_SECONDS,
        check=False,
    )


def dump_syntax_tree(shell: Path, script: Path, workspace: Path) -> tuple[Node, ...]:
    """Parse a generated script with PowerShell's own parser.

    Args:
        shell: PowerShell interpreter to run the dumper with.
        script: The script to parse.
        workspace: Directory the dumper itself may be written into.

    Returns:
        tuple[Node, ...]: Every syntax node the dumper reports.
    """
    dumper = workspace / "dump-ast.ps1"
    dumper.write_text(AST_DUMPER, encoding="ascii", newline="\r\n")
    completed = run_powershell(shell, dumper, "-Path", str(script))
    assert completed.returncode == 0, f"PowerShell could not parse the generated installer: {completed.stderr}"
    return parse_nodes(completed.stdout)


def combinations() -> tuple[tuple[str, str], ...]:
    """Enumerate every family and architecture pair a real medium carries.

    Returns:
        tuple[tuple[str, str], ...]: ``(family, architecture)`` pairs.
    """
    return tuple((family, architecture) for family in MEDIUM_FAMILIES for architecture in MEDIUM_ARCHITECTURES)


def build_medium(root: Path, pairs: tuple[tuple[str, str], ...], catalog: Path | None = None) -> Path:
    """Lay out a virtio-win medium holding the given family and architecture pairs.

    The marker directories are the ones the installer uses to recognise a medium
    at all, so they are taken from the provisioner rather than restated here.

    Args:
        root: Directory to populate; created if absent.
        pairs: ``(family, architecture)`` pairs to create under every driver
            directory.
        catalog: Real signed catalog to copy into every package. When omitted
            each package gets placeholder bytes, which is enough for the gates
            that never inspect a signature.

    Returns:
        Path: ``root``, populated.
    """
    payload = catalog.read_bytes() if catalog is not None else _PLACEHOLDER_CATALOG
    for driver in VIRTIO_MARKER_DIRECTORIES:
        for family, architecture in pairs:
            package = root / driver / family / architecture
            package.mkdir(parents=True, exist_ok=True)
            (package / f"{driver}.inf").write_text("this is not a valid inf\r\n", encoding="ascii")
            (package / f"{driver}.cat").write_bytes(payload)
    return root


def answer_settings() -> UnattendSettings:
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
        driver_directory=WINPE_DRIVER_STAGE_DIRECTORY,
        disable_guest_firewall=True,
        answer_script="scripts\\install-guest-agent.cmd",
    )


def bundled_payload(name: str) -> bytes:
    """Produce distinct bytes for one file of a stand-in bundled QEMU tree.

    Every file gets its own content so a gate can prove a specific file was
    copied rather than merely created with the right name.

    Args:
        name: File name the bytes belong to.

    Returns:
        bytes: Content unique to that name.
    """
    return b"MZ" + name.encode("ascii")


def build_bundled_tools(root: Path, *, spawn_helpers: bool = True) -> Path:
    """Lay out a directory shaped like Intellicrack's bundled QEMU tree.

    The agent binary, its runtime libraries and GLib's spawn helpers are the
    files :func:`stage_answer_tree` copies onto the answer medium; the names
    come from the provisioner rather than being restated here.

    Args:
        root: Directory to populate; created if absent.
        spawn_helpers: Whether the tree carries GLib's spawn helpers. QEMU's
            own Windows build does not, which is S17-D47.

    Returns:
        Path: ``root``, populated.
    """
    root.mkdir(parents=True, exist_ok=True)
    names = ["qemu-ga.exe", *QEMU_GUEST_AGENT_LIBRARIES]
    if spawn_helpers:
        names.extend(QEMU_GUEST_AGENT_SPAWN_HELPERS)
    for name in names:
        (root / name).write_bytes(bundled_payload(name))
    return root


def run_installer(shell: Path, script: Path, medium: Path, log: Path) -> tuple[int, list[str]]:
    """Run the generated installer against a medium and read back its log.

    Args:
        shell: PowerShell interpreter to run the script with.
        script: The generated installer.
        medium: Root of the virtio-win medium to install from.
        log: Path the installer should write its log to.

    Returns:
        tuple[int, list[str]]: The installer's exit status and its log lines.
    """
    completed = run_powershell(shell, script, "-Medium", str(medium), "-LogPath", str(log))
    lines = log.read_text(encoding="utf-8").splitlines() if log.is_file() else []
    return completed.returncode, lines


def selected_packages(lines: list[str]) -> list[str]:
    """Extract the package directories the installer reported choosing.

    Args:
        lines: The installer's log lines.

    Returns:
        list[str]: Absolute package paths, empty when it selected nothing.
    """
    for line in lines:
        marker = line.find(SELECTION_PREFIX)
        if marker < 0 or ":" not in line[marker:]:
            continue
        payload = line[marker:].split(":", 1)[1].strip()
        return [entry.strip() for entry in payload.split(SELECTION_SEPARATOR) if entry.strip()]
    return []


def guest_combination(paths: list[str]) -> tuple[str, str]:
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


def first_install_offset(syntax_tree: tuple[Node, ...]) -> int:
    """Locate the earliest ``pnputil`` invocation in a parsed installer.

    Args:
        syntax_tree: The generated installer's syntax nodes.

    Returns:
        int: Character offset of the first install command.
    """
    installs = [node for node in syntax_tree if node.kind == "command" and node.name.lower().startswith(PNPUTIL_COMMAND)]
    assert installs, f"the generated installer never invokes {PNPUTIL_COMMAND}, so it installs nothing at all"
    return min(node.offset for node in installs)
