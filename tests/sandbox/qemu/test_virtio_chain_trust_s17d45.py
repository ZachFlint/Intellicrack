# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Regression tests for S17-D45: chain trust, and what ``pnputil`` 259 means.

Measured on a real Windows 11 guest installing from a real virtio-win 0.1.285
medium, with the S17-D42 publisher-trust step in place::

    publisher CN=Microsoft Windows Hardware Compatibility Publisher... signs balloon.cat
    publisher CN=Red Hat Inc., OU=Dev, O=virtio-win signs smbus.cat
    trusted 3 publisher certificates
    pnputil F:\smbus\w11\amd64 exit -2146762487
    Failed to add driver package: A certificate chain processed, but terminated
    in a root certificate which is not trusted by the trust provider.
    installed 12 of 17 packages

Two independent defects sit in that excerpt.

**The signer is not the root.** Adding a signer to ``TrustedPublisher`` settles
who signed the catalog; it settles nothing about whether the guest can build a
chain to a root it trusts. Sixteen of the seventeen packages are signed by
``CN=Microsoft Windows Hardware Compatibility Publisher`` and chain three
elements to ``Microsoft Root Certificate Authority 2010``, which every Windows
install already trusts. ``smbus.cat`` is signed by ``CN=Red Hat Inc., OU=Dev,
O=virtio-win``, a self-signed development certificate whose chain is one element
long and terminates ``UntrustedRoot``; that package fails ``0x800B0109``
``CERT_E_UNTRUSTEDROOT`` no matter how trusted its publisher is.

The fix builds the chain for every signer and places each element in the store
its position calls for - terminal element in ``Root``, intermediates in ``CA``,
signer in ``TrustedPublisher`` - and touches ``Root`` only when the chain does
not already validate. That second half matters as much as the first: silently
adding roots for catalogs the guest can already validate would turn a driver
installer into a machine-wide trust-store rewriter.

**259 is not a failure.** ``ERROR_NO_MORE_ITEMS`` from ``pnputil`` means the
package is staged and no present device needed it - the expected result for the
storage and serial drivers WinPE already injected to make the installer's own
disk visible. Counting it as a failure is what turned a completely successful
install into "installed 12 of 17".

**How these gates avoid restating the code they test.** Both decisions live in
generated PowerShell functions, and the probes here lift those functions out of
the generated script with PowerShell's own parser and execute that exact source.
Nothing about the policy is written twice. The inputs are real: a certificate
taken from this machine's own ``LocalMachine\Root`` store for the chain that
already validates, a freshly minted self-signed certificate for the chain that
does not, and the real ``pnputil`` statuses a Windows guest returns.

Whether an input really is trusted is decided by an oracle the installer does
not share - ``X509Chain.Build`` returning true - so a precondition assertion
fails loudly rather than letting either direction pass vacuously.

On top of that, :meth:`TestTheWholeCertificateChainIsTrusted.test_an_untrusted_catalog_is_rooted_when_the_whole_script_runs`
runs the entire installer against a medium carrying a genuinely signed catalog,
which is what proves the decision function is wired into the script rather than
merely present in it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from scripts.sandbox.provision_windows_guest import DRIVER_ALREADY_CURRENT_EXIT
from tests.sandbox.qemu.virtio_installer_harness import (
    PNPUTIL_COMMAND,
    Node,
    build_medium,
    combinations,
    dump_syntax_tree,
    first_install_offset,
    resolve_powershell,
    run_installer,
    run_powershell,
    selected_packages,
    write_installer,
)


if TYPE_CHECKING:
    import subprocess


_PLACEMENT_PREFIX: Final[str] = "placing "
"""Log prefix the installer writes before touching a certificate store."""

_PLACEMENT_SEPARATOR: Final[str] = " in "
"""What separates the certificate subject from its destination store."""

_ROOT_STORE: Final[str] = "Root"
"""Machine store that decides which certificate authorities the guest believes."""

_TRUSTED_PUBLISHER_STORE: Final[str] = "TrustedPublisher"
"""Machine store that decides which publishers the guest accepts drivers from."""

_CATALOG_SOURCE: Final[Path] = Path("C:/Windows/System32/CatRoot")
"""Where Windows keeps the signed catalogs it validates its own packages against."""

_TEST_PUBLISHER_SUBJECT: Final[str] = "CN=Intellicrack virtio chain trust gate"
"""Subject of the throwaway certificate the untrusted-root direction signs with."""

_TRUST_POLICY_FUNCTION: Final[str] = "Get-TrustPlacement"
"""Generated function that decides which stores a signer's chain calls for."""

_EXIT_TALLY_FUNCTION: Final[str] = "Test-DriverExit"
"""Generated function that decides whether a ``pnputil`` status counts as failure."""

_CHAIN_BUILD_MEMBER: Final[str] = "Build"
"""The ``X509Chain`` member that decides whether the guest can validate a catalog."""

_ACCEPTED: Final[str] = "accepted"
"""What the exit-status probe prints when the generated policy tolerates a status."""

_REJECTED: Final[str] = "rejected"
"""What the exit-status probe prints when the generated policy counts a failure."""

_TRUSTED_MODE: Final[str] = "trusted"
"""Probe mode that feeds the policy a certificate this machine already validates."""

_SELF_SIGNED_MODE: Final[str] = "selfsigned"
"""Probe mode that feeds the policy a certificate nothing on this machine trusts."""

_FIELD_COUNT: Final[int] = 3
"""Fields every probe line carries: kind, first value, second value."""

_LIFT_PREAMBLE: Final[str] = """\
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
if ($errors -and $errors.Count -gt 0) { throw "the generated script does not parse: $($errors[0].Message)" }
$found = @($ast.FindAll({
    param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq '%s'
}, $true))
if ($found.Count -ne 1) { throw "the generated installer defines %s $($found.Count) times, not once" }
Invoke-Expression $found[0].Extent.Text
"""
"""Lifts one function out of the generated script and defines it here, verbatim."""

_TRUST_POLICY_PROBE: Final[str] = (
    "param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][string]$Mode, [string]$Subject = '')\r\n"
    + _LIFT_PREAMBLE % (_TRUST_POLICY_FUNCTION, _TRUST_POLICY_FUNCTION)
    + """\
$certificate = $null
if ($Mode -eq 'trusted') {
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
    $store.Open('ReadOnly')
    try {
        foreach ($candidate in $store.Certificates) {
            $probe = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
            $probe.ChainPolicy.RevocationMode = 'NoCheck'
            if ($probe.Build($candidate)) { $certificate = $candidate; break }
        }
    } finally {
        $store.Close()
    }
    if ($null -eq $certificate) { throw 'no certificate in LocalMachine\\Root validates on this machine' }
} else {
    $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject -CertStoreLocation Cert:\\CurrentUser\\My
}
try {
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $chain.ChainPolicy.RevocationMode = 'NoCheck'
    $validates = $chain.Build($certificate)
    "input`t$validates`t$($certificate.Thumbprint)"
    foreach ($placement in @(Get-TrustPlacement $certificate)) {
        "placement`t$($placement.Store)`t$($placement.Certificate.Thumbprint)"
    }
} finally {
    if ($Mode -ne 'trusted') { Remove-Item -Path "Cert:\\CurrentUser\\My\\$($certificate.Thumbprint)" -Force }
}
"""
)
"""Runs the generated trust policy against a real certificate of a chosen kind."""

_EXIT_POLICY_PROBE: Final[str] = (
    "param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][int]$Code)\r\n"
    + _LIFT_PREAMBLE % (_EXIT_TALLY_FUNCTION, _EXIT_TALLY_FUNCTION)
    + "if (Test-DriverExit $Code) { 'accepted' } else { 'rejected' }\r\n"
)
"""Runs the generated exit-status policy against a real ``pnputil`` status."""

_SELF_SIGNED_CATALOG_PROBE: Final[str] = """\
param(
    [Parameter(Mandatory=$true)][string]$Template,
    [Parameter(Mandatory=$true)][string]$Destination,
    [Parameter(Mandatory=$true)][string]$Subject
)
$ErrorActionPreference = 'Stop'
Copy-Item -Path $Template -Destination $Destination -Force
$certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject -CertStoreLocation Cert:\\CurrentUser\\My
try {
    $result = Set-AuthenticodeSignature -FilePath $Destination -Certificate $certificate -HashAlgorithm SHA256
    if ($result.Status -eq 'HashMismatch') { throw "signing produced a mismatched catalog: $($result.StatusMessage)" }
    $signature = Get-AuthenticodeSignature -FilePath $Destination
    if ($null -eq $signature.SignerCertificate) { throw 'the re-signed catalog carries no signer certificate' }
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $chain.ChainPolicy.RevocationMode = 'NoCheck'
    if ($chain.Build($signature.SignerCertificate)) {
        throw 'this machine already validates the throwaway chain, so the gate would prove nothing'
    }
    $signature.SignerCertificate.Subject
} finally {
    Remove-Item -Path "Cert:\\CurrentUser\\My\\$($certificate.Thumbprint)" -Force
}
"""
"""Re-signs a real catalog with a throwaway certificate no store on this machine trusts."""


@dataclass(frozen=True)
class _Placement:
    """One store the generated trust policy decided a certificate belongs in.

    Attributes:
        store: Certificate store name.
        thumbprint: Thumbprint of the certificate placed there.
    """

    store: str
    thumbprint: str


@dataclass(frozen=True)
class _PolicyRun:
    """What the generated trust policy did with one real certificate.

    Attributes:
        validates: Whether ``X509Chain.Build`` accepted the input outright.
        thumbprint: Thumbprint of the certificate handed to the policy.
        placements: Every store the policy decided to write, in order.
    """

    validates: bool
    thumbprint: str
    placements: tuple[_Placement, ...]

    @property
    def stores(self) -> tuple[str, ...]:
        """List the stores the policy chose.

        Returns:
            tuple[str, ...]: Store names, in decision order.
        """
        return tuple(placement.store for placement in self.placements)


def _parse_policy_run(payload: str) -> _PolicyRun:
    """Turn the trust probe's output into a typed result.

    Args:
        payload: The probe's standard output.

    Returns:
        _PolicyRun: What the policy was given and what it decided.
    """
    validates: bool | None = None
    thumbprint = ""
    placements: list[_Placement] = []
    for line in payload.splitlines():
        fields = line.split("\t")
        if len(fields) != _FIELD_COUNT:
            continue
        kind, first, second = fields
        if kind == "input":
            validates = first.strip().lower() == "true"
            thumbprint = second.strip()
        elif kind == "placement":
            placements.append(_Placement(store=first.strip(), thumbprint=second.strip()))
    assert validates is not None, f"the trust probe never reported the certificate it started from: {payload!r}"
    return _PolicyRun(validates=validates, thumbprint=thumbprint, placements=tuple(placements))


def _placements_from_log(lines: list[str]) -> list[str]:
    """Read the certificate stores the installer reported placing a certificate in.

    Args:
        lines: The installer's log lines.

    Returns:
        list[str]: One store name per placement, in the order they were made.
    """
    stores: list[str] = []
    for line in lines:
        marker = line.find(_PLACEMENT_PREFIX)
        if marker < 0 or _PLACEMENT_SEPARATOR not in line[marker:]:
            continue
        stores.append(line[marker:].rsplit(_PLACEMENT_SEPARATOR, 1)[1].strip())
    return stores


def _probe(shell: Path, workspace: Path, name: str, source: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    """Write one probe script out and run it.

    Args:
        shell: PowerShell interpreter to run the probe with.
        workspace: Directory the probe is written into.
        name: File name for the probe.
        source: The probe's PowerShell source.
        *arguments: Arguments to pass to the probe.

    Returns:
        subprocess.CompletedProcess[str]: The finished process.
    """
    script = workspace / name
    script.write_text(source, encoding="ascii", newline="\r\n")
    return run_powershell(shell, script, *arguments)


def _run_trust_policy(shell: Path, installer: Path, workspace: Path, mode: str) -> _PolicyRun:
    """Execute the generated trust policy against a real certificate.

    Args:
        shell: PowerShell interpreter to run the probe with.
        installer: The generated installer to lift the policy out of.
        workspace: Directory the probe is written into.
        mode: ``trusted`` or ``selfsigned``.

    Returns:
        _PolicyRun: What the policy was given and what it decided.
    """
    completed = _probe(
        shell,
        workspace,
        f"trust-policy-{mode}.ps1",
        _TRUST_POLICY_PROBE,
        "-Path",
        str(installer),
        "-Mode",
        mode,
        "-Subject",
        _TEST_PUBLISHER_SUBJECT,
    )
    assert completed.returncode == 0, f"could not run {_TRUST_POLICY_FUNCTION} in {mode} mode: {completed.stderr}"
    return _parse_policy_run(completed.stdout)


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
def catalog_template() -> Path:
    """Pick a real Windows catalog to re-sign, so the gate signs a real format.

    Returns:
        Path: A catalog file shipped with this Windows install.
    """
    assert _CATALOG_SOURCE.is_dir(), f"{_CATALOG_SOURCE} does not exist, so there is no real catalog to re-sign"
    catalogs = sorted(_CATALOG_SOURCE.rglob("*.cat"))
    assert catalogs, f"{_CATALOG_SOURCE} carries no catalogs, so there is no real catalog to re-sign"
    return catalogs[0]


class TestTheWholeCertificateChainIsTrusted:
    """Judge the generated trust policy by what it decides for real certificates."""

    def test_a_chain_this_machine_already_validates_stays_out_of_the_root_store(
        self,
        powershell: Path,
        installer: Path,
        tmp_path: Path,
    ) -> None:
        """A certificate the machine already trusts causes no root-store write.

        Args:
            powershell: Resolved PowerShell interpreter.
            installer: The generated installer script.
            tmp_path: Per-test temporary directory.
        """
        run = _run_trust_policy(powershell, installer, tmp_path, _TRUSTED_MODE)

        assert run.validates, (
            "the certificate this gate started from does not validate on this machine, so it cannot show what the "
            "policy does with one that does"
        )
        assert run.stores, f"{_TRUST_POLICY_FUNCTION} decided on no store at all, so the publisher is never trusted"
        assert _TRUSTED_PUBLISHER_STORE in run.stores, (
            f"{_TRUST_POLICY_FUNCTION} never places the signer in {_TRUSTED_PUBLISHER_STORE}, so pnputil still meets an "
            f"untrusted publisher and raises the modal dialog that blocks the unattended install: {run.stores}"
        )
        assert _ROOT_STORE not in run.stores, (
            f"{_TRUST_POLICY_FUNCTION} adds a certificate to the machine {_ROOT_STORE} store for a chain this machine "
            f"already validates. A driver installer must not rewrite machine-wide trust it does not need to "
            f"(S17-D45): {run.stores}"
        )

    def test_a_chain_that_terminates_in_an_untrusted_root_gets_that_root_trusted(
        self,
        powershell: Path,
        installer: Path,
        tmp_path: Path,
    ) -> None:
        """A self-signed signer has its own root trusted rather than failing 0x800B0109.

        This is the live discriminator: the certificate is real and freshly
        minted, its chain terminates in itself, and nothing on this machine
        trusts it - exactly the shape of virtio-win's ``smbus.cat``.

        Args:
            powershell: Resolved PowerShell interpreter.
            installer: The generated installer script.
            tmp_path: Per-test temporary directory.
        """
        run = _run_trust_policy(powershell, installer, tmp_path, _SELF_SIGNED_MODE)

        assert not run.validates, (
            "the freshly minted certificate this gate started from already validates on this machine, so it cannot "
            "show what the policy does with one that does not"
        )
        assert _ROOT_STORE in run.stores, (
            f"{_TRUST_POLICY_FUNCTION} trusts the publisher of a chain that terminates in an untrusted root without "
            f"ever trusting that root, so pnputil still fails the package 0x800B0109 CERT_E_UNTRUSTEDROOT - which is "
            f"exactly how virtio-win's smbus package was lost (S17-D45): {run.stores}"
        )
        rooted = [placement for placement in run.placements if placement.store == _ROOT_STORE]
        assert [placement.thumbprint for placement in rooted] == [run.thumbprint], (
            f"{_TRUST_POLICY_FUNCTION} rooted {[placement.thumbprint for placement in rooted]} rather than the chain's "
            f"own terminal certificate {run.thumbprint}, so the guest still cannot validate the catalog (S17-D45)"
        )

    def test_an_untrusted_catalog_is_rooted_when_the_whole_script_runs(
        self,
        powershell: Path,
        installer: Path,
        catalog_template: Path,
        tmp_path: Path,
    ) -> None:
        """The whole installer, run for real, reaches the root store for such a catalog.

        The two gates above prove the policy decides correctly; this one proves
        the script actually consults it, by running the entire installer against
        a medium carrying a genuinely signed catalog and reading back the log it
        wrote.

        Args:
            powershell: Resolved PowerShell interpreter.
            installer: The generated installer script.
            catalog_template: A real catalog to re-sign.
            tmp_path: Per-test temporary directory.
        """
        untrusted = tmp_path / "self-signed.cat"
        signed = _probe(
            powershell,
            tmp_path,
            "sign-catalog.ps1",
            _SELF_SIGNED_CATALOG_PROBE,
            "-Template",
            str(catalog_template),
            "-Destination",
            str(untrusted),
            "-Subject",
            _TEST_PUBLISHER_SUBJECT,
        )
        assert signed.returncode == 0, f"could not produce a self-signed catalog to test with: {signed.stderr}"
        assert _TEST_PUBLISHER_SUBJECT in signed.stdout, (
            f"the re-signed catalog is not signed by the throwaway certificate: {signed.stdout!r}"
        )
        medium = build_medium(tmp_path / "medium", combinations(), catalog=untrusted)

        _status, lines = run_installer(powershell, installer, medium, tmp_path / "install.log")

        report = "\n".join(lines)
        assert selected_packages(lines), f"the installer selected no packages, so it never examined the catalog:\n{report}"
        stores = _placements_from_log(lines)
        assert _ROOT_STORE in stores, (
            f"running the whole installer against a catalog whose chain terminates in an untrusted root never reached "
            f"the {_ROOT_STORE} store, so whatever {_TRUST_POLICY_FUNCTION} decides is not wired into the script "
            f"(S17-D45). Stores written: {stores}\n{report}"
        )

    def test_the_chain_is_built_before_any_package_is_installed(
        self,
        powershell: Path,
        installer: Path,
        tmp_path: Path,
    ) -> None:
        """The syntax tree reaches a chain build ahead of the first install.

        Args:
            powershell: Resolved PowerShell interpreter.
            installer: The generated installer script.
            tmp_path: Per-test temporary directory.
        """
        syntax_tree = dump_syntax_tree(powershell, installer, tmp_path)

        first_install = first_install_offset(syntax_tree)
        builds = [node for node in syntax_tree if node.kind == "member" and node.name == _CHAIN_BUILD_MEMBER]
        assert builds, (
            "the generated installer never builds a certificate chain, so it cannot know whether the guest can "
            "validate a catalog and cannot fix the case where it cannot (S17-D45)"
        )
        assert min(node.offset for node in builds) < first_install, (
            f"the generated installer builds a chain only after calling {PNPUTIL_COMMAND}, so the first package is "
            f"offered before its root is trusted (S17-D45)"
        )


class TestTheInstallTallyUnderstandsPnputilStatuses:
    """Run the generated exit-status policy against real ``pnputil`` statuses."""

    @pytest.mark.parametrize(
        ("code", "expected", "meaning"),
        [
            (0, _ACCEPTED, "the package installed"),
            (DRIVER_ALREADY_CURRENT_EXIT, _ACCEPTED, "ERROR_NO_MORE_ITEMS: staged already, no device needed it"),
            (1, _REJECTED, "a generic pnputil failure"),
            (-2146762487, _REJECTED, "0x800B0109 CERT_E_UNTRUSTEDROOT"),
        ],
    )
    def test_a_pnputil_status_is_tallied_the_way_windows_means_it(
        self,
        powershell: Path,
        installer: Path,
        tmp_path: Path,
        code: int,
        expected: str,
        meaning: str,
    ) -> None:
        """Each real status is counted as success or failure the way Windows means it.

        Args:
            powershell: Resolved PowerShell interpreter.
            installer: The generated installer script.
            tmp_path: Per-test temporary directory.
            code: Exit status ``pnputil`` really returns.
            expected: Whether the generated policy must tolerate it.
            meaning: What Windows means by that status, for the failure message.
        """
        completed = _probe(
            powershell,
            tmp_path,
            "exit-policy.ps1",
            _EXIT_POLICY_PROBE,
            "-Path",
            str(installer),
            f"-Code:{code}",
        )

        assert completed.returncode == 0, f"could not lift {_EXIT_TALLY_FUNCTION} out of the generated installer: {completed.stderr}"
        verdict = completed.stdout.strip()
        assert verdict == expected, (
            f"the generated installer's own {_EXIT_TALLY_FUNCTION} {verdict} pnputil status {code} ({meaning}), but it "
            f"must be {expected}. Counting {DRIVER_ALREADY_CURRENT_EXIT} as a failure is what reported a completely "
            f"successful install as 'installed 12 of 17' (S17-D45)"
        )

    def test_the_install_loop_actually_consults_that_policy(self, powershell: Path, installer: Path, tmp_path: Path) -> None:
        """The tally function is called after the install, not merely defined.

        Args:
            powershell: Resolved PowerShell interpreter.
            installer: The generated installer script.
            tmp_path: Per-test temporary directory.
        """
        syntax_tree: tuple[Node, ...] = dump_syntax_tree(powershell, installer, tmp_path)

        first_install = first_install_offset(syntax_tree)
        calls = [node for node in syntax_tree if node.kind == "command" and node.name == _EXIT_TALLY_FUNCTION]
        assert calls, (
            f"the generated installer never calls {_EXIT_TALLY_FUNCTION}, so whatever that function decides has no "
            f"bearing on the install tally (S17-D45)"
        )
        assert max(node.offset for node in calls) > first_install, (
            f"every call to {_EXIT_TALLY_FUNCTION} precedes {PNPUTIL_COMMAND}, so no pnputil status is ever judged by it (S17-D45)"
        )
