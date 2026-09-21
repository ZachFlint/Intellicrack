# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Falsifiable gates for the Inno Setup provisioning wiring.

The installer is compiled by Inno Setup's ``ISCC.exe``, which is not a conda or
PyPI package, so pixi cannot manage it. Instead ``scripts/install-inno.ps1``
downloads the latest Inno Setup from GitHub and portable-installs it into
``tools/innosetup``; ``scripts/build-installer.ps1`` resolves that compiler
(auto-provisioning it when absent) before compiling ``packaging/intellicrack.iss``.

The load-bearing behaviour is ``Select-InnoSetupAsset``: given a release's asset
names it must pick the real 64-bit installer and never a detached signature or a
non-installer asset. That function is *lifted verbatim* out of the production
script and executed under ``pwsh`` here against realistic asset lists, rather
than being restated -- breaking the prefer-x64 rule, the signature exclusion or
the ``innosetup-`` prefix filter reddens a test below. The download itself is
never exercised: it is network-bound, and the container the suite runs in is
network-isolated, so only the pure selection logic is run.

The remaining gates hold the wiring honest with real consistency checks: that
``install-all.ps1``'s advertised step count matches the steps it actually runs
(now including Inno Setup), that the build script drives the compile from the
resolved path rather than a bare ``PATH`` lookup, that the portable install is
git-ignored, and that the installer script passes the portable/silent switches
without which it would perform a machine-wide install or none at all.

``pwsh`` is required to run the lifted function, matching
``tests/packaging/test_build_installer_logging.py``.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Final

import pytest


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_INSTALL_INNO: Final[Path] = _REPO_ROOT / "scripts" / "install-inno.ps1"
_INSTALL_ALL: Final[Path] = _REPO_ROOT / "scripts" / "install-all.ps1"
_BUILD_INSTALLER: Final[Path] = _REPO_ROOT / "scripts" / "build-installer.ps1"
_JUSTFILE: Final[Path] = _REPO_ROOT / "justfile"
_GITIGNORE: Final[Path] = _REPO_ROOT / ".gitignore"

# install-all.ps1 runs three inline steps (drop pixi.lock, pixi install, fix SSL)
# before the recipe-driven substeps, so its advertised total must equal three
# plus the number of substep recipes.
_INLINE_INSTALL_STEPS: Final[int] = 3


def _extract_ps_function(source: str, name: str) -> str:
    """Return the brace-balanced source of a PowerShell function.

    Args:
        source: The full text of the PowerShell script.
        name: The function name, for example ``Select-InnoSetupAsset``.

    Returns:
        str: The ``function <name> { ... }`` text with balanced braces.
    """
    start = source.index(f"function {name} {{")
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    pytest.fail(f"unbalanced braces in function {name} in install-inno.ps1")


def _run_pwsh(script: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    """Execute a PowerShell script body and return the completed process.

    Args:
        script: The script text to run.
        tmp_path: Directory the script file is written into.

    Returns:
        subprocess.CompletedProcess[str]: The finished ``pwsh`` invocation.
    """
    pwsh = shutil.which("pwsh")
    assert pwsh is not None, "pwsh (PowerShell 7) is required to exercise install-inno.ps1"
    script_path = tmp_path / "probe.ps1"
    script_path.write_text(script, encoding="utf-8")
    return subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-File", str(script_path)],
        capture_output=True,
        text=True,
        check=False,
    )


def _select_asset(names: list[str], tmp_path: Path) -> str:
    """Run the lifted ``Select-InnoSetupAsset`` over asset names.

    Args:
        names: Release asset file names to offer the selector.
        tmp_path: Pytest per-test temporary directory for the probe script.

    Returns:
        str: The chosen asset name, or an empty string when the selector
            returned ``$null`` (no installer present).
    """
    func = _extract_ps_function(_INSTALL_INNO.read_text(encoding="utf-8"), "Select-InnoSetupAsset")
    array = ", ".join(f"'{name}'" for name in names)
    script = "\n".join(
        (
            "Set-StrictMode -Version Latest",
            "$ErrorActionPreference = 'Stop'",
            func,
            f"$r = Select-InnoSetupAsset -AssetNames @({array})",
            'Write-Output "RESULT=$r"',
        ),
    )
    completed = _run_pwsh(script, tmp_path)
    assert completed.returncode == 0, f"probe failed:\n{completed.stdout}\n{completed.stderr}"
    match = re.search(r"^RESULT=(.*)$", completed.stdout, re.MULTILINE)
    assert match is not None, f"probe produced no RESULT line:\n{completed.stdout}"
    return match[1].strip()


def test_prefers_the_x64_installer_for_a_split_release(tmp_path: Path) -> None:
    """The 64-bit installer wins when a release ships per-architecture builds.

    Inno Setup 7 publishes ``-x64.exe`` and ``-x86.exe`` side by side, each with a
    detached ``.asc`` signature, alongside sample ``.iss`` assets. The selector
    must return the x64 installer. Dropping the prefer-x64 branch makes it return
    the x86 build instead, reddening this.

    Args:
        tmp_path: Pytest per-test temporary directory.
    """
    chosen = _select_asset(
        [
            "innosetup-7.1.0-x86.exe",
            "innosetup-7.1.0-x64.exe",
            "innosetup-7.1.0-x64.exe.asc",
            "innosetup-7.1.0-x86.exe.asc",
            "ISetupSample.iss",
        ],
        tmp_path,
    )
    assert chosen == "innosetup-7.1.0-x64.exe", f"the selector did not prefer the x64 installer: {chosen!r}"


def test_falls_back_to_the_unsuffixed_installer_for_is6(tmp_path: Path) -> None:
    """A release with a single un-suffixed installer is still selected.

    The Inno Setup 6 line ships one ``innosetup-<ver>.exe`` with no architecture
    suffix. Requiring an ``-x64`` suffix outright would return nothing for that
    release; the fallback must pick the un-suffixed installer, never its
    signature.

    Args:
        tmp_path: Pytest per-test temporary directory.
    """
    chosen = _select_asset(["innosetup-6.7.3.exe", "innosetup-6.7.3.exe.asc"], tmp_path)
    assert chosen == "innosetup-6.7.3.exe", f"the selector did not fall back to the un-suffixed installer: {chosen!r}"


def test_never_selects_a_signature_or_non_installer_asset(tmp_path: Path) -> None:
    r"""No installer means no choice -- a signature or archive is never returned.

    The only assets here are a detached signature, a checksum file and a source
    archive. The selector must return ``$null`` (empty result). Loosening the
    ``^innosetup-.*\.exe$`` anchor so it matched ``.exe.asc`` would make it
    return the signature, which the build would then try to run as an installer.

    Args:
        tmp_path: Pytest per-test temporary directory.
    """
    chosen = _select_asset(
        ["innosetup-7.1.0-x64.exe.asc", "SHA256SUMS.txt", "source-code.zip"],
        tmp_path,
    )
    assert not chosen, f"a non-installer asset was selected: {chosen!r}"


def test_justfile_exposes_install_inno_delegating_to_the_script() -> None:
    """``just install-inno`` must exist and delegate to the provisioning script.

    A recipe that inlined the download instead would drift from the script the
    build auto-provisions with, so the two could diverge silently.
    """
    text = _JUSTFILE.read_text(encoding="utf-8")
    match = re.search(r"(?m)^install-inno:\n((?:[ \t]+.*\n?)+)", text)
    assert match is not None, "the justfile has no install-inno recipe"
    assert (
        "scripts/install-inno.ps1" in match[1]
    ), f"the install-inno recipe does not delegate to the script:\n{match.group(1)}"


def test_install_all_provisions_inno_and_step_count_stays_consistent() -> None:
    """``install-all.ps1`` runs install-inno and its advertised total is honest.

    The banner prints ``[step/$totalSteps]``, so a substep added without bumping
    ``$totalSteps`` (or vice versa) misreports progress. The total must equal the
    three inline steps plus every recipe substep, and Inno Setup must be one of
    those substeps.
    """
    text = _INSTALL_ALL.read_text(encoding="utf-8")
    assert "Recipe = 'install-inno'" in text, "install-all.ps1 no longer provisions Inno Setup"

    total_match = re.search(r"\$totalSteps\s*=\s*(\d+)", text)
    assert total_match is not None, "install-all.ps1 no longer declares $totalSteps"
    total = int(total_match[1])
    recipes = re.findall(r"Recipe = '([^']+)'", text)
    assert total == _INLINE_INSTALL_STEPS + len(recipes), (
        f"$totalSteps ({total}) != {_INLINE_INSTALL_STEPS} inline + {len(recipes)} recipe steps {recipes}"
    )


def test_build_installer_prefers_the_local_compiler_and_auto_provisions() -> None:
    r"""The build resolves the project-local compiler and self-provisions it.

    ``build-installer.ps1`` must look for ``tools\innosetup\ISCC.exe`` first,
    fall back to provisioning via ``install-inno.ps1`` when it is absent, and
    drive the compile step from the resolved path. Reverting to a bare
    ``Get-Command iscc`` PATH lookup removes these markers.
    """
    text = _BUILD_INSTALLER.read_text(encoding="utf-8")
    assert r"tools\innosetup\ISCC.exe" in text, "build-installer no longer resolves the project-local compiler"
    assert "install-inno.ps1" in text, "build-installer no longer auto-provisions Inno Setup when it is missing"
    assert "-FilePath $IsccPath" in text, "the compile step no longer runs the resolved compiler path"


def test_gitignore_excludes_the_portable_install() -> None:
    """The portable Inno Setup tree must never enter version control.

    ``tools/innosetup`` holds ``.isl``/``.iss``/``.e32`` support files the global
    ``*.exe`` rule does not cover, so the directory itself must be ignored.
    """
    text = _GITIGNORE.read_text(encoding="utf-8")
    assert re.search(r"(?m)^tools/innosetup/\s*$", text), "tools/innosetup/ is no longer git-ignored"


def test_install_inno_uses_portable_silent_switches_and_the_right_source() -> None:
    """The installer is driven silently, portably, and from the Inno Setup repo.

    Without ``/PORTABLE=1`` and ``/DIR=`` the installer would perform an
    interactive, machine-wide install rather than landing a self-contained tree
    under ``tools/innosetup``; without ``/VERYSILENT``/``/SUPPRESSMSGBOXES`` an
    unattended run would hang on a prompt. The source must be the Inno Setup
    GitHub repository's latest release.
    """
    text = _INSTALL_INNO.read_text(encoding="utf-8")
    for switch in ("/VERYSILENT", "/SUPPRESSMSGBOXES", "/PORTABLE=1", "/DIR="):
        assert switch in text, f"install-inno.ps1 no longer passes {switch}"
    assert "jrsoftware/issrc" in text, "install-inno.ps1 no longer targets the Inno Setup repository"
    assert "releases/latest" in text, "install-inno.ps1 no longer fetches the latest release"
