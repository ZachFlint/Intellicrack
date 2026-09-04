# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Falsifiable gates that installer staging never ships the Jython extension.

The bridge drives Ghidra through the CPython (PyGhidra/jfx_bridge) server, not
the legacy Jython interpreter. The S19 mitigation for this was a *manual*
rename of the checked-out ``tools/ghidra/Ghidra/Features/Jython`` directory to
``Jython.disabled`` on a gitignored tree -- a fix that a plain re-stage would
silently undo, because ``packaging/stage.ps1`` mirrored ``tools/ghidra``
verbatim and rebuilt ``build/stage`` from scratch on every run.

``packaging/stage.ps1`` Step 8 now (1) excludes ``Ghidra/Features/Jython``
from the ``Invoke-Robocopy`` mirror into the stage, and (2) asserts -- as a
hard build failure, not a warning -- that no ``Ghidra/Features/Jython/lib``
jar survives in the staged tree. These gates hold both halves honest by
*executing* the production statements rather than restating them, following
the same pattern ``tests/packaging/test_stage_excludes.py`` established for
``stage.ps1``'s runtime trim (there is no ``-DryRun`` switch on ``stage.ps1``
itself -- it is a real multi-hour build script -- so the host-side pattern for
exercising a piece of it without running the whole build is to lift the exact
statements out by their real anchors and run them with ``pwsh`` against a
synthetic tree):

* ``test_ghidra_copy_step_excludes_jython_from_the_staged_tree`` lifts the
  literal copy statements (the ``$GhidraJythonSrc`` assignment, the
  ``Invoke-Robocopy`` call with its ``-ExcludeDirs``, and the
  ``analyzeHeadless.bat`` payload check) and runs them against a fixture
  Ghidra source tree carrying a fake ``Ghidra/Features/Jython/lib/Jython.jar``.
  Removing the exclusion leaves the jar in the mirrored destination and
  reddens the absence assertion.
* ``test_ghidra_stage_guard_raises_when_a_jython_jar_survives`` lifts the
  literal post-copy guard statements and runs them against a *destination*
  tree that already carries a Jython jar -- simulating exactly the scenario
  the guard exists to catch: a re-stage (or a source tree) where the strip
  did not happen. Removing the guard, or narrowing its match, keeps the block
  from throwing and reddens this test.
* ``test_ghidra_stage_guard_is_silent_on_a_clean_tree`` is the guard's
  negative control: a destination with no Jython content must not throw, so a
  test that only checked "it can throw" could not be satisfied by a guard
  that always throws.

Extraction is anchored on the literal production text, not restated logic:
these tests go RED if the exclusion, the guard's ``Test-Path`` check, or its
``*.jar`` scan is weakened or removed from ``packaging/stage.ps1``.

``robocopy`` and ``pwsh`` are Windows host utilities, so these run in the
host-native pass.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]
_STAGE_PS1 = _REPO_ROOT / "packaging" / "stage.ps1"

# The literal anchors bounding the two production sub-blocks inside Step 8 of
# packaging/stage.ps1. Both are matched verbatim, so a rename or reflow of
# either statement fails extraction loudly instead of silently drifting.
_COPY_START = "$GhidraSrc = Join-Path $RepoRoot 'tools\\ghidra'"
_COPY_END_MARKER = "Assert-Produced -Path (Join-Path $GhidraDest 'support\\analyzeHeadless.bat') -What 'staged analyzeHeadless.bat'"
_GUARD_START = "$GhidraJythonDest = Join-Path $GhidraDest 'Ghidra\\Features\\Jython'"
_GUARD_END_MARKER = "Write-Success 'Ghidra staged (Jython extension excluded)'"

pytestmark = [
    pytest.mark.host_native,
    pytest.mark.skipif(sys.platform != "win32", reason="packaging/stage.ps1 is a Windows PowerShell tooling script"),
]


def _read_stage_script() -> str:
    """Read the staging script.

    Returns:
        str: The full text of ``packaging/stage.ps1``.
    """
    assert _STAGE_PS1.is_file(), f"staging script missing: {_STAGE_PS1}"
    return _STAGE_PS1.read_text(encoding="utf-8")


def _extract_block(start_marker: str, end_marker: str) -> str:
    """Return the literal production statements between two anchor lines.

    Args:
        start_marker: The exact text of the first statement to include.
        end_marker: The exact text of the last statement to include.

    Returns:
        str: The verbatim source text spanning both anchors, inclusive.

    Raises:
        AssertionError: If either anchor is no longer present in
            ``packaging/stage.ps1``, or if the end anchor precedes the start
            anchor in the script.
    """
    text = _read_stage_script()
    if start_marker not in text:
        msg = f"packaging/stage.ps1 no longer contains the expected statement: {start_marker!r}"
        raise AssertionError(msg)
    if end_marker not in text:
        msg = f"packaging/stage.ps1 no longer contains the expected statement: {end_marker!r}"
        raise AssertionError(msg)
    start = text.index(start_marker)
    end = text.index(end_marker, start) + len(end_marker)
    if end <= start:
        msg = "the Jython guard's end anchor precedes its start anchor in packaging/stage.ps1"
        raise AssertionError(msg)
    return text[start:end]


def _extract_ps_function(name: str) -> str:
    """Return the full source text of a PowerShell function from stage.ps1.

    Args:
        name: The function name, e.g. ``Invoke-Robocopy``.

    Returns:
        str: The ``function <name> { ... }`` text, brace-balanced.
    """
    text = _read_stage_script()
    start = text.index(f"function {name} {{")
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    pytest.fail(f"unbalanced braces in function {name} in stage.ps1")


def _pwsh() -> str:
    """Locate the PowerShell 7 executable.

    Returns:
        str: Absolute path to the ``pwsh`` executable.
    """
    exe = shutil.which("pwsh") or shutil.which("pwsh.exe")
    if exe is None:
        pytest.fail("pwsh (PowerShell 7) is required to exercise packaging/stage.ps1")
    return exe


def _run_pwsh(script: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    """Execute a PowerShell script body and return the completed process.

    Args:
        script: The script text to run.
        tmp_path: Directory the script file is written into.

    Returns:
        subprocess.CompletedProcess[str]: The finished ``pwsh`` invocation.
    """
    script_path = tmp_path / "probe.ps1"
    script_path.write_text(script, encoding="utf-8")
    return subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(script_path)],
        capture_output=True,
        text=True,
        check=False,
    )


def _make_fixture_ghidra_source(repo_root: Path) -> None:
    """Populate a fixture Ghidra tree carrying a fake Jython extension.

    Args:
        repo_root: The fixture ``$RepoRoot`` under which ``tools/ghidra`` is
            built, mirroring the real layout ``stage.ps1`` reads from.
    """
    ghidra = repo_root / "tools" / "ghidra"
    (ghidra / "support").mkdir(parents=True)
    (ghidra / "support" / "analyzeHeadless.bat").write_text("@echo off\r\n", encoding="utf-8")

    jython_lib = ghidra / "Ghidra" / "Features" / "Jython" / "lib"
    jython_lib.mkdir(parents=True)
    (jython_lib / "Jython.jar").write_bytes(b"PK\x03\x04fake-jython-jar")
    (ghidra / "Ghidra" / "Features" / "Jython" / "module.manifest").write_text("MODULE FILE\r\n", encoding="utf-8")

    pyghidra = ghidra / "Ghidra" / "Features" / "PyGhidra" / "lib"
    pyghidra.mkdir(parents=True)
    (pyghidra / "PyGhidra.jar").write_bytes(b"PK\x03\x04fake-pyghidra-jar")


def test_ghidra_copy_step_excludes_jython_from_the_staged_tree(tmp_path: Path) -> None:
    """Real gate: the production copy statements never mirror Jython into the stage.

    Lifts ``$GhidraJythonSrc``, the real ``Invoke-Robocopy`` call (with its
    ``-ExcludeDirs``) and the ``analyzeHeadless.bat`` payload check verbatim out
    of ``packaging/stage.ps1`` Step 8, and runs them with real ``robocopy``
    against a fixture Ghidra tree that carries a fake
    ``Ghidra/Features/Jython/lib/Jython.jar``. Dropping the ``-ExcludeDirs``
    argument (or retargeting it) leaves that jar in the staged tree and reddens
    the absence assertion below, while a genuine sibling payload
    (``PyGhidra.jar``) must still survive the mirror.

    Args:
        tmp_path: Pytest-provided per-test temporary directory.
    """
    repo_root = tmp_path / "repo"
    stage = tmp_path / "stage"
    _make_fixture_ghidra_source(repo_root)

    copy_block = _extract_block(_COPY_START, _COPY_END_MARKER)
    script = "\n".join(
        (
            "Set-StrictMode -Version Latest",
            "$ErrorActionPreference = 'Stop'",
            "$PSNativeCommandUseErrorActionPreference = $false",
            "function Write-Step { param([Parameter(ValueFromRemainingArguments)]$Rest) }",
            _extract_ps_function("Assert-Source"),
            _extract_ps_function("Assert-Produced"),
            _extract_ps_function("Invoke-Robocopy"),
            f"$RepoRoot = '{repo_root}'",
            f"$Stage = '{stage}'",
            copy_block,
        ),
    )
    completed = _run_pwsh(script, tmp_path)
    assert completed.returncode == 0, f"the Ghidra copy statements failed:\n{completed.stdout}\n{completed.stderr}"

    ghidra_dest = stage / "app" / "tools" / "ghidra"
    assert not (ghidra_dest / "Ghidra" / "Features" / "Jython").exists(), (
        "Ghidra/Features/Jython was mirrored into the staged tree; the Invoke-Robocopy -ExcludeDirs no longer excludes it"
    )
    assert (ghidra_dest / "support" / "analyzeHeadless.bat").is_file(), "a genuine Ghidra payload file was wrongly excluded from the stage"
    assert (ghidra_dest / "Ghidra" / "Features" / "PyGhidra" / "lib" / "PyGhidra.jar").is_file(), (
        "a genuine sibling extension (PyGhidra) was wrongly excluded from the stage"
    )


def test_ghidra_stage_guard_raises_when_a_jython_jar_survives(tmp_path: Path) -> None:
    """Real gate: the build-time guard fails the build when Jython reaches the stage.

    Lifts the literal post-copy guard statements out of ``packaging/stage.ps1``
    Step 8 and runs them against a *destination* tree built independently of the
    copy step, with a Jython jar already present under
    ``Ghidra/Features/Jython/lib`` -- exactly the state a re-stage that forgot
    the exclusion (or a source tree where Jython was never disabled) would
    produce. The guard must raise a terminating error (nonzero exit), which is
    the durable half of D11: even if the exclusion above is silently reverted,
    this assertion still stops the build from shipping Jython.

    Args:
        tmp_path: Pytest-provided per-test temporary directory.
    """
    ghidra_dest = tmp_path / "stage" / "app" / "tools" / "ghidra"
    jython_lib = ghidra_dest / "Ghidra" / "Features" / "Jython" / "lib"
    jython_lib.mkdir(parents=True)
    (jython_lib / "Jython.jar").write_bytes(b"PK\x03\x04fake-jython-jar")

    guard_block = _extract_block(_GUARD_START, _GUARD_END_MARKER)
    script = "\n".join(
        (
            "Set-StrictMode -Version Latest",
            "$ErrorActionPreference = 'Stop'",
            "function Write-Success { param([Parameter(ValueFromRemainingArguments)]$Rest) }",
            f"$GhidraDest = '{ghidra_dest}'",
            guard_block,
        ),
    )
    completed = _run_pwsh(script, tmp_path)
    assert completed.returncode != 0, (
        "the Ghidra stage guard did not fail the build with a surviving Jython jar in the staged tree "
        f"(exit {completed.returncode}):\n{completed.stdout}\n{completed.stderr}"
    )
    assert "Jython" in completed.stderr, f"the guard's failure does not mention Jython, so a build failure here would be undiagnosable:\n{completed.stderr}"


def test_ghidra_stage_guard_is_silent_on_a_clean_tree(tmp_path: Path) -> None:
    """The guard's negative control: a Jython-free stage must not fail the build.

    Without this, a guard that unconditionally threw would pass the test above
    for the wrong reason. The destination here carries only a sibling extension
    (PyGhidra), matching what the copy step is expected to leave behind.

    Args:
        tmp_path: Pytest-provided per-test temporary directory.
    """
    ghidra_dest = tmp_path / "stage" / "app" / "tools" / "ghidra"
    pyghidra_lib = ghidra_dest / "Ghidra" / "Features" / "PyGhidra" / "lib"
    pyghidra_lib.mkdir(parents=True)
    (pyghidra_lib / "PyGhidra.jar").write_bytes(b"PK\x03\x04fake-pyghidra-jar")

    guard_block = _extract_block(_GUARD_START, _GUARD_END_MARKER)
    script = "\n".join(
        (
            "Set-StrictMode -Version Latest",
            "$ErrorActionPreference = 'Stop'",
            "function Write-Success { param([Parameter(ValueFromRemainingArguments)]$Rest) }",
            f"$GhidraDest = '{ghidra_dest}'",
            guard_block,
        ),
    )
    completed = _run_pwsh(script, tmp_path)
    assert completed.returncode == 0, (
        f"the Ghidra stage guard failed the build on a Jython-free staged tree:\n{completed.stdout}\n{completed.stderr}"
    )
