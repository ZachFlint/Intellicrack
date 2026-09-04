# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Falsifiable tests that the installer build captures a reviewable log.

``just build-installer`` used to run its steps as separate recipe lines whose
output went only to the console. Once the terminal was cleared the build was
unreconstructable: no log file existed anywhere, so a warning noticed mid-build
could not be read back.

``scripts/build-installer.ps1`` now drives the whole pipeline -- stage the
payload, then compile it with ``iscc`` -- and streams every step's combined
stdout/stderr to ``logs/installer/build.log`` (a single rolling file, replaced
each run) as well as the console. It runs no tests: a build must not depend on
the test container being up, and an unrelated test failure must not fail a
compile, so staging and verification stay separate operations.

These gates hold that behavior honest by *executing* the script's real logging
functions rather than restating them: ``Write-LogLine``, ``Write-Both`` and
``Split-CommandArgument`` are lifted verbatim out of the production script, run
under ``pwsh`` against a temporary log, and their effects asserted. Deleting the
ANSI strip, the file append or the empty-argument guard reddens a test here. A
separate wiring gate holds that the recipe actually delegates to the script, so
the logging cannot be bypassed by a recipe edit.

``pwsh`` is a host utility, so these run in the host-native pass.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Final

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]
_BUILD_SCRIPT = _REPO_ROOT / "scripts" / "build-installer.ps1"
_JUSTFILE = _REPO_ROOT / "justfile"

# Invocations that would mean the installer build is running tests. Building and
# verifying are separate operations: a build must not depend on the test container
# being up, and an unrelated test failure must not fail a compile.
_TEST_RUNNER_TOKENS: Final[tuple[str, ...]] = (
    "docker_sandbox",
    "host_native_tests",
    "pytest",
    "just test",
    "unittest",
)


def _extract_ps_function(name: str) -> str:
    """Return the full source text of a PowerShell function from the build script.

    Args:
        name: The function name, e.g. ``Write-LogLine``.

    Returns:
        str: The ``function <name> { ... }`` text, brace-balanced.
    """
    text = _BUILD_SCRIPT.read_text(encoding="utf-8")
    start = text.index(f"function {name} {{")
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    pytest.fail(f"unbalanced braces in function {name} in build-installer.ps1")


def _ansi_pattern() -> str:
    """Return the ``$AnsiPattern`` assignment line from the build script.

    Returns:
        str: The PowerShell statement defining ``$AnsiPattern``.
    """
    text = _BUILD_SCRIPT.read_text(encoding="utf-8")
    match = re.search(r"^\$AnsiPattern\s*=.*$", text, re.MULTILINE)
    assert match is not None, "build-installer.ps1 no longer defines $AnsiPattern"
    return match.group(0)


def _run_pwsh(script: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    """Execute a PowerShell script body and return the completed process.

    Args:
        script: The script text to run.
        tmp_path: Directory the script file is written into.

    Returns:
        subprocess.CompletedProcess[str]: The finished ``pwsh`` invocation.
    """
    pwsh = shutil.which("pwsh")
    assert pwsh is not None, "pwsh (PowerShell 7) is required to exercise build-installer.ps1"
    script_path = tmp_path / "probe.ps1"
    script_path.write_text(script, encoding="utf-8")
    return subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-File", str(script_path)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_build_log_strips_ansi_but_keeps_console_colour(tmp_path: Path) -> None:
    """The log copy must be plain text while the console keeps its colour codes.

    ``Write-Both`` is lifted from the production script and given a line carrying
    a real CSI colour sequence. The console copy must still contain the escape
    (so the terminal renders colour) while the file copy must not (so the log is
    readable in an editor). Dropping the ``-replace $AnsiPattern`` reddens the
    file assertion; stripping the console path too reddens the console assertion.

    The probe forces ``$PSStyle.OutputRendering = 'Ansi'`` so the console-colour
    premise holds regardless of the outer environment. Otherwise an inherited
    ``NO_COLOR`` (honoured per no-color.org) or a redirected-pipe default would
    make ``pwsh`` strip the escape from every ``Write-Host`` line, failing the
    console assertion for an environmental reason rather than a product defect.

    Args:
        tmp_path: Pytest-provided per-test temporary directory.
    """
    log = tmp_path / "build.log"
    script = "\n".join(
        (
            "Set-StrictMode -Version Latest",
            "$ErrorActionPreference = 'Stop'",
            "$PSStyle.OutputRendering = 'Ansi'",
            _ansi_pattern(),
            f"$LogPath = '{log}'",
            "Set-Content -LiteralPath $LogPath -Value '' -Encoding utf8 -NoNewline",
            _extract_ps_function("Write-LogLine"),
            _extract_ps_function("Write-Both"),
            'Write-Both -Line "`e[32m[STAGE]`e[0m staged 12 files"',
        ),
    )
    completed = _run_pwsh(script, tmp_path)
    assert completed.returncode == 0, f"probe failed:\n{completed.stdout}\n{completed.stderr}"

    written = log.read_text(encoding="utf-8")
    assert "staged 12 files" in written, "the build log did not receive the line at all"
    assert "\x1b[" not in written, f"ANSI escapes leaked into the build log: {written!r}"
    assert "\x1b[32m" in completed.stdout, "the console copy lost its colour codes"


def test_build_log_accumulates_every_line_in_order(tmp_path: Path) -> None:
    """Successive log writes must append, not overwrite the previous line.

    A build log that overwrote itself per line would leave only the last line of a
    multi-step build. Replacing ``Add-Content`` with ``Set-Content`` reddens this.

    Args:
        tmp_path: Pytest-provided per-test temporary directory.
    """
    log = tmp_path / "build.log"
    script = "\n".join(
        (
            "Set-StrictMode -Version Latest",
            "$ErrorActionPreference = 'Stop'",
            _ansi_pattern(),
            f"$LogPath = '{log}'",
            "Set-Content -LiteralPath $LogPath -Value '' -Encoding utf8 -NoNewline",
            _extract_ps_function("Write-LogLine"),
            "Write-LogLine -Line 'first step'",
            "Write-LogLine -Line 'second step'",
            "Write-LogLine -Line 'third step'",
        ),
    )
    completed = _run_pwsh(script, tmp_path)
    assert completed.returncode == 0, f"probe failed:\n{completed.stdout}\n{completed.stderr}"

    lines = [line for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines == ["first step", "second step", "third step"], f"log did not accumulate in order: {lines}"


def test_empty_recipe_arguments_do_not_become_empty_command_arguments(tmp_path: Path) -> None:
    """A blank ``STAGE_ARGS``/``ARGS`` must produce no arguments at all.

    ``just`` substitutes an unset variable as an empty string. Splitting that
    naively yields one empty argument, which ``stage.ps1`` and ``iscc`` reject, so
    a default ``just build-installer`` would fail. The guard must return an empty
    array for empty and whitespace-only input while still splitting real flags.

    Args:
        tmp_path: Pytest-provided per-test temporary directory.
    """
    script = "\n".join(
        (
            "Set-StrictMode -Version Latest",
            "$ErrorActionPreference = 'Stop'",
            _extract_ps_function("Split-CommandArgument"),
            "$empty = @(Split-CommandArgument -Value '')",
            "$blank = @(Split-CommandArgument -Value '   ')",
            "$real = @(Split-CommandArgument -Value '-SkipJdkDownload -SkipGuestImage')",
            'Write-Output "empty=$($empty.Count)"',
            'Write-Output "blank=$($blank.Count)"',
            "Write-Output \"real=$($real.Count):$($real -join ',')\"",
        ),
    )
    completed = _run_pwsh(script, tmp_path)
    assert completed.returncode == 0, f"probe failed:\n{completed.stdout}\n{completed.stderr}"

    out = completed.stdout
    assert "empty=0" in out, f"an empty argument string produced arguments: {out}"
    assert "blank=0" in out, f"a whitespace-only argument string produced arguments: {out}"
    assert "real=2:-SkipJdkDownload,-SkipGuestImage" in out, f"real flags were not split correctly: {out}"


def test_logged_step_records_exit_code_and_duration(tmp_path: Path) -> None:
    """Every step must log a completion line carrying its real exit code and time.

    ``Invoke-LoggedStep`` is lifted verbatim and run against a child that prints a
    line and exits ``7``. The log must show the child's output followed by a
    ``done in <n>s (exit 7)`` line -- the exit code read from ``$LASTEXITCODE``,
    not a hardcoded ``0`` -- and the function must return that same ``7`` so the
    caller's failure check still fires. Deleting the completion line, hardcoding
    the code, or dropping the duration reddens this gate.

    Args:
        tmp_path: Pytest-provided per-test temporary directory.
    """
    log = tmp_path / "build.log"
    script = "\n".join(
        (
            "Set-StrictMode -Version Latest",
            "$ErrorActionPreference = 'Stop'",
            "$PSNativeCommandUseErrorActionPreference = $false",
            _ansi_pattern(),
            f"$LogPath = '{log}'",
            "Set-Content -LiteralPath $LogPath -Value '' -Encoding utf8 -NoNewline",
            _extract_ps_function("Write-LogLine"),
            _extract_ps_function("Write-Both"),
            _extract_ps_function("Invoke-LoggedStep"),
            "$pwsh = (Get-Process -Id $PID).Path",
            "$childArgs = @('-NoProfile', '-NonInteractive', '-Command', \"Write-Output 'child ran'; exit 7\")",
            "$code = Invoke-LoggedStep -What 'probe step' -FilePath $pwsh -ArgumentList $childArgs",
            'Write-Output "returned=$code"',
        ),
    )
    completed = _run_pwsh(script, tmp_path)
    assert completed.returncode == 0, f"probe failed:\n{completed.stdout}\n{completed.stderr}"

    assert "returned=7" in completed.stdout, (
        f"Invoke-LoggedStep did not return the child's exit code for the caller to check: {completed.stdout!r}"
    )

    written = log.read_text(encoding="utf-8")
    match = re.search(r"--- probe step : done in \d+(?:\.\d+)?s \(exit 7\) ---", written)
    assert match is not None, f"the log has no completion line with the real exit code and duration:\n{written}"

    child_at = written.index("child ran")
    assert child_at < match.start(), f"the completion line was logged before the step's own output, not after it:\n{written}"
    """``just build-installer`` must run the logging script, not inline the steps.

    If the recipe called ``iscc`` (or the staging script) directly again, the build
    would produce no log while every other gate here still passed, so the wiring is
    asserted at its source.
    """
    text = _JUSTFILE.read_text(encoding="utf-8")
    start = text.index("\nbuild-installer *ARGS:")
    end = text.index("\n[doc(", start)
    body = text[start:end]

    assert "scripts/build-installer.ps1" in body, f"build-installer no longer delegates to the logging script:\n{body}"
    for inlined in ("iscc packaging/intellicrack.iss", "docker_sandbox module"):
        assert inlined not in body, f"build-installer still runs '{inlined}' inline, bypassing the log:\n{body}"


def test_build_script_logs_to_the_repository_logs_directory() -> None:
    """The log must land in ``logs/installer/build.log`` as a single rolling file.

    ``logs/`` is git-ignored, so the build log never enters version control, and a
    fixed name keeps the newest build reviewable without hunting for a timestamp.
    """
    text = _BUILD_SCRIPT.read_text(encoding="utf-8")

    assert "'logs\\installer'" in text, "the build script no longer writes into logs/installer"
    assert "'build.log'" in text, "the build script no longer writes build.log"
    assert "Set-Content -LiteralPath $LogPath" in text, "the build script no longer truncates the log at start, so runs would concatenate"

    gitignore = (_REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert re.search(r"^logs/", gitignore, re.MULTILINE), "logs/ is no longer git-ignored; build logs would be committed"


def test_build_script_runs_no_tests() -> None:
    """The build pipeline must stage and compile only -- it must never run tests.

    An earlier revision of the recipe ran the staged-tree gate through the Docker
    test sandbox between staging and ``iscc``. That made a build depend on the
    container being up, turned an unrelated test failure into a failed build, and
    cost minutes on every compile. Building and verifying are deliberately
    separate operations here: run the gates yourself via the normal test runner.

    Re-adding any test-runner invocation to the build script or the recipe reddens
    this gate.
    """
    script_text = _BUILD_SCRIPT.read_text(encoding="utf-8")

    justfile_text = _JUSTFILE.read_text(encoding="utf-8")
    start = justfile_text.index("\nbuild-installer *ARGS:")
    end = justfile_text.index("\n[doc(", start)
    recipe_body = justfile_text[start:end]

    for source, label in ((script_text, "scripts/build-installer.ps1"), (recipe_body, "the build-installer recipe")):
        for token in _TEST_RUNNER_TOKENS:
            assert token not in source, (
                f"{label} invokes a test runner ({token!r}); the installer build must only stage and compile, never run tests"
            )


def test_build_script_streams_stderr_into_the_log() -> None:
    """Failing steps must have their stderr captured, not just stdout.

    A build log that dropped stderr would omit exactly the diagnostics needed to
    explain a failure, which is the situation this script exists to prevent.
    """
    text = _BUILD_SCRIPT.read_text(encoding="utf-8")
    invoke = text[text.index("function Invoke-LoggedStep") :]

    assert "2>&1" in invoke, "Invoke-LoggedStep no longer merges stderr into the logged output"
    assert "ErrorRecord" in invoke, "Invoke-LoggedStep no longer renders merged stderr records as text"
