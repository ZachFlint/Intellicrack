# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the ``just test-coverage`` dispatcher.

These tests exercise ``scripts/test-coverage.ps1`` in its ``-DryRun`` mode,
which resolves and prints the exact Rust and Python coverage commands without
running them. They assert the real dispatch behaviour: default runs both
toolchains, ``--rust`` / ``--python`` scope to one, extra flags are forwarded
to the selected target, and mixing extra flags with more than one target is
rejected.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "test-coverage.ps1"

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="test-coverage.ps1 is a Windows PowerShell tooling script",
)


def _pwsh() -> str:
    """Locate the PowerShell 7 executable.

    Returns:
        str: Absolute path to the ``pwsh`` executable.
    """
    exe = shutil.which("pwsh") or shutil.which("pwsh.exe")
    if exe is None:
        pytest.fail("pwsh (PowerShell 7) is required to exercise test-coverage.ps1")
    return exe


def _run(*flags: str) -> subprocess.CompletedProcess[str]:
    """Run the dispatcher in dry-run mode with the given flags.

    Args:
        *flags: Extra command-line tokens appended after ``-DryRun``.

    Returns:
        subprocess.CompletedProcess[str]: The completed subprocess with
            captured text stdout/stderr.
    """
    return subprocess.run(
        [
            _pwsh(),
            "-NoLogo",
            "-NonInteractive",
            "-File",
            str(_SCRIPT),
            "-Pixi",
            "pixi run",
            "-DryRun",
            *flags,
        ],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        check=False,
    )


def test_script_exists() -> None:
    """The dispatcher script must be present at the expected path."""
    assert _SCRIPT.is_file(), f"missing dispatcher: {_SCRIPT}"


def test_no_flags_runs_both_targets() -> None:
    """With no target flag, both Rust and Python coverage are planned."""
    result = _run()
    assert result.returncode == 0, result.stderr
    assert "DRYRUN RUST" in result.stdout
    assert "DRYRUN PYTHON" in result.stdout


def test_rust_only_excludes_python() -> None:
    """``--rust`` plans only the cargo llvm-cov run."""
    result = _run("--rust")
    assert result.returncode == 0, result.stderr
    assert "DRYRUN RUST" in result.stdout
    assert "DRYRUN PYTHON" not in result.stdout
    assert "cargo llvm-cov" in result.stdout


def test_python_only_excludes_rust() -> None:
    """``--python`` plans only the docker-sandbox coverage run."""
    result = _run("--python")
    assert result.returncode == 0, result.stderr
    assert "DRYRUN PYTHON" in result.stdout
    assert "DRYRUN RUST" not in result.stdout
    assert "scripts.sandbox.docker_sandbox coverage" in result.stdout


def test_python_forwards_extra_flags() -> None:
    """Extra flags after ``--python`` reach the sandbox command verbatim."""
    result = _run("--python", "--memory", "16g")
    assert result.returncode == 0, result.stderr
    python_line = next(line for line in result.stdout.splitlines() if line.startswith("DRYRUN PYTHON"))
    assert python_line.endswith("coverage --memory 16g")


def test_rust_extra_flags_use_passthrough_form() -> None:
    """Extra flags after ``--rust`` switch cargo to the passthrough command.

    The reporting-mode command (``nextest --no-fail-fast``) must not be used
    when the caller supplies their own cargo llvm-cov flags.
    """
    result = _run("--rust", "--html")
    assert result.returncode == 0, result.stderr
    rust_line = next(line for line in result.stdout.splitlines() if line.startswith("DRYRUN RUST"))
    assert rust_line == "DRYRUN RUST pixi run cargo llvm-cov --html"
    assert "nextest" not in rust_line


def test_extra_flags_without_target_are_rejected() -> None:
    """Extra flags with the default (both) target set fail loudly."""
    result = _run("--memory", "16g")
    assert result.returncode == 2
    assert "exactly one target" in result.stderr


def test_extra_flags_with_two_targets_are_rejected() -> None:
    """Extra flags are ambiguous when both targets are explicit."""
    result = _run("--rust", "--python", "--html")
    assert result.returncode == 2
    assert "exactly one target" in result.stderr
