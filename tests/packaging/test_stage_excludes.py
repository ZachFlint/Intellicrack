# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Falsifiable tests that installer staging drops dev/build-only artifacts.

``packaging/stage.ps1`` mirrors two trees whose sources carry material that must
never reach the shipped installer:

* the pixi runtime env keeps a top-level ``.trash`` quarantine of superseded
  binaries (old DLL/exe versions pip/pixi could not delete in place); and
* ``src/hexbench`` keeps its own ``tests`` suite, ``gate.ps1``,
  ``update-deps.ps1`` and ``.qodo`` dev tooling inside the package tree.

A plain ``robocopy /E`` shipped all of it into ``Setup.exe`` (~100 MB of dead
runtime binaries plus the entire hexbench test suite). The stager now passes
``/XD``/``/XF`` exclusions on both calls. These gates hold that behavior honest
end to end: they parse the *actual* exclude arguments out of ``stage.ps1`` -- so
the exclude set is derived from production rather than restated -- and then drive
real ``robocopy`` with them against a synthetic source tree, proving the excluded
entries do not survive the mirror while a genuine payload file does. Reverting
either exclusion in ``stage.ps1`` shrinks the parsed set, the synthetic artifact
survives the copy, and the assertion fails.

``robocopy`` is a Windows system utility, so these run in the host-native pass.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]
_STAGE_PS1 = _REPO_ROOT / "packaging" / "stage.ps1"

# robocopy reports success as a bitmask; only >= 8 is a genuine failure (1 == files
# copied, 2 == extra files/dirs present, 3 == both). Anything below 8 is success.
_ROBOCOPY_FAILURE_FLOOR = 8


def _folded_script() -> str:
    r"""Read ``stage.ps1`` with PowerShell backtick line-continuations folded.

    A single ``Invoke-Robocopy`` call may span several physical lines via trailing
    backticks; folding them yields one logical line per call so a call and all of
    its arguments can be matched together.

    Returns:
        str: The script text with backtick + newline continuations collapsed to a
            single space.
    """
    raw = _STAGE_PS1.read_text(encoding="utf-8")
    return re.sub(r"`\s*\r?\n\s*", " ", raw)


def _robocopy_call(dest_var: str) -> str:
    """Return the folded ``Invoke-Robocopy`` statement targeting a destination.

    Args:
        dest_var: The PowerShell destination variable the call mirrors into, e.g.
            ``$RuntimeDir`` or ``$HexbenchDest``.

    Returns:
        str: The single logical line of the matching ``Invoke-Robocopy`` call.
    """
    for line in _folded_script().splitlines():
        if "Invoke-Robocopy" in line and dest_var in line:
            return line.strip()
    pytest.fail(f"no Invoke-Robocopy call targeting {dest_var} found in stage.ps1")


def _exclude_names(flag: str, call: str) -> list[str]:
    """Extract the quoted names of a ``-ExcludeDirs``/``-ExcludeFiles`` argument.

    Args:
        flag: The PowerShell parameter name, ``-ExcludeDirs`` or
            ``-ExcludeFiles``.
        call: The folded ``Invoke-Robocopy`` statement to parse.

    Returns:
        list[str]: The single-quoted names inside the ``@( ... )`` array literal
            following ``flag``, or an empty list when the flag is absent.
    """
    match = re.search(re.escape(flag) + r"\s*@\(([^)]*)\)", call)
    if match is None:
        return []
    return re.findall(r"'([^']*)'", match.group(1))


def _run_robocopy(source: Path, dest: Path, exclude_dirs: list[str], exclude_files: list[str]) -> None:
    """Mirror ``source`` into ``dest`` with robocopy using the given exclusions.

    Args:
        source: Directory tree to mirror.
        dest: Destination directory (created by robocopy).
        exclude_dirs: Names passed as ``/XD`` (directory exclusions).
        exclude_files: Names/patterns passed as ``/XF`` (file exclusions).
    """
    argv = ["robocopy", str(source), str(dest), "/E", "/NFL", "/NDL", "/NJH", "/NJS", "/NP"]
    for name in exclude_dirs:
        argv += ["/XD", name]
    for name in exclude_files:
        argv += ["/XF", name]
    completed = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert completed.returncode < _ROBOCOPY_FAILURE_FLOOR, (
        f"robocopy failed (exit {completed.returncode}): {completed.stdout}\n{completed.stderr}"
    )


def test_runtime_stage_excludes_pixi_trash(tmp_path: Path) -> None:
    """The runtime mirror must drop the pixi ``.trash`` quarantine but keep binaries.

    The exclude set is parsed from the real runtime ``Invoke-Robocopy`` call, then
    exercised against a synthetic env containing a ``.trash`` dir and a payload
    ``python.exe``. If the ``.trash`` exclusion is removed from ``stage.ps1`` the
    parsed set no longer carries it, the quarantined file survives the mirror, and
    the first assertion fails.

    Args:
        tmp_path: Pytest-provided per-test temporary directory.
    """
    call = _robocopy_call("$RuntimeDir")
    exclude_dirs = _exclude_names("-ExcludeDirs", call)
    exclude_files = _exclude_names("-ExcludeFiles", call)
    assert ".trash" in exclude_dirs, f"runtime robocopy no longer excludes .trash: {exclude_dirs}"

    source = tmp_path / "env"
    (source / ".trash").mkdir(parents=True)
    (source / ".trash" / "capstone.dll.deadbeef.trash").write_bytes(b"stale")
    (source / "python.exe").write_bytes(b"MZ")

    dest = tmp_path / "runtime"
    _run_robocopy(source, dest, exclude_dirs, exclude_files)

    assert not (dest / ".trash").exists(), "pixi .trash quarantine leaked into the staged runtime"
    assert (dest / "python.exe").is_file(), "payload runtime binary was wrongly excluded"


def test_hexbench_stage_excludes_dev_tooling(tmp_path: Path) -> None:
    """The hexbench mirror must drop its test suite and dev scripts, keep the GUI.

    The exclude set is parsed from the real hexbench ``Invoke-Robocopy`` call and
    exercised against a synthetic tree carrying a ``tests`` dir, ``gate.ps1``,
    ``update-deps.ps1``, ``.qodo`` and ``hexbench.spec`` alongside a runtime
    module. Removing any of those exclusions from ``stage.ps1`` lets the
    corresponding artifact survive the mirror and fails the matching assertion.

    Args:
        tmp_path: Pytest-provided per-test temporary directory.
    """
    call = _robocopy_call("$HexbenchDest")
    exclude_dirs = _exclude_names("-ExcludeDirs", call)
    exclude_files = _exclude_names("-ExcludeFiles", call)
    for required in ("tests", ".qodo"):
        assert required in exclude_dirs, f"hexbench robocopy no longer excludes dir {required}: {exclude_dirs}"
    for required in ("gate.ps1", "update-deps.ps1", "hexbench.spec"):
        assert required in exclude_files, f"hexbench robocopy no longer excludes file {required}: {exclude_files}"

    source = tmp_path / "hexbench"
    (source / "tests").mkdir(parents=True)
    (source / "tests" / "test_server.py").write_text("def test_x() -> None:\n    assert True\n", encoding="utf-8")
    (source / ".qodo").mkdir()
    (source / ".qodo" / "config").write_text("x", encoding="utf-8")
    (source / "gate.ps1").write_text("Write-Host gate", encoding="utf-8")
    (source / "update-deps.ps1").write_text("Write-Host deps", encoding="utf-8")
    (source / "hexbench.spec").write_text("# pyinstaller spec", encoding="utf-8")
    (source / "server.py").write_text("PORT = 0\n", encoding="utf-8")

    dest = tmp_path / "staged"
    _run_robocopy(source, dest, exclude_dirs, exclude_files)

    assert not (dest / "tests").exists(), "hexbench tests/ leaked into the installer"
    assert not (dest / ".qodo").exists(), "hexbench .qodo/ dev tooling leaked into the installer"
    assert not (dest / "gate.ps1").exists(), "hexbench gate.ps1 leaked into the installer"
    assert not (dest / "update-deps.ps1").exists(), "hexbench update-deps.ps1 leaked into the installer"
    assert not (dest / "hexbench.spec").exists(), "hexbench.spec leaked into the installer"
    assert (dest / "server.py").is_file(), "runtime hexbench module was wrongly excluded"


def _extract_ps_function(name: str) -> str:
    """Return the full source text of a PowerShell function defined in stage.ps1.

    Args:
        name: The function name, e.g. ``Remove-MatchingItem``.

    Returns:
        str: The ``function <name> { ... }`` text, brace-balanced.
    """
    text = _STAGE_PS1.read_text(encoding="utf-8")
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


def _extract_trim_block() -> str:
    r"""Return stage.ps1's runtime-trim statements, verbatim.

    The block runs from the first ``Write-Progress 'Removing node.exe...`` banner
    through the end of the dead-directory loop. Lifting the statements verbatim -
    rather than restating them - is what makes the gate detect a commented-out,
    retargeted or neutered trim.

    Returns:
        str: The trim statements as they appear in the production script.
    """
    text = _STAGE_PS1.read_text(encoding="utf-8")
    start = text.index("Write-Progress 'Removing node.exe")
    end = text.index("foreach ($pth in @(", start)
    return text[start:end]


def _run_trim(tmp_path: Path) -> Path:
    r"""Build a synthetic staged runtime and run stage.ps1's real trim block on it.

    The tree carries one instance of every artifact the trim must delete plus
    payload files that must survive, including the ``include`` directories under
    site-packages that triton's XPU backend resolves at runtime.

    Args:
        tmp_path: Pytest-provided per-test temporary directory.

    Returns:
        Path: The synthetic runtime root after the production trim ran over it.
    """
    runtime = tmp_path / "runtime"
    site_packages = runtime / "Lib" / "site-packages"
    for rel in (
        "Lib/site-packages/numpy/tests",
        "Lib/site-packages/tornado/test",
        "Lib/site-packages/torch/include/torch/csrc",
        "Lib/site-packages/triton/backends/intel/include",
        "include/cpython",
        "Library/include/openssl",
        "share/doc/openssl",
        "share/man/man1",
        "Lib/site-packages/pkg/__pycache__",
        "opt/compiler/include",
        "Scripts",
    ):
        (runtime / rel).mkdir(parents=True, exist_ok=True)

    (runtime / "Lib/site-packages/numpy/tests/test_numeric.py").write_text("x = 1\n", encoding="utf-8")
    (runtime / "Lib/site-packages/tornado/test/runtests.py").write_text("x = 1\n", encoding="utf-8")
    (runtime / "Lib/site-packages/pkg/__pycache__/mod.cpython-313.pyc").write_bytes(b"\x00")
    (runtime / "include/cpython/Python.h").write_text("#define PY 1\n", encoding="utf-8")
    (runtime / "Library/include/openssl/ssl.h").write_text("#define SSL 1\n", encoding="utf-8")
    (runtime / "share/doc/openssl/README").write_text("docs\n", encoding="utf-8")
    (runtime / "share/man/man1/openssl.1").write_text("man\n", encoding="utf-8")
    (runtime / "libs").mkdir()
    (runtime / "libs/python313.lib").write_bytes(b"\x00lib")
    (runtime / "Scripts/node.exe").write_bytes(b"MZnode")
    (runtime / "python.pdb").write_bytes(b"\x00pdb")
    # Payload that must survive the trim.
    (runtime / "python.exe").write_bytes(b"MZ")
    (site_packages / "pkg").mkdir(parents=True, exist_ok=True)
    (site_packages / "pkg" / "__init__.py").write_text("VERSION = '1'\n", encoding="utf-8")
    (runtime / "Lib/site-packages/torch/include/torch/csrc/api.h").write_text("#define T 1\n", encoding="utf-8")
    (runtime / "Lib/site-packages/triton/backends/intel/include/sycl.h").write_text("#define S 1\n", encoding="utf-8")
    (runtime / "opt/compiler/include/omp.h").write_text("#define O 1\n", encoding="utf-8")

    script = "\n".join(
        (
            "Set-StrictMode -Version Latest",
            "$ErrorActionPreference = 'Stop'",
            "function Write-Progress { param([Parameter(ValueFromRemainingArguments)]$Rest) }",
            _extract_ps_function("Remove-MatchingItem"),
            f"$RuntimeDir = '{runtime}'",
            f"$RuntimeSitePackages = '{site_packages}'",
            _extract_trim_block(),
        ),
    )
    script_path = tmp_path / "trim.ps1"
    script_path.write_text(script, encoding="utf-8")
    pwsh = shutil.which("pwsh")
    assert pwsh is not None, "pwsh (PowerShell 7) is required to run stage.ps1's trim block"
    completed = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-File", str(script_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, f"trim block failed (exit {completed.returncode}):\n{completed.stdout}\n{completed.stderr}"
    return runtime


def test_runtime_trim_strips_libs_headers_tests_and_docs(tmp_path: Path) -> None:
    r"""The runtime trim must really delete libs, headers, package tests and docs.

    This lifts ``Remove-MatchingItem`` and the trim statements verbatim out of
    ``stage.ps1`` and executes them against a synthetic staged runtime, so it
    gates the *behavior*, not the presence of a token: commenting the statements
    out, retargeting a ``-Root``, or neutering the dead-directory loop all leave
    the corresponding artifact in place and redden an assertion here.

    Args:
        tmp_path: Pytest-provided per-test temporary directory.
    """
    runtime = _run_trim(tmp_path)

    removed = {
        "third-party test suite (numpy/tests)": runtime / "Lib/site-packages/numpy/tests",
        "third-party test suite (tornado/test)": runtime / "Lib/site-packages/tornado/test",
        "static import library": runtime / "libs/python313.lib",
        "interpreter C headers": runtime / "include",
        "conda C headers": runtime / "Library/include",
        "packaged documentation": runtime / "share/doc",
        "packaged man pages": runtime / "share/man",
        "bytecode cache": runtime / "Lib/site-packages/pkg/__pycache__",
        "bundled node.exe": runtime / "Scripts/node.exe",
        "debug symbols": runtime / "python.pdb",
    }
    for what, path in removed.items():
        assert not path.exists(), f"runtime trim no longer removes {what}: {path} survived"

    survived = {
        "interpreter": runtime / "python.exe",
        "shipped package": runtime / "Lib/site-packages/pkg/__init__.py",
        "torch headers (triton XPU JIT reads these)": runtime / "Lib/site-packages/torch/include/torch/csrc/api.h",
        "triton Intel headers": runtime / "Lib/site-packages/triton/backends/intel/include/sycl.h",
        "Intel compiler headers": runtime / "opt/compiler/include/omp.h",
    }
    for what, path in survived.items():
        assert path.exists(), f"runtime trim wrongly deleted the {what}: {path}"
