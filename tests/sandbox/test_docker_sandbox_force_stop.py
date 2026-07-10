# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gate for the host driver's timeout container force-stop.

When a sandbox run exceeds its host ``--timeout`` the driver
(:file:`scripts/sandbox/docker_sandbox.py`) must actually stop the container in
the Docker engine. Terminating the ``docker run`` client alone leaves the
detached Windows container running -- the exact defect that let a hung coverage
run continue for hours after the host timeout fired.

These tests drive the real ``_run_streamed`` function against a **stub** Docker
CLI placed first on ``PATH``. The stub is a real executable that records every
invocation to a log file, so the tests observe genuine subprocess behaviour --
not a mocked return value. A ``docker run`` that never returns forces the
timeout path; the gate then asserts the driver issued ``docker kill <name>``
(and, when the kill itself fails, the ``docker rm -f`` fallback). If the
force-stop is removed the log never records the ``kill`` and the assertion
fails.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="uses a Windows .cmd stub and targets the Windows container driver",
)

_CONTAINER = "intellicrack-sandbox-forcestop-test"


def _write_stub_docker(directory: Path, log_path: Path, *, kill_exit: int) -> None:
    """Create a stub ``docker.cmd`` that logs its invocations.

    The stub simulates a container that never returns for ``docker run`` (so
    the caller's timeout fires) and appends ``<verb> <args>`` to ``log_path``
    for every call, letting the test observe exactly which Docker commands the
    driver issued.

    Args:
        directory: Directory the ``docker.cmd`` stub is written to.
        log_path: File the stub appends each invocation to.
        kill_exit: Exit code the stub returns for ``docker kill`` (non-zero
            exercises the ``docker rm -f`` fallback).
    """
    stub = textwrap.dedent(
        f"""\
        @echo off
        if "%1"=="run" (
            echo run >> "{log_path}"
            ping -n 30 127.0.0.1 >nul 2>&1
            exit /b 0
        )
        if "%1"=="kill" (
            echo kill %2 >> "{log_path}"
            exit /b {kill_exit}
        )
        if "%1"=="rm" (
            echo rm %2 %3 >> "{log_path}"
            exit /b 0
        )
        echo other %* >> "{log_path}"
        exit /b 0
        """,
    )
    (directory / "docker.cmd").write_text(stub, encoding="utf-8")


def _run_driver(stub_dir: Path) -> subprocess.CompletedProcess[str]:
    """Invoke ``_run_streamed`` in a subprocess against the stub Docker CLI.

    The subprocess prepends ``stub_dir`` to ``PATH`` so the driver's
    ``shutil.which("docker")`` resolves to the stub, then calls ``_run_streamed``
    with a short timeout and a stub ``docker run`` that never returns.

    Args:
        stub_dir: Directory containing the ``docker.cmd`` stub (prepended to PATH).

    Returns:
        subprocess.CompletedProcess[str]: The completed driver subprocess. Its
            stdout carries the ``_run_streamed`` return code as ``RC=<n>``.
    """
    driver = stub_dir / "driver.py"
    driver.write_text(
        textwrap.dedent(
            f"""\
            import sys
            sys.path.insert(0, r"{_REPO_ROOT}")
            from scripts.sandbox.docker_sandbox import _run_streamed
            docker = r"{stub_dir / "docker.cmd"}"
            rc = _run_streamed(
                [docker, "run", "--name", "{_CONTAINER}", "busy"],
                timeout_seconds=3,
                container_name="{_CONTAINER}",
            )
            print(f"RC={{rc}}")
            """,
        ),
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PATH"] = f"{stub_dir}{os.pathsep}{env.get('PATH', '')}"
    return subprocess.run(
        [sys.executable, str(driver)],
        capture_output=True,
        text=True,
        env=env,
        timeout=90,
        check=False,
    )


def test_host_timeout_kills_the_detached_container(tmp_path: Path) -> None:
    """A host timeout must issue ``docker kill`` against the container name.

    The stub ``docker run`` never returns, so ``_run_streamed`` hits its 3 s
    timeout. The driver must then force-stop the container: the stub's log must
    record ``kill <container>`` and ``_run_streamed`` must return 124. Without
    the force-stop the detached container would keep running and the log would
    never contain the kill.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    log_path = tmp_path / "docker_calls.log"
    _write_stub_docker(tmp_path, log_path, kill_exit=0)

    result = _run_driver(tmp_path)

    assert "RC=124" in result.stdout, f"timeout must return 124; stdout={result.stdout} stderr={result.stderr}"
    assert log_path.is_file(), "stub docker was never invoked"
    calls = log_path.read_text(encoding="utf-8")
    assert "run" in calls, "the stub docker run was never launched"
    assert f"kill {_CONTAINER}" in calls, f"host timeout must docker-kill the container; calls={calls!r}"


def test_kill_failure_falls_back_to_rm_force(tmp_path: Path) -> None:
    """When ``docker kill`` fails the driver must fall back to ``docker rm -f``.

    A container that has already exited makes ``docker kill`` return non-zero;
    the driver must then remove any stale record so the next run's ``--name``
    does not conflict. The stub returns a non-zero kill exit and the log must
    contain both the ``kill`` attempt and the ``rm -f`` fallback.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    log_path = tmp_path / "docker_calls.log"
    _write_stub_docker(tmp_path, log_path, kill_exit=1)

    result = _run_driver(tmp_path)

    assert "RC=124" in result.stdout, f"timeout must return 124; stdout={result.stdout} stderr={result.stderr}"
    calls = log_path.read_text(encoding="utf-8")
    assert f"kill {_CONTAINER}" in calls, f"kill must be attempted; calls={calls!r}"
    assert f"rm -f {_CONTAINER}" in calls, f"failed kill must fall back to rm -f; calls={calls!r}"
