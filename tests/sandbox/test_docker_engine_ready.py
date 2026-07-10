# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the Docker container-engine readiness check.

``docker version`` answers as soon as the API server is up, but on Windows a
``docker run`` issued before the container engine has warmed up fails with
``unable to upgrade to tcp, received 500``. The driver therefore gates
readiness on ``docker ps`` (``_engine_ready``) in addition to ``docker version``
(``_daemon_ready``).

These tests drive the real driver functions in a subprocess against a **stub**
Docker CLI on ``PATH`` whose per-verb exit codes are controlled. The stub is a
real executable, so the tests observe genuine subprocess behaviour. If the
engine gate is removed -- so readiness reflects only the daemon --
``ensure_docker_running`` returns while ``docker ps`` is still failing and the
final test fails.
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


def _write_stub_docker(directory: Path, *, version_exit: int, ps_exit: int) -> None:
    """Create a stub ``docker.cmd`` with controllable per-verb exit codes.

    Args:
        directory: Directory the ``docker.cmd`` stub is written to.
        version_exit: Exit code returned for ``docker version``.
        ps_exit: Exit code returned for ``docker ps``.
    """
    stub = textwrap.dedent(
        f"""\
        @echo off
        if "%1"=="version" ( echo 29.0.0 & exit /b {version_exit} )
        if "%1"=="ps" ( exit /b {ps_exit} )
        exit /b 0
        """,
    )
    (directory / "docker.cmd").write_text(stub, encoding="utf-8")


def _run_driver(stub_dir: Path, body: str) -> subprocess.CompletedProcess[str]:
    """Run a driver snippet against the stub Docker CLI in a subprocess.

    The snippet is executed with ``stub_dir`` first on ``PATH`` (so
    ``shutil.which("docker")`` resolves to the stub) and the repository on
    ``sys.path`` (so the driver module imports).

    Args:
        stub_dir: Directory containing the ``docker.cmd`` stub.
        body: Python statements executed after the driver module is imported as
            ``docker_sandbox``.

    Returns:
        subprocess.CompletedProcess[str]: The completed driver subprocess.
    """
    driver = stub_dir / "driver.py"
    driver.write_text(
        textwrap.dedent(
            f"""\
            import os
            import sys
            sys.path.insert(0, r"{_REPO_ROOT}")
            os.environ["PATH"] = r"{stub_dir}" + os.pathsep + os.environ.get("PATH", "")
            from scripts.sandbox import docker_sandbox
            """,
        )
        + textwrap.dedent(body),
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PATH"] = f"{stub_dir}{os.pathsep}{env.get('PATH', '')}"
    return subprocess.run(
        [sys.executable, str(driver)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )


@pytest.mark.parametrize(
    ("ps_exit", "expected"),
    [(0, "ENGINE=True"), (1, "ENGINE=False")],
)
def test_engine_ready_reflects_docker_ps(tmp_path: Path, ps_exit: int, expected: str) -> None:
    """``_engine_ready`` must be true only when ``docker ps`` exits cleanly.

    A stub whose ``docker ps`` exits 0 must make ``_engine_ready`` return
    ``True``; a stub whose ``docker ps`` exits non-zero must make it return
    ``False``. If ``_engine_ready`` probed ``docker version`` instead of
    ``docker ps`` (which always exits 0 here) both cases would report ``True``
    and the ``ps_exit=1`` case would fail.

    Args:
        tmp_path: Pytest-provided temporary directory.
        ps_exit: Exit code the stub returns for ``docker ps``.
        expected: The expected ``ENGINE=<bool>`` line.
    """
    _write_stub_docker(tmp_path, version_exit=0, ps_exit=ps_exit)
    result = _run_driver(tmp_path, 'print("ENGINE=" + str(docker_sandbox._engine_ready()))')
    assert expected in result.stdout, f"expected {expected!r}; stdout={result.stdout} stderr={result.stderr}"


def test_ensure_docker_running_requires_engine_not_just_daemon(tmp_path: Path) -> None:
    """Readiness must require the engine, not merely the daemon.

    The stub reports the daemon up (``docker version`` exits 0) but the engine
    perpetually not ready (``docker ps`` exits 1). ``ensure_docker_running``
    must therefore never consider Docker ready and must raise ``SandboxError``
    once the (shortened) readiness deadline elapses. If the gate checked only
    the daemon it would return immediately and print ``RESULT=returned``,
    failing this assertion.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    _write_stub_docker(tmp_path, version_exit=0, ps_exit=1)
    body = """
        docker_sandbox._DOCKER_DAEMON_TIMEOUT_SECONDS = 4
        docker_sandbox._DOCKER_DAEMON_POLL_INTERVAL = 1.0
        try:
            docker_sandbox.ensure_docker_running()
            print("RESULT=returned")
        except docker_sandbox.SandboxError:
            print("RESULT=raised")
    """
    result = _run_driver(tmp_path, body)
    assert "RESULT=raised" in result.stdout, (
        f"ensure_docker_running must not report ready while docker ps fails; stdout={result.stdout} stderr={result.stderr}"
    )
