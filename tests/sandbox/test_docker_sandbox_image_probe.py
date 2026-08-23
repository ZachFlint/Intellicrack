# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for image-cache probing in the Docker sandbox driver.

``docker image inspect`` exits non-zero both when an image is genuinely absent
and when the probe simply could not tell -- a timeout while the engine is
saturated, a daemon still warming up, an invalid reference. Treating those
alike made the driver conclude a present 45 GB image was missing and start a
~30-minute rebuild of an image that already existed.

The driver therefore classifies a probe three ways (:class:`ImagePresence`) and
only accepts Docker's explicit "No such image" text as proof of absence;
``build_image`` refuses to rebuild on an inconclusive probe.

These tests drive the real driver functions in a subprocess against a **stub**
Docker CLI on ``PATH`` whose ``image inspect`` behaviour is controlled, so the
tests observe genuine subprocess behaviour rather than a mocked return value.
If the classification collapses back to ``returncode == 0``, the timeout and
daemon-error cases report ``ABSENT`` and those tests fail.
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

_ABSENT_STDERR = "Error response from daemon: No such image: intellicrack-sandbox:latest"
_DAEMON_ERROR_STDERR = "error during connect: this error may indicate that the docker daemon is not running"


def _write_stub_docker(directory: Path, *, inspect_exit: int, inspect_stderr: str = "", hang_seconds: int = 0) -> None:
    """Create a stub ``docker.cmd`` with controllable ``image inspect`` behaviour.

    Args:
        directory: Directory the ``docker.cmd`` stub is written to.
        inspect_exit: Exit code returned for ``docker image inspect``.
        inspect_stderr: Text the stub writes to stderr for ``image inspect``.
        hang_seconds: When positive, the stub sleeps this long before exiting so
            the driver's probe timeout elapses.
    """
    if hang_seconds > 0:
        inspect_body = f"ping -n {hang_seconds + 1} 127.0.0.1 >nul & exit /b {inspect_exit}"
    elif inspect_stderr:
        inspect_body = f"echo {inspect_stderr} 1>&2 & exit /b {inspect_exit}"
    else:
        inspect_body = f"exit /b {inspect_exit}"
    stub = textwrap.dedent(
        f"""\
        @echo off
        if "%1"=="image" ( {inspect_body} )
        exit /b 0
        """,
    )
    (directory / "docker.cmd").write_text(stub, encoding="utf-8")


def _run_driver(stub_dir: Path, body: str, *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    """Run a driver snippet against the stub Docker CLI in a subprocess.

    The snippet is executed with ``stub_dir`` first on ``PATH`` (so
    ``shutil.which("docker")`` resolves to the stub) and the repository on
    ``sys.path`` (so the driver module imports).

    Args:
        stub_dir: Directory containing the ``docker.cmd`` stub.
        body: Python statements executed after the driver module is imported as
            ``docker_sandbox``.
        timeout: Wall-clock limit for the driver subprocess, in seconds.

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
        timeout=timeout,
        check=False,
    )


_PROBE_BODY = """
    docker_sandbox._IMAGE_PROBE_RETRY_DELAY = 0.0
    print("PRESENCE=" + docker_sandbox._probe_image_presence("intellicrack-sandbox:latest").name)
"""


def test_probe_reports_present_when_inspect_succeeds(tmp_path: Path) -> None:
    """A clean ``docker image inspect`` must resolve to ``PRESENT``.

    This pins the positive case so a change that made every probe inconclusive
    (which would refuse to build even on a genuinely first run) is caught.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    _write_stub_docker(tmp_path, inspect_exit=0)
    result = _run_driver(tmp_path, _PROBE_BODY)
    assert "PRESENCE=PRESENT" in result.stdout, f"stdout={result.stdout} stderr={result.stderr}"


def test_probe_reports_absent_only_on_no_such_image(tmp_path: Path) -> None:
    """Docker's explicit "No such image" response must resolve to ``ABSENT``.

    This is the one failure that genuinely warrants a build, and it must keep
    working so a first run still builds the image.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    _write_stub_docker(tmp_path, inspect_exit=1, inspect_stderr=_ABSENT_STDERR)
    result = _run_driver(tmp_path, _PROBE_BODY)
    assert "PRESENCE=ABSENT" in result.stdout, f"stdout={result.stdout} stderr={result.stderr}"


def test_probe_reports_unknown_on_daemon_error(tmp_path: Path) -> None:
    """A non-zero exit without "No such image" must resolve to ``UNKNOWN``.

    A daemon-connection failure says nothing about whether the image exists.
    Under the previous ``returncode == 0`` test this classified as absent, so
    reverting the classification makes this assertion fail.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    _write_stub_docker(tmp_path, inspect_exit=1, inspect_stderr=_DAEMON_ERROR_STDERR)
    result = _run_driver(tmp_path, _PROBE_BODY)
    assert "PRESENCE=UNKNOWN" in result.stdout, f"stdout={result.stdout} stderr={result.stderr}"


def test_probe_reports_unknown_when_inspect_times_out(tmp_path: Path) -> None:
    """A probe that times out must resolve to ``UNKNOWN``, never ``ABSENT``.

    This reproduces the real incident: the engine was saturated, the probe
    timed out (exit 124), and the driver concluded the image was missing.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    _write_stub_docker(tmp_path, inspect_exit=0, hang_seconds=6)
    body = """
        docker_sandbox._IMAGE_PROBE_RETRY_DELAY = 0.0
        docker_sandbox._DOCKER_PROBE_TIMEOUT_SECONDS = 1.0
        print("PRESENCE=" + docker_sandbox._probe_image_presence("intellicrack-sandbox:latest").name)
    """
    result = _run_driver(tmp_path, body)
    assert "PRESENCE=UNKNOWN" in result.stdout, f"stdout={result.stdout} stderr={result.stderr}"


def test_probe_retries_until_a_definitive_answer(tmp_path: Path) -> None:
    """An inconclusive probe must be retried before giving up.

    The stub fails inconclusively on its first invocation and succeeds
    afterwards, driven by a counter file. A single-shot probe returns
    ``UNKNOWN`` here; only a retrying probe reaches ``PRESENT``.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    counter = tmp_path / "calls.txt"
    stub = textwrap.dedent(
        f"""\
        @echo off
        if not "%1"=="image" exit /b 0
        if exist "{counter}" ( exit /b 0 )
        echo done> "{counter}"
        echo {_DAEMON_ERROR_STDERR} 1>&2
        exit /b 1
        """,
    )
    (tmp_path / "docker.cmd").write_text(stub, encoding="utf-8")
    result = _run_driver(tmp_path, _PROBE_BODY)
    assert "PRESENCE=PRESENT" in result.stdout, f"stdout={result.stdout} stderr={result.stderr}"
    assert counter.exists(), "stub was never invoked; the probe did not run"


def _build_body(tmp_path: Path) -> str:
    """Build a driver snippet that calls ``build_image`` and reports the outcome.

    ``build_image`` rejects a missing Dockerfile before it probes the image
    cache, and the driver's ``_DOCKERFILE`` points at a hardcoded host path that
    does not exist inside the sandbox container. The snippet therefore redirects
    ``_DOCKERFILE`` at a real file in ``tmp_path`` so the probe decision -- the
    behaviour under test -- is the only thing that can decide the outcome.

    Args:
        tmp_path: Directory the placeholder Dockerfile is written to.

    Returns:
        str: Python statements to execute in the driver subprocess.
    """
    dockerfile = tmp_path / "Dockerfile.probe"
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")
    return f"""
        from pathlib import Path
        docker_sandbox._IMAGE_PROBE_RETRY_DELAY = 0.0
        docker_sandbox._DOCKERFILE = Path(r"{dockerfile}")
        assert docker_sandbox._DOCKERFILE.exists(), "precondition: Dockerfile must exist"
        try:
            tag = docker_sandbox.build_image("intellicrack-sandbox:latest")
            print("RESULT=built:" + tag)
        except docker_sandbox.SandboxError as exc:
            print("RESULT=raised")
            print("DETAIL=" + str(exc))
    """


def test_build_image_refuses_to_rebuild_on_inconclusive_probe(tmp_path: Path) -> None:
    """``build_image`` must raise rather than rebuild when presence is unknown.

    Rebuilding on an inconclusive probe discards a working multi-gigabyte image
    and costs a full rebuild. The stub answers every ``image inspect`` with a
    daemon error, so a driver that still treats non-zero as absent proceeds to
    ``docker build`` and prints ``RESULT=built`` instead of ``RESULT=raised``.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    _write_stub_docker(tmp_path, inspect_exit=1, inspect_stderr=_DAEMON_ERROR_STDERR)
    result = _run_driver(tmp_path, _build_body(tmp_path))
    assert "RESULT=raised" in result.stdout, (
        f"build_image must not rebuild on an inconclusive probe; stdout={result.stdout} stderr={result.stderr}"
    )
    assert "DETAIL=unable to determine whether image" in result.stdout, (
        "build_image must raise specifically because the probe was inconclusive, not for an "
        f"unrelated reason; stdout={result.stdout} stderr={result.stderr}"
    )


def test_build_image_still_builds_when_image_is_genuinely_absent(tmp_path: Path) -> None:
    """A definitive absence must still trigger a build.

    This guards the opposite failure: refusing to build on the first ever run.
    The stub reports "No such image" for ``image inspect`` and exits 0 for
    ``build``, so a correct driver builds and returns the tag.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    _write_stub_docker(tmp_path, inspect_exit=1, inspect_stderr=_ABSENT_STDERR)
    result = _run_driver(tmp_path, _build_body(tmp_path))
    assert "RESULT=built:intellicrack-sandbox:latest" in result.stdout, (
        f"a genuinely absent image must still build; stdout={result.stdout} stderr={result.stderr}"
    )
