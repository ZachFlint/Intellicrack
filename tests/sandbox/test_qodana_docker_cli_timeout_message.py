# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for ``_run_docker``'s timeout-message formatting.

Covers the 2026-09-20 Qodana ``PyStringFormatInspection`` finding: on a
``subprocess.TimeoutExpired``, the timeout message previously formatted the
call's own ``timeout: float | None`` parameter (``f"...after {timeout:g}s"``)
-- a value the type checker cannot prove is non-``None`` at that point, even
though a ``TimeoutExpired`` can only be raised when a real numeric timeout
was passed to ``subprocess.run``. The message now formats
``exc.timeout`` -- ``TimeoutExpired``'s own attribute, which
:mod:`subprocess` guarantees is the actual ``float`` timeout that was
exceeded -- which is both provably non-``None`` and, unlike the call's own
parameter, guaranteed to be the *effective* value even if a future caller
ever normalises or overrides it before the ``subprocess.run`` call.

Drives the real ``_run_docker`` function (via ``getattr``, bypassing
``reportPrivateUsage``, the project's established pattern for testing
private module internals -- see ``tests/bridges/test_process_bridge.py``)
against a real stub ``docker`` executable placed first on ``PATH`` (the
same real-subprocess technique used by
``tests/sandbox/test_docker_sandbox_force_stop.py``) that never returns, so
the timeout is a genuine OS-level subprocess timeout, not a simulated one.
"""

from __future__ import annotations

import os
import sys
import textwrap
from typing import TYPE_CHECKING

import pytest

from scripts.sandbox import docker_sandbox as docker_sandbox_module
from scripts.sandbox.docker_sandbox import SandboxError


if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="uses a Windows .cmd stub")

_ATTR_RUN_DOCKER = "_run_docker"
_TEST_TIMEOUT_SECONDS = 0.5


def _write_never_returning_docker_stub(directory: Path) -> None:
    """Create a stub ``docker.cmd`` that never returns for any invocation.

    Args:
        directory: Directory the ``docker.cmd`` stub is written to.
    """
    stub = textwrap.dedent(
        """\
        @echo off
        ping -n 3 127.0.0.1 >nul 2>&1
        exit /b 0
        """,
    )
    (directory / "docker.cmd").write_text(stub, encoding="utf-8")


def _invoke_run_docker(args: list[str], *, check: bool, timeout: float | None) -> object:
    """Invoke ``docker_sandbox._run_docker`` via ``getattr``, bypassing ``reportPrivateUsage``.

    Args:
        args: Argument list passed after the docker executable.
        check: When True, raise ``SandboxError`` on timeout/non-zero exit.
        timeout: Wall-clock limit in seconds.

    Returns:
        object: Whatever ``_run_docker`` returns.

    Raises:
        TypeError: If the resolved attribute is not callable.
    """
    fn: object = getattr(docker_sandbox_module, _ATTR_RUN_DOCKER)
    if not callable(fn):
        msg = f"docker_sandbox.{_ATTR_RUN_DOCKER} is not callable"
        raise TypeError(msg)
    return fn(args, check=check, timeout=timeout)


def test_timeout_message_reports_the_real_effective_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A genuine subprocess timeout must render ``exc.timeout``'s real value, not a stale one.

    Args:
        tmp_path: Pytest-provided scratch directory for the stub executable.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _write_never_returning_docker_stub(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}")

    with pytest.raises(SandboxError) as exc_info:
        _invoke_run_docker(["ps"], check=True, timeout=_TEST_TIMEOUT_SECONDS)

    assert f"timed out after {_TEST_TIMEOUT_SECONDS:g}s" in str(exc_info.value)


def test_timeout_without_check_returns_synthetic_124_with_real_timeout_in_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With ``check=False``, the synthetic result's return code is 124 on a genuine timeout.

    Args:
        tmp_path: Pytest-provided scratch directory for the stub executable.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _write_never_returning_docker_stub(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}")

    result = _invoke_run_docker(["ps"], check=False, timeout=_TEST_TIMEOUT_SECONDS)

    assert getattr(result, "returncode", None) == 124
