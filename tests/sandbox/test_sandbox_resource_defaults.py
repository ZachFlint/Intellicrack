# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the sandbox CPU/memory defaults and job forwarding.

These tests pin the operator-facing contract changed for full-suite coverage
runs: every ``docker run`` defaults to 16 CPUs and 32 GB of memory (still
overridable by ``--cpus`` / ``--memory``), and the ``COVERAGE_JOBS`` host
environment variable is forwarded into the container so coverage group
parallelism can be tuned. Each assertion fails loudly if a default regresses to
its previous value or the forwarding is removed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from scripts.sandbox import docker_sandbox
from scripts.sandbox.test_types import TestRunSpec, TestType


if TYPE_CHECKING:
    import argparse
    from collections.abc import Callable

    import pytest

_MODULE_MEMBERS = vars(docker_sandbox)
_build_parser = cast("Callable[[], argparse.ArgumentParser]", _MODULE_MEMBERS["_build_parser"])
_build_docker_run_argv = cast("Callable[..., list[str]]", _MODULE_MEMBERS["_build_docker_run_argv"])


def _flag_value(argv: list[str], flag: str) -> str:
    """Return the token immediately following ``flag`` in ``argv``.

    Args:
        argv: The ``docker run`` argument vector.
        flag: The flag whose adjacent value is wanted (for example ``--cpus``).

    Returns:
        str: The value token that follows the flag.
    """
    index = argv.index(flag)
    return argv[index + 1]


def _coverage_argv(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Build a coverage ``docker run`` argv with the docker binary stubbed.

    Only the external ``docker`` executable lookup is stubbed; the argv
    construction under test runs for real.

    Args:
        monkeypatch: pytest fixture used to stub the binary lookup.

    Returns:
        list[str]: The constructed ``docker run`` argument vector.
    """
    monkeypatch.setattr(docker_sandbox, "_docker_binary", lambda: "docker")
    spec = TestRunSpec(test_type=TestType.COVERAGE, timestamp="20260101_000000")
    return _build_docker_run_argv(
        spec,
        "intellicrack-sandbox:latest",
        memory="32g",
        cpus="16",
        network="none",
        writable_workspace=False,
        interactive=False,
    )


def test_cpu_default_is_sixteen() -> None:
    """The CLI parser defaults ``--cpus`` to 16."""
    args = _build_parser().parse_args(["coverage"])
    assert args.cpus == "16"


def test_memory_default_is_thirty_two_gigabytes() -> None:
    """The CLI parser defaults ``--memory`` to 32g."""
    args = _build_parser().parse_args(["coverage"])
    assert args.memory == "32g"


def test_cpu_flag_overrides_default() -> None:
    """An explicit ``--cpus`` still wins over the new default."""
    args = _build_parser().parse_args(["coverage", "--cpus", "4"])
    assert args.cpus == "4"


def test_memory_flag_overrides_default() -> None:
    """An explicit ``--memory`` still wins over the new default."""
    args = _build_parser().parse_args(["coverage", "--memory", "8g"])
    assert args.memory == "8g"


def test_sandbox_config_defaults_match_cli() -> None:
    """The programmatic ``DockerSandbox`` defaults match the CLI defaults."""
    sandbox = docker_sandbox.DockerSandbox()
    assert sandbox.cpus == "16"
    assert sandbox.memory == "32g"


def test_docker_argv_carries_cpu_and_memory_quotas(monkeypatch: pytest.MonkeyPatch) -> None:
    """The built ``docker run`` argv passes the CPU and memory quotas through."""
    argv = _coverage_argv(monkeypatch)
    assert _flag_value(argv, "--cpus") == "16"
    assert _flag_value(argv, "--memory") == "32g"


def test_coverage_jobs_forwarded_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """A host ``COVERAGE_JOBS`` value is forwarded as a container ``--env``."""
    monkeypatch.setenv("COVERAGE_JOBS", "8")
    argv = _coverage_argv(monkeypatch)
    assert "COVERAGE_JOBS=8" in argv
    assert argv[argv.index("COVERAGE_JOBS=8") - 1] == "--env"


def test_coverage_jobs_absent_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """No ``COVERAGE_JOBS`` env is injected when the host has none set."""
    monkeypatch.delenv("COVERAGE_JOBS", raising=False)
    argv = _coverage_argv(monkeypatch)
    assert not any(token.startswith("COVERAGE_JOBS=") for token in argv)
