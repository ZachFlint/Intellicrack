# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the sandbox CPU/memory defaults and job forwarding.

These tests pin the operator-facing contract for sandbox resource sizing: the
per-run CPU and memory share is left unpinned by default so the admission
governor can size it from the host (letting several runs fit concurrently),
an explicitly pinned ``--cpus`` / ``--memory`` is honoured verbatim, and the
``COVERAGE_JOBS`` host environment variable is forwarded into the container so
coverage group parallelism can be tuned. Each assertion fails loudly if sizing
regresses to a fixed constant, if a pinned value is silently rewritten, or if
the forwarding is removed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from scripts.sandbox import docker_sandbox
from scripts.sandbox.test_types import TestRunSpec, TestType


if TYPE_CHECKING:
    import argparse
    from collections.abc import Callable

    import pytest

    from scripts.sandbox.admission import CapacityPlan

_MODULE_MEMBERS = vars(docker_sandbox)
_build_parser = cast("Callable[[], argparse.ArgumentParser]", _MODULE_MEMBERS["_build_parser"])
_build_docker_run_argv = cast("Callable[..., list[str]]", _MODULE_MEMBERS["_build_docker_run_argv"])
_resolve_capacity_plan = cast("Callable[..., CapacityPlan]", _MODULE_MEMBERS["_resolve_capacity_plan"])


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


def test_cpu_and_memory_are_unpinned_by_default() -> None:
    """Omitting the flags must leave the per-run size for the governor to pick.

    A non-``None`` parser default would pin every run to one fixed size, which
    is what the admission governor replaced: sizing is derived from the host so
    several runs fit concurrently.
    """
    args = _build_parser().parse_args(["coverage"])
    assert args.cpus is None, f"--cpus must default to auto-sizing; got {args.cpus!r}"
    assert args.memory is None, f"--memory must default to auto-sizing; got {args.memory!r}"


def test_unpinned_defaults_resolve_to_a_host_derived_plan() -> None:
    """An unpinned run must still receive a concrete, host-derived quota.

    Auto-sizing must produce real ``docker run`` values rather than leaving the
    quota empty; a plan with no memory or CPU share would launch containers
    without limits and let concurrent runs exhaust the host.
    """
    plan = _resolve_capacity_plan(requested_memory=None, requested_cpus=None)

    assert plan.slots >= 1, f"the governor must allow at least one run; got {plan.slots}"
    assert plan.memory.endswith("g"), f"memory share is not a docker size: {plan.memory!r}"
    assert int(plan.memory.removesuffix("g")) > 0, f"memory share must be positive: {plan.memory!r}"
    assert int(plan.cpus) > 0, f"cpu share must be positive: {plan.cpus!r}"


def test_pinned_resources_are_honoured_verbatim() -> None:
    """An operator-pinned quota must survive the governor unchanged.

    The governor may shrink the slot budget around a pinned size, but must not
    rewrite the size itself; silently resizing an explicit request would defeat
    the override that :func:`test_cpu_flag_overrides_default` relies on.
    """
    plan = _resolve_capacity_plan(requested_memory="8g", requested_cpus="4")

    assert plan.memory == "8g", f"pinned memory was rewritten to {plan.memory!r}"
    assert plan.cpus == "4", f"pinned cpus was rewritten to {plan.cpus!r}"


def test_cpu_flag_overrides_default() -> None:
    """An explicit ``--cpus`` still wins over the new default."""
    args = _build_parser().parse_args(["coverage", "--cpus", "4"])
    assert args.cpus == "4"


def test_memory_flag_overrides_default() -> None:
    """An explicit ``--memory`` still wins over the new default."""
    args = _build_parser().parse_args(["coverage", "--memory", "8g"])
    assert args.memory == "8g"


def test_sandbox_config_carries_programmatic_fallback_sizes() -> None:
    """``DockerSandbox`` keeps concrete fallback sizes for programmatic callers.

    The CLI always passes governor-derived values, so these attribute defaults
    apply only when the class is constructed directly without a plan; they must
    stay concrete so such a caller still gets a bounded container.
    """
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
