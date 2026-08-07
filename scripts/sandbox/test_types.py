# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Test type specifications and pytest argument builder.

This module provides the single source of truth for Intellicrack's 15 test
execution modes. The :class:`TestType` enum captures the stable identifiers
accepted by the justfile and host driver, :class:`TestRunSpec` carries the
parameters for a single invocation, and :func:`build_pytest_args` deterministically
maps a spec to the concrete ``pytest`` argument vector. Host and container
share this definition via a serialized spec so the resulting command line is
identical regardless of where it is constructed.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath
from typing import cast


_CONTAINER_WORKSPACE = PurePosixPath("C:/app")
_CONTAINER_REPORTS = _CONTAINER_WORKSPACE / "reports" / "tests"
_RUN_ID_ENTROPY_BYTES = 3


def new_run_id() -> str:
    """Return a fresh identity component unique to a single sandbox run.

    The component pairs the launching host process id with a short random
    suffix, so two runs never share a container name, spec file, exit-code
    file, or report filename -- not across two driver processes, and not
    across two runs started from the same process within the same minute.
    Only characters valid in both Windows filenames and Docker container
    names are emitted.

    Returns:
        str: Run identity component, for example ``p20164-9fa3c1``.
    """
    return f"p{os.getpid()}-{secrets.token_hex(_RUN_ID_ENTROPY_BYTES)}"


class TestType(StrEnum):
    """Enumeration of supported test execution modes.

    Attributes:
        INTERACTIVE: Open a read-only shell inside the container.
        INTERACTIVE_RW: Open a shell with a writable workspace mount.
        UNIT: Quick unit tests excluding slow/integration/e2e markers.
        ALL: Full test suite across ``tests/``.
        COVERAGE: Full suite with coverage collection and a 95% gate.
        INTEGRATION: Integration-marker tests under ``tests/test_integration``.
        E2E: End-to-end scenarios under ``tests/test_hexcore_e2e``.
        SMOKE: Minimal smoke subset completing in under two minutes.
        PARALLEL: Full suite distributed via ``pytest-xdist``.
        FAILED: Re-run only the last failing tests.
        VERBOSE: Full suite with ``-vv`` trace output.
        BENCH: Benchmark suite via ``pytest-benchmark``.
        MODULE: Narrow run targeting a specific module path.
        MODULE_COV: Module run with coverage and an 80% gate.
        REGISTRY: Hardware-spoofer registry tests.
        CUSTOM: Pass-through mode forwarding operator-supplied args.
    """

    INTERACTIVE = "interactive"
    INTERACTIVE_RW = "interactive-rw"
    UNIT = "unit"
    ALL = "all"
    COVERAGE = "coverage"
    INTEGRATION = "integration"
    E2E = "e2e"
    SMOKE = "smoke"
    PARALLEL = "parallel"
    FAILED = "failed"
    VERBOSE = "verbose"
    BENCH = "bench"
    MODULE = "module"
    MODULE_COV = "module-cov"
    REGISTRY = "registry"
    CUSTOM = "custom"


@dataclass(frozen=True, slots=True)
class TestRunSpec:
    """Immutable specification for a single sandbox test run.

    Attributes:
        test_type: Selected test-execution mode.
        timestamp: UTC timestamp string ``yyyyMMdd_HHmmss`` identifying artifacts.
        module: Optional module path for :attr:`TestType.MODULE` / :attr:`TestType.MODULE_COV`.
        extra_args: Additional pytest arguments for :attr:`TestType.CUSTOM` or
            operator overrides.
        timeout_seconds: Hard timeout applied by the host driver.
        run_id: Identity component distinguishing this run from every other
            run, including one started in the same minute with the same test
            type. Defaults to a freshly generated value.
    """

    test_type: TestType
    timestamp: str
    module: str | None = None
    extra_args: tuple[str, ...] = field(default_factory=tuple)
    timeout_seconds: int = 7200
    run_id: str = field(default_factory=new_run_id)


def run_token(spec: TestRunSpec) -> str:
    """Return the token that identifies one run across every artifact.

    Every per-run name derived by the host driver, the container entrypoint,
    and the report harvester is built from this token, so a single definition
    keeps the three sides consistent.

    Args:
        spec: The active run specification.

    Returns:
        str: ``<test_type>_<timestamp>_<run_id>``.
    """
    return f"{spec.test_type.value}_{spec.timestamp}_{spec.run_id}"


def _artifact_paths(spec: TestRunSpec) -> dict[str, PurePosixPath]:
    """Return the per-run artifact paths inside the container.

    All artifacts live flat under ``reports/tests/`` with filenames of the form
    ``<kind>_<test_type>_<mm-dd-yyyy_HH-MM>_<run_id>.<ext>``. The run id keeps
    two runs started in the same minute from overwriting each other. The
    per-run ``log`` is written by the container; the aggregate
    ``test-log.txt`` history is appended host-side once the container has
    exited, so no two containers hold the same handle across the bind mount.

    Args:
        spec: The active run specification.

    Returns:
        dict[str, PurePosixPath]: Mapping from artifact kind to its container
            path. Keys: ``junit``, ``coverage_xml``, ``coverage_html``,
            ``html_report``, ``summary``, ``bench``, ``log``, ``shared_log``.
    """
    suffix = run_token(spec)
    return {
        "junit": _CONTAINER_REPORTS / f"junit_{suffix}.xml",
        "coverage_xml": _CONTAINER_REPORTS / f"coverage_{suffix}.xml",
        "coverage_html": _CONTAINER_REPORTS / f"coverage-html_{suffix}",
        "html_report": _CONTAINER_REPORTS / f"report_{suffix}.html",
        "summary": _CONTAINER_REPORTS / f"summary_{suffix}.json",
        "bench": _CONTAINER_REPORTS / f"bench_{suffix}.json",
        "log": _CONTAINER_REPORTS / f"test-log_{suffix}.txt",
        "shared_log": _CONTAINER_REPORTS / "test-log.txt",
    }


def _module_target(module: str) -> str:
    """Resolve a module name to a pytest target path.

    Accepts either a bare domain keyword (``bridges``, ``core``, ``ui``) which
    expands to ``tests/test_<keyword>``, or a direct ``tests/...`` path which
    is passed through unchanged so operators can target individual files.

    Args:
        module: Module keyword or explicit test path.

    Returns:
        str: The resolved pytest target path using forward slashes.
    """
    normalized = module.replace("\\", "/").strip("/")
    if normalized.startswith("tests/"):
        return normalized
    if "/" in normalized:
        return f"tests/{normalized}"
    return f"tests/test_{normalized}"


def build_pytest_args(spec: TestRunSpec) -> list[str]:
    """Build the concrete pytest argument vector for a run specification.

    The returned list is the complete tail passed to ``pytest`` after the
    interpreter, excluding the ``pytest`` executable itself. Arguments are
    deterministic and are produced identically on host and inside the
    container.

    Args:
        spec: The active run specification.

    Returns:
        list[str]: The pytest argument vector.

    Raises:
        ValueError: If the spec references :attr:`TestType.MODULE` or
            :attr:`TestType.MODULE_COV` without a module, or uses an interactive
            type that does not map to a pytest invocation.
    """
    if spec.test_type in {TestType.INTERACTIVE, TestType.INTERACTIVE_RW}:
        message = f"{spec.test_type.value} does not map to a pytest run"
        raise ValueError(message)

    paths = _artifact_paths(spec)
    base: list[str] = [
        f"--junitxml={paths['junit']}",
        f"--html={paths['html_report']}",
        "--self-contained-html",
        "-ra",
        "--strict-markers",
    ]

    match spec.test_type:
        case TestType.UNIT:
            args = [
                "tests/",
                "-m",
                "not slow and not integration",
                "--timeout=180",
                "--timeout-method=thread",
                "-p",
                "no:randomly",
                *base,
            ]
        case TestType.ALL:
            args = [
                "tests/",
                "--timeout=300",
                "--timeout-method=thread",
                "-p",
                "no:randomly",
                *base,
            ]
        case TestType.COVERAGE:
            args = [
                "tests/",
                "--cov=src/intellicrack",
                "--cov-branch",
                f"--cov-report=xml:{paths['coverage_xml']}",
                f"--cov-report=html:{paths['coverage_html']}",
                "--cov-report=term-missing",
                "--cov-fail-under=95",
                *base,
            ]
        case TestType.INTEGRATION:
            args = [
                "tests/",
                "-m",
                "integration",
                "--timeout=600",
                "--timeout-method=thread",
                "-p",
                "no:randomly",
                *base,
            ]
        case TestType.E2E:
            args = ["tests/test_hexcore_e2e/", *base]
        case TestType.SMOKE:
            args = [
                "tests/",
                "-k",
                "not slow",
                "-m",
                "not slow and not integration",
                "--timeout=60",
                *base,
            ]
        case TestType.PARALLEL:
            args = ["tests/", "-n", "auto", *base]
        case TestType.FAILED:
            args = ["tests/", "--last-failed", "--last-failed-no-failures=all", *base]
        case TestType.VERBOSE:
            args = ["tests/", "-vv", "--tb=long", "--showlocals", *base]
        case TestType.BENCH:
            args = [
                "tests/",
                "-m",
                "benchmark",
                "--benchmark-only",
                f"--benchmark-json={paths['bench']}",
                *base,
            ]
        case TestType.MODULE:
            if not spec.module:
                message = "TestType.MODULE requires a module name"
                raise ValueError(message)
            args = [_module_target(spec.module), *base]
        case TestType.MODULE_COV:
            if not spec.module:
                message = "TestType.MODULE_COV requires a module name"
                raise ValueError(message)
            args = [
                _module_target(spec.module),
                "--cov=src/intellicrack",
                "--cov-branch",
                f"--cov-report=xml:{paths['coverage_xml']}",
                f"--cov-report=html:{paths['coverage_html']}",
                "--cov-report=term-missing",
                "--cov-fail-under=80",
                *base,
            ]
        case TestType.REGISTRY:
            args = ["tests/", "-k", "registry or hw_spoofer or hwid", *base]
        case TestType.CUSTOM:
            args = [*base]
        case TestType.INTERACTIVE | TestType.INTERACTIVE_RW:
            message = f"{spec.test_type.value} does not map to a pytest run"
            raise ValueError(message)

    args.extend(spec.extra_args)
    return args


def spec_to_dict(spec: TestRunSpec) -> dict[str, object]:
    """Serialize a spec to a JSON-safe dictionary.

    Used by the host driver to forward a spec to the container entrypoint
    without re-parsing CLI flags in two places.

    Args:
        spec: The specification to serialize.

    Returns:
        dict[str, object]: JSON-safe dictionary representation.
    """
    return {
        "test_type": spec.test_type.value,
        "timestamp": spec.timestamp,
        "module": spec.module,
        "extra_args": list(spec.extra_args),
        "timeout_seconds": spec.timeout_seconds,
        "run_id": spec.run_id,
    }


def spec_from_dict(data: dict[str, object]) -> TestRunSpec:
    """Deserialize a spec produced by :func:`spec_to_dict`.

    A payload written before per-run identities existed carries no ``run_id``;
    a fresh one is generated so the reconstructed spec still resolves to
    collision-free artifact names.

    Args:
        data: Dictionary previously produced by :func:`spec_to_dict`.

    Returns:
        TestRunSpec: Reconstructed specification.

    Raises:
        KeyError: If required keys are absent from the dictionary.
        TypeError: If a known key holds a value of an unexpected type.
        ValueError: If ``test_type`` is not a recognized :class:`TestType`.
    """
    if "test_type" not in data:
        message = "missing required key: test_type"
        raise KeyError(message)
    if "timestamp" not in data:
        message = "missing required key: timestamp"
        raise KeyError(message)
    raw_type = data["test_type"]
    if not isinstance(raw_type, str):
        message = "test_type must be a string"
        raise TypeError(message)
    raw_timestamp = data["timestamp"]
    if not isinstance(raw_timestamp, str):
        message = "timestamp must be a string"
        raise TypeError(message)
    raw_module = data.get("module")
    module = raw_module if isinstance(raw_module, str) else None
    raw_extra = data.get("extra_args", [])
    if not isinstance(raw_extra, list):
        message = "extra_args must be a list"
        raise TypeError(message)
    typed_extra = cast("list[object]", raw_extra)
    extra_args = tuple(str(item) for item in typed_extra)
    raw_timeout = data.get("timeout_seconds", 7200)
    timeout = int(raw_timeout) if isinstance(raw_timeout, (int, float, str)) else 7200
    raw_run_id = data.get("run_id")
    run_id = raw_run_id if isinstance(raw_run_id, str) and raw_run_id else new_run_id()

    try:
        resolved_type = TestType(raw_type)
    except ValueError as exc:
        message = f"unknown test_type: {raw_type!r}"
        raise ValueError(message) from exc

    return TestRunSpec(
        test_type=resolved_type,
        timestamp=raw_timestamp,
        module=module,
        extra_args=extra_args,
        timeout_seconds=timeout,
        run_id=run_id,
    )
