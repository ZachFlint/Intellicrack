# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for importable (``--pyargs``) collection targets.

Addressing tests by filesystem path makes pytest build the target's package
chain twice inside the Windows container, so every test is collected under a
duplicate node. Run counts double, and in a package whose fixtures live in a
sibling ``conftest.py`` one of the two copies cannot resolve them (the ghidra
completeness slice reported 69 ``fixture 'connected_bridge' not found`` errors
for exactly this reason). Addressing the same tests by import path collects
each exactly once.

The argument-shaping tests drive the real :func:`build_pytest_args` rather than
restating the expected strings, so a regression in the production builder is
what fails. The final test runs a real nested collection with the argv the
builder produced and asserts every collected nodeid is unique -- it fails if
the targets revert to filesystem paths.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts.sandbox.test_types import (
    TestRunSpec,
    TestType,
    build_pytest_args,
    to_pyargs_argv,
    to_pyargs_target,
)


_REPO_ROOT = Path(__file__).resolve().parents[2]
_TESTS_ROOT = _REPO_ROOT / "tests"
_TIMESTAMP = "08-22-2026_12-00"

# A small, self-contained package used for the real nested collection.
_SAMPLE_PACKAGE = "tests/sandbox/analysis_regex"


def _args_for(
    test_type: TestType,
    *,
    module: str | None = None,
    extra_args: tuple[str, ...] = (),
) -> list[str]:
    """Build the production pytest argv for a test type.

    Args:
        test_type: The execution mode to build arguments for.
        module: Optional module target for module modes.
        extra_args: Optional operator-supplied pass-through arguments.

    Returns:
        list[str]: The argument vector produced by the production builder.
    """
    spec = TestRunSpec(
        test_type=test_type,
        timestamp=_TIMESTAMP,
        module=module,
        extra_args=extra_args,
    )
    return build_pytest_args(spec)


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("tests/", "tests"),
        ("tests", "tests"),
        ("tests/hexpat/e2e/", "tests.hexpat.e2e"),
        ("tests/core/test_x.py", "tests.core.test_x"),
        ("tests\\core\\test_x.py", "tests.core.test_x"),
        ("tests/core/test_x.py::TestC", "tests.core.test_x::TestC"),
        ("tests/core/test_x.py::TestC::test_m", "tests.core.test_x::TestC::test_m"),
        ("tests/a/test_x.py::TestC::test_m[kernel32.dll]", "tests.a.test_x::TestC::test_m[kernel32.dll]"),
    ],
)
def test_target_conversion_preserves_selection(target: str, expected: str) -> None:
    """Filesystem targets must convert to dotted targets, keeping any selector.

    The ``::`` node selector and its parametrization id must survive verbatim,
    otherwise targeting a single test or class through the harness breaks.

    Args:
        target: The filesystem-style target handed to the harness.
        expected: The importable target pytest should receive.
    """
    assert to_pyargs_target(target) == expected


@pytest.mark.parametrize(
    "test_type",
    [
        TestType.UNIT,
        TestType.ALL,
        TestType.COVERAGE,
        TestType.INTEGRATION,
        TestType.SMOKE,
        TestType.PARALLEL,
        TestType.FAILED,
        TestType.VERBOSE,
        TestType.BENCH,
        TestType.REGISTRY,
    ],
)
def test_whole_tree_modes_emit_importable_target(test_type: TestType) -> None:
    """Whole-tree modes must address ``tests`` by import path, not by path.

    A filesystem ``tests/`` target doubles the entire suite, which is where the
    inflated pass counts come from. If the builder stops converting, ``tests/``
    reappears and ``--pyargs`` is absent, failing both assertions.

    Args:
        test_type: The whole-tree execution mode under test.
    """
    args = _args_for(test_type)
    assert "--pyargs" in args, f"{test_type.value} must use importable targets: {args}"
    assert "tests" in args, f"{test_type.value} must target the tests package: {args}"
    assert "tests/" not in args, f"{test_type.value} still passes a filesystem target: {args}"


def test_e2e_mode_emits_importable_subpackage() -> None:
    """The e2e mode must address its subpackage by import path."""
    args = _args_for(TestType.E2E)
    assert "tests.hexpat.e2e" in args, f"e2e target not converted: {args}"
    assert "tests/hexpat/e2e/" not in args, f"e2e still passes a filesystem target: {args}"


@pytest.mark.parametrize(
    ("module", "expected"),
    [
        ("bridges", "tests.test_bridges"),
        ("tests/bridges/completeness/ghidra", "tests.bridges.completeness.ghidra"),
        ("tests/core/test_orchestrator_streaming_s16d04.py", "tests.core.test_orchestrator_streaming_s16d04"),
    ],
)
def test_module_mode_emits_importable_target(module: str, expected: str) -> None:
    """Module mode must convert every accepted module spelling.

    Module mode is how a single slice is targeted, so a keyword, a directory,
    and an explicit file must all resolve to importable targets.

    Args:
        module: The module argument accepted by the harness.
        expected: The importable target pytest should receive.
    """
    args = _args_for(TestType.MODULE, module=module)
    assert expected in args, f"module {module!r} produced {args}"


def test_operator_supplied_path_is_converted() -> None:
    """A path passed through ``--extra-args`` must also be converted.

    Custom mode is how targeted slices are run, and it carries its target in
    ``extra_args``; leaving those unconverted would keep doubling exactly the
    runs this fix exists for.
    """
    args = _args_for(TestType.CUSTOM, extra_args=(_SAMPLE_PACKAGE, "--collect-only"))
    assert "tests.sandbox.analysis_regex" in args, f"custom target not converted: {args}"
    assert _SAMPLE_PACKAGE not in args, f"custom target left as a path: {args}"


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--ignore", "tests/sandbox"),
        ("--deselect", "tests/core/test_x.py::TestC::test_m"),
        ("--confcutdir", "tests"),
        ("-k", "tests"),
    ],
)
def test_option_values_keep_filesystem_form(option: str, value: str) -> None:
    """A path that is an option's value must not be converted.

    ``--ignore`` and friends take a filesystem path; rewriting their value to a
    dotted name would silently stop the option from matching anything. A
    converter that rewrote every ``tests``-prefixed token would fail here.

    Args:
        option: The option consuming a separate value token.
        value: The value token that must survive unchanged.
    """
    converted = to_pyargs_argv([option, value])
    assert converted == [option, value], f"option value was rewritten: {converted}"


def test_flags_and_marker_expressions_are_untouched() -> None:
    """Flags and marker expressions must pass through unchanged.

    Marker expressions such as ``not slow and not integration`` and flags such
    as ``--cov=src/intellicrack`` must survive verbatim.
    """
    args = _args_for(TestType.UNIT)
    assert "not slow and not integration" in args, f"marker expression altered: {args}"
    coverage_args = _args_for(TestType.COVERAGE)
    assert "--cov=src/intellicrack" in coverage_args, f"coverage flag altered: {coverage_args}"


def test_pyargs_flag_is_not_duplicated() -> None:
    """An operator-supplied ``--pyargs`` must not be added a second time."""
    args = to_pyargs_argv(["--pyargs", "tests.core", "tests/ui"])
    assert args.count("--pyargs") == 1, f"--pyargs duplicated: {args}"


def test_every_test_package_is_importable() -> None:
    """Every directory holding test modules must carry an ``__init__.py``.

    ``--pyargs`` resolves a target by importing it, so a test directory without
    an ``__init__.py`` becomes unaddressable by the harness. This gate fails as
    soon as such a directory is added, which is the moment it can be fixed
    cheaply. Directories holding only data fixtures are exempt because they
    contain no modules and are never collection targets.
    """
    missing: list[str] = []
    for directory in sorted(_TESTS_ROOT.rglob("*")):
        if not directory.is_dir() or "__pycache__" in directory.parts:
            continue
        if not any(directory.glob("*.py")):
            continue
        if not (directory / "__init__.py").exists():
            missing.append(str(directory.relative_to(_REPO_ROOT)))
    assert not missing, f"test packages without __init__.py are unaddressable by --pyargs: {missing}"


def test_builder_argv_collects_each_test_exactly_once() -> None:
    """The builder's argv must collect every nodeid exactly once.

    This is the end-to-end proof of the fix. A real nested pytest collection is
    run with the argv the production builder produced for a small package; the
    collected nodeids must contain no duplicates. Reverting the builder to
    filesystem targets makes the same collection report each nodeid twice and
    fails this test.
    """
    args = _args_for(TestType.MODULE, module=_SAMPLE_PACKAGE)
    collection_args = [arg for arg in args if not arg.startswith(("--junitxml=", "--html=")) and arg != "--self-contained-html"]
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *collection_args, "--collect-only", "-q", "-p", "no:randomly", "-o", "addopts="],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    nodeids = [line.strip() for line in proc.stdout.splitlines() if "::" in line]
    assert nodeids, f"nested collection produced no nodeids; stdout={proc.stdout[-2000:]} stderr={proc.stderr[-2000:]}"
    duplicates = sorted({nodeid for nodeid in nodeids if nodeids.count(nodeid) > 1})
    assert not duplicates, f"{len(duplicates)} nodeid(s) collected more than once, e.g. {duplicates[:3]}"
