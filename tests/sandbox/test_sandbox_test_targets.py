# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the pytest targets each sandbox run mode selects.

A run mode whose target directory does not exist is not a loud failure: pytest
collects nothing, reports success, and the operator reads a green run as
coverage that never happened. ``TestType.E2E`` regressed exactly that way,
pointing at a ``tests/test_hexcore_e2e`` directory that does not exist.

These tests resolve the target of every mode that carries one against the real
repository tree and require it to be a directory holding collectable test
modules, so a stale or mistyped path fails here instead of masquerading as a
passing run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.sandbox.test_types import TestRunSpec, TestType, build_pytest_args


_REPO_ROOT = Path(__file__).resolve().parents[2]

_TIMESTAMP = "20260101_000000"

_NO_FIXED_TARGET = frozenset({
    TestType.INTERACTIVE,
    TestType.INTERACTIVE_RW,
    TestType.CUSTOM,
    TestType.MODULE,
    TestType.MODULE_COV,
})

_FIXED_TARGET_TYPES = tuple(t for t in TestType if t not in _NO_FIXED_TARGET)


def _target_of(test_type: TestType) -> str:
    """Return the pytest collection target a run mode selects.

    Targets are emitted as importable ``--pyargs`` names, so the vector leads
    with that flag; the target is the positional argument that follows it.

    Args:
        test_type: The run mode whose argument vector is built.

    Returns:
        str: The leading positional argument of the built pytest argv.
    """
    args = build_pytest_args(TestRunSpec(test_type=test_type, timestamp=_TIMESTAMP))
    positional = args[1:] if args and args[0] == "--pyargs" else args
    return positional[0]


def _resolve_target(target: str) -> Path:
    """Resolve an importable collection target to its directory on disk.

    Args:
        target: Dotted target such as ``tests.hexpat.e2e``.

    Returns:
        Path: The directory the target names within the repository.
    """
    return _REPO_ROOT / target.replace(".", "/")


def _collectable_modules(directory: Path) -> list[Path]:
    """Return the pytest-collectable test modules beneath a directory.

    Args:
        directory: Directory to search recursively.

    Returns:
        list[Path]: Every ``test_*.py`` file found under the directory.
    """
    return sorted(directory.rglob("test_*.py"))


def test_repo_root_resolves_to_the_tests_tree() -> None:
    """The path anchor these gates measure against must be the real repo root."""
    assert (_REPO_ROOT / "tests").is_dir(), f"repo root misresolved to {_REPO_ROOT}"
    assert (_REPO_ROOT / "scripts" / "sandbox" / "test_types.py").is_file()


@pytest.mark.parametrize(
    "test_type",
    _FIXED_TARGET_TYPES,
    ids=[t.value for t in _FIXED_TARGET_TYPES],
)
def test_fixed_target_mode_collects_existing_tests(test_type: TestType) -> None:
    """Every run mode with a built-in target must point at real, collectable tests.

    Args:
        test_type: The run mode under test.
    """
    target = _target_of(test_type)
    assert not target.startswith("-"), f"{test_type.value} has no leading positional target; got {target!r}"

    resolved = _resolve_target(target)
    assert resolved.is_dir(), f"{test_type.value} targets {target!r}, which is not a directory under {_REPO_ROOT}"

    modules = _collectable_modules(resolved)
    assert modules, f"{test_type.value} targets {target!r}, which holds no test_*.py modules"


def test_e2e_targets_the_hexpat_end_to_end_suite() -> None:
    """The e2e mode must select the hexpat end-to-end suite, not an absent directory."""
    target = _target_of(TestType.E2E)
    assert target == "tests.hexpat.e2e", f"e2e target regressed to {target!r}"

    modules = _collectable_modules(_resolve_target(target))
    names = {module.name for module in modules}
    assert "test_bridge_transforms_deep.py" in names, (
        f"e2e target {target!r} does not contain the bridge transform suite; found {sorted(names)}"
    )
