# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the isolated coverage group enumeration.

The coverage runner (:file:`docker/coverage_runner.py`) runs the ``coverage``
test type as one pytest process per *leaf* test directory so that a native
subsystem's teardown (Frida, Ghidra/JPype, Qt) cannot poison the interpreter
state of an unrelated group. These tests drive the runner's ``--list-groups``
mode against the real ``tests/`` tree and assert the grouping invariants that
make that isolation correct:

* every directory holding ``test_*.py`` files becomes its own group;
* a parent directory that only contains subdirectories is *not* a group;
* a parent that holds both loose files and a subdir (``test_ui`` +
  ``log_viewer``) yields two groups, and the parent ``--ignore``s the child so
  no test is measured twice;
* the natively fragile ``test_bridge_completeness`` suite is split into its
  per-tool subdirectories.

The gate fails loudly if the enumeration logic regresses to a coarser grouping
(which is exactly what reintroduces cross-test native contamination).
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[2]
_RUNNER = _REPO_ROOT / "docker" / "coverage_runner.py"
_TESTS_ROOT = _REPO_ROOT / "tests"


@dataclass(frozen=True)
class _Group:
    """A single enumerated coverage group.

    Attributes:
        name: Stable group identifier used for per-group artifact filenames.
        target: Absolute pytest target directory for the group.
        ignores: Absolute child directories excluded from the group's run.
    """

    name: str
    target: str
    ignores: tuple[str, ...]


def _list_groups() -> list[_Group]:
    """Enumerate coverage groups via the runner's ``--list-groups`` mode.

    Returns:
        list[_Group]: Parsed groups produced against the real ``tests/`` tree.
    """
    result = subprocess.run(
        [
            sys.executable,
            str(_RUNNER),
            "--tests-root",
            str(_TESTS_ROOT),
            "--list-groups",
        ],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        check=False,
    )
    assert result.returncode == 0, f"list mode failed: {result.stderr}"
    groups: list[_Group] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        assert len(parts) == 3, f"malformed group line: {line!r}"
        name, target, ignore_blob = parts
        ignores = tuple(p for p in ignore_blob.split(";") if p)
        groups.append(_Group(name=name, target=target, ignores=ignores))
    return groups


def test_runner_exists() -> None:
    """The coverage runner script must be present."""
    assert _RUNNER.is_file(), f"missing coverage runner: {_RUNNER}"


def test_every_leaf_test_dir_is_a_group() -> None:
    """Each directory with loose ``test_*.py`` files must appear as a group.

    This is the core isolation invariant: if a leaf test directory is missing
    from the enumeration its tests would never run under coverage, and if a
    non-leaf directory appeared its tests would run co-mingled with siblings.
    """
    groups = _list_groups()
    group_targets = {Path(g.target).resolve() for g in groups}

    expected: set[Path] = set()
    for path in _TESTS_ROOT.rglob("test_*.py"):
        if "__pycache__" in path.parts:
            continue
        expected.add(path.parent.resolve())

    missing = expected - group_targets
    extra = group_targets - expected
    assert not missing, f"leaf test dirs missing from groups: {sorted(map(str, missing))}"
    assert not extra, f"non-leaf dirs enumerated as groups: {sorted(map(str, extra))}"


def test_parent_without_loose_tests_is_not_a_group() -> None:
    """A directory that only holds subdirectories must not be its own group.

    ``test_bridge_completeness`` holds only per-tool subdirectories; enumerating
    the parent would run Frida, Ghidra and x64dbg suites in one process, which
    is the exact contamination this design eliminates.
    """
    names = {g.name for g in _list_groups()}
    assert "test_bridge_completeness" not in names
    assert "test_audit4" not in names
    assert "test_audit5" not in names


def test_bridge_completeness_split_into_per_tool_groups() -> None:
    """The natively fragile bridge-completeness suite runs one process per tool."""
    names = {g.name for g in _list_groups()}
    for tool in ("cutter", "frida", "ghidra", "hex_editor", "sandbox_process", "x64dbg"):
        assert f"test_bridge_completeness__{tool}" in names, f"missing bridge group: {tool}"


def test_mixed_parent_yields_two_groups_and_ignores_child() -> None:
    """``test_ui`` and its ``log_viewer`` subdir are separate, non-overlapping groups.

    The parent must ``--ignore`` the child so a test under ``log_viewer`` is not
    collected (and its coverage double-counted) by both the parent and child
    runs.
    """
    groups = {g.name: g for g in _list_groups()}
    assert "test_ui" in groups
    assert "test_ui__log_viewer" in groups

    parent = groups["test_ui"]
    child = groups["test_ui__log_viewer"]
    child_target = Path(child.target).resolve()
    ignored = {Path(p).resolve() for p in parent.ignores}
    assert child_target in ignored, f"test_ui must --ignore its log_viewer child; ignores={parent.ignores}"


def test_group_names_are_unique() -> None:
    """Group names must be unique so per-group artifact files never collide."""
    names = [g.name for g in _list_groups()]
    duplicates = {n for n in names if names.count(n) > 1}
    assert not duplicates, f"duplicate group names: {sorted(duplicates)}"


def test_group_ignores_every_immediate_test_child_dir() -> None:
    """A group must ``--ignore`` each immediate child dir that holds tests.

    This is the anti-double-counting invariant: tests living under a child
    directory run only in the deeper (child) group, so the parent group must
    exclude that child. A regression here would collect a subtree twice, once
    in the parent process and once in the child, inflating the coverage number
    and re-mingling the very suites the isolation is meant to separate.
    """
    groups = _list_groups()
    for group in groups:
        target = Path(group.target).resolve()
        ignored = {Path(p).resolve() for p in group.ignores}
        for child in target.iterdir():
            if not child.is_dir():
                continue
            if child.name == "__pycache__" or child.name.startswith("."):
                continue
            has_tests = any("__pycache__" not in p.parts for p in child.rglob("test_*.py"))
            if not has_tests:
                continue
            assert child.resolve() in ignored, f"group {group.name} must --ignore test-bearing child {child}"
