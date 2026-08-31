# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the coverage runner's collection targets.

The coverage runner spawns one pytest process per leaf test directory. When a
group is addressed by filesystem path, pytest builds the package chain twice
inside the container and every test in that group runs twice -- doubling an
already long coverage pass. Addressing the group by import path collects each
test once.

An import path is not always usable, though: it resolves only when the whole
chain is a real package *and* pytest runs from the directory that chain is
anchored at. ``--tests-root`` accepts any directory, so both can be false, and
emitting a dotted name anyway fails the group with a usage error instead of
running it. The runner falls back to a filesystem target there, and gates below
pin both halves of that condition.

These gates load the real runner module from :file:`docker/coverage_runner.py`
and drive its own :func:`discover_groups`, ``group_collection_target`` and
``_pytest_command``, so a regression in the production runner is what fails.
The final gate runs a real nested collection with the argv the runner produced
and asserts no nodeid is collected twice and that ignored child groups stay
excluded.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from types import ModuleType


_REPO_ROOT = Path(__file__).resolve().parents[2]
_TESTS_ROOT = _REPO_ROOT / "tests"
_RUNNER = _REPO_ROOT / "docker" / "coverage_runner.py"


def _load_runner() -> ModuleType:
    """Import the coverage runner module from its path.

    The runner ships inside :file:`docker/` and is deliberately standalone, so
    it is loaded by location rather than imported as a package.

    Returns:
        ModuleType: The imported coverage runner module.
    """
    spec = importlib.util.spec_from_file_location("coverage_runner_under_test", _RUNNER)
    assert spec is not None, f"cannot load {_RUNNER}"
    assert spec.loader is not None, f"no loader for {_RUNNER}"
    module = importlib.util.module_from_spec(spec)
    # ``@dataclass`` resolves its own module via ``sys.modules`` while the class
    # body executes, so the module must be registered before it is executed.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def runner() -> ModuleType:
    """Provide the loaded coverage runner module.

    Returns:
        ModuleType: The imported coverage runner module.
    """
    return _load_runner()


def test_group_dotted_names_match_their_directories(runner: ModuleType) -> None:
    """Every group's importable name must address its own directory.

    A dotted name that does not correspond to the group's directory would send
    the group's pytest process at the wrong tests, silently running one subtree
    twice and another not at all.

    Args:
        runner: The loaded coverage runner module.
    """
    for group in runner.discover_groups(_TESTS_ROOT):
        assert group.dotted is not None, f"group {group.name!r} under the real tests tree is not importable"
        resolved = _REPO_ROOT / Path(*group.dotted.split("."))
        assert resolved.resolve() == Path(group.target).resolve(), (
            f"group {group.name!r} dotted name {group.dotted!r} resolves to {resolved}, not {group.target}"
        )


def test_every_group_is_importable(runner: ModuleType) -> None:
    """Every group directory must be an importable package.

    ``--pyargs`` resolves a target by importing it, so a group directory
    without an ``__init__.py`` would be unaddressable and its tests would never
    run under coverage.

    Args:
        runner: The loaded coverage runner module.
    """
    missing = [group.dotted for group in runner.discover_groups(_TESTS_ROOT) if not (Path(group.target) / "__init__.py").is_file()]
    assert not missing, f"coverage groups without __init__.py are unaddressable by --pyargs: {missing}"


def test_command_addresses_the_group_by_import_path(runner: ModuleType) -> None:
    """The runner must emit ``--pyargs <dotted>`` rather than a filesystem path.

    A filesystem target doubles every test in the group. If the runner reverts
    to ``str(group.target)`` the ``--pyargs`` assertion fails and the raw path
    reappears in the argv.

    Args:
        runner: The loaded coverage runner module.
    """
    groups = {group.name: group for group in runner.discover_groups(_TESTS_ROOT)}
    group = groups["bridges__completeness__ghidra"]
    command = runner._pytest_command(group, _TESTS_ROOT / "junit.xml", [], tests_root=_TESTS_ROOT, workspace_root=_REPO_ROOT)

    assert "--pyargs" in command, f"coverage group is not addressed by import path: {command}"
    assert group.dotted in command, f"group target missing from argv: {command}"
    assert str(group.target) not in command, f"group still addressed by filesystem path: {command}"


def test_ignores_stay_filesystem_paths(runner: ModuleType) -> None:
    """Child-group exclusions must remain ``--ignore=<path>`` entries.

    ``--ignore`` matches on filesystem paths; rewriting those to dotted names
    would stop them matching, so each parent group would re-collect its child
    groups and double-count their coverage.

    Args:
        runner: The loaded coverage runner module.
    """
    groups = {group.name: group for group in runner.discover_groups(_TESTS_ROOT)}
    parent = groups["bridges"]
    assert parent.ignores, "the bridges group is expected to exclude child groups"

    command = runner._pytest_command(parent, _TESTS_ROOT / "junit.xml", [], tests_root=_TESTS_ROOT, workspace_root=_REPO_ROOT)
    for ignore in parent.ignores:
        assert f"--ignore={ignore}" in command, f"ignore entry lost its path form: {command}"


def _write_tree(root: Path, *, packaged: bool) -> None:
    """Create a two-level test tree, optionally as a real package chain.

    Args:
        root: Directory to create as the tests root.
        packaged: Whether every directory gets an ``__init__.py``.
    """
    leaf = root / "leaf"
    leaf.mkdir(parents=True)
    (leaf / "test_leaf.py").write_text("def test_leaf() -> None:\n    assert True\n", encoding="utf-8")
    if packaged:
        for directory in (root, leaf):
            (directory / "__init__.py").write_text("", encoding="utf-8")


def test_a_namespace_tree_is_addressed_by_path_not_import(runner: ModuleType, tmp_path: Path) -> None:
    """A tests root that is not a package must fall back to a path target.

    ``--pyargs`` resolves its target by importing it, so emitting a dotted name
    for a directory with no ``__init__.py`` makes pytest exit with a usage error
    and the group never runs at all. A path target still collects the right
    tests, so that is what such a tree gets.

    Args:
        runner: The loaded coverage runner module.
        tmp_path: Per-test temporary directory.
    """
    root = tmp_path / "tests"
    _write_tree(root, packaged=False)

    groups = runner.discover_groups(root)
    assert groups, "the synthetic tree produced no groups"
    for group in groups:
        assert group.dotted is None, f"a directory with no __init__.py was reported importable as {group.dotted!r}"
        target = runner.group_collection_target(group, root, tmp_path)
        assert target == [str(group.target)], f"a namespace group must be addressed by path, got {target}"


def test_a_package_tree_outside_the_workspace_is_addressed_by_path(runner: ModuleType, tmp_path: Path) -> None:
    """A dotted name is only usable when pytest runs from where it is anchored.

    ``--pyargs tests.leaf`` is resolved against the working directory pytest is
    launched in. When the tests root does not sit directly beneath that
    directory the same dotted name either fails to import or -- worse --
    resolves to an unrelated tree of the same name that happens to be there.

    Args:
        runner: The loaded coverage runner module.
        tmp_path: Per-test temporary directory.
    """
    root = tmp_path / "tests"
    _write_tree(root, packaged=True)

    groups = runner.discover_groups(root)
    assert groups, "the synthetic tree produced no groups"
    for group in groups:
        assert group.dotted is not None, "a full package chain must yield a dotted name"
        anchored = runner.group_collection_target(group, root, tmp_path)
        assert anchored == ["--pyargs", group.dotted], f"an anchored package group must use its import path, got {anchored}"

        adrift = runner.group_collection_target(group, root, _REPO_ROOT)
        assert adrift == [str(group.target)], f"a group pytest cannot import from its workspace must use a path, got {adrift}"


def test_runner_argv_collects_each_test_once_and_honours_ignores(runner: ModuleType) -> None:
    """The runner's argv must collect each nodeid once, excluding child groups.

    This is the end-to-end proof. A real nested collection is run with the argv
    the production runner built for a group that has child groups; no nodeid
    may repeat, and nothing under an ignored child may be collected. Reverting
    the runner to a filesystem target makes every nodeid appear twice.

    Args:
        runner: The loaded coverage runner module.
    """
    groups = {group.name: group for group in runner.discover_groups(_TESTS_ROOT)}
    group = groups["bridges"]
    command = runner._pytest_command(group, _TESTS_ROOT / "junit.xml", [], tests_root=_TESTS_ROOT, workspace_root=_REPO_ROOT)
    # A second ``-q`` switches pytest to a per-file count summary instead of
    # listing nodeids, so the runner's own quiet flag is dropped and exactly one
    # is supplied below.
    collection_args = [arg for arg in command[3:] if not arg.startswith(("--junitxml=", "--cov")) and arg != "-q"]

    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *collection_args, "--collect-only", "-q", "-o", "addopts="],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    nodeids = [line.strip() for line in proc.stdout.splitlines() if "::" in line]
    assert nodeids, f"nested collection produced no nodeids; stdout={proc.stdout[-2000:]} stderr={proc.stderr[-2000:]}"

    duplicates = sorted({nodeid for nodeid in nodeids if nodeids.count(nodeid) > 1})
    assert not duplicates, f"{len(duplicates)} nodeid(s) collected twice, e.g. {duplicates[:3]}"

    for ignore in group.ignores:
        prefix = Path(ignore).relative_to(_REPO_ROOT).as_posix()
        leaked = [nodeid for nodeid in nodeids if nodeid.replace("\\", "/").startswith(f"{prefix}/")]
        assert not leaked, f"ignored child group {prefix} was collected anyway, e.g. {leaked[:3]}"
