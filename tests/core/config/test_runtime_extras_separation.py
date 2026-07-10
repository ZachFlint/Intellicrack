# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Audit4 D1 (F-0001): pyproject.toml runtime/extras separation tests.

The defect: ``pyproject.toml`` declared 95+ dev/test/docs/profile packages
in ``[project].dependencies``. ``pip install intellicrack`` would pull
pytest, mypy, bandit, basedpyright, ruff, sphinx, mkdocs-material,
pre-commit, tox, nox, twine, monkeytype, pyannotate, safety, commitizen,
bumpversion as runtime requirements - none of which the production
runtime needs.

The fix: every dev/test/docs/profile-only package was moved into the
appropriate ``[project.optional-dependencies]`` extra (``dev``, ``test``,
``docs``, ``profile``). The runtime ``[project].dependencies`` keeps
only the packages the code actually imports at runtime.

These tests parse the canonical ``pyproject.toml`` directly and assert:
- known dev/test tools are NOT in ``[project].dependencies``
- the runtime list is small and contains only the genuine runtime deps
- known dev tools are present in ``optional-dependencies.dev``
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import Any, Final, cast


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_PYPROJECT_PATH: Final[Path] = _REPO_ROOT / "pyproject.toml"


_DEV_ONLY_PACKAGES: Final[frozenset[str]] = frozenset(
    {
        "pytest",
        "mypy",
        "bandit",
        "basedpyright",
        "ruff",
        "sphinx",
        "mkdocs-material",
        "pre-commit",
        "tox",
        "nox",
        "twine",
        "monkeytype",
        "pyannotate",
        "safety",
        "commitizen",
        "bumpversion",
        "black",
        "isort",
        "flake8",
        "pylint",
        "darglint",
        "pydoclint",
        "pydocstyle",
    },
)


def _strip_version_spec(requirement: str) -> str:
    """Return the bare package name from a PEP 508 requirement string.

    Args:
        requirement: A requirement entry such as ``"pytest>=8.0"`` or
            ``"my-pkg[extra]==1.2.3 ; python_version >= '3.13'"``.

    Returns:
        str: The lowercase package name (extras and version specifiers stripped).
    """
    name = re.split(r"[<>=!~;\[\s]", requirement, maxsplit=1)[0]
    return name.strip().lower()


def _load_pyproject() -> dict[str, Any]:
    """Load the repository ``pyproject.toml`` as a parsed dict.

    Returns:
        dict[str, Any]: Parsed TOML structure.
    """
    with _PYPROJECT_PATH.open("rb") as fh:
        return tomllib.load(fh)


def _runtime_dependencies() -> set[str]:
    """Return the package names in ``[project].dependencies``.

    Returns:
        set[str]: Bare lowercase package names declared as runtime deps.

    Raises:
        TypeError: If ``[project]`` is not a TOML table or
            ``[project].dependencies`` is not a list.
    """
    data = _load_pyproject()
    project_raw = data.get("project", {})
    if not isinstance(project_raw, dict):
        msg = "pyproject [project] is not a table"
        raise TypeError(msg)
    project = cast("dict[str, Any]", project_raw)
    deps_raw = project.get("dependencies", [])
    if not isinstance(deps_raw, list):
        msg = "[project].dependencies is not a list"
        raise TypeError(msg)
    deps = cast("list[Any]", deps_raw)
    return {_strip_version_spec(str(d)) for d in deps if isinstance(d, str)}


def _optional_dep_group(group: str) -> set[str]:
    """Return the package names in ``[project.optional-dependencies].<group>``.

    Args:
        group: Extras-group name, e.g. ``"dev"``.

    Returns:
        set[str]: Bare lowercase package names declared in that extras group.
    """
    data = _load_pyproject()
    project_raw = data.get("project", {})
    if not isinstance(project_raw, dict):
        return set()
    project = cast("dict[str, Any]", project_raw)
    extras_raw = project.get("optional-dependencies", {})
    if not isinstance(extras_raw, dict):
        return set()
    extras = cast("dict[str, Any]", extras_raw)
    items_raw = extras.get(group, [])
    if not isinstance(items_raw, list):
        return set()
    items = cast("list[Any]", items_raw)
    return {_strip_version_spec(str(d)) for d in items if isinstance(d, str)}


class TestRuntimeDependenciesAreLean:
    """The runtime dependency list must NOT contain dev-only tooling."""

    @staticmethod
    def test_dev_tools_absent_from_runtime_deps() -> None:
        """No known dev/test/docs tool may appear in ``[project].dependencies``.

        Also asserts that the runtime dependency list is non-empty. A
        pyproject.toml with an empty [project].dependencies would trivially
        satisfy the dev-tools-absent check while hiding a broken configuration
        where all dependencies were accidentally deleted; the non-empty assertion
        prevents that false pass.
        """
        runtime = _runtime_dependencies()

        assert len(runtime) > 0, (
            "[project].dependencies is empty — the pyproject.toml may be misconfigured; "
            "at minimum the production runtime imports must be declared."
        )

        leaked = runtime & _DEV_ONLY_PACKAGES
        assert not leaked, (
            f"dev/test/docs tools leaked into [project].dependencies: {sorted(leaked)}. "
            "Move them to [project.optional-dependencies] extras."
        )

    @staticmethod
    def test_runtime_deps_are_modest_in_size() -> None:
        """Runtime dependency count must be far below the pre-fix bloat (<= 25)."""
        runtime = _runtime_dependencies()
        assert len(runtime) <= 25, (
            f"runtime dependency count {len(runtime)} exceeds the lean budget; "
            "audit found 95+ packages incorrectly declared as runtime — confirm extras moved cleanly. "
            f"Current runtime deps: {sorted(runtime)}"
        )

    @staticmethod
    def test_runtime_and_extras_tables_are_declared() -> None:
        """The F-0001 restructure must keep both the runtime and the extras tables.

        The defect fix relies on two concrete tables existing: a non-empty
        ``[project].dependencies`` list (the lean runtime set) and a
        ``[project.optional-dependencies]`` table holding the moved dev/test
        tooling. Asserting these specific tables — rather than only that the
        document parses and has top-level ``project``/``build-system`` keys —
        catches a regression that deletes the extras table or empties the
        runtime list while leaving the document well-formed.
        """
        data = _load_pyproject()
        project_raw = data["project"]
        assert isinstance(project_raw, dict)
        project = cast("dict[str, Any]", project_raw)

        deps_raw = project["dependencies"]
        assert isinstance(deps_raw, list)
        deps = cast("list[Any]", deps_raw)
        assert len(deps) > 0, "[project].dependencies must declare the runtime imports"
        assert all(isinstance(d, str) for d in deps), "[project].dependencies entries must be PEP 508 strings"

        extras_raw = project["optional-dependencies"]
        assert isinstance(extras_raw, dict)
        extras = cast("dict[str, Any]", extras_raw)
        assert "dev" in extras, "[project.optional-dependencies] must declare the dev extras group after the F-0001 move"


class TestDevExtrasGroupContainsTooling:
    """The dev-extras group must contain the audit-defined dev/test packages."""

    @staticmethod
    def test_dev_extras_contains_canonical_dev_tools() -> None:
        """At least one canonical dev tool must be present in ``optional-dependencies.dev``."""
        dev = _optional_dep_group("dev")
        assert dev, "[project.optional-dependencies].dev is empty — dev tools were not moved into the extras group"
        canonical = {"pytest", "ruff", "basedpyright", "bandit"}
        present = dev & canonical
        assert present, f"none of the canonical dev tools {sorted(canonical)} are in [project.optional-dependencies].dev: {sorted(dev)}"


class TestPyprojectIsValid:
    """The pyproject must remain valid for the canonical Python version."""

    @staticmethod
    def test_runtime_deps_disjoint_from_moved_extras() -> None:
        """No package moved into an extras group may also remain a runtime dep.

        This is the core F-0001 separation invariant: every dev/test/docs/profile
        package must live in exactly one place — its extras group, never also in
        ``[project].dependencies``. A double-declaration regression (re-adding a
        moved tool to runtime while leaving it in its extra) would make
        ``pip install intellicrack`` pull dev tooling again, which is precisely
        the defect this module exists to prevent. The per-package ``_DEV_ONLY_PACKAGES``
        blocklist cannot catch tools that were not on that list, so this checks
        the structural disjointness directly.

        The interpreter precondition only guarantees ``tomllib`` is importable so
        the assertion can run; the disjointness comparison is the actual gate.
        """
        assert sys.version_info >= (3, 11), "tomllib was added in 3.11; this test requires it to be importable"

        runtime = _runtime_dependencies()
        moved = _optional_dep_group("dev") | _optional_dep_group("test") | _optional_dep_group("docs") | _optional_dep_group("profile")
        assert moved, "no extras groups (dev/test/docs/profile) were declared — the F-0001 move did not happen"

        double_declared = runtime & moved
        assert not double_declared, (
            f"packages declared in BOTH [project].dependencies and an extras group: {sorted(double_declared)}. "
            "Each dev/test/docs/profile package must live only in its extra, never also in the runtime list."
        )
