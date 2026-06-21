# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit7 F-0001 (config-pyproject): runtime dependencies.

The original defect documented in ``audit7.md`` was that
``pyproject.toml`` ``[project].dependencies`` redundantly declared 95+
development, testing, documentation, and profiling packages as runtime
requirements. Installing the distribution with ``pip install intellicrack``
would pull pytest, mypy, bandit, basedpyright, ruff, sphinx, mkdocs, tox,
nox, twine, and many more packages that have no business in a runtime
install.

The fix moved every non-runtime package out of ``[project].dependencies``
into the already-existing ``[project].optional-dependencies`` extras and
``[dependency-groups]`` tables (``dev``, ``test``, ``docs``, ``profile``).
The remaining ``[project].dependencies`` entries are the genuine runtime
imports under ``src/intellicrack/`` plus their version constraints.

These tests guard the regression by parsing the on-disk ``pyproject.toml``
with :mod:`tomllib` and asserting three invariants:

* a fixed BLOCKLIST of dev-only package names is absent from runtime deps,
* a fixed ALLOWLIST of genuine runtime package names is present in runtime
  deps,
* the total runtime dependency count stays under a small ceiling so the
  prune does not silently regress in the future.

The comparison strips PEP 508 version specifiers and extras and is
case-insensitive, matching the casefold/normalization rules pip applies to
distribution names.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any, Final, cast


_PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_PYPROJECT_PATH: Final[Path] = _PROJECT_ROOT / "pyproject.toml"

# Packages that must NEVER appear in [project].dependencies. They belong in
# [project].optional-dependencies / [dependency-groups] instead. Names are
# normalized to lowercase here; the comparison helper also normalizes the
# pyproject entries before checking membership.
_BLOCKLIST: Final[frozenset[str]] = frozenset(
    {
        "atheris",
        "bandit",
        "basedpyright",
        "black",
        "bumpversion",
        "commitizen",
        "darglint",
        "deadcode",
        "flake8",
        "git-cliff",
        "hypothesis",
        "isort",
        "liccheck",
        "memray",
        "mkdocs",
        "mkdocs-material",
        "monkeytype",
        "mutmut",
        "mypy",
        "nox",
        "nuitka",
        "pip-licenses",
        "pre-commit",
        "pyannotate",
        "pyclean",
        "pydoclint",
        "pydocstyle",
        "pylint",
        "pyright",
        "pytest",
        "pytest-asyncio",
        "pytest-cov",
        "pytest-qt",
        "pytest-xdist",
        "ruff",
        "safety",
        "sourcery",
        "sphinx",
        "syrupy",
        "tox",
        "twine",
        "validate-pyproject",
        "vulture",
    },
)

# Packages that MUST appear in [project].dependencies because they are
# genuine runtime imports under ``src/intellicrack/``. The list is derived
# from the runtime block of ``[tool.pixi]`` ``pypi-dependencies`` plus the
# additional packages (``keyring``, ``psutil``, ``yara-python``,
# ``cryptography``, ``pyyaml``, ``huggingface-hub``) that were already
# pinned at the top of ``[project].dependencies`` or imported directly
# under ``src/intellicrack/`` at module top level.
_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        "anthropic",
        "capstone",
        "cryptography",
        "frida",
        "ghidra-bridge",
        "google-genai",
        "httpx",
        "huggingface-hub",
        "keyring",
        "keystone-engine",
        "lief",
        "openai",
        "pefile",
        "psutil",
        "pyqt6",
        "pyyaml",
        "r2pipe",
        "structlog",
        "tiktoken",
        "tomli-w",
        "xxhash",
        "yara-python",
    },
)


_REQ_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")


def _normalize_distribution_name(name: str) -> str:
    """Normalize a PEP 503 distribution name for case-insensitive comparison.

    PEP 503 defines the normalized form of a distribution name as the
    lowercase of the original with runs of ``-``, ``_``, and ``.``
    collapsed to a single ``-``. Pip and the index treat ``PyYAML``,
    ``pyyaml``, and ``py-yaml`` as the same project under this rule.

    Args:
        name: The raw distribution name, possibly mixed case or containing
            underscores or dots.

    Returns:
        str: The lowercased, hyphen-collapsed canonical form.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def _extract_name_from_requirement(requirement: str) -> str:
    """Extract the bare project name from a PEP 508 requirement string.

    The function strips version specifiers (``>=``, ``<``, ``==``, ``~=``,
    ``!=``, ``===``), extras (``pkg[extra1,extra2]``), environment
    markers (``; python_version<'3.13'``), and surrounding whitespace.

    Args:
        requirement: A PEP 508 requirement string as it appears in
            ``[project].dependencies``.

    Returns:
        str: The bare project name, normalized via
        :func:`_normalize_distribution_name`.

    Raises:
        ValueError: If the requirement string does not start with a valid
            distribution name.
    """
    stripped = requirement.strip()
    match = _REQ_NAME_PATTERN.match(stripped)
    if match is None:
        msg = f"Could not parse distribution name from requirement: {requirement!r}"
        raise ValueError(msg)
    return _normalize_distribution_name(match.group(0))


def _load_runtime_dependencies() -> frozenset[str]:
    """Load and normalize the ``[project].dependencies`` entries from disk.

    The function parses ``pyproject.toml`` with :mod:`tomllib`, extracts the
    ``[project].dependencies`` array, strips PEP 508 version specifiers and
    extras from each entry, and PEP 503-normalizes the bare distribution
    name before returning the set. Type and shape are enforced with
    ``assert`` statements so a malformed ``pyproject.toml`` aborts the test
    session immediately with a clear message.

    Returns:
        frozenset[str]: The PEP 503-normalized distribution names declared
        in ``[project].dependencies``. The original ordering and version
        specifiers are discarded; only set membership matters for the
        assertions below.
    """
    with _PYPROJECT_PATH.open("rb") as handle:
        data: dict[str, Any] = tomllib.load(handle)
    project_table = cast("dict[str, Any]", data["project"])
    raw_dependencies_obj = project_table["dependencies"]
    assert isinstance(raw_dependencies_obj, list), "project.dependencies must be a TOML array"
    raw_dependencies = cast("list[Any]", raw_dependencies_obj)
    normalized: set[str] = set()
    for entry in raw_dependencies:
        assert isinstance(entry, str), f"project.dependencies entry must be str, got {type(entry).__name__}"
        normalized.add(_extract_name_from_requirement(entry))
    return frozenset(normalized)


def test_blocklist_absent_from_runtime_dependencies() -> None:
    """No dev/test/docs/profile package may appear in runtime dependencies.

    A failure here indicates that a development-only package has leaked
    back into ``[project].dependencies`` and would be pulled by ``pip
    install intellicrack`` on end-user machines.
    """
    runtime_dependencies = _load_runtime_dependencies()
    leaked = sorted(_BLOCKLIST & runtime_dependencies)
    assert not leaked, (
        "Dev-only packages leaked into [project].dependencies: "
        f"{leaked!r}. They belong in [project].optional-dependencies or "
        "[dependency-groups] instead."
    )


def test_allowlist_present_in_runtime_dependencies() -> None:
    """Every required runtime package must be declared in runtime dependencies.

    A failure here indicates the prune removed too much: a genuine
    runtime import was deleted from ``[project].dependencies`` and
    end-user installs would crash on import.
    """
    runtime_dependencies = _load_runtime_dependencies()
    missing = sorted(_ALLOWLIST - runtime_dependencies)
    assert not missing, (
        "Runtime packages missing from [project].dependencies: "
        f"{missing!r}. These are imported directly under src/intellicrack/ "
        "and must be installed by ``pip install intellicrack``."
    )


def test_runtime_dependency_count_is_lean() -> None:
    """Runtime dependency list must stay small after the F-0001 prune.

    Before the fix the list contained 111 entries; after the fix it should
    contain only genuine runtime requirements. This test fails loudly if a
    future change re-inflates the list past a sane ceiling, which is the
    most common way the regression would creep back in.
    """
    runtime_dependencies = _load_runtime_dependencies()
    assert len(runtime_dependencies) <= 40, (
        f"[project].dependencies has {len(runtime_dependencies)} entries; "
        "the F-0001 prune intended it to be tightly scoped to runtime "
        "imports only. Add new deps to [project].optional-dependencies or "
        "[dependency-groups] instead unless they are imported at top level "
        "under src/intellicrack/."
    )
