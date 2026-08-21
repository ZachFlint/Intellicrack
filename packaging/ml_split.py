# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Compute the ML-only top-level site-packages entries for installer staging.

``packaging/stage.ps1`` invokes this module with the bundled runtime's
``python.exe`` to decide which top-level ``site-packages`` entries belong to the
optional ML stack (``torch`` + ``transformers`` and their exclusive
dependencies) and must therefore be relocated out of the core ``runtime`` tree
into the separate ``ml_overlay``. The set is the dependency closure of the
``[project.optional-dependencies].ml`` roots minus the closure of the core
``[project.dependencies]`` roots, projected onto the top-level names each
distribution installs.

The projection deliberately ignores ``RECORD`` entries that escape
``site-packages`` (console scripts, man pages, and other data files installed
via relative ``../..`` paths). Those are not importable top-level packages, and
some distributions (for example ``sympy``) record them with OS-native
backslashes, which naive ``PackagePath.parts`` splitting -- which only splits on
``/`` -- would otherwise mistake for a single top-level entry and hand to
``Move-Item`` as a bogus ``..\\..\\share\\...`` destination.

Each surviving entry is written to stdout, one per line; a human-readable
summary is written to stderr. A missing ``RECORD`` for an ML-only distribution
is a hard error, never a silent skip, so staging cannot quietly ship a runtime
that still contains the multi-GB ML libraries.
"""

from __future__ import annotations

import sys
import tomllib
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from typing import TYPE_CHECKING

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


if TYPE_CHECKING:
    from collections.abc import Iterable


def top_level_name(record_path: str) -> str | None:
    r"""Return the top-level ``site-packages`` name a ``RECORD`` path installs.

    Normalises separators (a ``RECORD`` may use either ``/`` or ``\\``) and
    returns the first path component. Paths that escape ``site-packages`` -- an
    empty first component or a ``..`` parent reference -- are not importable
    top-level entries and yield ``None``.

    Args:
        record_path: A single path as listed in a distribution's ``RECORD``.

    Returns:
        str | None: The top-level entry name, or ``None`` when the path does not
        name a top-level ``site-packages`` entry.
    """
    first = record_path.replace("\\", "/").split("/", 1)[0]
    if not first or first == "..":
        return None
    return first


def top_level_names(record_paths: Iterable[str]) -> set[str]:
    """Project a distribution's ``RECORD`` paths onto its top-level entry names.

    Args:
        record_paths: The ``RECORD`` paths of a distribution.

    Returns:
        set[str]: The distinct top-level ``site-packages`` entries, excluding any
        path that escapes ``site-packages``.
    """
    names: set[str] = set()
    for record_path in record_paths:
        name = top_level_name(record_path)
        if name is not None:
            names.add(name)
    return names


def dependency_closure(roots: Iterable[str], environment: dict[str, str]) -> set[str]:
    """Return the canonical-name closure of a set of requirement roots.

    Walks each installed distribution's runtime requirements, honouring
    environment markers, so that only dependencies active for the current
    platform and Python are included.

    Args:
        roots: The root requirement names to expand.
        environment: The marker evaluation environment (``extra`` blanked).

    Returns:
        set[str]: Every canonical distribution name reachable from the roots.
    """
    seen: set[str] = set()
    stack: list[str] = list(roots)
    while stack:
        name = canonicalize_name(stack.pop())
        if name in seen:
            continue
        seen.add(name)
        try:
            dist = distribution(name)
        except PackageNotFoundError:
            continue
        for requirement_spec in dist.requires or []:
            requirement = Requirement(requirement_spec)
            if requirement.marker is not None and not requirement.marker.evaluate(environment):
                continue
            stack.append(requirement.name)
    return seen


def distribution_entries(names: Iterable[str], require_record: frozenset[str]) -> set[str]:
    """Collect the top-level ``site-packages`` entries for a set of distributions.

    Args:
        names: The canonical distribution names to project.
        require_record: Names for which a missing/empty ``RECORD`` is fatal
            (the ML-only distributions, which must be relocatable).

    Returns:
        set[str]: The union of every distribution's top-level entries.

    Raises:
        SystemExit: If a distribution in ``require_record`` has no ``RECORD``.
    """
    entries: set[str] = set()
    for name in names:
        try:
            dist = distribution(name)
        except PackageNotFoundError:
            continue
        files = dist.files or []
        if not files and name in require_record:
            message = f"ERROR: ML-only distribution {name!r} has no RECORD; cannot stage"
            raise SystemExit(message)
        entries |= top_level_names(str(path) for path in files)
    return entries


def compute_ml_only_entries(pyproject_path: Path) -> set[str]:
    """Compute the top-level entries unique to the ML optional-dependency stack.

    Args:
        pyproject_path: Path to the project's ``pyproject.toml``.

    Returns:
        set[str]: Top-level ``site-packages`` entries to move into ``ml_overlay``.
    """
    with pyproject_path.open("rb") as handle:
        data = tomllib.load(handle)

    project = data["project"]
    core_roots = [Requirement(spec).name for spec in project["dependencies"]]
    ml_roots = [Requirement(spec).name for spec in project["optional-dependencies"]["ml"]]

    environment: dict[str, str] = {key: str(value) for key, value in default_environment().items()}
    environment["extra"] = ""

    core = dependency_closure(core_roots, environment)
    ml = dependency_closure(ml_roots, environment)
    ml_only = ml - core

    core_entries = distribution_entries(core, frozenset())
    return distribution_entries(ml_only, frozenset(ml_only)) - core_entries


def main(argv: list[str]) -> int:
    """Write the ML-only top-level entries to stdout, one per line.

    Args:
        argv: Command-line arguments; ``argv[0]`` is the ``pyproject.toml`` path.

    Returns:
        int: Process exit code (``0`` on success).
    """
    pyproject_path = Path(argv[0])
    ml_entries = compute_ml_only_entries(pyproject_path)
    for entry in sorted(ml_entries):
        sys.stdout.write(entry + "\n")
    sys.stderr.write(f"ML split: {len(ml_entries)} top-level entries to move\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
