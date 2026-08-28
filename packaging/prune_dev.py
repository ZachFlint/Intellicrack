# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Compute the dev-only top-level site-packages entries for installer staging.

``packaging/stage.ps1`` invokes this module with the bundled runtime's
``python.exe`` to decide which top-level ``site-packages`` entries belong
exclusively to the development, test, documentation, and profiling toolchains and
must therefore be removed from the staged runtime. The staged runtime is copied
from the build environment, which has every extra installed, so without this
pruning the shipped product carries the entire linting/testing/packaging
toolchain (``bandit``, ``poetry``, ``twine``, ``scalene``, ``pip-audit``, and
dozens more) that the application never imports.

The set is the dependency closure of the non-shipped optional-dependency extras
(``dev``, ``docs``, ``profile``, ``test``) minus the closure of everything the
shipped product needs -- the core ``[project.dependencies]`` roots plus the
``[project.optional-dependencies].ml`` roots that are relocated into
``ml_overlay`` -- projected onto the top-level names each distribution installs.

Computing the difference against the shipped closure is what makes this safe: a
distribution shared between a dev tool and the runtime (or the ML stack) stays,
because it is reachable from the keep roots. Only entries reachable *solely* from
the dev/test/docs/profile roots are pruned. A small floor of foundational
packaging entries (``pip``, ``setuptools`` and its siblings, ``wheel``) is never
pruned even if it appears dev-only, so a frozen runtime keeps a coherent
packaging surface.

Each surviving entry is written to stdout, one per line; a human-readable summary
is written to stderr. Distributions with no ``RECORD`` are skipped rather than
fatal: a dev tool that cannot be projected simply is not pruned, which fails safe
(it ships) rather than removing something unknown.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

from ml_split import dependency_closure, distribution_entries
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


_KEEP_EXTRAS: tuple[str, ...] = ("ml",)
_PRUNE_EXTRAS: tuple[str, ...] = ("dev", "docs", "profile", "test")
_PROTECTED_ENTRIES: frozenset[str] = frozenset(
    {
        "pip",
        "pip.exe",
        "setuptools",
        "pkg_resources",
        "_distutils_hack",
        "distutils-precedence.pth",
        "wheel",
    },
)


def compute_dev_only_entries(pyproject_path: Path) -> set[str]:
    """Compute the top-level entries unique to the non-shipped dev toolchains.

    Args:
        pyproject_path: Path to the project's ``pyproject.toml``.

    Returns:
        set[str]: Top-level ``site-packages`` entries to delete from the staged
            runtime, with the foundational packaging floor excluded.
    """
    with pyproject_path.open("rb") as handle:
        data = tomllib.load(handle)

    project = data["project"]
    optional = project["optional-dependencies"]

    keep_roots = [Requirement(spec).name for spec in project["dependencies"]]
    for extra in _KEEP_EXTRAS:
        keep_roots.extend(Requirement(spec).name for spec in optional[extra])

    prune_roots: list[str] = []
    for extra in _PRUNE_EXTRAS:
        prune_roots.extend(Requirement(spec).name for spec in optional[extra])

    environment: dict[str, str] = {key: str(value) for key, value in default_environment().items()}
    environment["extra"] = ""

    keep = dependency_closure(keep_roots, environment)
    prune = dependency_closure(prune_roots, environment)
    dev_only = prune - keep

    keep_entries = distribution_entries(keep, frozenset())
    protected = {canonicalize_name(entry) for entry in _PROTECTED_ENTRIES}
    dev_entries = distribution_entries(dev_only, frozenset())
    return {
        entry
        for entry in (dev_entries - keep_entries)
        if entry not in _PROTECTED_ENTRIES and canonicalize_name(entry) not in protected
    }


def main(argv: list[str]) -> int:
    """Write the dev-only top-level entries to stdout, one per line.

    Args:
        argv: Command-line arguments; ``argv[0]`` is the ``pyproject.toml`` path.

    Returns:
        int: Process exit code (``0`` on success).
    """
    pyproject_path = Path(argv[0])
    dev_entries = compute_dev_only_entries(pyproject_path)
    for entry in sorted(dev_entries):
        sys.stdout.write(entry + "\n")
    sys.stderr.write(f"Dev prune: {len(dev_entries)} top-level entries to remove\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
