# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Working out what this editor depends on, by reading it rather than a list.

A hand-kept list of dependencies is wrong the moment someone adds an import, so
this derives the answer from the source: every module the package imports, minus
the standard library, minus itself, resolved to the distributions that provide
them and then split by whether the environment manifest actually declares each
one. ``update-deps.ps1`` upgrades the declared half and reports the rest.

Two things are not visible to a reader of the import statements and are added
deliberately. The window toolkit is imported by name through ``importlib`` so
that the modes opening no window keep working without it, and the name is taken
from :mod:`hexbench.window` rather than repeated here. The build description is
scanned along with the modules, because what builds the executable is as much a
dependency as what runs it, and it is the only thing that names the freezer.

The undeclared half is not a fault. The engine is built into the environment by
``just build-hexcore`` instead of being resolved from an index, so it is
reported and left alone.
"""

from __future__ import annotations

import ast
import json
import sys
import tomllib
from importlib.metadata import packages_distributions, version
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple, cast

from hexbench.window import TOOLKIT_MODULE


if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


__all__ = ["Dependency", "Report", "main", "scan"]

_SOURCE_PATTERNS: Final = ("*.py", "*.spec")
_SOURCE_ROOT: Final = "src"
_PACKAGE_NAME: Final = "hexbench"
_PIXI_TABLE: Final = "pixi"
_TOOL_TABLE: Final = "tool"
_PYPI_KEY: Final = "pypi-dependencies"
_FEATURE_TABLE: Final = "feature"
_UNKNOWN_VERSION: Final = "unknown"
_EXPECTED_ARGUMENTS: Final = 2


class Dependency(NamedTuple):
    """One distribution this editor needs, and what is known about it."""

    distribution: str
    installed: str
    declared: bool
    built_here: bool
    imported_as: tuple[str, ...]


class Report(NamedTuple):
    """What a scan of the package found."""

    modules: tuple[str, ...]
    dependencies: tuple[Dependency, ...]


def source_files(root: Path) -> list[Path]:
    """Find every file in the package that a scan should read.

    Args:
        root: Directory of the package.

    Returns:
        list[Path]: The source files, in a stable order.
    """
    found: list[Path] = []
    for pattern in _SOURCE_PATTERNS:
        found.extend(root.rglob(pattern))
    return sorted(set(found))


def imported_names(sources: Iterable[Path]) -> set[str]:
    """Collect the top-level module each import statement reaches for.

    A file that cannot be parsed is left to fail out of here rather than being
    skipped over: skipping would silently drop whatever that file imports, and
    the caller is about to upgrade packages based on the answer.

    Args:
        sources: Files to read.

    Returns:
        set[str]: Top-level module names, such as ``webview`` for
        ``webview.platforms``.
    """
    names: set[str] = set()
    for source in sources:
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name.partition(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None:
                names.add(node.module.partition(".")[0])
    return names


def third_party(names: Iterable[str]) -> set[str]:
    """Reduce a set of imports to the ones that come from somewhere else.

    Args:
        names: Top-level module names.

    Returns:
        set[str]: The names that are neither this package nor standard library.
    """
    return {name for name in names if name != _PACKAGE_NAME and name not in sys.stdlib_module_names}


def _table(source: dict[str, object], key: str) -> dict[str, object]:
    """Read one sub-table out of a parsed manifest.

    Args:
        source: The table to read from.
        key: Name of the sub-table.

    Returns:
        dict[str, object]: The sub-table, or an empty one if it is absent or is
        not a table at all.
    """
    value = source.get(key)
    if not isinstance(value, dict):
        return {}
    entries = cast("dict[object, object]", value)
    return {str(name): item for name, item in entries.items()}


def declared_distributions(manifest: Path) -> set[str]:
    """Read the distributions the environment manifest resolves from an index.

    Pixi splits its index dependencies across the top-level table and one table
    per named feature, and an environment is composed from several of those
    features, so a distribution is declared if any of the tables carries it.
    Reading the top-level table alone reports everything a feature declares --
    the freezer among them -- as a gap a fresh install would be missing.

    Args:
        manifest: Path to ``pyproject.toml``.

    Returns:
        set[str]: Declared distribution names, normalised for comparison.
    """
    document: dict[str, object] = tomllib.loads(manifest.read_text(encoding="utf-8"))
    pixi = _table(_table(document, _TOOL_TABLE), _PIXI_TABLE)
    features = _table(pixi, _FEATURE_TABLE)
    tables = [_table(pixi, _PYPI_KEY), *(_table(_table(features, name), _PYPI_KEY) for name in features)]
    return {_normalise(name) for table in tables for name in table}


def _normalise(name: str) -> str:
    """Fold a distribution name to the spelling comparisons should use.

    Args:
        name: A distribution name as written anywhere.

    Returns:
        str: The lowercase form with separators unified.
    """
    return name.lower().replace("_", "-")


def _installed_version(distribution: str) -> str:
    """Report the version of an installed distribution.

    Args:
        distribution: Name of the distribution.

    Returns:
        str: The installed version, or a placeholder if it cannot be read.
    """
    try:
        return version(distribution)
    except (ImportError, ValueError, LookupError):
        return _UNKNOWN_VERSION


def _is_built_here(distribution: str, repository: Path) -> bool:
    """Decide whether a distribution is built from this repository.

    The engine is compiled into the environment by ``just build-hexcore`` rather
    than resolved from a package index, so it is legitimately absent from the
    manifest's index dependencies and must not be reported as a gap. What makes
    it recognisable is that its source lives here, under ``src`` beside this
    package, so that is what gets checked rather than its name.

    Args:
        distribution: Normalised distribution name.
        repository: Directory holding the manifest.

    Returns:
        bool: Whether this repository contains the source for it.
    """
    return (repository / _SOURCE_ROOT / distribution).is_dir()


def scan(root: Path, manifest: Path) -> Report:
    """Work out which distributions this editor depends on.

    Args:
        root: Directory of the package.
        manifest: Path to ``pyproject.toml``, whose directory is taken to be the
            root of the repository.

    Returns:
        Report: The third-party modules found and the distributions behind them.
    """
    names = third_party(imported_names(source_files(root)) | {TOOLKIT_MODULE})
    declared = declared_distributions(manifest)
    repository = manifest.resolve().parent
    providers = packages_distributions()
    owners: dict[str, set[str]] = {}
    for name in names:
        for distribution in providers.get(name, [name]):
            owners.setdefault(_normalise(distribution), set()).add(name)
    dependencies = tuple(
        Dependency(
            distribution=distribution,
            installed=_installed_version(distribution),
            declared=distribution in declared,
            built_here=_is_built_here(distribution, repository),
            imported_as=tuple(sorted(modules)),
        )
        for distribution, modules in sorted(owners.items())
    )
    return Report(modules=tuple(sorted(names)), dependencies=dependencies)


def main(argv: Sequence[str] | None = None) -> int:
    """Print a scan of the package as JSON, for a caller that can upgrade things.

    Args:
        argv: Command line arguments, or ``None`` to read them from the process.

    Returns:
        int: Process exit status; zero once the scan has been written.
    """
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != _EXPECTED_ARGUMENTS:
        sys.stderr.write("usage: python -m hexbench.dependencies <package-root> <pyproject.toml>\n")
        return 2
    report = scan(Path(arguments[0]), Path(arguments[1]))
    payload = {
        "modules": list(report.modules),
        "dependencies": [dependency._asdict() for dependency in report.dependencies],
    }
    sys.stdout.write(json.dumps(payload, indent=2))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
