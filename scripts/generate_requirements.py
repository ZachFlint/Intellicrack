#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Generate requirements.txt from the pixi lockfile.

Reads ``pixi.lock`` directly to extract resolved PyPI package versions and
writes them to ``requirements.txt`` in pip-compatible format. Cross-references
the lock against ``[tool.pixi].pypi-dependencies`` declared in
``pyproject.toml`` and fails when the lock is out of sync with the declared
dependencies. Skips regeneration when the output is newer than both source
files to keep ``just git-commit`` fast on commits that do not touch deps.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import cast

import yaml


_NAME_NORMALIZE_RE: re.Pattern[str] = re.compile(r"[-_.]+")
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent


def _normalize_name(name: str) -> str:
    """Return the PEP 503 normalized form of a project name.

    Args:
        name: Raw distribution name as written in pyproject.toml or the lock.

    Returns:
        str: Lowercased name with runs of ``-``, ``_``, and ``.`` collapsed
            to ``-``.
    """
    return _NAME_NORMALIZE_RE.sub("-", name).lower()


def _coerce_str_mapping(value: object) -> dict[str, object]:
    """Coerce ``value`` into a string-keyed mapping with object values.

    Args:
        value: Arbitrary value to coerce.

    Returns:
        dict[str, object]: A new mapping containing every entry of ``value``
            whose key is a string, or an empty dict when ``value`` is not a
            mapping.
    """
    if not isinstance(value, dict):
        return {}
    raw = cast("dict[object, object]", value)
    return {key: item for key, item in raw.items() if isinstance(key, str)}


def _require_object_list(value: object, field_name: str) -> list[object]:
    """Coerce ``value`` into a ``list[object]`` or raise ``TypeError``.

    Args:
        value: Arbitrary value to coerce.
        field_name: Source field name used in the error message.

    Returns:
        list[object]: The coerced list of object entries.

    Raises:
        TypeError: If ``value`` is not a list.
    """
    if not isinstance(value, list):
        msg = f"Expected '{field_name}' to be a list (got {type(value).__name__})"
        raise TypeError(msg)
    return list(cast("list[object]", value))


def _load_lock_pypi_packages(lock_path: Path) -> dict[str, tuple[str, str]]:
    """Load PyPI package entries from a pixi lockfile.

    Args:
        lock_path: Path to the pixi.lock file.

    Returns:
        dict[str, tuple[str, str]]: Mapping of normalized project name to
            ``(original_name, version)``. Entries without an explicit version
            (e.g. the editable self-install) are skipped.

    Raises:
        TypeError: If the lockfile root is not a mapping or its ``packages``
            field is not a list.
    """
    with lock_path.open("rb") as fh:
        loaded: object = cast("object", yaml.safe_load(fh))

    root = _coerce_str_mapping(loaded)
    if not root:
        msg = f"pixi.lock root must be a non-empty mapping (got {type(loaded).__name__})"
        raise TypeError(msg)

    packages: dict[str, tuple[str, str]] = {}
    for entry in _require_object_list(root.get("packages"), "packages"):
        fields = _coerce_str_mapping(entry)
        if "pypi" not in fields:
            continue
        raw_name = fields.get("name")
        raw_version = fields.get("version")
        if not isinstance(raw_name, str) or not raw_name:
            continue
        if isinstance(raw_version, str):
            version = raw_version.strip()
        elif isinstance(raw_version, (int, float)):
            version = str(raw_version).strip()
        else:
            continue
        if not version:
            continue
        packages[_normalize_name(raw_name)] = (raw_name, version)
    return packages


def _load_declared_pypi_deps(pyproject_path: Path) -> tuple[dict[str, str], set[str]]:
    """Load declared dependencies from ``[tool.pixi]`` in pyproject.toml.

    Args:
        pyproject_path: Path to the pyproject.toml file.

    Returns:
        tuple[dict[str, str], set[str]]: A tuple of
            ``(pypi_dependencies, conda_dependency_names)``. ``pypi_dependencies``
            maps normalized project name to declared version specifier;
            entries that point at a local path, URL, or git ref are skipped.
            ``conda_dependency_names`` holds normalized names declared under
            ``[tool.pixi].dependencies`` and is used to exclude conda-satisfied
            packages from the PyPI presence check.
    """
    with pyproject_path.open("rb") as fh:
        loaded = tomllib.load(fh)

    root = _coerce_str_mapping(loaded)
    tool = _coerce_str_mapping(root.get("tool"))
    pixi_section = _coerce_str_mapping(tool.get("pixi"))
    raw_pypi = _coerce_str_mapping(pixi_section.get("pypi-dependencies"))
    raw_conda = _coerce_str_mapping(pixi_section.get("dependencies"))

    conda_names: set[str] = {_normalize_name(name) for name in raw_conda if name}

    declared: dict[str, str] = {}
    for raw_name, spec in raw_pypi.items():
        if not raw_name:
            continue
        spec_map = _coerce_str_mapping(spec)
        if spec_map:
            if any(key in spec_map for key in ("path", "url", "git")):
                continue
            version_spec = spec_map.get("version", "*")
            if not isinstance(version_spec, str):
                continue
            specifier = version_spec
        elif isinstance(spec, str):
            specifier = spec
        else:
            continue
        declared[_normalize_name(raw_name)] = specifier
    return declared, conda_names


def _is_outdated(output: Path, sources: list[Path]) -> bool:
    """Return ``True`` when ``output`` should be regenerated.

    Args:
        output: The generated artifact whose freshness is being checked.
        sources: Source files whose mtimes determine whether ``output`` is stale.

    Returns:
        bool: ``True`` if ``output`` does not exist or any source has a newer
            mtime, otherwise ``False``.
    """
    if not output.exists():
        return True
    output_mtime = output.stat().st_mtime
    return any(src.exists() and src.stat().st_mtime > output_mtime for src in sources)


def generate_requirements(output_path: str = "requirements.txt") -> int:
    """Generate requirements.txt from the pixi lockfile.

    Args:
        output_path: Destination path for the requirements file. Resolved
            relative to the project root when not absolute.

    Returns:
        int: ``0`` on success or when the output is already up to date, ``1``
            when a source file is missing, malformed, or the lock is out of
            sync with ``pyproject.toml``.
    """
    lock_path: Path = _PROJECT_ROOT / "pixi.lock"
    pyproject_path: Path = _PROJECT_ROOT / "pyproject.toml"
    output_arg: Path = Path(output_path)
    output: Path = output_arg if output_arg.is_absolute() else _PROJECT_ROOT / output_arg

    if not lock_path.is_file():
        print(f"Error: {lock_path} not found", file=sys.stderr)
        return 1
    if not pyproject_path.is_file():
        print(f"Error: {pyproject_path} not found", file=sys.stderr)
        return 1

    if not _is_outdated(output, [lock_path, pyproject_path]):
        print(f"{output_path} is up to date (pixi.lock and pyproject.toml unchanged)")
        return 0

    try:
        lock_packages = _load_lock_pypi_packages(lock_path)
    except (OSError, TypeError, yaml.YAMLError) as exc:
        print(f"Error: failed to read {lock_path}: {exc}", file=sys.stderr)
        return 1

    try:
        declared, conda_names = _load_declared_pypi_deps(pyproject_path)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"Error: failed to read {pyproject_path}: {exc}", file=sys.stderr)
        return 1

    pip_required = {name: spec for name, spec in declared.items() if name not in conda_names}
    missing = sorted(name for name in pip_required if name not in lock_packages)
    if missing:
        print(
            "Error: declared pypi-dependencies missing from pixi.lock:",
            file=sys.stderr,
        )
        for name in missing:
            print(f"  - {name} (declared as {pip_required[name]!r})", file=sys.stderr)
        print(
            "The lockfile is out of sync with pyproject.toml. Run 'pixi install' to refresh it.",
            file=sys.stderr,
        )
        return 1

    sorted_entries = sorted(lock_packages.values(), key=lambda item: item[0].lower())
    lines = [f"{name}=={version}" for name, version in sorted_entries]
    _ = output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        f"Generated {output_path}: {len(lines)} pinned packages ({len(pip_required)} pip-resolved declared deps verified)",
    )
    return 0


if __name__ == "__main__":
    sys.exit(generate_requirements())
