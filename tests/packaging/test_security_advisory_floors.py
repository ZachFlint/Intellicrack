# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Falsifiable gates for the dependency security floors that clear Dependabot.

Two transitive PyPI distributions carried Dependabot advisories:

* **GitPython** (pulled by ``bandit``/``wily``/``pygount`` in the dev feature)
  had a run of git-option-injection, config-injection and environment-variable
  exfiltration advisories, all fixed by ``3.1.58``; and
* **pyasn1** (shipped at runtime via ``google-genai -> google-auth ->
  pyasn1-modules -> pyasn1``) had three decoder / OID / REAL denial-of-service
  advisories (CVE-2026-59884 / CVE-2026-59885 / CVE-2026-59886), all fixed by
  ``0.6.4``.

The fix expresses a minimum-version floor for each in ``pyproject.toml`` --
``pyasn1`` in the default (runtime) ``[tool.pixi].pypi-dependencies`` and
``gitpython`` in ``[tool.pixi.feature.dev.pypi-dependencies]`` so it stays out of
the shipped runtime environment. These gates hold that fix at three layers:

* the declared specifier in ``pyproject.toml`` must admit the patched version
  and reject the representative still-vulnerable version;
* the version resolved into ``pixi.lock`` must be at or above the floor; and
* the pin exported to ``requirements.txt`` -- the exact manifest Dependabot
  scans -- must be at or above the floor.

Removing or weakening a pin, a re-solve that regresses a package below its floor,
or a stale ``requirements.txt`` each reddens a gate. ``pyproject.toml``,
``pixi.lock`` and ``requirements.txt`` all live at the repository root, which is
not mounted into the test container, so these run in the host-native pass.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any, Final, cast

import yaml
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_PYPROJECT: Final[Path] = _REPO_ROOT / "pyproject.toml"
_PIXI_LOCK: Final[Path] = _REPO_ROOT / "pixi.lock"
_REQUIREMENTS: Final[Path] = _REPO_ROOT / "requirements.txt"

# Canonical distribution name -> (first patched version, a representative
# version still covered by the advisories). The patched floor must be admitted
# by every layer; the vulnerable sample must be rejected by the declared spec.
_GITPYTHON: Final[str] = str(canonicalize_name("GitPython"))
_PYASN1: Final[str] = str(canonicalize_name("pyasn1"))
_FLOORS: Final[dict[str, tuple[Version, Version]]] = {
    _GITPYTHON: (Version("3.1.58"), Version("3.1.50")),
    _PYASN1: (Version("0.6.4"), Version("0.6.3")),
}

_REQUIREMENT_LINE: Final[re.Pattern[str]] = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([^\s;#]+)")


def _as_str_mapping(value: object) -> dict[str, object]:
    """Coerce ``value`` into a string-keyed mapping with object values.

    Args:
        value: Arbitrary value to coerce.

    Returns:
        dict[str, object]: A new mapping of every string-keyed entry of
            ``value``, or an empty dict when ``value`` is not a mapping.
    """
    if not isinstance(value, dict):
        return {}
    raw = cast("dict[object, object]", value)
    return {key: item for key, item in raw.items() if isinstance(key, str)}


def _load_pyproject() -> dict[str, Any]:
    """Return the parsed ``pyproject.toml`` document.

    Returns:
        dict[str, Any]: The full parsed TOML mapping.
    """
    with _PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)


def _declared_specifier(dist: str, *table_path: str) -> SpecifierSet:
    """Return the declared version specifier for a pixi PyPI dependency.

    Args:
        dist: Canonical distribution name to look up.
        *table_path: Keys navigating from the parsed document root to the
            ``pypi-dependencies`` sub-table (for example ``"tool"``, ``"pixi"``,
            ``"pypi-dependencies"``).

    Returns:
        SpecifierSet: The parsed specifier declared for ``dist``. An empty
            ``SpecifierSet`` when the distribution is not declared in the table,
            which the caller asserts against.
    """
    node: dict[str, object] = _as_str_mapping(_load_pyproject())
    for key in table_path:
        node = _as_str_mapping(node.get(key))
    for raw_name, spec in node.items():
        if str(canonicalize_name(raw_name)) != dist:
            continue
        if isinstance(spec, str):
            return SpecifierSet(spec)
        version = _as_str_mapping(spec).get("version")
        if isinstance(version, str):
            return SpecifierSet(version)
        return SpecifierSet()
    return SpecifierSet()


def _lock_versions(dist: str) -> list[Version]:
    """Return every resolved PyPI version of ``dist`` recorded in ``pixi.lock``.

    Args:
        dist: Canonical distribution name to collect.

    Returns:
        list[Version]: One entry per matching PyPI package record in the
            lockfile (a package resolved into multiple environments of the same
            solve group appears once per environment share).
    """
    with _PIXI_LOCK.open("rb") as handle:
        document = _as_str_mapping(cast("object", yaml.safe_load(handle)))
    versions: list[Version] = []
    packages = document.get("packages")
    if not isinstance(packages, list):
        return versions
    for entry in cast("list[object]", packages):
        fields = _as_str_mapping(entry)
        if "pypi" not in fields:
            continue
        name = fields.get("name")
        version = fields.get("version")
        if not isinstance(name, str) or str(canonicalize_name(name)) != dist:
            continue
        if isinstance(version, str) and version.strip():
            versions.append(Version(version.strip()))
    return versions


def _requirements_pin(dist: str) -> Version | None:
    """Return the pinned version of ``dist`` in ``requirements.txt``.

    Args:
        dist: Canonical distribution name to find.

    Returns:
        Version | None: The pinned version, or ``None`` when ``dist`` is not
            pinned in the file.
    """
    for line in _REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        match = _REQUIREMENT_LINE.match(line)
        if match is None:
            continue
        if str(canonicalize_name(match.group(1))) == dist:
            return Version(match.group(2))
    return None


def test_pyproject_declares_pyasn1_runtime_security_floor() -> None:
    """pyasn1 must carry a runtime floor that rejects the vulnerable release.

    The pin lives in the default-feature ``[tool.pixi].pypi-dependencies`` so the
    patched pyasn1 ships in the runtime environment. Weakening or dropping it
    would let the resolver fall back to a version covered by the DoS advisories.
    """
    floor, vulnerable = _FLOORS[_PYASN1]
    spec = _declared_specifier(_PYASN1, "tool", "pixi", "pypi-dependencies")
    assert str(spec), "pyasn1 is not declared in [tool.pixi].pypi-dependencies"
    assert spec.contains(floor), f"pyasn1 spec {spec} excludes the patched floor {floor}"
    assert not spec.contains(vulnerable), f"pyasn1 spec {spec} still admits the vulnerable {vulnerable} (CVE-2026-59884/59885/59886)"


def test_pyproject_declares_gitpython_dev_security_floor() -> None:
    """GitPython must carry a dev-feature floor that rejects the vulnerable range.

    The pin lives in ``[tool.pixi.feature.dev.pypi-dependencies]`` -- keeping the
    patched GitPython in the dev toolchain that pulls it (bandit/wily/pygount)
    without dragging it into the shipped runtime environment. It must also not be
    declared in the default-feature table, which would leak it into the runtime.
    """
    floor, vulnerable = _FLOORS[_GITPYTHON]
    spec = _declared_specifier(_GITPYTHON, "tool", "pixi", "feature", "dev", "pypi-dependencies")
    assert str(spec), "gitpython is not declared in [tool.pixi.feature.dev.pypi-dependencies]"
    assert spec.contains(floor), f"gitpython spec {spec} excludes the patched floor {floor}"
    assert not spec.contains(vulnerable), f"gitpython spec {spec} still admits the vulnerable {vulnerable}"
    runtime_spec = _declared_specifier(_GITPYTHON, "tool", "pixi", "pypi-dependencies")
    assert not str(runtime_spec), "gitpython is declared in the default-feature pypi-dependencies, leaking it into the runtime env"


def test_pixi_lock_resolves_patched_versions() -> None:
    """Every resolved lockfile version of the flagged packages must clear its floor.

    This gates the actual solve, not just the declared intent: a re-solve that
    regresses GitPython or pyasn1 below its first-patched version reddens here.
    """
    for dist, (floor, _vulnerable) in _FLOORS.items():
        resolved = _lock_versions(dist)
        assert resolved, f"{dist} is not resolved in pixi.lock"
        below = sorted(str(v) for v in resolved if v < floor)
        assert not below, f"pixi.lock resolves {dist} below the patched floor {floor}: {below}"


def test_requirements_txt_pins_patched_versions() -> None:
    """The exported requirements.txt manifest must pin patched versions.

    ``requirements.txt`` is the manifest Dependabot scans. A pin at or above each
    first-patched version is what actually clears the alerts, so the generated
    file is asserted directly and a stale export reddens the gate.
    """
    for dist, (floor, _vulnerable) in _FLOORS.items():
        pinned = _requirements_pin(dist)
        assert pinned is not None, f"{dist} is not pinned in requirements.txt"
        assert pinned >= floor, f"requirements.txt pins {dist}=={pinned}, below the patched floor {floor}"
