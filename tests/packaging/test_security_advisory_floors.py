# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Tests for the dependency security floors that clear Dependabot.

Several PyPI distributions carried Dependabot advisories:

* **GitPython** (pulled by ``bandit``/``wily``/``pygount`` in the dev feature)
  had a long run of git-option-injection, config-injection and environment-variable
  exfiltration advisories; the most recent batch (including the critical
  GitConfigParser directive-corruption RCE, GHSA-284h-m62q-gf8w) is fixed only in
  ``3.1.59``, and the dev pin sits conservatively at ``>=3.1.62`` above that floor;
* **pyasn1** (shipped at runtime via ``google-genai -> google-auth ->
  pyasn1-modules -> pyasn1``) had three decoder / OID / REAL denial-of-service
  advisories (CVE-2026-59884 / CVE-2026-59885 / CVE-2026-59886), all fixed by
  ``0.6.4``; and
* **httpx2** and its transport **httpcore2** (shipped at runtime via
  ``anthropic``/``openai``/``mcp``) had a run of advisories -- a SOCKS-proxied
  WebSocket TLS bypass, quadratic SSE line-buffering DoS, multipart header
  injection, conflicting ``Content-Length``/``Transfer-Encoding``, and streaming
  decompression amplification (CVE-2026-84378 through CVE-2026-84382). ``httpx2``
  is fully patched by ``2.12.0`` and ``httpcore2`` clears its half of
  CVE-2026-84381 by ``2.10.0``;
* **certifi** (shipped at runtime via ``requests``/``httpx``) bundled the emSign
  roots whose intermediate CA keys were compromised (GHSA-6q48-6c7w-9gw2),
  removed in ``2026.10.19``;
* **opentelemetry-api** (shipped at runtime via ``mcp``/``anthropic``) parsed
  ``tracestate`` without bounds (GHSA-xcq7-p3pf-p88h), fixed in ``1.45.1``; and
* **virtualenv** (pulled by ``tox``/``nox``/``pre-commit``/``poetry`` in the dev
  toolchain) had a run of activation-script injection, seeding verification and
  link-following advisories, all fixed by ``21.14.9``.

Each gets a minimum-version floor in ``pyproject.toml`` --
``pyasn1``, ``httpx2``, ``httpcore2``, ``certifi`` and ``opentelemetry-api`` in
the default (runtime) ``[tool.pixi].pypi-dependencies``, and ``gitpython`` and
``virtualenv`` in ``[tool.pixi.feature.dev.pypi-dependencies]`` so they stay out
of the shipped runtime environment. These gates hold that fix at three layers:

* the declared specifier in ``pyproject.toml`` must admit the patched version
  and reject the representative still-vulnerable version;
* the version resolved into ``pixi.lock`` must be at or above the floor; and
* the pin exported to ``requirements.txt`` -- the exact manifest Dependabot
  scans -- must be at or above the floor.

The npm transitive **katex** (``markdownlint-cli2 -> micromark-extension-math ->
katex``) let existing prototype pollution bypass its trust restrictions
(GHSA-238p-pmpm-9mq7), fixed in ``0.18.2``. Its parent caps it at ``^0.16.0``, so
``package.json`` forces it through both ``resolutions`` (Yarn) and ``overrides``
(npm), and every ``yarn.lock`` entry for it must resolve at or above the floor.

Removing or weakening a pin, a re-solve that regresses a package below its floor,
or a stale ``requirements.txt`` or ``yarn.lock`` each reddens a gate.
``pyproject.toml``, ``pixi.lock``, ``requirements.txt``, ``package.json`` and
``yarn.lock`` all live at the repository root, which is not mounted into the
test container, so these run in the host-native pass.
"""

from __future__ import annotations

import json
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
_PACKAGE_JSON: Final[Path] = _REPO_ROOT / "package.json"
_YARN_LOCK: Final[Path] = _REPO_ROOT / "yarn.lock"

# Canonical distribution name -> (first patched version, a representative
# version still covered by the advisories). The patched floor must be admitted
# by every layer; the vulnerable sample must be rejected by the declared spec.
_GITPYTHON: Final[str] = str(canonicalize_name("GitPython"))
_PYASN1: Final[str] = str(canonicalize_name("pyasn1"))
_HTTPX2: Final[str] = str(canonicalize_name("httpx2"))
_HTTPCORE2: Final[str] = str(canonicalize_name("httpcore2"))
_CERTIFI: Final[str] = str(canonicalize_name("certifi"))
_OPENTELEMETRY_API: Final[str] = str(canonicalize_name("opentelemetry-api"))
_VIRTUALENV: Final[str] = str(canonicalize_name("virtualenv"))
_FLOORS: Final[dict[str, tuple[Version, Version]]] = {
    _GITPYTHON: (Version("3.1.59"), Version("3.1.58")),
    _PYASN1: (Version("0.6.4"), Version("0.6.3")),
    _HTTPX2: (Version("2.13.0"), Version("2.9.1")),
    _HTTPCORE2: (Version("2.13.0"), Version("2.9.1")),
    _CERTIFI: (Version("2026.10.19"), Version("2026.7.22")),
    _OPENTELEMETRY_API: (Version("1.45.1"), Version("1.45.0")),
    _VIRTUALENV: (Version("21.14.9"), Version("21.14.8")),
}

_KATEX: Final[str] = "katex"
_KATEX_FLOOR: Final[Version] = Version("0.18.2")

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
        return SpecifierSet(version) if isinstance(version, str) else SpecifierSet()
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


def _declared_lower_bound(spec: SpecifierSet) -> Version | None:
    """Return the lowest version a specifier set can admit, from its lower-bounding clauses.

    Args:
        spec: The declared specifier set.

    Returns:
        Version | None: The highest version named by a ``>=``, ``>``, ``==``,
            ``~=`` or ``===`` clause, which no admitted version is below, or
            ``None`` when the set has no lower bound.
    """
    bounds = [Version(clause.version) for clause in spec if clause.operator in {">=", ">", "==", "~=", "==="}]
    return max(bounds, default=None)


def test_pyproject_declares_httpx_stack_runtime_security_floor() -> None:
    """httpx2 and httpcore2 must carry runtime floors that reject the vulnerable releases.

    Both pins live in the default-feature ``[tool.pixi].pypi-dependencies`` so the
    patched HTTP stack ships in the runtime environment used by the anthropic,
    openai and mcp clients. Weakening or dropping either would let the resolver
    fall back to a version covered by the WebSocket-TLS-bypass, SSE-DoS, header
    injection or decompression-amplification advisories.

    Like the GitPython pin, each shipped floor tracks the locked release and may
    be stricter than the advisory's first-patched version, so this asserts the
    declared lower bound is *at least* the advisory floor, that a vulnerable
    release is rejected, and that the version ``pixi.lock`` actually ships is
    admitted.
    """
    for dist, cves in ((_HTTPX2, "CVE-2026-84378..84382"), (_HTTPCORE2, "CVE-2026-84381")):
        _assert_declared_floor(dist, cves, "tool", "pixi", "pypi-dependencies")


def _assert_declared_floor(dist: str, advisories: str, *table_path: str) -> None:
    """Assert a declared pixi pin clears its advisory floor and admits the locked release.

    Args:
        dist: Canonical distribution name from ``_FLOORS``.
        advisories: Advisory identifiers named in failure messages.
        *table_path: Keys navigating from the parsed document root to the
            ``pypi-dependencies`` sub-table that must declare ``dist``.
    """
    floor, vulnerable = _FLOORS[dist]
    table = ".".join(table_path)
    spec = _declared_specifier(dist, *table_path)
    assert str(spec), f"{dist} is not declared in [{table}]"
    lower_bound = _declared_lower_bound(spec)
    assert lower_bound is not None, f"{dist} spec {spec} has no lower bound, so it admits every vulnerable release ({advisories})"
    assert lower_bound >= floor, f"{dist} spec {spec} admits releases below the patched floor {floor} ({advisories})"
    assert not spec.contains(vulnerable), f"{dist} spec {spec} still admits the vulnerable {vulnerable} ({advisories})"
    shipped = _lock_versions(dist)
    assert shipped, f"{dist} is not resolved in pixi.lock"
    rejected = sorted(str(version) for version in shipped if not spec.contains(version))
    assert not rejected, f"{dist} spec {spec} rejects the version pixi.lock ships: {rejected}"


def test_pyproject_declares_certifi_and_opentelemetry_runtime_security_floors() -> None:
    """The certifi and opentelemetry-api pins must be runtime floors that reject the vulnerable releases.

    Both pins live in the default-feature ``[tool.pixi].pypi-dependencies`` so the
    patched CA bundle (used by requests and httpx) and the patched tracing API
    (used by mcp and anthropic) ship in the runtime environment. Each declared
    lower bound must be at least the advisory floor, the last vulnerable release
    must be rejected, and the release ``pixi.lock`` resolves must be admitted.
    """
    for dist, advisories in ((_CERTIFI, "GHSA-6q48-6c7w-9gw2"), (_OPENTELEMETRY_API, "GHSA-xcq7-p3pf-p88h")):
        _assert_declared_floor(dist, advisories, "tool", "pixi", "pypi-dependencies")


def test_pyproject_declares_virtualenv_dev_security_floor() -> None:
    """The virtualenv pin must be a dev-feature floor that stays out of the runtime table.

    tox, nox, pre-commit and poetry pull virtualenv into the dev toolchain only,
    so its pin lives in ``[tool.pixi.feature.dev.pypi-dependencies]``. The
    declared lower bound must clear 21.14.9 (the release fixing every open
    virtualenv advisory), reject 21.14.8, admit the locked release, and the
    default-feature table must not declare it.
    """
    _assert_declared_floor(_VIRTUALENV, "virtualenv activation/seeding advisories", "tool", "pixi", "feature", "dev", "pypi-dependencies")
    runtime_spec = _declared_specifier(_VIRTUALENV, "tool", "pixi", "pypi-dependencies")
    assert not str(runtime_spec), "virtualenv is declared in the default-feature pypi-dependencies, leaking it into the runtime env"


def test_pyproject_declares_gitpython_dev_security_floor() -> None:
    """GitPython must carry a dev-feature floor that rejects the vulnerable range.

    The pin lives in ``[tool.pixi.feature.dev.pypi-dependencies]`` -- keeping the
    patched GitPython in the dev toolchain that pulls it (bandit/wily/pygount)
    without dragging it into the shipped runtime environment. It must also not be
    declared in the default-feature table, which would leak it into the runtime.

    The shipped pin tracks the locked release and is stricter than the advisory
    first-patched version, so this asserts the declared lower bound is *at least*
    the advisory floor, that the last vulnerable release is rejected, and that
    the release ``pixi.lock`` resolves is admitted.
    """
    _assert_declared_floor(_GITPYTHON, "GHSA-284h-m62q-gf8w", "tool", "pixi", "feature", "dev", "pypi-dependencies")
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


def _yarn_lock_versions(package: str) -> list[Version]:
    """Return every resolved version of an npm ``package`` recorded in ``yarn.lock``.

    Args:
        package: Exact npm package name to collect.

    Returns:
        list[Version]: One entry per lockfile record whose ``resolution`` names
            ``package`` from the npm registry.
    """
    with _YARN_LOCK.open("rb") as handle:
        document = _as_str_mapping(cast("object", yaml.safe_load(handle)))
    prefix = f"{package}@npm:"
    versions: list[Version] = []
    for entry in document.values():
        fields = _as_str_mapping(entry)
        resolution = fields.get("resolution")
        version = fields.get("version")
        if isinstance(resolution, str) and resolution.startswith(prefix) and isinstance(version, str):
            versions.append(Version(version))
    return versions


def test_package_json_forces_patched_katex() -> None:
    """package.json must force katex to a patched release for both Yarn and npm.

    micromark-extension-math declares ``katex: ^0.16.0``, which only admits
    releases covered by GHSA-238p-pmpm-9mq7. The ``resolutions`` (Yarn) and
    ``overrides`` (npm) entries must each pin an exact katex version at or above
    0.18.2.
    """
    manifest = _as_str_mapping(cast("object", json.loads(_PACKAGE_JSON.read_text(encoding="utf-8"))))
    for field in ("resolutions", "overrides"):
        pinned = _as_str_mapping(manifest.get(field)).get(_KATEX)
        assert isinstance(pinned, str), f"package.json {field} does not pin {_KATEX}"
        version = Version(pinned)
        assert version >= _KATEX_FLOOR, f"package.json {field} pins {_KATEX} {version}, below the patched floor {_KATEX_FLOOR}"


def test_yarn_lock_resolves_patched_katex() -> None:
    """Every katex record in yarn.lock must resolve at or above the patched floor.

    ``yarn.lock`` is the npm manifest Dependabot scans, so a stale lock that still
    resolves 0.16.x keeps GHSA-238p-pmpm-9mq7 open even with the package.json
    override in place.
    """
    resolved = _yarn_lock_versions(_KATEX)
    assert resolved, f"{_KATEX} is not resolved in yarn.lock"
    below = sorted(str(version) for version in resolved if version < _KATEX_FLOOR)
    assert not below, f"yarn.lock resolves {_KATEX} below the patched floor {_KATEX_FLOOR}: {below}"
