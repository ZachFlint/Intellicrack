# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates that the project version is single-sourced everywhere.

The version string is repeated across the repository -- ``pyproject.toml`` (the
package version and the pixi workspace version), ``src/intellicrack/_metadata.py``,
``package.json``, ``docs/source/conf.py``, and the installer's
``packaging/version.generated.iss``. With no gate, any one of them can silently
drift and ship an installer whose ``AppVersion`` disagrees with the package.

Two independent gates close that gap:

* The installer-critical coupling runs in the Docker sandbox against the mounted
  ``src`` and ``packaging`` trees: ``version.generated.iss`` must carry the exact
  ``_metadata.__version__`` as ``AppVersion`` and the 4-part numeric derived from
  it (prerelease suffix stripped, zero-padded) as ``AppVerNumeric`` -- exactly the
  transform ``packaging/stage.ps1`` applies when it regenerates that file.
* The developer-metadata agreement (``pyproject.toml``, ``package.json``,
  ``docs/source/conf.py``) reads files that live at the repository root, outside
  the sandbox's mounted subtree, so those tests are registered ``host_native``
  and run in the host-native pass. They anchor every location on the canonical
  ``[project] version`` in ``pyproject.toml``.

The numeric-derivation function is pure and its falsifiability proof runs
everywhere, so the sandbox verifies the core transform even where the root files
are absent.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Final


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

_PYPROJECT: Final[Path] = _REPO_ROOT / "pyproject.toml"
_METADATA: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "_metadata.py"
_PACKAGE_JSON: Final[Path] = _REPO_ROOT / "package.json"
_DOCS_CONF: Final[Path] = _REPO_ROOT / "docs" / "source" / "conf.py"
_GENERATED_ISS: Final[Path] = _REPO_ROOT / "packaging" / "version.generated.iss"

_METADATA_VERSION_RE: Final[re.Pattern[str]] = re.compile(r'(?m)^__version__\s*:\s*str\s*=\s*"([^"]+)"')
_WORKSPACE_VERSION_RE: Final[re.Pattern[str]] = re.compile(r'(?m)^\s*workspace\.version\s*=\s*"([^"]+)"')
_CONF_RELEASE_RE: Final[re.Pattern[str]] = re.compile(r'(?m)^release\s*=\s*"([^"]+)"')
_CONF_VERSION_RE: Final[re.Pattern[str]] = re.compile(r'(?m)^version\s*=\s*"([^"]+)"')
_ISS_DEFINE_RE: Final[re.Pattern[str]] = re.compile(r'(?m)^#define\s+(\w+)\s+"([^"]*)"')

# Prerelease/dev/post suffix stripped when deriving the 4-part numeric version.
_PRERELEASE_RE: Final[re.Pattern[str]] = re.compile(r"(a|b|rc|\.dev|\.post)\d+$")
_NUMERIC_PARTS: Final[int] = 4


def derive_numeric_version(version: str) -> str:
    """Derive the 4-part numeric ``VersionInfoVersion`` from a PEP 440 version.

    The prerelease/dev/post suffix (for example ``a1``) is removed and the
    remaining dotted release is zero-padded to exactly four components, matching
    the transform ``packaging/stage.ps1`` writes into ``version.generated.iss``.

    Args:
        version: A PEP 440 version string such as ``"0.1.0a1"``.

    Returns:
        str: The 4-part numeric version, for example ``"0.1.0.0"``.
    """
    base = _PRERELEASE_RE.sub("", version)
    parts = [*base.split("."), "0", "0", "0", "0"][:_NUMERIC_PARTS]
    return ".".join(parts)


def _read_metadata_version() -> str:
    """Read ``__version__`` from ``src/intellicrack/_metadata.py``.

    Returns:
        str: The version literal declared in the metadata module.
    """
    assert _METADATA.is_file(), f"metadata module missing: {_METADATA}"
    match = _METADATA_VERSION_RE.search(_METADATA.read_text(encoding="utf-8"))
    assert match is not None, "could not find __version__ in _metadata.py"
    return match.group(1)


def _read_generated_defines() -> dict[str, str]:
    """Read the ``#define`` table from ``packaging/version.generated.iss``.

    Returns:
        dict[str, str]: Mapping of each generated define name to its value.
    """
    assert _GENERATED_ISS.is_file(), f"version.generated.iss missing: {_GENERATED_ISS} (run packaging/stage.ps1 to regenerate it)"
    text = _GENERATED_ISS.read_text(encoding="utf-8-sig")
    return dict(_ISS_DEFINE_RE.findall(text))


# --- Numeric derivation (pure; runs everywhere including the sandbox) ---------


def test_numeric_derivation_strips_prerelease_and_pads() -> None:
    """The numeric derivation strips the prerelease suffix and zero-pads to four."""
    assert derive_numeric_version("0.1.0a1") == "0.1.0.0"
    assert derive_numeric_version("1.2.3") == "1.2.3.0"
    assert derive_numeric_version("2.0.0rc2") == "2.0.0.0"
    assert derive_numeric_version("1.4.0.dev5") == "1.4.0.0"
    assert derive_numeric_version("3.1") == "3.1.0.0"


# --- Installer-critical coupling (sandbox: mounted src + packaging) -----------


def test_generated_iss_appversion_matches_metadata() -> None:
    """Real gate: ``version.generated.iss`` AppVersion equals ``_metadata.__version__``.

    This is the coupling the installer ships: the wizard's displayed version and
    the package version must be one and the same. Bumping ``_metadata`` without
    regenerating the include (or hand-editing the include) turns this red.
    """
    metadata_version = _read_metadata_version()
    defines = _read_generated_defines()

    assert defines.get("AppVersion") == metadata_version, (
        f"version.generated.iss AppVersion is {defines.get('AppVersion')!r}, "
        f"but _metadata.__version__ is {metadata_version!r} -- regenerate it with packaging/stage.ps1"
    )


def test_generated_iss_numeric_is_derived_from_metadata() -> None:
    """Real gate: ``version.generated.iss`` AppVerNumeric is the derived 4-part numeric.

    ``VersionInfoVersion`` requires a 4-part numeric; the generated file must hold
    exactly ``derive_numeric_version(_metadata.__version__)``. A hand-edited or
    stale numeric fails here.
    """
    metadata_version = _read_metadata_version()
    defines = _read_generated_defines()
    expected = derive_numeric_version(metadata_version)

    assert defines.get("AppVerNumeric") == expected, (
        f"version.generated.iss AppVerNumeric is {defines.get('AppVerNumeric')!r}, "
        f"but the derived numeric for {metadata_version!r} is {expected!r}"
    )


# --- Developer-metadata agreement (host-native: repo-root files) --------------


def test_pyproject_package_and_workspace_versions_agree() -> None:
    """Real gate: both ``pyproject.toml`` versions agree (canonical anchor).

    The ``[project] version`` is the single source of truth; the pixi
    ``workspace.version`` must match it. Reads repo-root ``pyproject.toml`` and so
    runs in the host-native pass.
    """
    text = _PYPROJECT.read_text(encoding="utf-8")
    data = tomllib.loads(text)
    canonical = data["project"]["version"]
    assert isinstance(canonical, str), "pyproject [project] version must be a string"
    assert canonical, "pyproject [project] version must be non-empty"

    workspace_match = _WORKSPACE_VERSION_RE.search(text)
    assert workspace_match is not None, "pyproject.toml declares no pixi workspace.version"
    assert workspace_match.group(1) == canonical, (
        f"pixi workspace.version {workspace_match.group(1)!r} disagrees with [project] version {canonical!r}"
    )


def test_all_metadata_locations_agree_with_pyproject() -> None:
    """Real gate: metadata, package.json, docs, and the installer all match pyproject.

    Anchors every version location on the canonical ``[project] version`` in
    ``pyproject.toml``: the Python metadata module, ``package.json``, the Sphinx
    ``release`` (full) and ``version`` (major.minor), and the generated installer
    ``AppVersion``/``AppVerNumeric``. Reads repo-root files, so it runs in the
    host-native pass. Bumping any one location out of sync turns this red.
    """
    canonical = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    assert isinstance(canonical, str)

    assert _read_metadata_version() == canonical, "src/intellicrack/_metadata.py __version__ disagrees with pyproject"

    package_version = json.loads(_PACKAGE_JSON.read_text(encoding="utf-8")).get("version")
    assert package_version == canonical, f"package.json version {package_version!r} disagrees with pyproject {canonical!r}"

    conf_text = _DOCS_CONF.read_text(encoding="utf-8")
    release_match = _CONF_RELEASE_RE.search(conf_text)
    version_match = _CONF_VERSION_RE.search(conf_text)
    assert release_match is not None, "docs/source/conf.py declares no release"
    assert version_match is not None, "docs/source/conf.py declares no version"
    assert release_match.group(1) == canonical, f"docs conf.py release {release_match.group(1)!r} disagrees with pyproject {canonical!r}"
    expected_short = ".".join(canonical.split(".")[:2])
    assert version_match.group(1) == expected_short, (
        f"docs conf.py version {version_match.group(1)!r} must be the major.minor {expected_short!r} of {canonical!r}"
    )

    defines = _read_generated_defines()
    assert defines.get("AppVersion") == canonical, (
        f"installer AppVersion {defines.get('AppVersion')!r} disagrees with pyproject {canonical!r}"
    )
    assert defines.get("AppVerNumeric") == derive_numeric_version(canonical), (
        f"installer AppVerNumeric {defines.get('AppVerNumeric')!r} is not the derived numeric of {canonical!r}"
    )
