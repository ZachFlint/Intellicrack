# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Falsifiable tests for the pixi runtime/build environment split.

The installer stages its runtime from the dedicated ``runtime`` pixi environment
instead of the all-in-one ``default`` environment. The split is expressed in
``[tool.pixi]`` of ``pyproject.toml``:

* the default feature declares only what the shipped app needs at runtime;
* the Rust and clang toolchains, ``cmake``/``ninja`` and the PyPI
  linter/formatter/test/docs/profile stacks live in named features
  (``build``/``tooling``/``dev``/``test``/``docs``/``profile``);
* the ``runtime`` environment composes *only* the default feature, so ~2 GB of
  build-only payload never reaches the installer, while the ``default``
  environment still composes every feature for development.

These gates hold that structure. Moving a build package back into the default
feature, adding a build/dev feature to the ``runtime`` environment, or dropping a
feature from the ``default`` environment each reddens a test. ``pyproject.toml``
is not mounted into the test container, so these run in the host-native pass.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


_REPO_ROOT = Path(__file__).resolve().parents[2]
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_STAGE_PS1 = _REPO_ROOT / "packaging" / "stage.ps1"

_NAMED_FEATURES = frozenset({"build", "tooling", "dev", "test", "docs", "profile"})
# Conda packages that make up the build toolchain; none may ship at runtime.
_BUILD_TOOLCHAIN = frozenset({"rust", "rust-src", "clang-tools", "cppcheck", "cmake", "cmake-format", "ninja"})
# Representative dev/test/docs/profile PyPI tools that must not be in the runtime feature.
_DEV_TOOLS = frozenset({"ruff", "pytest", "mypy", "black", "pylint", "sphinx", "scalene"})
# Distributions the shipped product imports; the runtime feature must keep them.
_RUNTIME_ESSENTIALS = frozenset(
    {"torch", "PyQt6", "lief", "capstone", "frida", "httpx", "anthropic", "openai", "pywebview"},
)


def _pixi() -> dict[str, Any]:
    """Return the parsed ``[tool.pixi]`` table from ``pyproject.toml``.

    Returns:
        dict[str, Any]: The ``tool.pixi`` mapping.
    """
    with _PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)["tool"]["pixi"]


def _feature_dep_names(table: dict[str, Any]) -> set[str]:
    """Collect canonicalized conda + PyPI dependency names from a pixi table.

    Args:
        table: A pixi feature table (or the default-feature ``[tool.pixi]`` table)
            holding ``dependencies`` and/or ``pypi-dependencies`` sub-tables.

    Returns:
        set[str]: Canonicalized distribution names declared in the table.
    """
    names: set[str] = set()
    for key in ("dependencies", "pypi-dependencies"):
        section = table.get(key, {})
        names |= {str(canonicalize_name(name)) for name in section}
    return names


def _canon(names: frozenset[str]) -> set[str]:
    """Canonicalize a set of distribution names for comparison.

    Args:
        names: Raw distribution names.

    Returns:
        set[str]: Canonicalized names.
    """
    return {str(canonicalize_name(name)) for name in names}


def test_runtime_environment_excludes_build_and_dev_features() -> None:
    """The ``runtime`` environment must compose only the default feature.

    ``[tool.pixi.environments].runtime`` may not list any of the named build/dev
    features; if it did, the build toolchain would be installed into the runtime
    environment and shipped. An empty feature list means the environment resolves
    to the default (runtime) feature alone.
    """
    envs = _pixi()["environments"]
    assert "runtime" in envs, "the 'runtime' environment is not defined"
    runtime_features = set(envs["runtime"].get("features", []))
    leaked = runtime_features & _NAMED_FEATURES
    assert not leaked, f"runtime environment must not compose build/dev features, but includes: {sorted(leaked)}"


def test_build_toolchain_lives_only_in_the_build_feature() -> None:
    """Rust/clang/cmake/ninja must be in the build feature, not the runtime feature.

    The build toolchain is what the split is meant to keep out of the installer.
    Each toolchain package must be declared under the ``build`` feature and must
    be absent from the default (runtime) feature. Moving any back to the default
    feature reddens this.
    """
    pixi = _pixi()
    build_names = _feature_dep_names(pixi["feature"]["build"])
    runtime_names = _feature_dep_names(pixi)
    toolchain = _canon(_BUILD_TOOLCHAIN)

    missing_from_build = sorted(toolchain - build_names)
    assert not missing_from_build, f"build toolchain packages not declared in the build feature: {missing_from_build}"

    leaked_into_runtime = sorted(toolchain & runtime_names)
    assert not leaked_into_runtime, f"build toolchain leaked into the runtime feature: {leaked_into_runtime}"


def test_runtime_feature_retains_shipping_dependencies() -> None:
    """The runtime feature must keep every shipped dependency and no dev tools.

    The default (runtime) feature must declare the distributions the product
    imports -- dropping one would produce a runtime environment that crashes the
    shipped app -- and must not declare dev/test/docs/profile tooling, which would
    put it back into the installer.
    """
    runtime_names = _feature_dep_names(_pixi())

    missing = sorted(_canon(_RUNTIME_ESSENTIALS) - runtime_names)
    assert not missing, f"runtime feature is missing shipped dependencies: {missing}"

    dev_leak = sorted(_canon(_DEV_TOOLS) & runtime_names)
    assert not dev_leak, f"dev tools wrongly declared in the runtime feature: {dev_leak}"


def test_every_project_dependency_is_declared_in_the_runtime_feature() -> None:
    """Every ``[project.dependencies]`` distribution must be declared for runtime.

    The ``runtime`` environment composes only the default feature, so a package
    that is merely *resolved* into it -- reachable through the shared solve group
    but declared nowhere -- can silently vanish on a re-solve and take the shipped
    app down with it (``keyring`` backs the credential store, ``pyghidra``/
    ``jpype1`` are loaded by the shipped interpreter). Requiring each declared
    project dependency to also be declared in the runtime feature makes that
    impossible to lose by accident.
    """
    with _PYPROJECT.open("rb") as handle:
        project_deps = tomllib.load(handle)["project"]["dependencies"]

    required = {str(canonicalize_name(Requirement(spec).name)) for spec in project_deps}
    declared = _feature_dep_names(_pixi())

    missing = sorted(required - declared)
    assert not missing, (
        "these [project.dependencies] are not declared in the pixi runtime feature, "
        f"so the shipped runtime only carries them by chance: {missing}"
    )


def test_stage_script_sources_the_runtime_environment() -> None:
    r"""``stage.ps1`` must copy the installer runtime from ``.pixi\envs\runtime``.

    This is the behavior the whole feature/environment split exists to produce.
    If ``$PixiEnv`` is ever pointed back at the ``default`` environment the
    installer silently regains the ~2 GB build toolchain while every other gate
    here still passes, so the staging source is asserted directly.
    """
    text = _STAGE_PS1.read_text(encoding="utf-8")
    match = re.search(r"\$PixiEnv\s*=\s*Join-Path\s+\$RepoRoot\s+'([^']*)'", text)
    assert match is not None, "stage.ps1 no longer assigns $PixiEnv from $RepoRoot"

    assert match.group(1) == r".pixi\envs\runtime", (
        f"stage.ps1 stages the installer runtime from '{match.group(1)}', not the slim runtime env"
    )


def test_default_environment_still_composes_every_feature() -> None:
    """The ``default`` environment must keep composing every named feature.

    Development, the maturin/pyinstaller build steps and the whole test/lint
    toolchain all run in the ``default`` environment, so it must continue to pull
    in every named feature. Dropping one from the environment's feature list would
    silently remove that toolchain from the dev environment.
    """
    default_env = _pixi()["environments"]["default"]
    default_features = set(default_env.get("features", []))
    missing = sorted(_NAMED_FEATURES - default_features)
    assert not missing, f"default environment no longer composes these features: {missing}"
