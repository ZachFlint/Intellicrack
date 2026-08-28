# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Falsifiable tests for the installer dev-tooling prune projection.

``packaging/prune_dev.py`` decides which top-level ``site-packages`` entries the
installer stager deletes from the bundled runtime because they belong only to the
development, test, documentation, and profiling toolchains. The old stager used a
six-pattern denylist (``pytest*``/``ruff*``/``sphinx*``/...) that missed the bulk
of the toolchain (``bandit``, ``poetry``, ``twine``, ``scalene``, ...). The
replacement computes ``closure(dev+docs+profile+test) - closure(core+ml)`` so the
removal is complete yet can never touch a distribution the shipped product needs.

These gates exercise the real projection against the installed environment: a
known dev-only tool must be pruned, and no runtime dependency of the shipped
product -- nor the foundational packaging floor -- may ever appear in the removal
set. Reverting the keep/prune split, or dropping the floor, reddens them.

Both modules are standalone build scripts outside the ``intellicrack`` package.
``prune_dev`` imports helpers from its sibling ``ml_split`` module, so ``ml_split``
is loaded and registered in ``sys.modules`` before ``prune_dev`` is executed.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from types import ModuleType

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PACKAGING_DIR = _REPO_ROOT / "packaging"
_PYPROJECT = _REPO_ROOT / "pyproject.toml"


def _load_module(name: str, path: Path) -> ModuleType:
    """Load a standalone packaging script as a module and register it.

    The module is registered in ``sys.modules`` under ``name`` before its code
    runs so that a sibling script importing it by name resolves against this
    same instance.

    Args:
        name: Module name to register.
        path: Filesystem path to the ``.py`` file.

    Returns:
        ModuleType: The imported module.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        pytest.fail(f"could not load {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_load_module("ml_split", _PACKAGING_DIR / "ml_split.py")
prune_dev = _load_module("prune_dev", _PACKAGING_DIR / "prune_dev.py")


_RUNTIME_MODULES_THAT_MUST_SURVIVE = (
    "PyQt6",
    "httpx",
    "structlog",
    "openai",
    "anthropic",
    "lief",
    "capstone",
    "pefile",
)
_KNOWN_DEV_TOOLS = ("bandit", "black", "pylint", "isort")
_FOUNDATIONAL_FLOOR = ("pip", "setuptools", "pkg_resources", "_distutils_hack", "wheel")
# Transitive dependencies of the core HTTP stack (httpx/openai/anthropic) that the
# dev toolchain also pulls in. They are reachable from the prune roots, so only the
# keep-closure subtraction keeps them out of the removal set. Dropping that
# subtraction -- or dropping the HTTP clients from [project.dependencies] -- would
# let these shared packages be deleted from the shipped runtime.
_SHARED_RUNTIME_TRANSITIVES = ("certifi", "idna", "anyio", "h11")


@pytest.fixture(scope="module")
def dev_only_entries() -> frozenset[str]:
    """Compute the real dev-only prune set once for the module.

    Returns:
        frozenset[str]: The top-level entries ``prune_dev`` would remove.
    """
    return frozenset(str(entry) for entry in prune_dev.compute_dev_only_entries(_PYPROJECT))


def test_prune_set_is_non_trivial(dev_only_entries: frozenset[str]) -> None:
    """The projection must resolve to a substantial removal set.

    The build environment installs dozens of dev/test/docs/profile tools; a set
    that collapsed to a handful would mean the closure computation is broken and
    the runtime would ship the toolchain. A generous floor guards against that
    without pinning an exact count that drifts as extras change.
    """
    assert len(dev_only_entries) > 50


def test_known_dev_tools_are_pruned(dev_only_entries: frozenset[str]) -> None:
    """Representative dev-only tools the old denylist missed must be pruned.

    ``bandit``/``black``/``pylint``/``isort`` are declared only under the ``dev``
    extra and imported nowhere in the shipped product, so each must fall out of
    ``closure(dev+docs+profile+test) - closure(core+ml)``. If the keep and prune
    root sets were swapped, or a runtime root leaked into the prune roots, these
    would no longer be dev-only and the assertion fails.
    """
    for tool in _KNOWN_DEV_TOOLS:
        assert tool in dev_only_entries, f"{tool} should be pruned but is not in the set"


def test_runtime_dependencies_are_never_pruned(dev_only_entries: frozenset[str]) -> None:
    """No shipped-runtime top-level package may appear in the removal set.

    This is the safety invariant: computing the difference against the keep
    closure must exclude every distribution the application imports. Two classes
    are checked. Top-level runtime packages must never be pruned. And the shared
    transitive dependencies of the core HTTP stack -- which the dev toolchain also
    reaches -- must survive too; those only stay because the keep-closure
    subtraction protects them, so pruning by extra membership alone (ignoring the
    keep closure) sweeps them up and this reddens.
    """
    leaked = [m for m in _RUNTIME_MODULES_THAT_MUST_SURVIVE if m in dev_only_entries]
    assert not leaked, f"runtime modules wrongly pruned: {leaked}"

    shared_leaked = [m for m in _SHARED_RUNTIME_TRANSITIVES if m in dev_only_entries]
    assert not shared_leaked, (
        f"shared runtime transitives wrongly pruned: {shared_leaked}; the keep-closure subtraction is not protecting them"
    )


def test_foundational_packaging_floor_is_protected(dev_only_entries: frozenset[str]) -> None:
    """pip/setuptools and their siblings must never be pruned.

    Even if a foundational packaging entry were reachable only from dev roots,
    removing it would leave the frozen runtime with an incoherent packaging
    surface. The explicit floor in ``prune_dev`` must keep them out of the set.
    """
    leaked = [f for f in _FOUNDATIONAL_FLOOR if f in dev_only_entries]
    assert not leaked, f"foundational packaging entries wrongly pruned: {leaked}"


def test_keep_and_prune_extras_are_disjoint() -> None:
    """The shipped-extra and pruned-extra root sets must not overlap.

    An extra appearing in both would be simultaneously kept and pruned; the ML
    extra in particular must be a keep root (its packages are relocated into
    ``ml_overlay``, not deleted).
    """
    keep = {str(extra) for extra in prune_dev._KEEP_EXTRAS}
    prune = {str(extra) for extra in prune_dev._PRUNE_EXTRAS}
    assert keep.isdisjoint(prune)
    assert "ml" in keep
    assert {"dev", "test", "docs", "profile"} <= prune
