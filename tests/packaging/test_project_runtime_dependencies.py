# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Falsifiable tests that ``[project.dependencies]`` describes the real runtime.

The installer stager and the ML-split projection both trust
``[project.dependencies]`` in ``pyproject.toml`` to enumerate everything the
shipped product imports. When that list was incomplete (only eight packages while
``src/intellicrack`` imports two dozen at module scope), two things broke: the
project metadata under-declared its own runtime, and -- because ``ml_split``
computes ``closure(ml_roots) - closure(core_roots)`` -- shared foundational
packages such as ``setuptools`` were wrongly relocated into ``ml_overlay``
because they were not reachable from the (too-small) core closure.

The contract itself lives in ``packaging/check_runtime_deps.py`` -- the same gate
``just update`` runs after every upgrade -- so these tests and the recipe guard
cannot drift apart. Each test exercises the shared checker against the real
manifest and the real ``src`` tree:

* every distribution added to close the gap is still declared;
* every module-level third-party import in ``src/intellicrack`` that resolves to
  an installed distribution is declared (catches future drift); and
* the real ``ml_split`` projection keeps the foundational packaging entries in the
  core runtime while still relocating the heavy ML stack, which only holds when
  the core closure is complete.

``check_runtime_deps`` and ``ml_split`` are standalone build scripts outside the
``intellicrack`` package and are loaded here directly from their file paths.
"""

from __future__ import annotations

import importlib.util
import sys
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


if TYPE_CHECKING:
    from types import ModuleType

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_SRC = _REPO_ROOT / "src" / "intellicrack"
_PACKAGING = _REPO_ROOT / "packaging"


def _load_script(name: str) -> ModuleType:
    """Load a standalone build script from ``packaging/`` by file path.

    Args:
        name: The module name (without ``.py``) under ``packaging/``.

    Returns:
        ModuleType: The imported module.
    """
    path = _PACKAGING / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        pytest.fail(f"could not load {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


check_runtime_deps = _load_script("check_runtime_deps")
ml_split = _load_script("ml_split")


def test_added_runtime_distributions_are_declared() -> None:
    """Every distribution added to close the metadata gap must stay declared.

    Reverting the ``[project.dependencies]`` expansion removes these names and the
    checker reports them, which is exactly the under-declaration this guards.
    """
    declared = check_runtime_deps.declared_dependencies(_PYPROJECT)
    missing = [
        name
        for name in check_runtime_deps.REQUIRED_RUNTIME_DISTRIBUTIONS
        if str(canonicalize_name(name)) not in declared
    ]
    assert not missing, f"runtime distributions missing from [project.dependencies]: {missing}"


def test_every_module_level_src_import_is_declared() -> None:
    """Module-scope third-party imports must map to a declared dependency.

    Each top-level module imported at column zero in ``src/intellicrack`` is
    resolved to its installed distribution(s); any that resolves to a real
    distribution must have that distribution declared in
    ``[project.dependencies]``. Adding a new third-party module-scope import
    without declaring it reddens this test.
    """
    declared = check_runtime_deps.declared_dependencies(_PYPROJECT)
    violations = check_runtime_deps.undeclared_module_level_imports(_SRC, declared)
    assert not violations, f"module-level imports resolve to undeclared distributions: {violations}"


def test_core_packaging_stays_out_of_ml_overlay() -> None:
    """The ML-split projection must keep foundational packaging in core.

    The first assertion is the env-robust root-cause gate: ``setuptools`` must be a
    member of the real core dependency closure (only ``setuptools`` itself need be
    installed, which it always is), and reverting its declaration drops it out --
    exactly the state that caused the over-move. The second confirms the
    observable outcome end-to-end via the shared checker: no foundational packaging
    entry appears in the relocation set. The final block adds relocation coverage
    only where the ML stack is installed, so the gate stays meaningful in a
    runtime-only container.
    """
    with _PYPROJECT.open("rb") as handle:
        data = tomllib.load(handle)
    core_roots = [str(Requirement(spec).name) for spec in data["project"]["dependencies"]]
    environment = {key: str(value) for key, value in default_environment().items()}
    environment["extra"] = ""
    core_closure = {str(name) for name in ml_split.dependency_closure(core_roots, environment)}
    assert str(canonicalize_name("setuptools")) in core_closure, (
        "setuptools is not in the core dependency closure; ml_split would relocate it out of the shipped runtime"
    )

    ml_only = check_runtime_deps.relocated_ml_entries(_PYPROJECT)
    leaked = [entry for entry in check_runtime_deps.CORE_PACKAGING_ENTRIES if entry in ml_only]
    assert not leaked, f"foundational packaging entries wrongly relocated to ml_overlay: {leaked}"

    if importlib.util.find_spec("torch") is not None:
        relocated = [entry for entry in check_runtime_deps.ML_RELOCATED_ENTRIES if entry in ml_only]
        assert relocated, "torch is installed but ml_split relocated none of the ML stack; the projection is broken"
