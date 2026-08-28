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

These gates hold the declaration honest:

* every distribution added to close that gap is still declared;
* every module-level third-party import in ``src/intellicrack`` that resolves to
  an installed distribution is declared (catches future drift); and
* the real ``ml_split`` projection keeps the foundational packaging entries in the
  core runtime while still relocating the heavy ML stack, which only holds when
  the core closure is complete.

``ml_split`` is a standalone build script outside the ``intellicrack`` package and
is loaded here directly from its file path.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import tomllib
from importlib import metadata
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
_ML_SPLIT_PATH = _REPO_ROOT / "packaging" / "ml_split.py"

_LOCAL_MODULES = frozenset({"intellicrack", "hexbench", "intellicrack_hexcore", "__future__"})
_MODULE_IMPORT_RE = re.compile(r"^(?:import|from)\s+([a-zA-Z0-9_]+)")

_ADDED_RUNTIME_DISTS = (
    "anthropic",
    "capstone",
    "frida",
    "google-genai",
    "httpx",
    "keystone-engine",
    "lief",
    "openai",
    "pefile",
    "PyQt6",
    "r2pipe",
    "rzpipe",
    "setuptools",
    "structlog",
    "tiktoken",
    "xxhash",
)
_CORE_PACKAGING_ENTRIES = ("setuptools", "pkg_resources", "_distutils_hack", "wheel")
_ML_RELOCATED_ENTRIES = ("torch", "transformers", "tokenizers", "safetensors")


def _load_ml_split() -> ModuleType:
    """Load ``packaging/ml_split.py`` as a module from its file path.

    Returns:
        ModuleType: The imported ``ml_split`` module.
    """
    spec = importlib.util.spec_from_file_location("ml_split", _ML_SPLIT_PATH)
    if spec is None or spec.loader is None:
        pytest.fail(f"could not load ml_split from {_ML_SPLIT_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["ml_split"] = module
    spec.loader.exec_module(module)
    return module


ml_split = _load_ml_split()


def _declared_dependencies() -> set[str]:
    """Return the canonicalized names in ``[project.dependencies]``.

    Returns:
        set[str]: Canonical distribution names declared as core runtime
            dependencies.
    """
    with _PYPROJECT.open("rb") as handle:
        data = tomllib.load(handle)
    specs = data["project"]["dependencies"]
    return {str(canonicalize_name(Requirement(spec).name)) for spec in specs}


def _module_level_imports() -> set[str]:
    """Collect the top-level modules imported at module scope across ``src``.

    Only lines beginning in column zero are considered, so imports nested inside
    functions or ``TYPE_CHECKING`` guards -- which may be optional -- are ignored.

    Returns:
        set[str]: Distinct top-level module names imported at module scope.
    """
    modules: set[str] = set()
    for py_file in _SRC.rglob("*.py"):
        text = py_file.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            match = _MODULE_IMPORT_RE.match(line)
            if match is not None:
                modules.add(match.group(1))
    return modules


def test_added_runtime_distributions_are_declared() -> None:
    """Every distribution added to close the metadata gap must stay declared.

    Reverting the ``[project.dependencies]`` expansion removes these names and
    the assertion fails, which is exactly the under-declaration this guards.
    """
    declared = _declared_dependencies()
    missing = [name for name in _ADDED_RUNTIME_DISTS if str(canonicalize_name(name)) not in declared]
    assert not missing, f"runtime distributions missing from [project.dependencies]: {missing}"


def test_every_module_level_src_import_is_declared() -> None:
    """Module-scope third-party imports must map to a declared dependency.

    Each top-level module imported at column zero in ``src/intellicrack`` is
    resolved to its installed distribution(s); any that resolves to a real
    distribution must have that distribution declared in
    ``[project.dependencies]``. Standard-library, first-party, and tokens that do
    not resolve to an installed distribution (e.g. a Java ``ghidra`` import string)
    are ignored, so the gate flags genuine undeclared runtime imports without
    false positives. Adding a new third-party module-scope import without
    declaring it reddens this test.
    """
    declared = _declared_dependencies()
    packages_to_dists = metadata.packages_distributions()
    stdlib = sys.stdlib_module_names

    violations: dict[str, list[str]] = {}
    for module in sorted(_module_level_imports()):
        if module in stdlib or module in _LOCAL_MODULES:
            continue
        dists = packages_to_dists.get(module, [])
        if not dists:
            continue
        canonical = {str(canonicalize_name(dist)) for dist in dists}
        if not (canonical & declared):
            violations[module] = dists

    assert not violations, f"module-level imports resolve to undeclared distributions: {violations}"


def test_core_packaging_stays_out_of_ml_overlay() -> None:
    """The ML-split projection must keep foundational packaging in core.

    ``ml_split`` relocates ``ml_roots`` entries that are *not* reachable from the
    core closure. ``setuptools`` was being relocated because, with the old
    eight-package ``[project.dependencies]``, it was not reachable from the core
    roots; declaring it puts it in the core closure and the relocation stops.

    The first assertion is the env-robust root-cause gate: ``setuptools`` must be a
    member of the real core dependency closure (only ``setuptools`` itself need be
    installed, which it always is), and reverting its declaration drops it out --
    exactly the state that caused the over-move. The second confirms the
    observable outcome end-to-end: no foundational packaging entry appears in the
    relocation set. The final block adds relocation coverage only where the ML
    stack is installed, so the gate stays meaningful in a runtime-only container.
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

    ml_only = {str(entry) for entry in ml_split.compute_ml_only_entries(_PYPROJECT)}
    leaked = [entry for entry in _CORE_PACKAGING_ENTRIES if entry in ml_only]
    assert not leaked, f"foundational packaging entries wrongly relocated to ml_overlay: {leaked}"

    if importlib.util.find_spec("torch") is not None:
        relocated = [entry for entry in _ML_RELOCATED_ENTRIES if entry in ml_only]
        assert relocated, "torch is installed but ml_split relocated none of the ML stack; the projection is broken"
