# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Tests that ``[project.dependencies]`` describes the real runtime.

The installer stager and the ML-split projection both trust
``[project.dependencies]`` in ``pyproject.toml`` to enumerate the packages the
shipped product imports. When that list was pruned (only ``pyyaml`` and
``setuptools`` while ``src/intellicrack`` imports two dozen at module scope),
``ml_split`` -- which computes ``closure(ml_roots) - closure(core_roots)`` --
misclassified shared foundational packages as ML-only and relocated them out of
the core runtime, so the installer's core-runtime gate rejected the build.

The contract lives in ``packaging/check_runtime_deps.py`` -- the same guard the
``just git-commit`` prep runs -- so these tests and the commit-time guard cannot
drift. The required set is derived from the source tree, never a hand-kept list:
a distribution is required iff ``src/intellicrack`` imports it at module scope and
it resolves to an installed distribution, so a dependency legitimately removed
from both the code and the manifest raises nothing while a still-imported one is
flagged.

``check_runtime_deps`` and ``ml_split`` are standalone build scripts outside the
``intellicrack`` package and are loaded here directly from their file paths.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
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


def test_real_manifest_describes_the_runtime() -> None:
    """The live ``pyproject.toml`` must raise no runtime-dependency violation.

    Pruning any module-scope-imported dependency from ``[project.dependencies]``
    reddens this: ``collect_violations`` reports it as imported-but-undeclared.
    """
    violations = check_runtime_deps.collect_violations(_REPO_ROOT)
    assert violations == [], f"runtime dependency manifest violations: {violations}"


def test_core_packaging_stays_out_of_ml_overlay() -> None:
    """The ML-split projection must keep foundational packaging in core.

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

    ml_only = check_runtime_deps.relocated_ml_entries(_PYPROJECT)
    leaked = [entry for entry in check_runtime_deps.CORE_PACKAGING_ENTRIES if entry in ml_only]
    assert not leaked, f"foundational packaging entries wrongly relocated to ml_overlay: {leaked}"

    if importlib.util.find_spec("torch") is not None:
        relocated = [entry for entry in check_runtime_deps.ML_RELOCATED_ENTRIES if entry in ml_only]
        assert relocated, "torch is installed but ml_split relocated none of the ML stack; the projection is broken"


def _write_synthetic_repo(root: Path, declared: list[str], imported_module: str, pixi_pypi: dict[str, str]) -> None:
    """Write a minimal repo whose manifest and source the guard can analyse.

    Args:
        root: Directory to populate as the repository root.
        declared: The ``[project.dependencies]`` entries to write.
        imported_module: A module name to import at module scope in the fake
            ``src/intellicrack`` source.
        pixi_pypi: ``name -> version`` entries for the ``[tool.pixi]``
            ``pypi-dependencies`` table (the constraint source).
    """
    deps = "".join(f'  "{entry}",\n' for entry in declared)
    pixi_lines = "".join(f'pypi-dependencies.{name} = "{spec}"\n' for name, spec in pixi_pypi.items())
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "synthetic"\nversion = "0"\ndependencies = [\n{deps}]\n\n[tool.pixi]\n{pixi_lines}',
        encoding="utf-8",
    )
    src = root / "src" / "intellicrack"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("", encoding="utf-8")
    (src / "mod.py").write_text(f"import {imported_module}\n", encoding="utf-8")


def test_fix_restores_a_module_scope_import_from_the_pixi_constraint(tmp_path: Path) -> None:
    """``apply_fix`` restores an imported-but-undeclared dependency, idempotently.

    ``psutil`` is imported at module scope but absent from the synthetic
    ``[project.dependencies]``; the fixer must re-add it with the exact bound from
    the pixi table. A second pass must be a no-op. If the fixer regresses, the
    entry is not restored and the assertion fails.
    """
    _write_synthetic_repo(
        tmp_path,
        declared=["pyyaml"],
        imported_module="psutil",
        pixi_pypi={"psutil": ">=7.2.2, <8", "rich": ">=15, <16"},
    )

    analysis = check_runtime_deps.apply_fix(tmp_path)
    restored = {restoration.name: restoration.requirement() for restoration in analysis.restorations}
    assert restored.get("psutil") == "psutil>=7.2.2,<8", f"psutil not restored from the pixi constraint: {restored}"

    declared_after = check_runtime_deps.declared_dependencies(tmp_path / "pyproject.toml")
    assert str(canonicalize_name("psutil")) in declared_after

    second = check_runtime_deps.apply_fix(tmp_path)
    assert second.restorations == (), f"fixer is not idempotent; re-restored {second.restorations}"


def test_fix_does_not_demand_a_pixi_dependency_that_is_not_imported(tmp_path: Path) -> None:
    """A pixi-declared dependency the code never imports is never restored.

    This is the no-misfire guarantee: ``rich`` is in the pixi table but imported
    nowhere, so a legitimate removal of it from ``[project.dependencies]`` must not
    be reversed. If the rule wrongly treated the pixi manifest as the required
    set, ``rich`` would appear and the assertion fails.
    """
    _write_synthetic_repo(
        tmp_path,
        declared=["pyyaml"],
        imported_module="psutil",
        pixi_pypi={"psutil": ">=7.2.2, <8", "rich": ">=15, <16"},
    )

    analysis = check_runtime_deps.apply_fix(tmp_path)
    names = {restoration.name for restoration in analysis.restorations}
    assert "rich" not in names, "rich is not imported; restoring it would misfire on a legitimate removal"


def _git(repo: Path, *args: str) -> None:
    """Run a git subcommand in ``repo``, failing the test on error.

    Args:
        repo: The repository to operate in.
        args: The git subcommand and arguments.
    """
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not available on PATH")
    subprocess.run(
        [git, "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def test_fix_fully_reverts_a_prune_via_the_committed_head_baseline(tmp_path: Path) -> None:
    """A prune is fully reverted, and a real removal from pixi is respected.

    ``capstone`` is committed in ``[project.dependencies]`` but never imported, so
    only the ``HEAD`` baseline can recover it; ``psutil`` is imported. Both are
    pruned from the working tree and must both come back. ``gone`` is committed
    too but removed from the pixi manifest alongside the prune -- an intended
    removal -- so it must NOT be restored. If the baseline recovery regresses,
    ``capstone`` stays missing; if it ignores the pixi filter, ``gone`` reappears.
    """
    repo = tmp_path
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "synthetic"\nversion = "0"\n'
        'dependencies = [\n  "capstone",\n  "gone>=1,<2",\n  "psutil>=7.2.2,<8",\n]\n\n'
        "[tool.pixi]\n"
        'pypi-dependencies.capstone = "*"\n'
        'pypi-dependencies.gone = ">=1, <2"\n'
        'pypi-dependencies.psutil = ">=7.2.2, <8"\n',
        encoding="utf-8",
    )
    src = repo / "src" / "intellicrack"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("", encoding="utf-8")
    (src / "mod.py").write_text("import psutil\n", encoding="utf-8")

    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "add", "-A")
    _git(repo, "commit", "--no-verify", "-m", "baseline")

    # Working-tree prune: drop every runtime entry, and fully retire ``gone``
    # by also removing it from the pixi manifest.
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "synthetic"\nversion = "0"\n'
        "dependencies = [\n]\n\n"
        "[tool.pixi]\n"
        'pypi-dependencies.capstone = "*"\n'
        'pypi-dependencies.psutil = ">=7.2.2, <8"\n',
        encoding="utf-8",
    )

    analysis = check_runtime_deps.apply_fix(repo)
    restored = {restoration.name for restoration in analysis.restorations}
    assert "capstone" in restored, "lazily-imported committed dependency not recovered from the HEAD baseline"
    assert "psutil" in restored, "module-scope import not recovered"
    assert "gone" not in restored, "a dependency removed from the pixi manifest must be treated as a real removal"

    declared = check_runtime_deps.declared_dependencies(repo / "pyproject.toml")
    assert "gone" not in declared
