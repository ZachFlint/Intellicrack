# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Guard that ``[project.dependencies]`` still describes the shipped runtime.

``packaging/stage.ps1`` relocates the optional ML stack into ``ml_overlay`` using
``packaging/ml_split.py``, which computes ``closure(ml_roots) - closure(core_roots)``
with ``core_roots`` read straight from ``[project.dependencies]``. That subtraction
is only meaningful while ``[project.dependencies]`` actually enumerates the
packages the core product imports: if the table is pruned, every shared
foundational package (the provider/HTTP stack, ``psutil``, ``regex``,
``typing_extensions`` and the rest) stops being reachable from the core closure,
gets misclassified as ML-only, and is moved out of the core runtime -- which the
installer's core-runtime gate then rejects, breaking ``just build --all``.

The environment that ``just update`` maintains is governed by the ``[tool.pixi]``
tables, not by this one, so a pruned ``[project.dependencies]`` leaves the
installed environment untouched and the breakage stays invisible until the next
installer build. This module is the fast, falsifiable gate that closes that gap:
``just update`` runs it after every upgrade, so a manifest that can no longer
support the ML split fails loudly at update time instead of days later.

Three checks, each capable of reddening on a real regression:

* every distribution added to close the historical under-declaration stays
  declared (``REQUIRED_RUNTIME_DISTRIBUTIONS``);
* every module-level third-party import in ``src/intellicrack`` that resolves to
  an installed distribution is declared (catches future drift); and
* the real ``ml_split`` projection keeps the foundational packaging entries in the
  core runtime, which only holds when the core closure is complete.

Run directly (``python packaging/check_runtime_deps.py``) or with an explicit
repository root as the first argument. Exit code ``0`` means the manifest is
honest; ``1`` means it would ship a broken core runtime.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import tomllib
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from types import ModuleType


_MODULE_DIR = Path(__file__).resolve().parent
_ML_SPLIT_PATH = _MODULE_DIR / "ml_split.py"

_LOCAL_MODULES = frozenset({"intellicrack", "hexbench", "intellicrack_hexcore", "__future__"})
_MODULE_IMPORT_RE = re.compile(r"^(?:import|from)\s+([a-zA-Z0-9_]+)")

#: Distributions imported at module scope by the shipped app or loaded by the
#: shipped interpreter. These were added to close an earlier under-declaration and
#: must stay declared; the import-surface check below enforces completeness, while
#: this explicit set stays meaningful even where a name does not resolve through
#: ``packages_distributions`` on the building host.
REQUIRED_RUNTIME_DISTRIBUTIONS: tuple[str, ...] = (
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

#: Foundational packaging entries that must never be relocated into ``ml_overlay``.
#: Their presence in the relocation set is the observable symptom of a collapsed
#: core closure.
CORE_PACKAGING_ENTRIES: tuple[str, ...] = ("setuptools", "pkg_resources", "_distutils_hack", "wheel")

#: ML-stack top-level entries the split must still relocate. Checked only where the
#: ML stack is installed, so the gate stays meaningful in a runtime-only container.
ML_RELOCATED_ENTRIES: tuple[str, ...] = ("torch", "transformers", "tokenizers", "safetensors")


def _canonical(name: str) -> str:
    """Return the canonical distribution name for comparison.

    Args:
        name: A distribution name as written in a requirement or ``RECORD``.

    Returns:
        str: The lowercased, dash-normalised canonical form.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def _load_ml_split() -> ModuleType:
    """Load ``packaging/ml_split.py`` as a module from its file path.

    ``packaging`` is not an importable package (it has no ``__init__.py``), so the
    sibling split script is loaded directly from disk, mirroring how
    ``stage.ps1`` invokes it.

    Returns:
        ModuleType: The imported ``ml_split`` module.

    Raises:
        SystemExit: If the module cannot be loaded from ``_ML_SPLIT_PATH``.
    """
    spec = importlib.util.spec_from_file_location("ml_split", _ML_SPLIT_PATH)
    if spec is None or spec.loader is None:
        message = f"ERROR: could not load ml_split from {_ML_SPLIT_PATH}"
        raise SystemExit(message)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ml_split"] = module
    spec.loader.exec_module(module)
    return module


def declared_dependencies(pyproject_path: Path) -> set[str]:
    """Return the canonical names declared in ``[project.dependencies]``.

    Args:
        pyproject_path: Path to the project's ``pyproject.toml``.

    Returns:
        set[str]: Canonical distribution names declared as core runtime
        dependencies.
    """
    with pyproject_path.open("rb") as handle:
        data = tomllib.load(handle)
    specs = data["project"]["dependencies"]
    return {_canonical(_requirement_name(spec)) for spec in specs}


def _requirement_name(spec: str) -> str:
    """Return the distribution name from a PEP 508 requirement string.

    Splits on the first character that cannot belong to a name, which is enough
    for the simple ``name>=x,<y`` specs this manifest uses and avoids a runtime
    dependency on ``packaging`` from this guard.

    Args:
        spec: A requirement specifier such as ``"httpx>=0.28.1,<0.29"``.

    Returns:
        str: The bare distribution name.
    """
    match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", spec)
    if match is None:
        return spec.strip()
    return match.group(1)


def module_level_imports(src_root: Path) -> set[str]:
    """Collect top-level modules imported at module scope across the app source.

    Only lines beginning in column zero are considered, so imports nested inside
    functions or ``TYPE_CHECKING`` guards -- which may be optional -- are ignored,
    matching the surface the installer's core-runtime gate must satisfy.

    Args:
        src_root: The ``src/intellicrack`` directory to scan.

    Returns:
        set[str]: Distinct top-level module names imported at module scope.
    """
    modules: set[str] = set()
    for py_file in src_root.rglob("*.py"):
        text = py_file.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            match = _MODULE_IMPORT_RE.match(line)
            if match is not None:
                modules.add(match.group(1))
    return modules


def undeclared_module_level_imports(src_root: Path, declared: set[str]) -> dict[str, list[str]]:
    """Map each module-scope third-party import to its distribution, if undeclared.

    Each top-level module imported at column zero in ``src_root`` is resolved to
    its installed distribution(s); standard-library, first-party, and tokens that
    do not resolve to an installed distribution (for example a Java ``ghidra``
    import string) are ignored, so the result flags only genuine undeclared
    runtime imports.

    Args:
        src_root: The ``src/intellicrack`` directory to scan.
        declared: Canonical names declared in ``[project.dependencies]``.

    Returns:
        dict[str, list[str]]: Each offending module mapped to the distribution
        name(s) it resolves to.
    """
    packages_to_dists = metadata.packages_distributions()
    stdlib = sys.stdlib_module_names
    violations: dict[str, list[str]] = {}
    for module in sorted(module_level_imports(src_root)):
        if module in stdlib or module in _LOCAL_MODULES:
            continue
        dists = packages_to_dists.get(module, [])
        if not dists:
            continue
        if not ({_canonical(dist) for dist in dists} & declared):
            violations[module] = list(dists)
    return violations


def relocated_ml_entries(pyproject_path: Path) -> set[str]:
    """Return the top-level entries ``ml_split`` would move into ``ml_overlay``.

    Args:
        pyproject_path: Path to the project's ``pyproject.toml``.

    Returns:
        set[str]: The ML-only relocation set computed by the real split logic.
    """
    ml_split = _load_ml_split()
    return {str(entry) for entry in ml_split.compute_ml_only_entries(pyproject_path)}


def collect_violations(repo_root: Path) -> list[str]:
    """Run every manifest check and return a message for each violation.

    Args:
        repo_root: The repository root containing ``pyproject.toml`` and ``src``.

    Returns:
        list[str]: Human-readable violation messages; empty when the manifest is
        honest.
    """
    pyproject_path = repo_root / "pyproject.toml"
    src_root = repo_root / "src" / "intellicrack"
    declared = declared_dependencies(pyproject_path)

    messages: list[str] = []

    missing_required = [name for name in REQUIRED_RUNTIME_DISTRIBUTIONS if _canonical(name) not in declared]
    if missing_required:
        messages.append(
            "runtime distributions missing from [project.dependencies]: " + ", ".join(sorted(missing_required)),
        )

    undeclared = undeclared_module_level_imports(src_root, declared)
    messages.extend(
        f"module-level import {module!r} resolves to undeclared distribution(s): " + ", ".join(undeclared[module])
        for module in sorted(undeclared)
    )

    ml_only = relocated_ml_entries(pyproject_path)
    leaked = [entry for entry in CORE_PACKAGING_ENTRIES if entry in ml_only]
    if leaked:
        messages.append(
            "foundational packaging entries wrongly relocated to ml_overlay: " + ", ".join(sorted(leaked)),
        )

    if importlib.util.find_spec("torch") is not None and not any(
        entry in ml_only for entry in ML_RELOCATED_ENTRIES
    ):
        messages.append("torch is installed but ml_split relocated none of the ML stack; the projection is broken")

    return messages


def main(argv: list[str]) -> int:
    """Check the runtime-dependency manifest and report any violations.

    Args:
        argv: Optional ``argv[0]`` giving the repository root; defaults to the
            repository that contains this script.

    Returns:
        int: ``0`` when the manifest is honest, ``1`` otherwise.
    """
    repo_root = Path(argv[0]).resolve() if argv else _MODULE_DIR.parent
    violations = collect_violations(repo_root)
    if violations:
        sys.stderr.write("ERROR: [project.dependencies] no longer describes the shipped runtime:\n")
        for message in violations:
            sys.stderr.write(f"  - {message}\n")
        sys.stderr.write(
            "The ML split reads this table as its core-closure root set; restore the missing "
            "declarations so the installer does not relocate core packages into ml_overlay.\n",
        )
        return 1
    sys.stdout.write("runtime dependency manifest check: [project.dependencies] describes the shipped runtime\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
