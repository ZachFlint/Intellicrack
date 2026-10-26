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
installer's core-runtime gate then rejects, breaking ``just build --all``. This
is easy to trigger by accident: a maintenance edit "cleans up" the table believing
it duplicates the ``[tool.pixi]`` manifest, not realising the installer reads it.

This guard closes that hole without a package list to maintain. The contract it
enforces is derived entirely from the source tree and the pixi manifest, so it
tracks real additions and removals on its own and never misfires on them:

* **Requirement is derived, never declared.** A distribution belongs in
  ``[project.dependencies]`` iff ``src/intellicrack`` imports it at module scope
  and it resolves to an installed distribution. Add an import -> it becomes
  required; drop the import -> it stops being required. A dependency legitimately
  removed from both the code and the manifest raises nothing; only a dependency
  the committed code still imports but the manifest forgot is flagged.
* **Constraints are sourced, never invented.** When a required declaration is
  missing, its version bound is read from the ``[tool.pixi]`` ``pypi-dependencies``
  (or conda ``dependencies``) table -- the manifest ``just update`` already
  maintains -- so the fix restores exactly what the environment pins.

Two modes:

* default (report): print every violation and exit non-zero. Used by the
  ``verify-runtime-deps`` pre-commit hook and the packaging tests.
* ``--fix`` (self-heal): restore any required-but-missing declaration from the
  pixi constraint, rewrite ``[project.dependencies]`` in place, and exit zero. A
  module imported but declared in no manifest at all (the one case a constraint
  cannot be sourced for) is reported and exits non-zero even under ``--fix``,
  because that is an undeclared-everywhere error, not a prune. The
  ``just git-commit`` prep runs this before ``git add -A``, with ``HEAD`` still
  holding the pre-prune manifest, so an agent that drops dependencies is fully
  healed before the commit is formed (see :func:`apply_fix` for the two sources).
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast


if TYPE_CHECKING:
    from collections.abc import Iterable
    from types import ModuleType


_MODULE_DIR = Path(__file__).resolve().parent
_ML_SPLIT_PATH = _MODULE_DIR / "ml_split.py"

_LOCAL_MODULES = frozenset({"intellicrack", "hexbench", "intellicrack_hexcore", "__future__"})
_MODULE_IMPORT_RE = re.compile(r"^(?:import|from)\s+([a-zA-Z0-9_]+)")
_DEPS_BLOCK_RE = re.compile(r"(?ms)^dependencies = \[\n(?P<body>.*?)^\]")
_DEPS_ENTRY_RE = re.compile(r'^\s*"([^"]+)"\s*,?\s*$')

#: Foundational packaging entries that must never be relocated into ``ml_overlay``.
#: Their presence in the relocation set is the observable symptom of a collapsed
#: core closure.
CORE_PACKAGING_ENTRIES: tuple[str, ...] = ("setuptools", "pkg_resources", "_distutils_hack", "wheel")

#: ML-stack top-level entries the split must still relocate. Checked only where the
#: ML stack is installed, so the gate stays meaningful in a runtime-only container.
ML_RELOCATED_ENTRIES: tuple[str, ...] = ("torch", "transformers", "tokenizers", "safetensors")


@dataclass(frozen=True, slots=True)
class Restoration:
    """A declaration the fixer can restore to ``[project.dependencies]``.

    Attributes:
        name: The distribution name exactly as the pixi manifest spells it.
        spec: The PEP 508 version bound (for example ``">=2.3.0,<3"``), or
            ``None`` when the source table pins no version.
        source: Which pixi table supplied the constraint (``"pixi-pypi"`` or
            ``"pixi-conda"``).
    """

    name: str
    spec: str | None
    source: str

    def requirement(self) -> str:
        """Render the restoration as a PEP 508 requirement string.

        Returns:
            str: ``name`` with its spec appended, or the bare ``name`` when no
            version is pinned.
        """
        return f"{self.name}{self.spec}" if self.spec else self.name


def _canonical(name: str) -> str:
    """Return the canonical distribution name for comparison.

    Args:
        name: A distribution name as written in a requirement or manifest.

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


def _load_pyproject(pyproject_path: Path) -> dict[str, Any]:
    """Parse ``pyproject.toml`` into a mapping.

    Args:
        pyproject_path: Path to the project's ``pyproject.toml``.

    Returns:
        dict[str, Any]: The parsed TOML document.
    """
    with pyproject_path.open("rb") as handle:
        return tomllib.load(handle)


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


def _project_dependency_specs(data: dict[str, Any]) -> list[str]:
    """Return the raw requirement strings in ``[project.dependencies]``.

    Args:
        data: A parsed ``pyproject.toml`` document.

    Returns:
        list[str]: The requirement specifiers, in declaration order.
    """
    project = cast("dict[str, Any]", data.get("project", {}))
    specs = cast("list[Any]", project.get("dependencies", []))
    return [str(spec) for spec in specs]


def declared_dependencies(pyproject_path: Path) -> set[str]:
    """Return the canonical names declared in ``[project.dependencies]``.

    Args:
        pyproject_path: Path to the project's ``pyproject.toml``.

    Returns:
        set[str]: Canonical distribution names declared as core runtime
        dependencies.
    """
    return {_canonical(_requirement_name(spec)) for spec in _project_dependency_specs(_load_pyproject(pyproject_path))}


def _normalise_spec(raw: str) -> str | None:
    """Convert a pixi version specifier into a PEP 508 bound.

    Args:
        raw: A pixi version string such as ``">=2.3.0, <3"`` or ``"*"``.

    Returns:
        str | None: The space-free PEP 508 bound, or ``None`` for an unpinned
        (``"*"`` or empty) specifier.
    """
    text = raw.strip()
    if not text or text == "*":
        return None
    return re.sub(r",\s+", ",", text)


def _collect_table(table: object, source: str, index: dict[str, Restoration]) -> None:
    """Add the entries of one pixi dependency table to the constraint index.

    String values yield a version bound; mapping values (for example a pinned
    ``{ version = "*", index = ... }``) contribute only their ``version`` key.
    Entries already present are kept, so the first (root) table wins over a
    feature table that re-declares the same name.

    Args:
        table: The raw value of a pixi ``dependencies`` / ``pypi-dependencies``
            table, or any non-mapping (ignored).
        source: The source label recorded on each restoration.
        index: The canonical-name to :class:`Restoration` map being populated.
    """
    if not isinstance(table, dict):
        return
    for raw_name, raw_value in cast("dict[str, Any]", table).items():
        name = str(raw_name)
        canonical = _canonical(name)
        if canonical in index:
            continue
        if isinstance(raw_value, str):
            spec = _normalise_spec(raw_value)
        elif isinstance(raw_value, dict):
            version = cast("dict[str, Any]", raw_value).get("version")
            spec = _normalise_spec(str(version)) if isinstance(version, str) else None
        else:
            spec = None
        index[canonical] = Restoration(name=name, spec=spec, source=source)


def _pixi_constraint_index(data: dict[str, Any]) -> dict[str, Restoration]:
    """Build a canonical-name index of every pixi-declared distribution.

    PyPI tables take precedence over conda tables, and the root tables over
    feature tables, so the recorded constraint is the one the runtime resolves
    against.

    Args:
        data: A parsed ``pyproject.toml`` document.

    Returns:
        dict[str, Restoration]: Canonical distribution name to its restoration.
    """
    tool = cast("dict[str, Any]", data.get("tool", {}))
    pixi = cast("dict[str, Any]", tool.get("pixi", {}))
    features = cast("dict[str, Any]", pixi.get("feature", {}))

    index: dict[str, Restoration] = {}
    _collect_table(pixi.get("pypi-dependencies"), "pixi-pypi", index)
    for feature in features.values():
        if isinstance(feature, dict):
            _collect_table(cast("dict[str, Any]", feature).get("pypi-dependencies"), "pixi-pypi", index)
    _collect_table(pixi.get("dependencies"), "pixi-conda", index)
    for feature in features.values():
        if isinstance(feature, dict):
            _collect_table(cast("dict[str, Any]", feature).get("dependencies"), "pixi-conda", index)
    return index


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


def _import_distributions(src_root: Path) -> dict[str, list[str]]:
    """Map each module-scope third-party import to its installed distribution(s).

    Standard-library, first-party, and tokens that do not resolve to an installed
    distribution (for example a Java ``ghidra`` import string) are dropped, so the
    result names only imports a shipped runtime must satisfy.

    Args:
        src_root: The ``src/intellicrack`` directory to scan.

    Returns:
        dict[str, list[str]]: Each importable module mapped to the distribution
        name(s) that provide it.
    """
    packages_to_dists = metadata.packages_distributions()
    stdlib = sys.stdlib_module_names
    resolved: dict[str, list[str]] = {}
    for module in sorted(module_level_imports(src_root)):
        if module in stdlib or module in _LOCAL_MODULES:
            continue
        dists = packages_to_dists.get(module, [])
        if dists:
            resolved[module] = list(dists)
    return resolved


@dataclass(frozen=True, slots=True)
class MissingAnalysis:
    """The outcome of comparing imports against ``[project.dependencies]``.

    Attributes:
        restorations: Required declarations that are missing but can be sourced
            from a pixi table.
        undeclared: Modules imported by the code whose providing distributions
            are declared in no manifest at all (cannot be auto-restored).
    """

    restorations: tuple[Restoration, ...]
    undeclared: tuple[tuple[str, tuple[str, ...]], ...]


def analyse_missing(repo_root: Path) -> MissingAnalysis:
    """Determine which required declarations are missing and how to restore them.

    A module is satisfied when any distribution that provides it is already
    declared. Otherwise the first providing distribution that the pixi manifest
    pins yields a restoration; a module with no pinned provider is reported as
    undeclared-everywhere.

    Args:
        repo_root: The repository root containing ``pyproject.toml`` and ``src``.

    Returns:
        MissingAnalysis: The restorations to apply and the unfixable modules.
    """
    pyproject_path = repo_root / "pyproject.toml"
    src_root = repo_root / "src" / "intellicrack"
    data = _load_pyproject(pyproject_path)
    declared = {_canonical(_requirement_name(spec)) for spec in _project_dependency_specs(data)}
    pixi_index = _pixi_constraint_index(data)

    restorations: dict[str, Restoration] = {}
    undeclared: list[tuple[str, tuple[str, ...]]] = []
    for module, dists in _import_distributions(src_root).items():
        canonicals = [_canonical(dist) for dist in dists]
        if any(canonical in declared for canonical in canonicals):
            continue
        chosen = next((canonical for canonical in canonicals if canonical in pixi_index), None)
        if chosen is None:
            undeclared.append((module, tuple(sorted(dists))))
            continue
        restoration = pixi_index[chosen]
        restorations.setdefault(chosen, restoration)
    ordered = tuple(sorted(restorations.values(), key=lambda item: item.name))
    return MissingAnalysis(restorations=ordered, undeclared=tuple(undeclared))


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
        list[str]: Human-readable violation messages; empty when the manifest
        matches the shipped runtime.
    """
    messages: list[str] = []
    analysis = analyse_missing(repo_root)
    messages.extend(
        f"imported at module scope but missing from [project.dependencies]: "
        f"{restoration.requirement()} (restorable from {restoration.source})"
        for restoration in analysis.restorations
    )
    messages.extend(
        f"imported module {module!r} resolves to distribution(s) declared in no manifest: {', '.join(dists)}"
        for module, dists in analysis.undeclared
    )

    pyproject_path = repo_root / "pyproject.toml"
    ml_only = relocated_ml_entries(pyproject_path)
    leaked = [entry for entry in CORE_PACKAGING_ENTRIES if entry in ml_only]
    if leaked:
        messages.append("foundational packaging entries wrongly relocated to ml_overlay: " + ", ".join(sorted(leaked)))

    if importlib.util.find_spec("torch") is not None and not any(entry in ml_only for entry in ML_RELOCATED_ENTRIES):
        messages.append("torch is installed but ml_split relocated none of the ML stack; the projection is broken")

    return messages


def _rewrite_dependencies(pyproject_path: Path, additions: Iterable[Restoration]) -> list[str]:
    """Insert missing declarations into ``[project.dependencies]`` in place.

    The ``[project.dependencies]`` array is the only top-level ``dependencies = [``
    block in the file; its entries are merged with the additions, sorted by
    distribution name (the existing order), and written back with the file's
    one-entry-per-line style preserved.

    Args:
        pyproject_path: Path to the project's ``pyproject.toml``.
        additions: Restorations to add; entries whose name is already present are
            skipped.

    Returns:
        list[str]: The requirement strings actually inserted.

    Raises:
        RuntimeError: If the ``[project.dependencies]`` block is not found exactly
            once, which would make an in-place edit unsafe.
    """
    text = pyproject_path.read_text(encoding="utf-8")
    matches = list(_DEPS_BLOCK_RE.finditer(text))
    if len(matches) != 1:
        message = f"expected exactly one top-level 'dependencies = [' block, found {len(matches)}"
        raise RuntimeError(message)
    block = matches[0]

    existing = [match.group(1) for match in (_DEPS_ENTRY_RE.match(line) for line in block.group("body").splitlines()) if match]
    present = {_canonical(_requirement_name(spec)) for spec in existing}

    inserted: list[str] = []
    merged = list(existing)
    for restoration in additions:
        if _canonical(restoration.name) in present:
            continue
        requirement = restoration.requirement()
        merged.append(requirement)
        present.add(_canonical(restoration.name))
        inserted.append(requirement)

    if not inserted:
        return []

    merged.sort(key=_requirement_name)
    body = "".join(f'  "{spec}",\n' for spec in merged)
    rebuilt = f"dependencies = [\n{body}]"
    pyproject_path.write_text(text[: block.start()] + rebuilt + text[block.end() :], encoding="utf-8")
    return inserted


def _head_project_dependency_names(repo_root: Path) -> set[str] | None:
    """Return the canonical ``[project.dependencies]`` names committed at ``HEAD``.

    In the ``just git-commit`` prep this runs before ``git add -A``, so ``HEAD``
    still holds the manifest as last committed -- the baseline a working-tree
    prune is measured against.

    Args:
        repo_root: The repository root.

    Returns:
        set[str] | None: Canonical names declared at ``HEAD``, or ``None`` when
        ``git`` or ``HEAD:pyproject.toml`` cannot be read (outside a work tree, an
        unborn branch, or an unparseable committed manifest), in which case the
        baseline is simply unavailable and only the import-surface heal applies.
    """
    git = shutil.which("git")
    if git is None:
        return None
    try:
        completed = subprocess.run(
            [git, "-C", str(repo_root), "show", "HEAD:pyproject.toml"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    try:
        data = tomllib.loads(completed.stdout)
    except tomllib.TOMLDecodeError:
        return None
    return {_canonical(_requirement_name(spec)) for spec in _project_dependency_specs(data)}


def apply_fix(repo_root: Path) -> MissingAnalysis:
    """Restore every sourceable missing declaration and report what remains.

    Two sources feed the restore, both constrained by the pixi manifest so a fix
    only ever re-adds a runtime dependency the pixi manifest still declares:

    * **Import surface** - a distribution imported at module scope in
      ``src/intellicrack`` but absent from ``[project.dependencies]``.
    * **Committed baseline** - a distribution present in ``HEAD``'s
      ``[project.dependencies]`` but dropped from the working tree, as long as it
      is still pinned in a ``[tool.pixi]`` runtime table. This recovers the
      lazily-imported and subprocess-loaded entries the import surface cannot see,
      so a prune is fully reverted rather than partially. A *legitimate* removal
      drops the package from the pixi manifest too, so it is not in the restore
      set and is left alone.

    The restored version bound always comes from the current pixi table, never a
    stale ``HEAD`` spec, so the manifest stays consistent with what the runtime
    resolves.

    Args:
        repo_root: The repository root containing ``pyproject.toml`` and ``src``.

    Returns:
        MissingAnalysis: ``restorations`` lists what was inserted; ``undeclared``
        lists modules whose provider is pinned in no manifest and so could not be
        restored.
    """
    pyproject_path = repo_root / "pyproject.toml"
    data = _load_pyproject(pyproject_path)
    declared = {_canonical(_requirement_name(spec)) for spec in _project_dependency_specs(data)}
    pixi_index = _pixi_constraint_index(data)

    analysis = analyse_missing(repo_root)
    restorations: dict[str, Restoration] = {_canonical(item.name): item for item in analysis.restorations}

    head_names = _head_project_dependency_names(repo_root)
    if head_names is not None:
        for name in sorted(head_names - declared):
            if name in restorations or name not in pixi_index:
                continue
            restorations[name] = pixi_index[name]

    ordered = tuple(sorted(restorations.values(), key=lambda item: item.name))
    if ordered:
        _rewrite_dependencies(pyproject_path, ordered)
    return MissingAnalysis(restorations=ordered, undeclared=analysis.undeclared)


def _run_report(repo_root: Path) -> int:
    """Report violations without modifying anything.

    Args:
        repo_root: The repository root to check.

    Returns:
        int: ``0`` when the manifest matches the shipped runtime, ``1`` otherwise.
    """
    violations = collect_violations(repo_root)
    if violations:
        sys.stderr.write("ERROR: [project.dependencies] no longer describes the shipped runtime:\n")
        for message in violations:
            sys.stderr.write(f"  - {message}\n")
        sys.stderr.write(
            "The ML split reads this table as its core-closure root set. Run "
            "'python packaging/check_runtime_deps.py --fix' to restore the pruned declarations.\n",
        )
        return 1
    sys.stdout.write("runtime dependency manifest check: [project.dependencies] describes the shipped runtime\n")
    return 0


def _run_fix(repo_root: Path) -> int:
    """Restore missing declarations and report any unfixable gaps.

    Args:
        repo_root: The repository root to heal.

    Returns:
        int: ``0`` when the manifest now matches the shipped runtime, ``1`` when a module is imported
        whose provider is declared in no manifest (a constraint cannot be sourced).
    """
    analysis = apply_fix(repo_root)
    for restoration in analysis.restorations:
        sys.stdout.write(
            f"restored runtime dependency to [project.dependencies]: "
            f"{restoration.requirement()} (from {restoration.source})\n",
        )
    if analysis.undeclared:
        sys.stderr.write("ERROR: imported modules whose providing distribution is declared in no manifest:\n")
        for module, dists in analysis.undeclared:
            sys.stderr.write(f"  - {module} -> {', '.join(dists)}\n")
        sys.stderr.write("Declare each under [tool.pixi] pypi-dependencies so its version can be sourced.\n")
        return 1
    if not analysis.restorations:
        sys.stdout.write("runtime dependency manifest check: nothing to restore\n")
    return 0


def main(argv: list[str]) -> int:
    """Check the runtime-dependency manifest, optionally healing it.

    Args:
        argv: Command-line arguments (excluding the program name).

    Returns:
        int: ``0`` on success, ``1`` on an unresolved violation.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fix", action="store_true", help="Restore missing declarations instead of only reporting them.")
    parser.add_argument("--repo", default=None, help="Repository root (defaults to the repository that contains this script).")
    args = parser.parse_args(argv)

    repo_root = Path(cast("str", args.repo)).resolve() if args.repo else _MODULE_DIR.parent
    if bool(args.fix):
        return _run_fix(repo_root)
    return _run_report(repo_root)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
