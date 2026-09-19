# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gate: every ``intellicrack`` import in the repository resolves.

A test module that imports a name its target module no longer defines is not one failing test. pytest reports it as a collection error and
stops: ``Interrupted: 1 error during collection``, no tests run at all, no coverage written. That is what happened when a name a module
merely re-exported by accident -- ``GenericCallableWorker``, imported by ``ui/log_viewer/window.py`` and read back out of it by the log
viewer's own gate -- was replaced by the dispatcher the module actually calls now. The whole 13,217-test suite collected zero.

Resolving the names by parsing rather than importing is what makes this gate cheap enough to be worth running everywhere: it needs no Qt
platform, no native extension and no provider credentials, so it catches a rename that would otherwise only surface as an aborted suite.

An import resolves when its module is a file in this source tree and the module binds the imported name in module scope: a def, a class,
an assignment, an annotated assignment, a ``type`` alias, or an import of its own. Bindings inside ``if TYPE_CHECKING`` and
``try``/``except ImportError`` blocks count, since those are importable at type-check time and at runtime respectively; bindings inside a
function or class body do not, since they belong to that scope rather than the module. A dotted name that is itself a module in the
package resolves as a submodule import.
"""

from __future__ import annotations

import ast
from functools import cache
from pathlib import Path
from typing import Final


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_SRC_ROOT: Final[Path] = _REPO_ROOT / "src"
_SCANNED_ROOTS: Final[tuple[Path, ...]] = (_SRC_ROOT / "intellicrack", _REPO_ROOT / "tests")
_PACKAGE_ROOT: Final[str] = "intellicrack"
_STAR_IMPORT: Final[str] = "*"


def _is_package_module(dotted: str) -> bool:
    """Report whether a dotted path names the ``intellicrack`` package or a module inside it.

    A plain prefix test is not enough. ``intellicrack_hexcore`` is a separate, natively built top-level package whose name also starts
    with ``intellicrack``, and its modules are compiled rather than files in this tree, so treating them as package modules would report
    every one of its imports as missing.

    Args:
        dotted: Fully qualified module name taken from an import statement.

    Returns:
        bool: ``True`` when the path is ``intellicrack`` itself or a dotted path beneath it.
    """
    return dotted == _PACKAGE_ROOT or dotted.startswith(f"{_PACKAGE_ROOT}.")


@cache
def _module_file(dotted: str) -> Path | None:
    """Return the file backing a dotted ``intellicrack`` module path.

    The result is cached: the scan asks after the same few hundred modules thousands of times, and repeating the two filesystem probes for
    each is pure overhead.

    Args:
        dotted: Fully qualified module name, such as ``intellicrack.ui.log_viewer.window``.

    Returns:
        Path | None: The module or package file, or ``None`` when the path names nothing in this source tree.
    """
    relative = Path(*dotted.split("."))
    for candidate in (_SRC_ROOT / relative.with_suffix(".py"), _SRC_ROOT / relative / "__init__.py"):
        if candidate.is_file():
            return candidate
    return None


def _describe(path: Path) -> str:
    """Return a stable, short description of a scanned file's location.

    Args:
        path: File that was scanned.

    Returns:
        str: The path relative to the repository root when it lies inside it, otherwise the path as given.
    """
    return str(path.relative_to(_REPO_ROOT)) if path.is_relative_to(_REPO_ROOT) else str(path)


def _bound_names(node: ast.AST) -> set[str]:
    """Collect the names a single statement binds.

    Args:
        node: Statement from a module body, or a statement nested in a guard block.

    Returns:
        set[str]: Names the statement binds in the scope it executes in.
    """
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    if isinstance(node, ast.Assign):
        return {target.id for target in node.targets if isinstance(target, ast.Name)}
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return {node.target.id}
    if isinstance(node, ast.TypeAlias):
        return {node.name.id}
    if isinstance(node, ast.Import):
        return {alias.asname or alias.name.split(".")[0] for alias in node.names}
    if isinstance(node, ast.ImportFrom):
        return {alias.asname or alias.name for alias in node.names}
    return set()


def _module_scope_bindings(node: ast.AST) -> set[str]:
    """Collect every name a module-level statement binds in module scope.

    Descent stops at a function or class body. Statements there bind in that scope, not the module's, so an importer naming one of them
    still fails at runtime; counting them as exports would let exactly the collection error this gate exists to catch pass unnoticed. Only
    the function's or class's own name is importable, so that is what such a node contributes. Every other nested statement list is
    descended into, which is what makes a binding under ``if TYPE_CHECKING`` or in a ``try``/``except ImportError`` fallback count.

    Args:
        node: A statement from a module body, or a node nested inside one.

    Returns:
        set[str]: Names the statement makes importable from the module.
    """
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    bound = _bound_names(node)
    for child in ast.iter_child_nodes(node):
        bound |= _module_scope_bindings(child)
    return bound


@cache
def _module_exports(path: Path) -> frozenset[str]:
    """Return every name importable from a module, by parsing it.

    The result is cached, since a module read by many importers would otherwise be parsed once per import statement: caching takes the
    repository scan from 49 seconds to 6. Returning a ``frozenset`` keeps a caller from mutating the cached value.

    Args:
        path: Module file to parse.

    Returns:
        frozenset[str]: Importable names.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    exported: set[str] = set()
    for node in tree.body:
        exported |= _module_scope_bindings(node)
    return frozenset(exported)


def _unresolved_imports(roots: tuple[Path, ...]) -> list[str]:
    """Find every ``intellicrack`` import under ``roots`` that names something absent.

    Args:
        roots: Directories scanned recursively for Python files.

    Returns:
        list[str]: One description per unresolved import, naming the file, the line and what is missing; empty when every import resolves.
    """
    unresolved: list[str] = []
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom) or node.level or node.module is None:
                    continue
                if not _is_package_module(node.module):
                    continue
                location = f"{_describe(path)}:{node.lineno}"
                target = _module_file(node.module)
                if target is None:
                    unresolved.append(f"{location} imports from {node.module}, which is not a module in this source tree")
                    continue
                exported = _module_exports(target)
                for alias in node.names:
                    if alias.name == _STAR_IMPORT or alias.name in exported:
                        continue
                    if _module_file(f"{node.module}.{alias.name}") is not None:
                        continue
                    unresolved.append(f"{location} cannot import {alias.name!r} from {node.module}")
    return unresolved


def test_every_intellicrack_import_resolves() -> None:
    """No module or test may import an ``intellicrack`` name that does not exist.

    Renaming or moving a name and missing one reader is a collection error, which costs the entire suite rather than one test. Point an
    import at a name its module does not bind and this turns red, naming the file, the line and the name.
    """
    unresolved = _unresolved_imports(_SCANNED_ROOTS)

    assert unresolved == [], "imports name symbols their modules do not provide, which aborts pytest collection:\n" + "\n".join(
        unresolved,
    )


def test_the_resolver_sees_the_names_modules_actually_export() -> None:
    """The resolver must accept the binding forms this package really uses.

    Without this, the gate above could pass by resolving nothing. Each name below is exported by a different binding form in the real
    package: a class, a function, a module-level constant, a ``type`` alias, and a name a module re-exports through its own import.
    """
    bridge = _module_file("intellicrack.ui.panels.async_bridge")
    assert bridge is not None, "the async-bridge module was not found in the source tree"
    bridge_exports = _module_exports(bridge)
    assert {"RetainedWorker", "run_callable_async", "WORKER_DEFAULT_EXCEPTIONS"} <= bridge_exports

    ast_nodes = _module_file("intellicrack.core.hexpat.ast_nodes")
    assert ast_nodes is not None, "the hexpat AST module was not found in the source tree"
    assert {"DeclNode", "StmtNode"} <= _module_exports(ast_nodes), "type aliases are not being resolved"

    window = _module_file("intellicrack.ui.log_viewer.window")
    assert window is not None, "the log viewer window module was not found in the source tree"
    assert "run_callable_async" in _module_exports(window), "a module's own imports are not being resolved"


def test_an_import_from_a_module_that_does_not_exist_is_reported(tmp_path: Path) -> None:
    """A module that was renamed, deleted or mistyped must be reported, not passed over.

    ``from intellicrack.<gone> import Name`` raises ``ModuleNotFoundError`` during collection and costs the whole suite exactly as a
    missing name does, so an unresolvable module cannot be treated as nothing left to check. The file is written outside the tree the
    other gate scans, because a broken import committed into it would abort collection instead of failing one test.

    Args:
        tmp_path: Temporary directory holding the scanned file.
    """
    reader = tmp_path / "reads_a_missing_module.py"
    reader.write_text("from intellicrack.no_such_module import Anything\n", encoding="utf-8")

    reported = _unresolved_imports((tmp_path,))

    assert len(reported) == 1, f"expected the missing module to be reported exactly once, got {reported}"
    assert "reads_a_missing_module.py:1" in reported[0], f"the report does not locate the import: {reported[0]}"
    assert "intellicrack.no_such_module" in reported[0], f"the report does not name the missing module: {reported[0]}"


def test_a_name_bound_inside_a_guarded_function_or_class_is_not_an_export(tmp_path: Path) -> None:
    """Locals of a function or class under a top-level guard must not count as importable.

    A name assigned in a function body belongs to that function and a class attribute to that class, so importing either fails at runtime.
    Collecting them as exports would make this gate accept the import it exists to reject, while the names the guard really does export
    must still be seen.

    Args:
        tmp_path: Temporary directory holding the parsed module.
    """
    guarded = tmp_path / "guarded.py"
    guarded.write_text(
        "from typing import TYPE_CHECKING\n"
        "\n"
        "if TYPE_CHECKING:\n"
        "    def helper() -> int:\n"
        "        function_local = 1\n"
        "        return function_local\n"
        "\n"
        "    class Holder:\n"
        "        class_attribute = 2\n"
        "\n"
        "try:\n"
        "    from json import dumps as guarded_export\n"
        "except ImportError:\n"
        "    guarded_export = None\n",
        encoding="utf-8",
    )

    exported = _module_exports(guarded)

    assert {"TYPE_CHECKING", "helper", "Holder", "guarded_export"} <= exported, f"module-scope bindings were missed: {sorted(exported)}"
    assert "function_local" not in exported, "a function local is being counted as a module export"
    assert "class_attribute" not in exported, "a class attribute is being counted as a module export"
