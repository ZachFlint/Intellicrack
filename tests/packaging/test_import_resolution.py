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

A name counts as resolved when the target module binds it at module level (a def, a class, an assignment, an annotated assignment, a
``type`` alias, or an import of its own), including inside ``if TYPE_CHECKING`` and ``try``/``except ImportError`` blocks, since those
bindings are importable at type-check time and at runtime respectively. A dotted name that is itself a module in the package resolves as a
submodule import.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_SRC_ROOT: Final[Path] = _REPO_ROOT / "src"
_SCANNED_ROOTS: Final[tuple[Path, ...]] = (_SRC_ROOT / "intellicrack", _REPO_ROOT / "tests")
_PACKAGE_PREFIX: Final[str] = "intellicrack"
_STAR_IMPORT: Final[str] = "*"


def _module_file(dotted: str) -> Path | None:
    """Return the file backing a dotted ``intellicrack`` module path.

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


def _bound_names(node: ast.AST) -> set[str]:
    """Collect the module-level names a statement binds.

    Args:
        node: Statement from a module body, or a statement nested in a guard block.

    Returns:
        set[str]: Names the statement makes importable from the module.
    """
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    if isinstance(node, ast.Assign):
        return {target.id for target in node.targets if isinstance(target, ast.Name)}
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return {node.target.id}
    if isinstance(node, ast.TypeAlias) and isinstance(node.name, ast.Name):
        return {node.name.id}
    if isinstance(node, ast.Import):
        return {alias.asname or alias.name.split(".")[0] for alias in node.names}
    if isinstance(node, ast.ImportFrom):
        return {alias.asname or alias.name for alias in node.names}
    return set()


def _module_exports(path: Path) -> set[str]:
    """Return every name importable from a module, by parsing it.

    Nested statements are walked as well as top-level ones, so a name bound only under ``if TYPE_CHECKING`` or inside a
    ``try``/``except ImportError`` fallback still counts.

    Args:
        path: Module file to parse.

    Returns:
        set[str]: Importable names.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    exported: set[str] = set()
    for node in tree.body:
        exported |= _bound_names(node)
        if isinstance(node, (ast.If, ast.Try)):
            for nested in ast.walk(node):
                exported |= _bound_names(nested)
    return exported


def _unresolved_imports() -> list[str]:
    """Find every ``intellicrack`` import in the repository that names something absent.

    Returns:
        list[str]: One ``<path>:<line> cannot import <name> from <module>`` description per unresolved import, empty when all resolve.
    """
    unresolved: list[str] = []
    for root in _SCANNED_ROOTS:
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom) or node.level or node.module is None:
                    continue
                if not node.module.startswith(_PACKAGE_PREFIX):
                    continue
                target = _module_file(node.module)
                if target is None:
                    continue
                exported = _module_exports(target)
                for alias in node.names:
                    if alias.name == _STAR_IMPORT or alias.name in exported:
                        continue
                    if _module_file(f"{node.module}.{alias.name}") is not None:
                        continue
                    relative = path.relative_to(_REPO_ROOT)
                    unresolved.append(f"{relative}:{node.lineno} cannot import {alias.name!r} from {node.module}")
    return unresolved


def test_every_intellicrack_import_resolves() -> None:
    """No module or test may import an ``intellicrack`` name that does not exist.

    Renaming or moving a name and missing one reader is a collection error, which costs the entire suite rather than one test. Point an
    import at a name its module does not bind and this turns red, naming the file, the line and the name.
    """
    unresolved = _unresolved_imports()

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
