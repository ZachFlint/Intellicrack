# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Every ``type`` alias in the package evaluates at runtime.

A ``type X = ...`` statement is evaluated lazily: importing its module succeeds even when the value names something imported only under
``TYPE_CHECKING``, and the ``NameError`` waits for the first read of ``X.__value__``. Sphinx autodoc reads it, so such an alias broke the
documentation build. These gates find every alias in ``src/intellicrack`` by parsing the source and evaluate each one as autodoc does.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
from typing import Final, TypeAliasType

import pytest


_SOURCE_ROOT: Final[Path] = Path(__file__).resolve().parents[2] / "src"
_PACKAGE_ROOT: Final[Path] = _SOURCE_ROOT / "intellicrack"


def _declared_aliases() -> list[tuple[str, str]]:
    """Find every ``type`` statement in the package.

    Returns:
        list[tuple[str, str]]: Each alias as its module's dotted name and the
        alias name, in source order.
    """
    found: list[tuple[str, str]] = []
    for path in sorted(_PACKAGE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        module = ".".join(path.relative_to(_SOURCE_ROOT).with_suffix("").parts)
        found.extend((module, node.name.id) for node in ast.walk(tree) if isinstance(node, ast.TypeAlias))
    return found


_ALIASES: Final[list[tuple[str, str]]] = _declared_aliases()


def test_the_package_declares_type_aliases() -> None:
    """The source scan finds the aliases the package is known to declare, so the gate below is not vacuous."""
    assert ("intellicrack.core.token_encoding", "AddressResolver") in _ALIASES
    assert ("intellicrack.mcp.progress", "ProgressFn") in _ALIASES


@pytest.mark.parametrize(("module_name", "alias_name"), _ALIASES, ids=[f"{module}.{alias}" for module, alias in _ALIASES])
def test_every_type_alias_evaluates(module_name: str, alias_name: str) -> None:
    """Each alias's value can be read at runtime, which is what Sphinx autodoc does.

    Args:
        module_name: The module declaring the alias.
        alias_name: The alias.
    """
    alias = getattr(importlib.import_module(module_name), alias_name)

    assert isinstance(alias, TypeAliasType)
    assert alias.__value__ is not None
