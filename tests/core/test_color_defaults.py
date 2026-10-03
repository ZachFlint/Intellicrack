# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the Qt-free colour defaults the non-UI layers share with the theme system.

The hex-editor bridge and the HexPat evaluator must not import Qt or the UI package, yet both hand colours to their callers. Their defaults
live in :mod:`intellicrack.core.color_defaults`; these gates hold that module to being importable without Qt, hold the two consumers to
carrying no colour literal of their own, and pin the values, because tool schemas, bridge responses and saved bookmarks all carry them.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from intellicrack.core import color_defaults
from intellicrack.core.hexpat.evaluator import HexPatEvaluator


_SRC_ROOT: Path = Path(__file__).resolve().parents[2] / "src"
_HEX_COLOR: re.Pattern[str] = re.compile(r"#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6})(?![0-9A-Za-z_])")
_STRICT_HEX_COLOR: re.Pattern[str] = re.compile(r"#[0-9a-fA-F]{6}")
_CONSUMERS: tuple[str, ...] = (
    "intellicrack/bridges/hex_editor.py",
    "intellicrack/core/hexpat/evaluator.py",
)
_CONTRACT_VALUES: dict[str, str | tuple[str, ...]] = {
    "DEFAULT_BOOKMARK_COLOR": "#FFFF00",
    "DEFAULT_HIGHLIGHT_COLOR": "#FFFF00",
    "STRUCTURE_HEADER_COLOR": "#FF6B6B",
    "STRUCTURE_TABLE_COLOR": "#4ECDC4",
    "STRUCTURE_SECTION_COLOR": "#45B7D1",
    "STRUCTURE_SECTION_ALT_COLOR": "#96CEB4",
    "STRUCTURE_COLORS": ("#FF6B6B", "#4ECDC4", "#45B7D1"),
    "PE_STRUCTURE_COLORS": ("#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4"),
    "SECTION_CYCLE_COLORS": ("#45B7D1", "#96CEB4", "#FFEAA7", "#DDA0DD", "#98D8C8"),
    "UNSAFE_COLOR_FALLBACK": "#888888",
    "HTML_EXPORT_BACKGROUND": "#1e1e2e",
    "HTML_EXPORT_TEXT": "#cdd6f4",
    "HTML_EXPORT_OFFSET": "#89b4fa",
    "HTML_EXPORT_ASCII": "#a6e3a1",
    "HEXPAT_FIELD_COLORS": (
        "#E06C75",
        "#61AFEF",
        "#98C379",
        "#E5C07B",
        "#C678DD",
        "#56B6C2",
        "#BE5046",
        "#D19A66",
        "#7EC8E3",
        "#C3E88D",
    ),
}


def _docstring_constants(tree: ast.AST) -> set[int]:
    """Collect the string constants that are docstrings or bare string statements.

    Args:
        tree: Parsed module.

    Returns:
        set[int]: ``id`` of every constant node that documents rather than computes.
    """
    return {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
    }


def _color_literals(path: Path) -> list[tuple[int, str]]:
    """Find every colour literal a module computes with.

    Args:
        path: Python source file to scan.

    Returns:
        list[tuple[int, str]]: Line number and colour text of each ``#RRGGBB`` / ``#RRGGBBAA`` string constant outside docstrings.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    documentation = _docstring_constants(tree)
    return [
        (node.lineno, found.group(0))
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in documentation
        for found in _HEX_COLOR.finditer(node.value)
    ]


def test_module_imports_nothing_beyond_the_standard_library() -> None:
    """The defaults module must stay importable by layers that may not import Qt or the UI."""
    source = (_SRC_ROOT / "intellicrack" / "core" / "color_defaults.py").read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported <= {"__future__", "typing"}, f"color_defaults imports {sorted(imported)}"


@pytest.mark.parametrize("consumer", _CONSUMERS)
def test_non_ui_consumers_carry_no_colour_literal(consumer: str) -> None:
    """The bridge and the evaluator take every colour from the shared defaults module.

    Args:
        consumer: Source path of the consumer, relative to ``src``.
    """
    literals = _color_literals(_SRC_ROOT / consumer)
    assert literals == [], f"{consumer} still hard-codes colours: {literals}"


@pytest.mark.parametrize(("name", "expected"), sorted(_CONTRACT_VALUES.items()))
def test_contract_values_are_unchanged(name: str, expected: str | tuple[str, ...]) -> None:
    """Centralising the defaults must not change what tools, responses and saved bookmarks carry.

    Args:
        name: Constant name in the defaults module.
        expected: The value the bridge or evaluator used before the defaults were centralised.
    """
    assert getattr(color_defaults, name) == expected


def test_every_default_is_a_plain_hex_colour() -> None:
    """Every exported default is a ``#RRGGBB`` string, the only form the HTML exporter accepts unescaped."""
    for name in _CONTRACT_VALUES:
        value = getattr(color_defaults, name)
        colours = (value,) if isinstance(value, str) else value
        for colour in colours:
            assert _STRICT_HEX_COLOR.fullmatch(colour), f"{name} holds {colour!r}"


def test_evaluator_field_rotation_is_the_shared_palette() -> None:
    """The evaluator's field rotation is the shared constant, not a copy of it."""
    assert HexPatEvaluator.FIELD_COLORS is color_defaults.HEXPAT_FIELD_COLORS
