# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Source gates that keep the theme system the only place the UI gets colours from.

Three properties are held over the real source tree under ``src/intellicrack/ui``:

* No module other than ``theme_manager.py`` builds a colour from a literal: no ``QColor(...)`` with a constant argument, no ``#rrggbb`` /
  ``rgb(...)`` string, no named ``Qt.GlobalColor`` other than ``transparent``.
* No module styles a widget with its own ``setStyleSheet`` call; styling belongs in the four theme stylesheets.
* Every key of every :class:`ThemeManager` palette is read by the widget code that palette exists for, so a palette cannot grow entries
  nothing renders.

The few places that legitimately keep a literal are listed, with the reason, in :data:`_ALLOWED`. The allowlist is exact: an entry that no
longer matches anything fails the gate as well, so it cannot outlive the code it excuses.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.resources.theme_manager import ThemeManager


if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping


_UI_ROOT: Path = Path(__file__).resolve().parents[2] / "src" / "intellicrack" / "ui"
_THEME_MANAGER: str = "resources/theme_manager.py"
_HEX_COLOR: re.Pattern[str] = re.compile(r"#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3})(?![0-9A-Za-z_])")
_RGB_FUNCTION: re.Pattern[str] = re.compile(r"rgba?\(\s*\d[^)]*\)")
_SET_STYLE_SHEET: str = "setStyleSheet"
_TRANSPARENT: str = "transparent"

_SPLASH: str = "dialogs/splash_screen.py"
_SPLASH_FALLBACK: str = (
    "Startup fallback: the splash is shown before any theme is applied and reads the dark theme's entry first, using this literal only "
    "when the theme system hands back no valid colour."
)
_SPLASH_ARTWORK: str = "The splash paints its own always-dark artwork, which is deliberately not themed."
_ALLOWED: dict[tuple[str, str], str] = {
    (_SPLASH, "#d4d4d4"): _SPLASH_FALLBACK,
    (_SPLASH, "#007acc"): _SPLASH_FALLBACK,
    (_SPLASH, "#3e3e42"): _SPLASH_FALLBACK,
    (_SPLASH, "#888888"): _SPLASH_FALLBACK,
    (_SPLASH, "#555555"): _SPLASH_FALLBACK,
    (_SPLASH, "#cc3333"): _SPLASH_FALLBACK,
    (_SPLASH, "#1e1e1e"): _SPLASH_ARTWORK,
    (_SPLASH, "#1a1a1a"): _SPLASH_ARTWORK,
    (_SPLASH, "#121212"): _SPLASH_ARTWORK,
    (_SPLASH, "#0a0a0a"): _SPLASH_ARTWORK,
    (_SPLASH, "QColor(255, 255, 255)"): _SPLASH_ARTWORK,
    (_SPLASH, _SET_STYLE_SHEET): "The splash styles its own overlay because it is on screen before the application stylesheet exists.",
    ("panels/vnc_widget.py", "QColor(0, 0, 0)"): "Clears the remote framebuffer image; those are guest screen pixels, not UI chrome.",
}
"""Every literal the UI may keep, keyed by ``(module, literal)``, with the reason it is not a theme entry."""

_PALETTE_CONSUMERS: dict[str, tuple[str, ...]] = {
    "get_analysis_colors": ("",),
    "get_hex_editor_colors": ("panels/hex_editor_widget.py",),
    "get_chart_colors": ("panels/hex_editor/widgets.py",),
    "get_graph_colors": ("panels/graph_view.py",),
    "get_stack_colors": ("panels/stack_viewer.py",),
    "get_credential_source_colors": ("provider_config.py",),
    "get_hex_mark_colors": ("panels/hex_editor/",),
    "get_splash_colors": (_SPLASH,),
}
"""Palette accessor name mapped to the path prefixes of the modules that must read its keys (``""`` is the whole UI package).

The theme manager itself is always included, because it derives the splash palette from the dark theme's general entries.
"""


def _ui_modules() -> list[Path]:
    """List every UI source module the gates cover.

    Returns:
        list[Path]: Every ``.py`` file under the UI package except the theme manager itself.
    """
    return sorted(path for path in _UI_ROOT.rglob("*.py") if path.relative_to(_UI_ROOT).as_posix() != _THEME_MANAGER)


def _documentation_constants(tree: ast.AST) -> set[int]:
    """Collect the string constants that document rather than compute.

    Args:
        tree: Parsed module.

    Returns:
        set[int]: ``id`` of every docstring and bare string-statement constant.
    """
    return {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
    }


def _called_name(node: ast.Call) -> str:
    """Name the function or method a call invokes.

    Args:
        node: Call node.

    Returns:
        str: The bare name or the attribute name being called, or an empty string for any other callee.
    """
    callee = node.func
    if isinstance(callee, ast.Name):
        return callee.id
    if isinstance(callee, ast.Attribute):
        return callee.attr
    return ""


def _findings(path: Path) -> set[str]:
    """Find every theme bypass in one module.

    Args:
        path: UI source file to scan.

    Returns:
        set[str]: The literal text of each bypass: a colour string, the source of a ``QColor`` call with a constant argument, a named
        ``Qt.GlobalColor``, or ``"setStyleSheet"`` for an inline stylesheet call.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    documentation = _documentation_constants(tree)
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _called_name(node)
            if name == "QColor" and any(isinstance(arg, ast.Constant) and isinstance(arg.value, (int, str)) for arg in node.args):
                found.add(ast.unparse(node))
            elif name == _SET_STYLE_SHEET:
                found.add(_SET_STYLE_SHEET)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in documentation:
            found.update(match.group(0) for match in _HEX_COLOR.finditer(node.value))
            found.update(match.group(0) for match in _RGB_FUNCTION.finditer(node.value))
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "GlobalColor"
            and node.attr != _TRANSPARENT
        ):
            found.add(f"Qt.GlobalColor.{node.attr}")
    return found


def _all_findings() -> set[tuple[str, str]]:
    """Scan the whole UI package.

    Returns:
        set[tuple[str, str]]: ``(module, literal)`` for every theme bypass found.
    """
    return {(path.relative_to(_UI_ROOT).as_posix(), literal) for path in _ui_modules() for literal in _findings(path)}


def _strings_read(paths: Iterable[Path]) -> set[str]:
    """Collect every string a set of modules uses other than to name an entry it defines.

    A palette is built as a dict display, whose keys are string constants too. Those are definitions, not reads, so the keys of every dict
    display are left out; a key counts as read only where code subscripts with it or carries it as a value.

    Args:
        paths: Source files to read.

    Returns:
        set[str]: Every string constant in those files that is neither documentation nor the key of a dict display.
    """
    read: set[str] = set()
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        skipped = _documentation_constants(tree)
        skipped.update(id(key) for node in ast.walk(tree) if isinstance(node, ast.Dict) for key in node.keys if key is not None)
        read.update(
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skipped
        )
    return read


def _scanner_sample(directory: Path) -> Path:
    """Write a module that contains one of every bypass form, plus the look-alikes that must be ignored.

    Args:
        directory: Directory to write the sample into.

    Returns:
        Path: The sample module.
    """
    sample = directory / "sample.py"
    _ = sample.write_text(
        '"""Doc mentioning #123456 must be ignored."""\n'
        "from PyQt6.QtCore import Qt\n"
        "from PyQt6.QtGui import QColor\n"
        "a = QColor(1, 2, 3)\n"
        'b = QColor("#abcdef")\n'
        'c = "color: #A1B2C3; background: rgba(1, 2, 3, 0.5);"\n'
        "d = Qt.GlobalColor.red\n"
        "e = Qt.GlobalColor.transparent\n"
        "def style(widget: object, colour: QColor) -> None:\n"
        '    """Mention rgb(9, 9, 9) in a docstring."""\n'
        '    widget.setStyleSheet("")\n'
        "    f = QColor(colour)\n",
        encoding="utf-8",
    )
    return sample


def test_no_ui_module_builds_a_colour_or_stylesheet_outside_the_theme_system(tmp_path: Path) -> None:
    """Every colour literal and inline stylesheet in the UI package is either gone or explicitly justified.

    The scanner is first run over a sample holding one of each bypass form, so a clean result over the real tree means the tree is clean
    and not that the scanner is blind. The real findings must then equal the allowlist exactly: nothing unlisted, and no listed exemption
    that has stopped matching code and would otherwise sit there to excuse a future regression.

    Args:
        tmp_path: Per-test temporary directory for the scanner sample.
    """
    assert _findings(_scanner_sample(tmp_path)) == {
        "QColor(1, 2, 3)",
        "QColor('#abcdef')",
        "#abcdef",
        "#A1B2C3",
        "rgba(1, 2, 3, 0.5)",
        "Qt.GlobalColor.red",
        "setStyleSheet",
    }

    found = _all_findings()
    unexpected = sorted(found - set(_ALLOWED))
    assert unexpected == [], "theme bypasses outside the allowlist:\n" + "\n".join(
        f"  {module}: {literal}" for module, literal in unexpected
    )
    stale = sorted(set(_ALLOWED) - found)
    assert stale == [], f"allowlist entries that no longer match any code: {stale}"
    unexplained = sorted(key for key, reason in _ALLOWED.items() if not reason.strip())
    assert unexplained == [], f"allowlist entries without a justification: {unexplained}"


def _palette(accessor: str) -> Mapping[str, object]:
    """Read one palette from the theme manager.

    Args:
        accessor: Name of the ``ThemeManager`` palette accessor.

    Returns:
        Mapping[str, object]: The palette the accessor returns for the active theme.
    """
    owner: object = ThemeManager if accessor == "get_splash_colors" else ThemeManager.get_instance()
    palette: Mapping[str, object] = getattr(owner, accessor)()
    return palette


@pytest.mark.usefixtures("qapp")
@pytest.mark.parametrize("accessor", sorted(_PALETTE_CONSUMERS))
def test_every_palette_key_is_read_by_its_widgets(accessor: str) -> None:
    """A palette holds no entry that the code it serves never reads.

    Args:
        accessor: Name of the ``ThemeManager`` palette accessor under test.
    """
    prefixes = _PALETTE_CONSUMERS[accessor]
    consumers = [path for path in _ui_modules() if path.relative_to(_UI_ROOT).as_posix().startswith(prefixes)]
    assert consumers, f"no consumer modules found for {accessor}"
    read = _strings_read([*consumers, _UI_ROOT / _THEME_MANAGER])
    dead = sorted(key for key in _palette(accessor) if key not in read)
    assert dead == [], f"{accessor} defines keys nothing reads: {dead}"
