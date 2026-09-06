# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the S19 GUI-audit findings in ``session_manager``.

Covers:

* D34 -- ``TagChipsWidget._add_chip`` styled every tag chip with a
  per-widget stylesheet built from Qt palette-role functions
  (``palette(mid)``, ``palette(button)``, ``palette(highlight)``). Those
  functions resolve against the widget's native ``QPalette``, which
  Intellicrack never changes -- the app's dark/light look is applied
  entirely through :class:`ThemeManager`'s QSS stylesheet swap -- so a chip
  rendered under one theme kept exactly the same colors after the app
  switched to the other. The fix drops the ``palette()`` roles for
  theme-resolved hex colors sourced from
  :meth:`ThemeManager.get_analysis_colors`, and reconnects
  :attr:`ThemeManager.theme_changed` so every already-rendered chip is
  restyled the moment the theme actually changes. The recolor gate walks
  all four concrete themes (:data:`THEME_DARK`, :data:`THEME_LIGHT`,
  :data:`THEME_DARK2`, :data:`THEME_LIGHT2`), not just the dark/light pair.
* D36 -- ``SessionManagerDialog``'s preview text widget hard-coded
  ``font-family: 'Consolas', 'Courier New', monospace;`` via
  ``setStyleSheet`` instead of using the shared :class:`FontManager`
  monospace stack. The fix calls ``setFont(FontManager.get_instance().get_code_font(9))``.

All tests drive real :class:`TagChipsWidget` / :class:`SessionManagerDialog`
instances under an offscreen ``QApplication``, with themes applied through
the real :class:`ThemeManager` singleton (backed by the actual bundled
``dark_theme.qss`` / ``light_theme.qss`` assets) rather than any stand-in.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from PyQt6.QtGui import QColor

from intellicrack.core.session import Session
from intellicrack.core.types import ProviderName
from intellicrack.ui.resources.font_manager import FALLBACK_CODE_FONTS, FontManager
from intellicrack.ui.resources.theme_manager import (
    THEME_DARK,
    THEME_DARK2,
    THEME_LIGHT,
    THEME_LIGHT2,
    ThemeManager,
)
from intellicrack.ui.session_manager import SessionManagerDialog, TagChipsWidget


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication, QPushButton


_BASE_RULE_PATTERN = re.compile(
    r"QPushButton#tagChip\s*\{([^}]*)\}",
)
_BACKGROUND_PATTERN = re.compile(r"background:\s*(#[0-9a-fA-F]{6})")
_COLOR_PATTERN = re.compile(r"(?<!background-)color:\s*(#[0-9a-fA-F]{6})")


def _build_session() -> Session:
    """Build a throw-away in-memory session with one tag.

    Returns:
        Session: A fresh ``Session`` instance carrying the ``"triage"`` tag.
    """
    session = Session.create(provider=ProviderName.OPENAI, model="gpt-4")
    session.add_tag("triage")
    return session


def _base_rule_colors(stylesheet: str) -> tuple[QColor, QColor]:
    """Extract the base (non-hover) ``background``/``color`` from a chip stylesheet.

    Args:
        stylesheet: The full ``QPushButton#tagChip { ... } ... :hover { ... }``
            stylesheet text produced for one chip.

    Returns:
        tuple[QColor, QColor]: The resolved ``(background, text)`` colors of
        the base (non-hover) rule.
    """
    base_match = _BASE_RULE_PATTERN.search(stylesheet)
    assert base_match is not None, f"expected a QPushButton#tagChip rule in stylesheet: {stylesheet!r}"
    base_rule = base_match.group(1)

    bg_match = _BACKGROUND_PATTERN.search(base_rule)
    color_match = _COLOR_PATTERN.search(base_rule)
    assert bg_match is not None, f"expected a literal '#rrggbb' background in the base tagChip rule (not a palette() role): {base_rule!r}"
    assert color_match is not None, (
        f"expected a literal '#rrggbb' text color in the base tagChip rule (not a palette() role): {base_rule!r}"
    )
    return QColor(bg_match.group(1)), QColor(color_match.group(1))


def _apply_and_get_chip_colors(
    theme_manager: ThemeManager,
    theme: str,
    chip: QPushButton,
) -> tuple[str, tuple[QColor, QColor]]:
    """Apply ``theme`` and read back the given chip's resolved stylesheet and colors.

    Args:
        theme_manager: The live ``ThemeManager`` singleton to apply the theme through.
        theme: The concrete theme name to apply (one of ``THEME_DARK``,
            ``THEME_LIGHT``, ``THEME_DARK2``, ``THEME_LIGHT2``).
        chip: The tag chip button whose ``styleSheet()`` is read back after
            the theme switch.

    Returns:
        tuple[str, tuple[QColor, QColor]]: The chip's full stylesheet text
        after the switch, paired with its resolved ``(background, text)``
        base-rule colors.
    """
    theme_manager.apply_theme(theme)
    stylesheet = chip.styleSheet()
    assert "palette(" not in stylesheet, "tag chip must be recolored via theme-resolved literal colors, not Qt palette() roles"
    return stylesheet, _base_rule_colors(stylesheet)


def test_d34_tag_chip_recolors_across_theme_switch(qapp: QApplication) -> None:
    """D34: an existing tag chip's colors must track a live theme switch across all four themes.

    Pre-fix, ``_add_chip`` styled the chip with ``palette(mid)``/
    ``palette(button)``/``palette(highlight)``, which resolve against the
    widget's static native ``QPalette`` and therefore stayed byte-identical
    regardless of which theme :class:`ThemeManager` had applied -- so this
    test fails against that code because the "before" and "after" colors
    (and the raw stylesheet text) come out equal. Post-fix, the base rule's
    background/text colors are literal theme-resolved hex values that
    differ between the dark family (:data:`THEME_DARK`, :data:`THEME_DARK2`)
    and the light family (:data:`THEME_LIGHT`, :data:`THEME_LIGHT2`), and
    the values genuinely change after switching without reconstructing the
    widget.

    ``ThemeManager.get_analysis_colors`` -- the chip's color source -- keys
    purely off :meth:`ThemeManager.is_dark_theme`, so :data:`THEME_DARK` and
    :data:`THEME_DARK2` resolve to the same literal chip colors as each
    other (and likewise :data:`THEME_LIGHT`/:data:`THEME_LIGHT2`); the QSS
    variant only changes the surrounding chrome, not this widget's own
    painted colors. The walk below therefore asserts a color change on every
    dark<->light family crossing (dark -> light, light -> dark2,
    dark2 -> light2, light2 -> dark) and asserts the *same* resolved colors
    on same-family switches (dark2 reproducing dark's colors, light2
    reproducing light's), while checking on every step that no
    ``palette(...)`` role function survives in the stylesheet.

    Args:
        qapp: Session ``QApplication`` fixture; ``ThemeManager.apply_theme``
            requires a live ``QApplication`` instance to take effect.
    """
    del qapp
    theme_manager = ThemeManager.get_instance()
    widget = TagChipsWidget(session=_build_session())
    try:
        chip = widget._chip_buttons["triage"]

        dark_result = _apply_and_get_chip_colors(theme_manager, THEME_DARK, chip)
        light_result = _apply_and_get_chip_colors(theme_manager, THEME_LIGHT, chip)
        assert light_result[0] != dark_result[0], (
            "switching the live theme must change the already-rendered chip's stylesheet without recreating it"
        )
        assert light_result[1] != dark_result[1], "chip colors must resolve differently between dark and light themes"

        dark2_result = _apply_and_get_chip_colors(theme_manager, THEME_DARK2, chip)
        assert dark2_result[0] != light_result[0], (
            "switching from light to dark2 must change the already-rendered chip's stylesheet without recreating it"
        )
        assert dark2_result[1] != light_result[1], "chip colors must resolve differently between light and dark2 themes"
        assert dark2_result == dark_result, "dark2 is a restyled dark-family variant and must resolve the same analysis colors as dark"

        light2_result = _apply_and_get_chip_colors(theme_manager, THEME_LIGHT2, chip)
        assert light2_result[0] != dark2_result[0], (
            "switching from dark2 to light2 must change the already-rendered chip's stylesheet without recreating it"
        )
        assert light2_result[1] != dark2_result[1], "chip colors must resolve differently between dark2 and light2 themes"
        assert light2_result == light_result, "light2 is a restyled light-family variant and must resolve the same analysis colors as light"

        dark_again_result = _apply_and_get_chip_colors(theme_manager, THEME_DARK, chip)
        assert dark_again_result == dark_result, (
            "switching back to dark must restore the original dark colors, proving the recolor is a durable subscription and not a one-shot"
        )
    finally:
        theme_manager.apply_theme(THEME_DARK)
        widget.deleteLater()


def test_d34_new_chip_added_after_theme_switch_matches_current_theme(qapp: QApplication) -> None:
    """D34: a chip added after a theme switch must use the new theme's colors.

    Guards against a fix that only re-styles chips existing at switch time
    (e.g. a snapshot taken once in ``__init__``) while leaving the
    per-chip color computation itself theme-blind.

    Args:
        qapp: Session ``QApplication`` fixture.
    """
    del qapp
    theme_manager = ThemeManager.get_instance()
    session = _build_session()
    widget = TagChipsWidget(session=session)
    try:
        theme_manager.apply_theme(THEME_LIGHT)

        widget._tag_input.setText("fresh")
        widget._on_add_clicked()
        fresh_chip = widget._chip_buttons["fresh"]
        fresh_bg, _fresh_fg = _base_rule_colors(fresh_chip.styleSheet())

        existing_chip = widget._chip_buttons["triage"]
        existing_bg, _existing_fg = _base_rule_colors(existing_chip.styleSheet())

        assert fresh_bg == existing_bg, "a chip created under the light theme must match an existing light-themed chip"
    finally:
        theme_manager.apply_theme(THEME_DARK)
        widget.deleteLater()


def test_d36_preview_text_font_is_fontmanager_code_font(qapp: QApplication) -> None:
    """D36: the session preview text must use FontManager's monospace stack, not a hard-coded Consolas QSS rule.

    Pre-fix, ``setStyleSheet("font-family: 'Consolas', 'Courier New', monospace; ...")``
    never called ``setFont``, so ``QTextEdit.font().family()`` reported
    whatever default UI font the widget inherited (never a code-font
    candidate), and the family was independent of ``FontManager``
    entirely. Post-fix, ``setFont(FontManager.get_instance().get_code_font(9))``
    makes the widget's actual ``QFont`` match one of FontManager's known
    monospace candidates.

    Args:
        qapp: Session ``QApplication`` fixture.
    """
    del qapp
    dialog = SessionManagerDialog()
    try:
        family = dialog._preview_text.font().family()
        assert family in FALLBACK_CODE_FONTS, (
            f"preview text font family {family!r} must be one of FontManager's code-font candidates {FALLBACK_CODE_FONTS!r}"
        )
        assert family == FontManager.get_instance().get_code_font().family(), (
            "preview text font must be sourced from FontManager.get_code_font(), not an independent literal"
        )
    finally:
        dialog.deleteLater()
