# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the S19 GUI-audit findings in ``session_manager``.

Covers:

* D34 -- tag chips must follow the application theme. They were first styled
  from Qt palette-role functions, which never change with the theme, and then
  from a per-chip stylesheet rebuilt on every theme change. They are now
  styled by the ``QPushButton#tagChip`` rules of the four theme stylesheets
  and carry no stylesheet of their own, so this gate holds them to that:
  no inline stylesheet, and the colours Qt resolves change with the theme.
  The rule-by-rule checks live in ``test_theme_qss_widgets.py``.
* D36 -- ``SessionManagerDialog``'s preview text widget hard-coded
  ``font-family: 'Consolas', 'Courier New', monospace;`` via
  ``setStyleSheet`` instead of using the shared :class:`FontManager`
  monospace stack. The fix calls ``setFont(FontManager.get_instance().get_code_font(9))``.

All tests drive real :class:`TagChipsWidget` / :class:`SessionManagerDialog`
instances under an offscreen ``QApplication``, with themes applied through
the real :class:`ThemeManager` singleton (backed by the actual bundled
theme stylesheets) rather than any stand-in.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtGui import QPalette

from intellicrack.core.session import Session
from intellicrack.providers import ids as provider_ids
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
    from PyQt6.QtGui import QColor
    from PyQt6.QtWidgets import QApplication, QPushButton


def _build_session() -> Session:
    """Build a throw-away in-memory session with one tag.

    Returns:
        Session: A fresh ``Session`` instance carrying the ``"triage"`` tag.
    """
    session = Session.create(provider=provider_ids.OPENAI, model="gpt-4")
    session.add_tag("triage")
    return session


def _apply_and_get_chip_colors(theme_manager: ThemeManager, theme: str, chip: QPushButton) -> tuple[QColor, QColor]:
    """Apply ``theme`` and read back the colours Qt resolved for an existing chip.

    Args:
        theme_manager: The live ``ThemeManager`` singleton to apply the theme through.
        theme: The concrete theme name to apply.
        chip: The tag chip button, created before the switch.

    Returns:
        tuple[QColor, QColor]: The chip's resolved ``(background, text)`` colours.
    """
    assert theme_manager.apply_theme(theme) is True
    chip.ensurePolished()
    assert not chip.styleSheet(), "a tag chip must be styled by the theme stylesheets, not by a stylesheet of its own"
    palette = chip.palette()
    return palette.color(QPalette.ColorRole.Button), palette.color(QPalette.ColorRole.ButtonText)


def test_d34_tag_chip_recolors_across_theme_switch(qapp: QApplication) -> None:
    """D34: an existing tag chip's colors must track a live theme switch across all four themes.

    The chip is created once and never rebuilt. Every dark<->light crossing
    (dark -> light, light -> dark2, dark2 -> light2, light2 -> dark) must
    change the colours Qt resolves for it, and returning to dark must
    restore the original dark colours, proving the chip is restyled by the
    application stylesheet on every switch rather than once.

    Args:
        qapp: Session ``QApplication`` fixture; ``ThemeManager.apply_theme``
            requires a live ``QApplication`` instance to take effect.
    """
    del qapp
    ThemeManager.reset_instance()
    theme_manager = ThemeManager.get_instance()
    widget = TagChipsWidget(session=_build_session())
    try:
        chip = widget._chip_buttons["triage"]

        dark_result = _apply_and_get_chip_colors(theme_manager, THEME_DARK, chip)
        light_result = _apply_and_get_chip_colors(theme_manager, THEME_LIGHT, chip)
        assert light_result != dark_result, "chip colors must resolve differently between dark and light themes"

        dark2_result = _apply_and_get_chip_colors(theme_manager, THEME_DARK2, chip)
        assert dark2_result != light_result, "chip colors must resolve differently between light and dark2 themes"

        light2_result = _apply_and_get_chip_colors(theme_manager, THEME_LIGHT2, chip)
        assert light2_result != dark2_result, "chip colors must resolve differently between dark2 and light2 themes"

        dark_again_result = _apply_and_get_chip_colors(theme_manager, THEME_DARK, chip)
        assert dark_again_result == dark_result, (
            "switching back to dark must restore the original dark colors, proving the recolor is durable and not a one-shot"
        )
    finally:
        theme_manager.apply_theme(THEME_DARK)
        widget.deleteLater()


def test_d34_new_chip_added_after_theme_switch_matches_current_theme(qapp: QApplication) -> None:
    """D34: a chip added after a theme switch must use the new theme's colors.

    Guards against chips that only pick up the theme that was active when
    the widget was constructed.

    Args:
        qapp: Session ``QApplication`` fixture.
    """
    del qapp
    ThemeManager.reset_instance()
    theme_manager = ThemeManager.get_instance()
    session = _build_session()
    widget = TagChipsWidget(session=session)
    try:
        existing_chip = widget._chip_buttons["triage"]
        existing = _apply_and_get_chip_colors(theme_manager, THEME_LIGHT, existing_chip)

        widget._tag_input.setText("fresh")
        widget._on_add_clicked()
        fresh_chip = widget._chip_buttons["fresh"]
        fresh_chip.ensurePolished()
        fresh_palette = fresh_chip.palette()
        fresh = (fresh_palette.color(QPalette.ColorRole.Button), fresh_palette.color(QPalette.ColorRole.ButtonText))

        assert fresh == existing, "a chip created under the light theme must match an existing light-themed chip"
        assert not fresh_chip.styleSheet()
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
