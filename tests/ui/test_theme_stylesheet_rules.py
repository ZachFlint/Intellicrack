# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the four QSS stylesheets and their embedded fallbacks.

Parses the on-disk ``dark``, ``dark2``, ``light``, and ``light2`` ``.qss``
assets and the two embedded fallback stylesheet strings in
:mod:`intellicrack.ui.resources.theme_manager` as plain text, with no Qt
runtime involved, and asserts on the concrete selector rules the S19 GUI
audit required (D29-D33, D35, D36, D04, D37). Every assertion targets a
specific rule addition, removal, or rename and fails if that fix is
reverted.
"""

from __future__ import annotations

import re
from pathlib import Path

from intellicrack.ui.resources.resource_helper import get_style_path
from intellicrack.ui.resources.theme_manager import (
    DARK_THEME_FALLBACK,
    LIGHT_THEME_FALLBACK,
)


_COMMENT_RE: re.Pattern[str] = re.compile(r"/\*.*?\*/", re.DOTALL)
_RULE_RE: re.Pattern[str] = re.compile(r"([^{}]+)\{[^{}]*\}")

_DEAD_ATTRIBUTE_SELECTORS: tuple[str, ...] = (
    'QPushButton[secondary="true"]',
    'QPushButton[danger="true"]',
    'QLabel[subheading="true"]',
    'QFrame[panelHeader="true"]',
    'QLabel[error="true"]',
    'QLabel[warning="true"]',
    'QLabel[info="true"]',
)
_DEAD_OBJECT_NAME_SELECTOR: str = "QLabel#muted_label"

_FONT_SIZE_PT_RE: re.Pattern[str] = re.compile(r"font-size\s*:\s*\d+pt\b")
_FONT_SIZE_PX_RE: re.Pattern[str] = re.compile(r"font-size\s*:\s*\d+px\b")
_FONT_FAMILY_RE: re.Pattern[str] = re.compile(r"font-family\s*:\s*([^;]+);")
_BARE_CONSOLAS_RE: re.Pattern[str] = re.compile(
    r'font-family\s*:\s*"Consolas"\s*;',
    re.IGNORECASE,
)
_EXPECTED_PT_COUNT: int = 0
_EXPECTED_PX_COUNT: int = 14

_DEAD_PROPERTY_NAMES: tuple[str, ...] = (
    "secondary",
    "danger",
    "subheading",
    "panelHeader",
    "error",
    "warning",
    "info",
)
_DEAD_SET_PROPERTY_RE: re.Pattern[str] = re.compile(
    r"""setProperty\(\s*["'](""" + "|".join(_DEAD_PROPERTY_NAMES) + r""")["']""",
)
_UI_SOURCE_ROOT: Path = Path(__file__).resolve().parents[2] / "src" / "intellicrack" / "ui"


def _extract_top_level_selectors(css_text: str) -> set[str]:
    """Extract the set of top-level selectors declared in a QSS document.

    Strips ``/* ... */`` comments, then for every ``selector { ... }`` block
    splits a comma-separated compound selector header into its individual
    selector strings so that selector-set comparisons are not thrown off by
    incidental whitespace or grouping differences between two sources.

    Args:
        css_text: Raw QSS (or QSS-like) stylesheet text.

    Returns:
        set[str]: Every individual selector text found at the top level of
        the stylesheet, whitespace-normalized.
    """
    stripped = _COMMENT_RE.sub("", css_text)
    selectors: set[str] = set()
    for match in _RULE_RE.finditer(stripped):
        header = " ".join(match.group(1).split())
        if not header:
            continue
        for raw_part in header.split(","):
            part = raw_part.strip()
            if part:
                selectors.add(part)
    return selectors


def _read_qss(theme: str) -> str:
    """Read a bundled QSS stylesheet's raw text by theme name.

    Args:
        theme: One of ``"dark"``, ``"dark2"``, ``"light"``, or ``"light2"``.

    Returns:
        str: The stylesheet's full text content.
    """
    path = get_style_path(f"{theme}_theme.qss")
    return path.read_text(encoding="utf-8")


_DARK_QSS: str = _read_qss("dark")
_DARK2_QSS: str = _read_qss("dark2")
_LIGHT_QSS: str = _read_qss("light")
_LIGHT2_QSS: str = _read_qss("light2")
_ALL_QSS_SOURCES: tuple[tuple[str, str], ...] = (
    ("dark_theme.qss", _DARK_QSS),
    ("dark2_theme.qss", _DARK2_QSS),
    ("light_theme.qss", _LIGHT_QSS),
    ("light2_theme.qss", _LIGHT2_QSS),
)
_ALL_SOURCES: tuple[tuple[str, str], ...] = (
    *_ALL_QSS_SOURCES,
    ("DARK_THEME_FALLBACK", DARK_THEME_FALLBACK),
    ("LIGHT_THEME_FALLBACK", LIGHT_THEME_FALLBACK),
)


class TestCodePreviewTextSelector:
    """D30: ``code_preview_text`` is a QTextEdit, not a QPlainTextEdit."""

    @staticmethod
    def test_qtextedit_selector_present_in_all_sources() -> None:
        """Every style source styles ``code_preview_text`` as a QTextEdit."""
        for name, text in _ALL_SOURCES:
            assert "QTextEdit#code_preview_text" in text, f"{name} is missing the QTextEdit#code_preview_text rule"

    @staticmethod
    def test_qplaintextedit_selector_absent_in_all_sources() -> None:
        """The stale QPlainTextEdit#code_preview_text selector is gone."""
        for name, text in _ALL_SOURCES:
            assert "QPlainTextEdit#code_preview_text" not in text, f"{name} still has the stale QPlainTextEdit#code_preview_text rule"


class TestUserNotesTextRule:
    """D31: the ``user_notes_text`` QTextEdit has a real themed rule."""

    @staticmethod
    def test_user_notes_text_rule_present_in_all_sources() -> None:
        """Every style source declares a QTextEdit#user_notes_text rule."""
        for name, text in _ALL_SOURCES:
            assert "QTextEdit#user_notes_text" in text, f"{name} is missing the QTextEdit#user_notes_text rule"


class TestToolButtonRule:
    """D29: 227 widgets set objectName('tool_button') with no matching rule."""

    @staticmethod
    def test_tool_button_base_rule_present_in_all_sources() -> None:
        """A real #tool_button rule exists in every style source."""
        for name, text in _ALL_SOURCES:
            assert "QPushButton#tool_button {" in text, f"{name} is missing the QPushButton#tool_button rule"

    @staticmethod
    def test_tool_button_has_hover_pressed_disabled_states() -> None:
        """The #tool_button rule covers hover, pressed, and disabled states."""
        for name, text in _ALL_SOURCES:
            assert "QPushButton#tool_button:hover" in text, f"{name} missing #tool_button:hover"
            assert "QPushButton#tool_button:pressed" in text, f"{name} missing #tool_button:pressed"
            assert "QPushButton#tool_button:disabled" in text, f"{name} missing #tool_button:disabled"

    @staticmethod
    def test_tool_button_rule_present_in_exactly_four_qss_files() -> None:
        """The #tool_button rule exists in each of the four on-disk .qss themes."""
        themes_with_rule = [name for name, text in _ALL_QSS_SOURCES if "QPushButton#tool_button {" in text]
        assert len(themes_with_rule) == 4, (
            f"expected QPushButton#tool_button in all 4 theme .qss files, found it in {len(themes_with_rule)}: {themes_with_rule}"
        )


class TestDeadSelectorsRemoved:
    """D32: dead attribute selectors and the dead #muted_label rule are gone."""

    @staticmethod
    def test_dead_attribute_selectors_absent_in_all_sources() -> None:
        """None of the unused attribute selectors remain in any source."""
        for name, text in _ALL_SOURCES:
            for selector in _DEAD_ATTRIBUTE_SELECTORS:
                assert selector not in text, f"{name} still contains dead selector {selector}"

    @staticmethod
    def test_dead_muted_label_object_name_absent_in_all_sources() -> None:
        """The dead QLabel#muted_label objectName rule is removed."""
        for name, text in _ALL_SOURCES:
            assert _DEAD_OBJECT_NAME_SELECTOR not in text, f"{name} still contains the dead {_DEAD_OBJECT_NAME_SELECTOR} rule"

    @staticmethod
    def test_muted_property_selector_still_present() -> None:
        """The live QLabel[muted='true'] property selector was NOT deleted."""
        for name, text in _ALL_SOURCES:
            assert 'QLabel[muted="true"]' in text, f"{name} lost the still-used QLabel[muted='true'] rule"

    @staticmethod
    def test_dead_properties_never_set_via_set_property_in_ui_source() -> None:
        """No widget under src/intellicrack/ui sets a dead property via setProperty().

        Reads every real ``.py`` file under the ``ui`` package source tree and
        greps for ``setProperty("secondary"|"danger"|...)`` calls. If a dead
        attribute selector's backing property is reintroduced through code
        even after being dropped from the stylesheets, this fails loudly.
        """
        offenders: list[str] = []
        for py_file in _UI_SOURCE_ROOT.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            offenders.extend(f"{py_file}: setProperty({match.group(1)!r}, ...)" for match in _DEAD_SET_PROPERTY_RE.finditer(content))
        assert not offenders, f"dead attribute-selector properties are still set via setProperty() in ui source: {offenders}"


class TestPushButtonCheckedState:
    """D04: QPushButton needs a generic :checked visual state for toggles."""

    @staticmethod
    def test_generic_checked_rule_present_in_all_sources() -> None:
        """A base QPushButton:checked rule exists (used by hex Bit Editor toggles)."""
        for name, text in _ALL_SOURCES:
            assert "QPushButton:checked {" in text, f"{name} is missing a generic QPushButton:checked rule"


class TestAttachHintOverlayRules:
    """D37: attach-hint overlay object names need themed dark AND light rules."""

    @staticmethod
    def test_overlay_and_label_rules_present_in_all_sources() -> None:
        """Both attach_hint_overlay and attach_hint_label are themed everywhere."""
        for name, text in _ALL_SOURCES:
            assert "#attach_hint_overlay {" in text, f"{name} missing #attach_hint_overlay rule"
            assert "#attach_hint_label {" in text, f"{name} missing #attach_hint_label rule"


class TestFontSizeUnitsNormalized:
    """D35: font-size units are normalized to px across all style sources."""

    @staticmethod
    def test_no_point_sized_font_declarations_remain() -> None:
        """No ``font-size: <n>pt`` declarations survive in any style source."""
        for name, text in _ALL_SOURCES:
            matches = _FONT_SIZE_PT_RE.findall(text)
            assert not matches, f"{name} still has pt-unit font-size declarations: {matches}"

    @staticmethod
    def test_zero_pt_font_size_declarations_in_each_qss_file() -> None:
        """Each of the four on-disk .qss themes has exactly 0 pt font-size rules."""
        for name, text in _ALL_QSS_SOURCES:
            pt_count = len(_FONT_SIZE_PT_RE.findall(text))
            assert pt_count == _EXPECTED_PT_COUNT, f"{name} has {pt_count} pt-unit font-size declarations, expected {_EXPECTED_PT_COUNT}"

    @staticmethod
    def test_px_font_size_declaration_count_in_each_qss_file() -> None:
        """Each of the four on-disk .qss themes carries the same px font-size count.

        Pins the count to the value the D35 normalization produced (14 px
        declarations per theme file) so a future partial revert that drops
        some but not all px declarations, or that reintroduces pt units
        without removing the equivalent px rule, is still caught.
        """
        for name, text in _ALL_QSS_SOURCES:
            px_count = len(_FONT_SIZE_PX_RE.findall(text))
            assert px_count == _EXPECTED_PX_COUNT, f"{name} has {px_count} px-unit font-size declarations, expected {_EXPECTED_PX_COUNT}"


class TestMonospaceFontFallback:
    """D36: every monospace font-family declaration carries a fallback stack."""

    @staticmethod
    def test_consolas_declarations_include_generic_monospace_fallback() -> None:
        """Any font-family referencing Consolas also lists the monospace fallback."""
        for name, text in _ALL_QSS_SOURCES:
            for declaration in _FONT_FAMILY_RE.findall(text):
                if "consolas" not in declaration.lower():
                    continue
                assert "monospace" in declaration.lower(), (
                    f"{name} has a Consolas font-family with no monospace fallback: font-family:{declaration};"
                )

    @staticmethod
    def test_no_bare_consolas_only_font_family_declaration() -> None:
        """No font-family declaration hardcodes a bare, fallback-less Consolas."""
        for name, text in _ALL_QSS_SOURCES:
            matches = _BARE_CONSOLAS_RE.findall(text)
            assert not matches, f"{name} has a bare Consolas-only font-family with no fallback stack"


class TestFallbackSelectorSetMatchesQss:
    """D33: the embedded fallback selector-set equals the .qss selector-set."""

    @staticmethod
    def test_dark_fallback_selectors_equal_dark_qss_selectors() -> None:
        """DARK_THEME_FALLBACK declares exactly the selectors dark_theme.qss does."""
        qss_selectors = _extract_top_level_selectors(_DARK_QSS)
        fallback_selectors = _extract_top_level_selectors(DARK_THEME_FALLBACK)
        missing_from_fallback = qss_selectors - fallback_selectors
        missing_from_qss = fallback_selectors - qss_selectors
        assert not missing_from_fallback, (
            f"DARK_THEME_FALLBACK is missing selectors present in dark_theme.qss: {sorted(missing_from_fallback)}"
        )
        assert not missing_from_qss, f"dark_theme.qss is missing selectors present in DARK_THEME_FALLBACK: {sorted(missing_from_qss)}"

    @staticmethod
    def test_light_fallback_selectors_equal_light_qss_selectors() -> None:
        """LIGHT_THEME_FALLBACK declares exactly the selectors light_theme.qss does."""
        qss_selectors = _extract_top_level_selectors(_LIGHT_QSS)
        fallback_selectors = _extract_top_level_selectors(LIGHT_THEME_FALLBACK)
        missing_from_fallback = qss_selectors - fallback_selectors
        missing_from_qss = fallback_selectors - qss_selectors
        assert not missing_from_fallback, (
            f"LIGHT_THEME_FALLBACK is missing selectors present in light_theme.qss: {sorted(missing_from_fallback)}"
        )
        assert not missing_from_qss, f"light_theme.qss is missing selectors present in LIGHT_THEME_FALLBACK: {sorted(missing_from_qss)}"

    @staticmethod
    def test_close_button_selector_present_in_qss_files() -> None:
        """QTabBar::close-button, previously fallback-only, now lives in the .qss too."""
        assert "QTabBar::close-button" in _DARK_QSS
        assert "QTabBar::close-button" in _LIGHT_QSS

    @staticmethod
    def test_chat_surface_selectors_present_in_fallbacks() -> None:
        """The chat surface selectors, previously qss-only, now live in the fallbacks too."""
        for selector in (
            "QFrame#chat_panel",
            "QFrame#chat_header",
            "QFrame#chat_input_bar",
            "QPushButton#chat_send_button",
        ):
            assert selector in DARK_THEME_FALLBACK, f"DARK_THEME_FALLBACK missing {selector}"
            assert selector in LIGHT_THEME_FALLBACK, f"LIGHT_THEME_FALLBACK missing {selector}"
