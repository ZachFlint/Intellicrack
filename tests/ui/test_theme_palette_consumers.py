# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates that every painted view takes its colours from the ThemeManager palette of the active theme id.

The hex editor, its charts, the control-flow graph, the call-stack table, the credential indicators and the hex-mark defaults used to hold
private dark/light tables keyed off ``is_dark_theme()``, so ``dark2`` could never differ from ``dark``. These gates build the real widgets,
apply themes through the real :class:`ThemeManager`, and read back what the widgets resolved. The decisive check gives ``dark2`` a palette
entry of its own and requires the widget to show it under ``dark2`` only: a widget that still reads a private table, or a family-wide one,
cannot pass.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

import intellicrack_hexcore
import pytest
from mcp_types import ElicitRequestFormParams
from PyQt6.QtGui import QColor, QTextDocument
from PyQt6.QtWidgets import QApplication, QColorDialog, QInputDialog, QLabel, QWidget

from intellicrack.mcp.consent import DangerousPattern
from intellicrack.ui.dialogs import splash_screen
from intellicrack.ui.mcp_consent_dialog import _DangerousPatternHighlighter
from intellicrack.ui.mcp_elicitation_dialog import McpElicitationDialog
from intellicrack.ui.panels.graph_view import BasicBlockItem, CFGGraphView
from intellicrack.ui.panels.hex_editor import highlighting, pattern_editor, search, templates, yara
from intellicrack.ui.panels.hex_editor.bookmarks import BookmarksMixin
from intellicrack.ui.panels.hex_editor.widgets import ByteDistributionWidget, EntropyGraphWidget
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget
from intellicrack.ui.panels.stack_viewer import StackFrame, StackFrameTable
from intellicrack.ui.provider_config import CredentialSource, CredentialSourceDetector
from intellicrack.ui.resources import theme_manager as theme_manager_module
from intellicrack.ui.resources.theme_manager import (
    THEME_DARK,
    THEME_DARK2,
    THEME_LIGHT,
    THEME_LIGHT2,
    ChartColors,
    CredentialSourceColors,
    GraphColors,
    HexEditorColors,
    HexMarkColors,
    SplashColors,
    StackColors,
    ThemeManager,
)


if TYPE_CHECKING:
    from collections.abc import Callable


_THEMES: tuple[str, ...] = (THEME_DARK, THEME_LIGHT, THEME_DARK2, THEME_LIGHT2)
_BASE_OF: dict[str, str] = {THEME_DARK2: THEME_DARK, THEME_LIGHT2: THEME_LIGHT}
_SENTINEL: QColor = QColor(1, 2, 3)
_SENTINEL_MARK: str = "#010203"
_FLAG_ALPHA: int = 96
_VERSION_ALPHA: int = 153
_CHART_WIDTH: int = 240
_CHART_HEIGHT: int = 140
_BOOKMARK_DOCUMENT_SIZE: int = 16
_REMOVED_ANALYSIS_KEYS: tuple[str, ...] = (
    "selection",
    "entropy_low",
    "entropy_mid",
    "entropy_high",
    "graph_edge",
    "graph_node_bg",
    "graph_node_border",
    "hex_zero",
    "hex_printable",
    "hex_nonprintable",
    "hex_modified",
    "offset_text",
    "separator",
    "minimap_bg",
    "minimap_indicator",
    "mnemonic_nop",
    "info",
    "surface",
)
_REMOVED_STACK_KEYS: tuple[str, ...] = ("muted", "error", "connected")


@pytest.fixture
def manager(qapp: QApplication) -> ThemeManager:
    """Provide a fresh theme manager with the dark theme applied.

    Args:
        qapp: The session ``QApplication``.

    Returns:
        ThemeManager: The singleton, rebuilt so widgets created by the test subscribe to this instance.
    """
    del qapp
    ThemeManager.reset_instance()
    fresh = ThemeManager.get_instance()
    assert fresh.apply_theme(THEME_DARK) is True
    return fresh


@pytest.fixture(params=_THEMES)
def theme(request: pytest.FixtureRequest) -> str:
    """Parametrize a test over every shipped theme id.

    Args:
        request: Pytest fixture request carrying the theme id.

    Returns:
        str: The theme id to apply.
    """
    return str(request.param)


def _frame() -> StackFrame:
    """Build one resolved stack frame.

    Returns:
        StackFrame: A frame with every column populated.
    """
    return StackFrame(
        index=0,
        return_address=0x7FFE0000,
        function_name="CreateFileW",
        module_name="kernel32.dll",
        offset=0x10,
        frame_pointer=0x2000,
        stack_pointer=0x3000,
    )


def _corner(widget: QWidget) -> QColor:
    """Render a widget and read the pixel in its top-left corner.

    Args:
        widget: The widget to render.

    Returns:
        QColor: The colour the widget painted at ``(0, 0)``.
    """
    widget.resize(_CHART_WIDTH, _CHART_HEIGHT)
    return widget.grab().toImage().pixelColor(0, 0)


class _BookmarkHost(BookmarksMixin, QWidget):
    """The real bookmarks mixin on a bare widget, with a real document and nothing else attached."""

    def __init__(self) -> None:
        """Open a small in-memory document for the mixin to bookmark."""
        super().__init__()
        self.document = intellicrack_hexcore.HexDocument.open_bytes(bytes(_BOOKMARK_DOCUMENT_SIZE))
        self._document = self.document
        self._hex_widget = None
        self._bookmarks_tree = None
        self.state_holder = None
        self.file_path = None


def _item_color(table: StackFrameTable, column: int) -> QColor:
    """Read the text colour of one cell of the first stack row.

    Args:
        table: The stack table.
        column: Column index.

    Returns:
        QColor: The cell's foreground colour.
    """
    item = table.item(0, column)
    assert item is not None, f"stack table has no item in column {column}"
    return item.foreground().color()


class TestPaletteRegistry:
    """ThemeManager holds one palette per theme id, and the restyled themes start as copies."""

    @staticmethod
    def test_every_shipped_theme_has_a_palette_entry_of_its_own() -> None:
        """``dark2`` and ``light2`` are separate registry entries, not aliases of ``dark`` and ``light``."""
        palettes = theme_manager_module._THEME_PALETTES
        assert set(palettes) == set(_THEMES)
        assert len({id(palette) for palette in palettes.values()}) == len(_THEMES)

    @staticmethod
    @pytest.mark.parametrize("restyled", sorted(_BASE_OF))
    def test_restyled_theme_initially_copies_its_base(manager: ThemeManager, restyled: str) -> None:
        """Until a restyled theme is given colours of its own, every palette equals its base theme's.

        Args:
            manager: Fresh theme manager.
            restyled: ``dark2`` or ``light2``.
        """
        base = _BASE_OF[restyled]
        assert manager.get_analysis_colors(restyled) == manager.get_analysis_colors(base)
        assert manager.get_hex_editor_colors(restyled) == manager.get_hex_editor_colors(base)
        assert manager.get_chart_colors(restyled) == manager.get_chart_colors(base)
        assert manager.get_graph_colors(restyled) == manager.get_graph_colors(base)
        assert manager.get_stack_colors(restyled) == manager.get_stack_colors(base)
        assert manager.get_credential_source_colors(restyled) == manager.get_credential_source_colors(base)
        assert manager.get_hex_mark_colors(restyled) == manager.get_hex_mark_colors(base)

    @staticmethod
    def test_accessors_default_to_the_theme_being_rendered(manager: ThemeManager, theme: str) -> None:
        """With no argument an accessor returns the palette of the applied theme.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to apply.
        """
        assert manager.apply_theme(theme) is True
        assert manager.get_hex_editor_colors() == manager.get_hex_editor_colors(theme)
        assert manager.get_graph_colors() == manager.get_graph_colors(theme)
        assert manager.get_hex_mark_colors() == manager.get_hex_mark_colors(theme)

    @staticmethod
    def test_palettes_hand_out_fresh_colours(manager: ThemeManager) -> None:
        """A caller that adjusts a colour it was given must not change the palette for everyone else.

        Args:
            manager: Fresh theme manager.
        """
        first = manager.get_hex_editor_colors()
        first["editor_bg"].setAlpha(7)
        assert manager.get_hex_editor_colors()["editor_bg"].alpha() != first["editor_bg"].alpha()

    @staticmethod
    def test_dead_analysis_keys_are_gone(manager: ThemeManager, theme: str) -> None:
        """The analysis palette no longer carries keys that duplicated, with other values, what widgets really paint.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to read.
        """
        analysis = manager.get_analysis_colors(theme)
        assert [key for key in _REMOVED_ANALYSIS_KEYS if key in analysis] == []
        stack: dict[str, QColor] = dict(manager.get_stack_colors(theme))
        assert [key for key in _REMOVED_STACK_KEYS if key in stack] == []


class TestWidgetsShowThePaletteOfTheActiveThemeId:
    """Each painted view resolves the ThemeManager entry of the theme id that is active, and follows a live switch."""

    @staticmethod
    def test_hex_editor_and_minimap(manager: ThemeManager, theme: str) -> None:
        """The hex grid and its minimap cache exactly the active theme's hex editor palette.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to switch to after the widget exists.
        """
        widget = HexEditorWidget()
        try:
            assert manager.apply_theme(theme) is True
            expected = manager.get_hex_editor_colors(theme)
            assert widget._colors == expected
            assert widget._minimap._colors == expected
        finally:
            widget.deleteLater()

    @staticmethod
    def test_charts(manager: ThemeManager, theme: str) -> None:
        """The entropy graph and the byte histogram paint the active theme's chart background.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to switch to after the widgets exist.
        """
        entropy = EntropyGraphWidget()
        histogram = ByteDistributionWidget()
        try:
            assert manager.apply_theme(theme) is True
            expected = manager.get_chart_colors(theme)["bg"]
            assert _corner(entropy) == expected
            assert _corner(histogram) == expected
        finally:
            entropy.deleteLater()
            histogram.deleteLater()

    @staticmethod
    def test_control_flow_graph(manager: ThemeManager, theme: str) -> None:
        """The graph canvas and an existing basic block take the active theme's graph colours.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to switch to after the view exists.
        """
        view = CFGGraphView()
        block = BasicBlockItem(0x1000, [{"disasm": "ret"}])
        scene = view.scene()
        assert scene is not None
        scene.addItem(block)
        try:
            assert manager.apply_theme(theme) is True
            expected = manager.get_graph_colors(theme)
            assert view.backgroundBrush().color() == expected["background"]
            assert block.brush().color() == expected["block_bg"]
            assert block.pen().color() == expected["block_border"]
        finally:
            view.deleteLater()

    @staticmethod
    def test_stack_table(manager: ThemeManager, theme: str) -> None:
        """Rows already in the stack table are recoloured from the active theme's stack palette.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to switch to after the rows exist.
        """
        table = StackFrameTable()
        try:
            table.set_frames([_frame()])
            assert manager.apply_theme(theme) is True
            expected = manager.get_stack_colors(theme)
            assert _item_color(table, 0) == expected["index_highlight"]
            assert _item_color(table, 1) == expected["address"]
            assert _item_color(table, 2) == expected["function_known"]
            assert _item_color(table, 3) == expected["module"]
            assert _item_color(table, 4) == expected["offset"]
            assert _item_color(table, 5) == expected["pointer"]
        finally:
            table.deleteLater()

    @staticmethod
    def test_credential_source_colours(manager: ThemeManager, theme: str) -> None:
        """The credential indicators resolve the active theme's credential-source palette.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to apply.
        """
        assert manager.apply_theme(theme) is True
        expected = manager.get_credential_source_colors(theme)
        assert CredentialSourceDetector.get_source_color(CredentialSource.ENV_FILE) == expected["env_file"]
        assert CredentialSourceDetector.get_source_color(CredentialSource.ENVIRONMENT) == expected["environment"]
        assert CredentialSourceDetector.get_source_color(CredentialSource.MANUAL) == expected["manual"]
        assert CredentialSourceDetector.get_source_color(CredentialSource.NOT_CONFIGURED) == expected["not_configured"]
        assert CredentialSourceDetector.get_source_color("a source nobody defined") == expected["default"]

    @staticmethod
    def test_hex_mark_defaults(manager: ThemeManager, theme: str) -> None:
        """Every default the hex editor gives a new mark is the active theme's hex-mark entry.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to apply.
        """
        assert manager.apply_theme(theme) is True
        expected = manager.get_hex_mark_colors(theme)
        assert search._get_highlight_color() == expected["search_match"]
        assert yara._get_yara_match_color() == expected["yara_match"]
        assert pattern_editor._get_default_pattern_field_color() == expected["pattern_field"]
        assert templates._get_default_template_color() == expected["template_field"]
        assert highlighting._get_default_highlight_color() == expected["highlight_rule"]
        assert templates._get_structure_colors() == expected


class TestRestyledThemeCanCarryItsOwnPaintedColours:
    """Giving ``dark2`` its own palette entry changes what the widgets show under ``dark2`` and nowhere else."""

    @staticmethod
    def _install(monkeypatch: pytest.MonkeyPatch, **fields: Callable[[], object]) -> None:
        """Replace fields of the ``dark2`` palette entry for one test.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
            **fields: Palette field names mapped to the factory ``dark2`` should use instead.
        """
        palettes = theme_manager_module._THEME_PALETTES
        monkeypatch.setitem(palettes, THEME_DARK2, replace(palettes[THEME_DARK2], **fields))

    def test_hex_editor(self, manager: ThemeManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """A live hex editor shows ``dark2``'s own grid background under ``dark2`` and ``dark``'s under ``dark``.

        Args:
            manager: Fresh theme manager.
            monkeypatch: Pytest monkeypatch fixture.
        """
        base = manager.get_hex_editor_colors(THEME_DARK)

        def restyled() -> HexEditorColors:
            """Build the dark hex editor palette with a distinct grid background.

            Returns:
                HexEditorColors: The dark palette with ``editor_bg`` replaced.
            """
            colors = manager.get_hex_editor_colors(THEME_DARK)
            colors["editor_bg"] = QColor(_SENTINEL)
            return colors

        self._install(monkeypatch, hex_editor=restyled)
        widget = HexEditorWidget()
        try:
            assert widget._colors["editor_bg"] == base["editor_bg"]
            assert manager.apply_theme(THEME_DARK2) is True
            assert widget._colors["editor_bg"] == _SENTINEL
            assert widget._minimap._colors["editor_bg"] == _SENTINEL
            assert manager.apply_theme(THEME_DARK) is True
            assert widget._colors["editor_bg"] == base["editor_bg"]
        finally:
            widget.deleteLater()

    def test_charts(self, manager: ThemeManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """The entropy graph paints ``dark2``'s own chart background under ``dark2`` only.

        Args:
            manager: Fresh theme manager.
            monkeypatch: Pytest monkeypatch fixture.
        """
        base = manager.get_chart_colors(THEME_DARK)["bg"]

        def restyled() -> ChartColors:
            """Build the dark chart palette with a distinct background.

            Returns:
                ChartColors: The dark palette with ``bg`` replaced.
            """
            colors = manager.get_chart_colors(THEME_DARK)
            colors["bg"] = QColor(_SENTINEL)
            return colors

        self._install(monkeypatch, charts=restyled)
        entropy = EntropyGraphWidget()
        try:
            assert _corner(entropy) == base
            assert manager.apply_theme(THEME_DARK2) is True
            assert _corner(entropy) == _SENTINEL
            assert manager.apply_theme(THEME_DARK) is True
            assert _corner(entropy) == base
        finally:
            entropy.deleteLater()

    def test_control_flow_graph(self, manager: ThemeManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """A live graph view shows ``dark2``'s own canvas colour under ``dark2`` only.

        Args:
            manager: Fresh theme manager.
            monkeypatch: Pytest monkeypatch fixture.
        """
        base = manager.get_graph_colors(THEME_DARK)["background"]

        def restyled() -> GraphColors:
            """Build the dark graph palette with a distinct canvas colour.

            Returns:
                GraphColors: The dark palette with ``background`` replaced.
            """
            colors = manager.get_graph_colors(THEME_DARK)
            colors["background"] = QColor(_SENTINEL)
            return colors

        self._install(monkeypatch, graph=restyled)
        view = CFGGraphView()
        try:
            assert view.backgroundBrush().color() == base
            assert manager.apply_theme(THEME_DARK2) is True
            assert view.backgroundBrush().color() == _SENTINEL
            assert manager.apply_theme(THEME_DARK) is True
            assert view.backgroundBrush().color() == base
        finally:
            view.deleteLater()

    def test_stack_table(self, manager: ThemeManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Existing stack rows take ``dark2``'s own address colour under ``dark2`` only.

        Args:
            manager: Fresh theme manager.
            monkeypatch: Pytest monkeypatch fixture.
        """
        base = manager.get_stack_colors(THEME_DARK)["address"]

        def restyled() -> StackColors:
            """Build the dark stack palette with a distinct address colour.

            Returns:
                StackColors: The dark palette with ``address`` replaced.
            """
            colors = manager.get_stack_colors(THEME_DARK)
            colors["address"] = QColor(_SENTINEL)
            return colors

        self._install(monkeypatch, stack=restyled)
        table = StackFrameTable()
        try:
            table.set_frames([_frame()])
            assert _item_color(table, 1) == base
            assert manager.apply_theme(THEME_DARK2) is True
            assert _item_color(table, 1) == _SENTINEL
            assert manager.apply_theme(THEME_DARK) is True
            assert _item_color(table, 1) == base
        finally:
            table.deleteLater()

    def test_credential_sources(self, manager: ThemeManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """The credential indicator colour follows ``dark2``'s own entry under ``dark2`` only.

        Args:
            manager: Fresh theme manager.
            monkeypatch: Pytest monkeypatch fixture.
        """
        base = manager.get_credential_source_colors(THEME_DARK)["manual"]

        def restyled() -> CredentialSourceColors:
            """Build the dark credential-source palette with a distinct manual-entry colour.

            Returns:
                CredentialSourceColors: The dark palette with ``manual`` replaced.
            """
            colors = manager.get_credential_source_colors(THEME_DARK)
            colors["manual"] = QColor(_SENTINEL)
            return colors

        self._install(monkeypatch, credential_sources=restyled)
        assert CredentialSourceDetector.get_source_color(CredentialSource.MANUAL) == base
        assert manager.apply_theme(THEME_DARK2) is True
        assert CredentialSourceDetector.get_source_color(CredentialSource.MANUAL) == _SENTINEL
        assert manager.apply_theme(THEME_DARK) is True
        assert CredentialSourceDetector.get_source_color(CredentialSource.MANUAL) == base

    def test_hex_marks(self, manager: ThemeManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """New search highlights and bookmarks start from ``dark2``'s own entries under ``dark2`` only.

        Args:
            manager: Fresh theme manager.
            monkeypatch: Pytest monkeypatch fixture.
        """
        base = manager.get_hex_mark_colors(THEME_DARK)

        def restyled() -> HexMarkColors:
            """Build the dark hex-mark palette with distinct search and bookmark colours.

            Returns:
                HexMarkColors: The dark palette with ``search_match`` and ``bookmark`` replaced.
            """
            colors = manager.get_hex_mark_colors(THEME_DARK)
            colors["search_match"] = _SENTINEL_MARK
            colors["bookmark"] = _SENTINEL_MARK
            return colors

        self._install(monkeypatch, hex_marks=restyled)
        assert search._get_highlight_color() == base["search_match"]
        assert manager.apply_theme(THEME_DARK2) is True
        assert search._get_highlight_color() == _SENTINEL_MARK
        assert manager.get_hex_mark_colors()["bookmark"] == _SENTINEL_MARK
        assert manager.apply_theme(THEME_DARK) is True
        assert search._get_highlight_color() == base["search_match"]


class TestBookmarkDialogStartsFromTheThemeEntry:
    """The colour picker for a new bookmark opens on the theme's bookmark entry, never on a literal."""

    @staticmethod
    def test_picker_is_offered_the_theme_bookmark_colour(
        manager: ThemeManager,
        theme: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Adding a bookmark hands the colour picker the active theme's bookmark colour as its starting point.

        The picker is replaced by a recorder that declines, so no modal dialog opens and no bookmark is written.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to apply.
            monkeypatch: Pytest monkeypatch fixture.
        """
        assert manager.apply_theme(theme) is True
        offered: list[QColor] = []

        def decline(initial: QColor, *_args: object, **_kwargs: object) -> QColor:
            """Record the colour the picker would open on, then act as if the user cancelled.

            Args:
                initial: The colour passed as the picker's starting point.
                *_args: Remaining positional arguments of ``QColorDialog.getColor``.
                **_kwargs: Keyword arguments of ``QColorDialog.getColor``.

            Returns:
                QColor: An invalid colour, which is what a cancelled picker returns.
            """
            offered.append(QColor(initial))
            return QColor()

        def name_it(*_args: object, **_kwargs: object) -> tuple[str, bool]:
            """Answer the bookmark-name prompt.

            Args:
                *_args: Positional arguments of ``QInputDialog.getText``.
                **_kwargs: Keyword arguments of ``QInputDialog.getText``.

            Returns:
                tuple[str, bool]: A name and an accepted flag.
            """
            return "mark", True

        monkeypatch.setattr(QColorDialog, "getColor", staticmethod(decline))
        monkeypatch.setattr(QInputDialog, "getText", staticmethod(name_it))

        host = _BookmarkHost()
        try:
            host._on_add_bookmark()
            assert offered == [QColor(manager.get_hex_mark_colors(theme)["bookmark"])]
            assert host.document.get_bookmarks() == [], "a cancelled colour picker must not create a bookmark"
        finally:
            host.deleteLater()


class TestConsentFlagFollowsTheThemeWarning:
    """Flagged command fragments are washed in the theme's warning colour instead of a fixed amber."""

    @staticmethod
    def test_flag_wash_tracks_live_theme_switches(manager: ThemeManager) -> None:
        """The highlighter's wash is the active theme's warning colour at reduced opacity, before and after a switch.

        Args:
            manager: Fresh theme manager.
        """
        document = QTextDocument("powershell -enc AAAA")
        pattern = DangerousPattern(token="-enc", reason="encoded command")
        highlighter = _DangerousPatternHighlighter(document, [pattern])
        seen: set[tuple[int, int, int, int]] = set()
        for theme_id in _THEMES:
            assert manager.apply_theme(theme_id) is True
            expected = QColor(manager.get_analysis_colors(theme_id)["warning"])
            expected.setAlpha(_FLAG_ALPHA)
            assert highlighter.flag_background() == expected
            rgba = highlighter.flag_background().getRgb()
            seen.add((rgba[0], rgba[1], rgba[2], rgba[3]))
        assert len(seen) > 1, "the wash never changed across the dark and light themes"


class TestSplashReadsTheDarkThemeEntries:
    """The splash takes its colours from the dark theme's entries, whatever theme is active, with its literals as the fallback."""

    @staticmethod
    def test_splash_colours_are_the_dark_theme_entries_under_every_theme(manager: ThemeManager, theme: str) -> None:
        """The splash palette equals the dark theme's entries and does not move when another theme is applied.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to apply.
        """
        assert manager.apply_theme(theme) is True
        dark = manager.get_analysis_colors(THEME_DARK)
        version_text = QColor(dark["foreground"])
        version_text.setAlpha(_VERSION_ALPHA)
        resolved = splash_screen._splash_colors()
        assert resolved == ThemeManager.get_splash_colors()
        assert resolved["accent"] == dark["accent"]
        assert resolved["glow"] == dark["accent"]
        assert resolved["text"] == dark["foreground"]
        assert resolved["subtitle"] == dark["muted"]
        assert resolved["track"] == dark["border"]
        assert resolved["version_text"] == version_text

    @staticmethod
    def test_dark_theme_entries_reproduce_the_splash_literals() -> None:
        """Reading the dark theme's entries leaves the splash looking exactly as its own literals made it."""
        assert ThemeManager.get_splash_colors() == splash_screen._fallback_splash_colors()

    @staticmethod
    def test_splash_follows_a_change_to_the_dark_theme_entry(monkeypatch: pytest.MonkeyPatch) -> None:
        """Changing the dark theme's accent changes the splash accent, so the splash holds no colour of its own.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """
        palettes = theme_manager_module._THEME_PALETTES
        dark_analysis = palettes[THEME_DARK].analysis

        def restyled() -> dict[str, QColor]:
            """Build the dark analysis palette with a distinct accent.

            Returns:
                dict[str, QColor]: The dark palette with ``accent`` replaced.
            """
            colors = dark_analysis()
            colors["accent"] = QColor(_SENTINEL)
            return colors

        monkeypatch.setitem(palettes, THEME_DARK, replace(palettes[THEME_DARK], analysis=restyled))
        resolved = splash_screen._splash_colors()
        assert resolved["accent"] == _SENTINEL
        assert resolved["glow"] == _SENTINEL

    @staticmethod
    def test_splash_falls_back_to_its_literal_when_the_theme_has_no_valid_colour(monkeypatch: pytest.MonkeyPatch) -> None:
        """A role the theme system cannot supply is painted with the splash's own literal instead of an invalid colour.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """
        fallback = splash_screen._fallback_splash_colors()

        def unusable() -> SplashColors:
            """Build a splash palette whose every colour is invalid.

            Returns:
                SplashColors: A palette of default-constructed, invalid colours.
            """
            return {
                "accent": QColor(),
                "glow": QColor(),
                "text": QColor(),
                "subtitle": QColor(),
                "track": QColor(),
                "stage_pending": QColor(),
                "stage_error": QColor(),
                "version_text": QColor(),
            }

        monkeypatch.setattr(ThemeManager, "get_splash_colors", staticmethod(unusable))
        assert splash_screen._splash_colors() == fallback


class TestElicitationErrorsUseTheThemedStatusRule:
    """The elicitation dialog's error labels are styled by the shared ``status="error"`` rule."""

    @staticmethod
    def test_error_labels_resolve_the_theme_error_colour(manager: ThemeManager, theme: str) -> None:
        """The summary and per-field error labels carry the status property and show the stylesheet's error colour.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to apply.
        """
        assert manager.apply_theme(theme) is True
        schema = {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}
        dialog = McpElicitationDialog("srv", ElicitRequestFormParams(message="Fill this in.", requested_schema=schema))
        probe = QLabel()
        probe.setProperty("status", "error")
        try:
            probe.ensurePolished()
            expected = probe.palette().color(probe.foregroundRole())
            for name in ("mcp_elicit_errors", "mcp_elicit_error_name"):
                label = dialog.findChild(QLabel, name)
                assert label is not None, f"dialog has no {name} label"
                assert label.property("status") == "error"
                label.ensurePolished()
                assert label.palette().color(label.foregroundRole()) == expected
            plain = dialog.findChild(QLabel, "mcp_elicit_message")
            assert plain is not None
            plain.ensurePolished()
            assert plain.palette().color(plain.foregroundRole()) != expected, "test premise: the error colour differs from plain text"
        finally:
            probe.deleteLater()
            dialog.deleteLater()
            QApplication.processEvents()
