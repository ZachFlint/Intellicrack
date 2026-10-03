# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Theme management for Intellicrack UI.

Provides centralized theme and stylesheet management with support for dark, light, and system themes. The system theme follows the operating
system's light/dark preference and tracks live OS changes.

The module is also the single source of every colour the UI paints itself rather than leaving to the stylesheets: one palette per theme id,
read through the typed ``ThemeManager.get_*_colors`` accessors. Widgets hold no colour tables of their own.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, replace
from importlib import resources
from typing import TYPE_CHECKING, ClassVar, Final, TypedDict, override

from PyQt6.QtCore import QEvent, QObject, Qt, pyqtBoundSignal, pyqtSignal
from PyQt6.QtGui import QColor, QGuiApplication
from PyQt6.QtWidgets import QAbstractScrollArea, QApplication, QFrame, QMenuBar, QStyle, QToolBar, QWidget

from intellicrack.core.color_defaults import (
    DEFAULT_BOOKMARK_COLOR,
    DEFAULT_HIGHLIGHT_COLOR,
    SECTION_CYCLE_COLORS,
    STRUCTURE_HEADER_COLOR,
    STRUCTURE_SECTION_COLOR,
    STRUCTURE_TABLE_COLOR,
)
from intellicrack.core.logging import get_logger
from intellicrack.ui.resources.resource_helper import get_assets_path, get_style_path


if TYPE_CHECKING:
    from collections.abc import Callable


if sys.platform == "win32":
    import winreg


_logger = get_logger(__name__)


THEME_DARK: Final[str] = "dark"
THEME_LIGHT: Final[str] = "light"
THEME_DARK2: Final[str] = "dark2"
THEME_LIGHT2: Final[str] = "light2"
THEME_SYSTEM: Final[str] = "system"
DEFAULT_THEME: Final[str] = THEME_DARK

_DARK_FAMILY: Final[frozenset[str]] = frozenset({THEME_DARK, THEME_DARK2})
_CONCRETE_THEMES: Final[frozenset[str]] = frozenset({THEME_DARK, THEME_LIGHT, THEME_DARK2, THEME_LIGHT2})
_SELECTABLE_THEMES: Final[frozenset[str]] = frozenset(
    {THEME_DARK, THEME_LIGHT, THEME_DARK2, THEME_LIGHT2, THEME_SYSTEM},
)
_TOGGLE_PARTNER: Final[dict[str, str]] = {
    THEME_DARK: THEME_LIGHT,
    THEME_LIGHT: THEME_DARK,
    THEME_DARK2: THEME_LIGHT2,
    THEME_LIGHT2: THEME_DARK2,
}

_WINDOWS_PERSONALIZE_KEY: Final[str] = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
_WINDOWS_APPS_LIGHT_VALUE: Final[str] = "AppsUseLightTheme"

_STYLED_GENERATION_PROPERTY: Final[str] = "_ic_theme_styled_generation"
_LAZY_REPOLISH_FILTER_PROPERTY: Final[str] = "_ic_theme_lazy_repolish_filter_installed"


def _detect_windows_system_theme() -> str | None:
    """Detect the active Windows app color mode from the registry.

    Reads ``AppsUseLightTheme`` under the per-user *Personalize* key, which
    Windows updates whenever the user switches the system app color mode
    between light and dark.

    Returns:
        str | None: :data:`THEME_LIGHT` or :data:`THEME_DARK` when the value
        can be read, otherwise ``None`` (non-Windows platforms or when the
        value is absent or unreadable).
    """
    if sys.platform != "win32":
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WINDOWS_PERSONALIZE_KEY) as key:
            value, _ = winreg.QueryValueEx(key, _WINDOWS_APPS_LIGHT_VALUE)
    except OSError:
        _logger.debug("windows_theme_registry_unavailable", exc_info=True)
        return None
    return THEME_LIGHT if value else THEME_DARK


class _ThemeNotifier(QObject):
    """Qt signal carrier for theme changes.

    ``ThemeManager`` is a plain singleton, so it delegates Qt signalling to
    this lightweight :class:`~PyQt6.QtCore.QObject` to broadcast the resolved
    theme name whenever the active theme changes.

    Attributes:
        theme_changed: Emitted with the resolved theme name
            (:data:`THEME_DARK` or :data:`THEME_LIGHT`) after a new theme is
            applied to the application.
    """

    theme_changed = pyqtSignal(str)


class _LazyChromeRepolishFilter(QObject):
    """Repolishes a hidden chrome widget the next time it becomes visible.

    ``ThemeManager._repolish_chrome`` only unpolishes/repolishes chrome that is visible at the moment a theme is applied. A widget that was
    hidden at that moment (an inactive tab page, a docked panel nobody has opened, a detached window that is not currently shown) would
    otherwise keep rendering with whichever theme it was last polished under until *some* unrelated event happened to touch it. This filter
    is installed once per chrome widget and, on every :attr:`~PyQt6.QtCore.QEvent.Type.Show` event, asks the owning :class:`ThemeManager` to
    repolish the widget only if it is stale relative to the most recent ``apply_theme`` call -- so a widget shown and hidden repeatedly
    between theme changes is repolished at most once per change, never once per show.
    """

    def __init__(self, theme_manager: ThemeManager, widget: QWidget) -> None:
        """Initialize the filter and install it on the target widget.

        Args:
            theme_manager: Owning theme manager, consulted for the current
                styled generation whenever the widget is shown.
            widget: The chrome widget this filter watches and repolishes.
        """
        super().__init__(widget)
        self._theme_manager = theme_manager
        self._widget = widget
        widget.installEventFilter(self)

    @override
    def eventFilter(self, a0: QObject | None, a1: QEvent | None) -> bool:
        """Repolish the watched widget on Show if it is stale.

        Args:
            a0: The watched object (expected to be the widget this filter
                was installed on).
            a1: The event being filtered.

        Returns:
            bool: Always False; the event is never consumed.
        """
        if a1 is not None and a1.type() == QEvent.Type.Show and a0 is self._widget:
            self._theme_manager.repolish_if_stale(self._widget)
        return False


_PACKAGE_NAME: Final[str] = "intellicrack"

_EMERGENCY_STYLESHEET_DARK: Final[str] = "QWidget { background-color: #1e1e1e; color: #d4d4d4; } QMainWindow { background-color: #1e1e1e; }"
_EMERGENCY_STYLESHEET_LIGHT: Final[str] = (
    "QWidget { background-color: #eceef2; color: #1a1d21; } QMainWindow { background-color: #eceef2; }"
)


def _family_theme_filename(theme: str) -> str:
    """Get the representative stylesheet file name for a theme's family.

    Args:
        theme: Theme name.

    Returns:
        str: ``"dark_theme.qss"`` for the dark family (:data:`THEME_DARK` or
        :data:`THEME_DARK2`), otherwise ``"light_theme.qss"``.
    """
    return f"{THEME_DARK if theme in _DARK_FAMILY else THEME_LIGHT}_theme.qss"


def _read_packaged_theme_asset(filename: str) -> str:
    """Read a packaged theme stylesheet through :mod:`importlib.resources`.

    Resolves ``filename`` inside the installed ``intellicrack`` distribution
    -- a source checkout, an installed wheel, or a frozen bundle that
    preserves package data -- so the caller reads the exact bytes shipped in
    ``assets/styles`` without duplicating that text as a literal Python
    string.

    Args:
        filename: Stylesheet file name relative to ``assets/styles``, e.g.
            ``"dark_theme.qss"``.

    Returns:
        str: The full text contents of the asset.
    """
    asset = resources.files(_PACKAGE_NAME).joinpath("assets", "styles", filename)
    return asset.read_text(encoding="utf-8")


def _read_bundled_theme_asset(filename: str) -> str:
    """Read a packaged theme stylesheet from the resolved assets directory.

    Secondary read route used when :func:`_read_packaged_theme_asset` cannot
    resolve the asset. Resolves through the same
    :func:`~intellicrack.ui.resources.resource_helper.get_style_path` path
    resolution used for the theme-specific stylesheet lookup, which also
    covers frozen (PyInstaller) builds.

    Args:
        filename: Stylesheet file name relative to ``assets/styles``, e.g.
            ``"dark_theme.qss"``.

    Returns:
        str: The full text contents of the asset.
    """
    return get_style_path(filename).read_text(encoding="utf-8")


def _load_family_fallback_stylesheet(theme: str) -> str:
    """Load the representative stylesheet asset for a theme's family.

    Used whenever the theme-specific ``.qss`` asset cannot be read. Both
    read routes resolve the exact same packaged ``dark_theme.qss`` /
    ``light_theme.qss`` file, so the value returned here can never diverge
    from the ``.qss`` asset it stands in for -- there is no hand-maintained
    copy of the stylesheet text to fall out of sync with the asset.

    Args:
        theme: Theme name whose family's representative stylesheet should be
            returned.

    Returns:
        str: The full contents of the representative stylesheet asset, or a
        minimal built-in stylesheet if the asset cannot be read through
        either route.
    """
    filename = _family_theme_filename(theme)
    try:
        return _read_packaged_theme_asset(filename)
    except (ModuleNotFoundError, OSError):
        _logger.debug("packaged_theme_asset_unavailable", style_file=filename)
    try:
        return _read_bundled_theme_asset(filename)
    except OSError:
        _logger.exception("bundled_theme_asset_unreadable", style_file=filename)
    return _EMERGENCY_STYLESHEET_DARK if theme in _DARK_FAMILY else _EMERGENCY_STYLESHEET_LIGHT


DARK_THEME_FALLBACK: Final[str] = _load_family_fallback_stylesheet(THEME_DARK)
LIGHT_THEME_FALLBACK: Final[str] = _load_family_fallback_stylesheet(THEME_LIGHT)


class HexEditorColors(TypedDict):
    """Colours the hex editor grid, its entropy minimap and its colour modes paint with.

    Attributes:
        minimap_bg: Background of the entropy minimap strip.
        minimap_indicator: Translucent fill of the minimap's visible-region marker.
        minimap_indicator_border: Outline of the minimap's visible-region marker.
        entropy_low: Low end of the entropy heat-map ramp.
        entropy_mid: Middle of the entropy heat-map ramp.
        entropy_high: High end of the entropy heat-map ramp.
        editor_bg: Background of the hex grid.
        offset_text: Offset column and column-header text.
        separator: Rule drawn between the offset, hex and ASCII columns.
        selection_bg: Fill behind selected bytes.
        hex_normal: Hex digits of an unmodified, non-zero byte.
        hex_modified: Text of a byte edited since the last save.
        hex_zero: Hex digits of a zero byte.
        ascii_printable: ASCII-column text of a printable byte.
        ascii_nonprintable: ASCII-column placeholder of a non-printable byte.
        cursor_text: Text of selected bytes and the cursor outline.
        alignment_grid: Dashed alignment-grid lines.
        content_null: Content-class tint for null or padding blocks.
        content_text: Content-class tint for text blocks.
        content_generic: Content-class tint for unclassified data blocks.
        content_code: Content-class tint for machine-code blocks.
        content_compressed: Content-class tint for compressed or encrypted blocks.
    """

    minimap_bg: QColor
    minimap_indicator: QColor
    minimap_indicator_border: QColor
    entropy_low: QColor
    entropy_mid: QColor
    entropy_high: QColor
    editor_bg: QColor
    offset_text: QColor
    separator: QColor
    selection_bg: QColor
    hex_normal: QColor
    hex_modified: QColor
    hex_zero: QColor
    ascii_printable: QColor
    ascii_nonprintable: QColor
    cursor_text: QColor
    alignment_grid: QColor
    content_null: QColor
    content_text: QColor
    content_generic: QColor
    content_code: QColor
    content_compressed: QColor


class ChartColors(TypedDict):
    """Colours of the hex editor's statistics charts: entropy graph, byte histogram and digram heat map.

    Attributes:
        bg: Chart background.
        entropy_low: Entropy line colour below the low threshold.
        entropy_mid: Entropy line colour between the thresholds.
        entropy_high: Entropy line colour above the high threshold.
        axis: Axis lines and labels.
        bar_normal: Histogram bar.
        bar_hovered: Histogram bar under the pointer.
        gradient_low: Background band of the low-entropy range.
        gradient_mid: Background band of the mid-entropy range.
        gradient_high: Background band of the high-entropy range.
        heatmap_zero: Digram heat-map cell for a byte pair that never occurs.
    """

    bg: QColor
    entropy_low: QColor
    entropy_mid: QColor
    entropy_high: QColor
    axis: QColor
    bar_normal: QColor
    bar_hovered: QColor
    gradient_low: QColor
    gradient_mid: QColor
    gradient_high: QColor
    heatmap_zero: QColor


class GraphColors(TypedDict):
    """Colours of the control-flow graph view.

    Attributes:
        block_bg: Basic-block body fill.
        block_border: Basic-block outline.
        header_bg: Basic-block address header fill.
        header_text: Basic-block address header text.
        asm_text: Instruction text with no special role.
        mnemonic_jump: Jump instructions.
        mnemonic_call: Call instructions.
        mnemonic_ret: Return instructions.
        edge_true: Edge taken when a branch condition holds.
        edge_false: Edge taken when a branch condition fails.
        edge_uncond: Unconditional edge.
        selected_border: Outline of the selected basic block.
        background: Graph canvas.
    """

    block_bg: QColor
    block_border: QColor
    header_bg: QColor
    header_text: QColor
    asm_text: QColor
    mnemonic_jump: QColor
    mnemonic_call: QColor
    mnemonic_ret: QColor
    edge_true: QColor
    edge_false: QColor
    edge_uncond: QColor
    selected_border: QColor
    background: QColor


class StackColors(TypedDict):
    """Text colours of the call-stack table.

    Attributes:
        index_highlight: Index of the innermost frame.
        address: Return address.
        function_known: Resolved function name.
        function_unknown: Placeholder shown for an unresolved function.
        module: Module name.
        offset: Offset into the function.
        pointer: Frame and stack pointer values.
    """

    index_highlight: QColor
    address: QColor
    function_known: QColor
    function_unknown: QColor
    module: QColor
    offset: QColor
    pointer: QColor


class CredentialSourceColors(TypedDict):
    """Colours that say where a provider credential comes from.

    The four source entries are also declared, value for value, by the ``QLabel#credential_source_label[credentialSource=...]`` rules of the
    theme stylesheets, which is what styles the source badge itself.

    Attributes:
        env_file: Credential read from the ``.env`` file.
        environment: Credential read from the process environment.
        manual: Credential typed into the dialog.
        not_configured: No credential available.
        default: Any source the UI does not recognise.
        configured: Provider list entry with a working credential.
        unconfigured: Provider list entry without one.
    """

    env_file: QColor
    environment: QColor
    manual: QColor
    not_configured: QColor
    default: QColor
    configured: QColor
    unconfigured: QColor


class HexMarkColors(TypedDict):
    """Default colours for marks the hex editor stores in a document.

    These are ``#RRGGBB`` strings rather than :class:`~PyQt6.QtGui.QColor` objects because they are written into bookmarks, highlight rules
    and highlight regions, which persist them as text. A theme entry only supplies the colour a new mark starts with; a mark that already
    exists keeps the colour it was created or saved with.

    Attributes:
        search_match: Highlight of a search hit.
        yara_match: Highlight of a YARA rule match.
        pattern_field: Highlight of a pattern field that declares no colour.
        template_field: Highlight of a template field that declares no colour.
        bookmark: Colour offered for a new bookmark.
        highlight_rule: Colour offered for a new byte highlight rule.
        structure_header: Auto-bookmark of a file header (DOS, ELF).
        structure_table: Auto-bookmark of a header table (PE headers, program headers).
        structure_section: Auto-bookmark of section-level structures (section headers).
        section_cycle: Rotation used when each section gets its own auto-bookmark.
    """

    search_match: str
    yara_match: str
    pattern_field: str
    template_field: str
    bookmark: str
    highlight_rule: str
    structure_header: str
    structure_table: str
    structure_section: str
    section_cycle: tuple[str, ...]


class SplashColors(TypedDict):
    """Colours of the startup splash screen.

    The splash paints its own dark background whatever theme is configured, so there is one splash palette rather than one per theme, and
    it is derived from the dark theme's entries.

    Attributes:
        accent: Progress fill, the active pipeline stage and the accent bar.
        glow: Tint of the glow drawn around the brand mark.
        text: Status, stage-label and title text.
        subtitle: Subtitle text.
        track: Unfilled part of the progress bar.
        stage_pending: Pipeline stage that has not started.
        stage_error: Pipeline stage that failed.
        version_text: Version label, the text colour at reduced opacity.
    """

    accent: QColor
    glow: QColor
    text: QColor
    subtitle: QColor
    track: QColor
    stage_pending: QColor
    stage_error: QColor
    version_text: QColor


_SPLASH_VERSION_ALPHA: Final[int] = 153
_LUMINANCE_MIDPOINT: Final[float] = 0.5
_LUMINANCE_RED_WEIGHT: Final[float] = 0.299
_LUMINANCE_GREEN_WEIGHT: Final[float] = 0.587
_LUMINANCE_BLUE_WEIGHT: Final[float] = 0.114


def _dark_analysis_colors() -> dict[str, QColor]:
    """Build the dark theme's general semantic colours.

    Returns:
        dict[str, QColor]: Mapping of semantic colour names to fresh QColor instances.
    """
    return {
        "background": QColor(30, 30, 30),
        "foreground": QColor(212, 212, 212),
        "accent": QColor(0, 122, 204),
        "success": QColor(76, 175, 80),
        "error": QColor(244, 67, 54),
        "warning": QColor(255, 152, 0),
        "muted": QColor(136, 136, 136),
        "border": QColor(62, 62, 66),
        "mnemonic_jump": QColor(86, 156, 214),
        "mnemonic_call": QColor(220, 220, 170),
        "mnemonic_ret": QColor(206, 145, 120),
        "operand_register": QColor(78, 201, 176),
        "operand_immediate": QColor(181, 206, 168),
        "operand_memory": QColor(156, 220, 254),
    }


def _light_analysis_colors() -> dict[str, QColor]:
    """Build the light theme's general semantic colours.

    Returns:
        dict[str, QColor]: Mapping of semantic colour names to fresh QColor instances.
    """
    return {
        "background": QColor(236, 238, 242),
        "foreground": QColor(26, 29, 33),
        "accent": QColor(0, 103, 192),
        "success": QColor(46, 125, 50),
        "error": QColor(198, 40, 40),
        "warning": QColor(239, 108, 0),
        "muted": QColor(90, 99, 112),
        "border": QColor(194, 200, 208),
        "mnemonic_jump": QColor(0, 0, 255),
        "mnemonic_call": QColor(121, 94, 38),
        "mnemonic_ret": QColor(163, 21, 21),
        "operand_register": QColor(0, 128, 128),
        "operand_immediate": QColor(9, 134, 88),
        "operand_memory": QColor(4, 81, 165),
    }


def _dark_hex_editor_colors() -> HexEditorColors:
    """Build the dark theme's hex editor colours.

    Returns:
        HexEditorColors: Fresh QColor instances for every hex editor role.
    """
    return {
        "minimap_bg": QColor(25, 25, 25),
        "minimap_indicator": QColor(100, 150, 255, 100),
        "minimap_indicator_border": QColor(150, 190, 255),
        "entropy_low": QColor("#4CAF50"),
        "entropy_mid": QColor("#FFC107"),
        "entropy_high": QColor("#F44336"),
        "editor_bg": QColor(30, 30, 30),
        "offset_text": QColor(128, 128, 128),
        "separator": QColor(60, 60, 60),
        "selection_bg": QColor(100, 149, 237),
        "hex_normal": QColor(212, 212, 212),
        "hex_modified": QColor(255, 80, 80),
        "hex_zero": QColor(80, 80, 80),
        "ascii_printable": QColor(180, 200, 180),
        "ascii_nonprintable": QColor(80, 80, 80),
        "cursor_text": QColor(255, 255, 255),
        "alignment_grid": QColor(120, 120, 200, 140),
        "content_null": QColor(90, 90, 90),
        "content_text": QColor(66, 165, 245),
        "content_generic": QColor(171, 71, 188),
        "content_code": QColor(255, 202, 40),
        "content_compressed": QColor(239, 83, 80),
    }


def _light_hex_editor_colors() -> HexEditorColors:
    """Build the light theme's hex editor colours.

    Returns:
        HexEditorColors: Fresh QColor instances for every hex editor role.
    """
    return {
        "minimap_bg": QColor(245, 245, 245),
        "minimap_indicator": QColor(50, 100, 220, 100),
        "minimap_indicator_border": QColor(50, 100, 220),
        "entropy_low": QColor("#2E7D32"),
        "entropy_mid": QColor("#EF6C00"),
        "entropy_high": QColor("#C62828"),
        "editor_bg": QColor(255, 255, 255),
        "offset_text": QColor(117, 117, 117),
        "separator": QColor(224, 224, 224),
        "selection_bg": QColor(0, 120, 212, 80),
        "hex_normal": QColor(26, 26, 26),
        "hex_modified": QColor(198, 40, 40),
        "hex_zero": QColor(180, 180, 180),
        "ascii_printable": QColor(46, 125, 50),
        "ascii_nonprintable": QColor(180, 180, 180),
        "cursor_text": QColor(0, 0, 0),
        "alignment_grid": QColor(80, 80, 170, 140),
        "content_null": QColor(158, 158, 158),
        "content_text": QColor(21, 101, 192),
        "content_generic": QColor(106, 27, 154),
        "content_code": QColor(245, 127, 23),
        "content_compressed": QColor(183, 28, 28),
    }


def _dark_chart_colors() -> ChartColors:
    """Build the dark theme's statistics-chart colours.

    Returns:
        ChartColors: Fresh QColor instances for every chart role.
    """
    return {
        "bg": QColor("#1E1E1E"),
        "entropy_low": QColor("#4CAF50"),
        "entropy_mid": QColor("#FFC107"),
        "entropy_high": QColor("#F44336"),
        "axis": QColor("#888888"),
        "bar_normal": QColor("#2196F3"),
        "bar_hovered": QColor("#4CAF50"),
        "gradient_low": QColor("#1B3A1F"),
        "gradient_mid": QColor("#3A3A1B"),
        "gradient_high": QColor("#3A1B1B"),
        "heatmap_zero": QColor(0, 0, 0),
    }


def _light_chart_colors() -> ChartColors:
    """Build the light theme's statistics-chart colours.

    Returns:
        ChartColors: Fresh QColor instances for every chart role.
    """
    return {
        "bg": QColor("#FFFFFF"),
        "entropy_low": QColor("#2E7D32"),
        "entropy_mid": QColor("#EF6C00"),
        "entropy_high": QColor("#C62828"),
        "axis": QColor("#5a6370"),
        "bar_normal": QColor("#1565C0"),
        "bar_hovered": QColor("#2E7D32"),
        "gradient_low": QColor("#E8F5E9"),
        "gradient_mid": QColor("#FFF3E0"),
        "gradient_high": QColor("#FFEBEE"),
        "heatmap_zero": QColor(0, 0, 0),
    }


def _dark_graph_colors() -> GraphColors:
    """Build the dark theme's control-flow graph colours.

    Returns:
        GraphColors: Fresh QColor instances for every graph role.
    """
    return {
        "block_bg": QColor(40, 44, 52),
        "block_border": QColor(80, 85, 95),
        "header_bg": QColor(55, 60, 72),
        "header_text": QColor(220, 220, 220),
        "asm_text": QColor(190, 190, 190),
        "mnemonic_jump": QColor(86, 156, 214),
        "mnemonic_call": QColor(78, 201, 176),
        "mnemonic_ret": QColor(206, 106, 106),
        "edge_true": QColor(80, 200, 80),
        "edge_false": QColor(200, 80, 80),
        "edge_uncond": QColor(150, 150, 150),
        "selected_border": QColor(100, 150, 255),
        "background": QColor(30, 30, 30),
    }


def _light_graph_colors() -> GraphColors:
    """Build the light theme's control-flow graph colours.

    Returns:
        GraphColors: Fresh QColor instances for every graph role.
    """
    return {
        "block_bg": QColor(255, 255, 255),
        "block_border": QColor(200, 200, 210),
        "header_bg": QColor(230, 235, 245),
        "header_text": QColor(30, 30, 30),
        "asm_text": QColor(60, 60, 60),
        "mnemonic_jump": QColor(0, 0, 200),
        "mnemonic_call": QColor(0, 128, 128),
        "mnemonic_ret": QColor(180, 50, 50),
        "edge_true": QColor(40, 160, 40),
        "edge_false": QColor(200, 40, 40),
        "edge_uncond": QColor(120, 120, 120),
        "selected_border": QColor(50, 100, 220),
        "background": QColor(248, 248, 248),
    }


def _dark_stack_colors() -> StackColors:
    """Build the dark theme's call-stack table colours.

    Returns:
        StackColors: Fresh QColor instances for every stack-table role.
    """
    return {
        "index_highlight": QColor("#4ec9b0"),
        "address": QColor("#569cd6"),
        "function_known": QColor("#dcdcaa"),
        "function_unknown": QColor("#888888"),
        "module": QColor("#4ec9b0"),
        "offset": QColor("#b5cea8"),
        "pointer": QColor("#ce9178"),
    }


def _light_stack_colors() -> StackColors:
    """Build the light theme's call-stack table colours.

    Returns:
        StackColors: Fresh QColor instances for every stack-table role.
    """
    return {
        "index_highlight": QColor("#0067c0"),
        "address": QColor("#0451a5"),
        "function_known": QColor("#795e26"),
        "function_unknown": QColor("#5a6370"),
        "module": QColor("#0067c0"),
        "offset": QColor("#098658"),
        "pointer": QColor("#a31515"),
    }


def _dark_credential_source_colors() -> CredentialSourceColors:
    """Build the dark theme's credential-source colours.

    Returns:
        CredentialSourceColors: Fresh QColor instances for every credential-source role.
    """
    return {
        "env_file": QColor(34, 139, 34),
        "environment": QColor(70, 130, 180),
        "manual": QColor(218, 165, 32),
        "not_configured": QColor(178, 34, 34),
        "default": QColor(128, 128, 128),
        "configured": QColor(34, 139, 34),
        "unconfigured": QColor(169, 169, 169),
    }


def _light_credential_source_colors() -> CredentialSourceColors:
    """Build the light theme's credential-source colours.

    Returns:
        CredentialSourceColors: Fresh QColor instances for every credential-source role.
    """
    return {
        "env_file": QColor(46, 125, 50),
        "environment": QColor(21, 101, 192),
        "manual": QColor(239, 108, 0),
        "not_configured": QColor(198, 40, 40),
        "default": QColor(117, 117, 117),
        "configured": QColor(46, 125, 50),
        "unconfigured": QColor(117, 117, 117),
    }


def _dark_hex_mark_colors() -> HexMarkColors:
    """Build the dark theme's default hex-mark colours.

    The bookmark, highlight-rule and structure entries are the defaults the hex-editor bridge advertises, read from
    :mod:`intellicrack.core.color_defaults` so the dark theme and the bridge contract stay one value.

    Returns:
        HexMarkColors: Default colour strings for every kind of mark.
    """
    return {
        "search_match": "#FFAA00",
        "yara_match": "#AA44FF",
        "pattern_field": "#FFD080",
        "template_field": "#44FF44",
        "bookmark": DEFAULT_BOOKMARK_COLOR,
        "highlight_rule": DEFAULT_HIGHLIGHT_COLOR,
        "structure_header": STRUCTURE_HEADER_COLOR,
        "structure_table": STRUCTURE_TABLE_COLOR,
        "structure_section": STRUCTURE_SECTION_COLOR,
        "section_cycle": SECTION_CYCLE_COLORS,
    }


def _light_hex_mark_colors() -> HexMarkColors:
    """Build the light theme's default hex-mark colours.

    Marks are painted as translucent washes behind dark text on a white grid, so the light theme uses deeper, more saturated hues than the
    pastels that read well on the dark grid.

    Returns:
        HexMarkColors: Default colour strings for every kind of mark.
    """
    return {
        "search_match": "#FF8800",
        "yara_match": "#7B1FA2",
        "pattern_field": "#E65100",
        "template_field": "#2E7D32",
        "bookmark": "#F9A825",
        "highlight_rule": "#F9A825",
        "structure_header": "#C62828",
        "structure_table": "#00897B",
        "structure_section": "#0277BD",
        "section_cycle": ("#0277BD", "#2E7D32", "#F9A825", "#8E24AA", "#00897B"),
    }


@dataclass(frozen=True, slots=True)
class _ThemePalette:
    """Every painted-colour table of one theme.

    Each field is a factory rather than a stored mapping, so every caller receives fresh :class:`~PyQt6.QtGui.QColor` objects it may adjust
    (for example with ``setAlpha``) without disturbing the palette.

    Attributes:
        analysis: General semantic colours and disassembly token colours.
        hex_editor: Hex grid, minimap and colour-mode colours.
        charts: Entropy graph, byte histogram and digram heat-map colours.
        graph: Control-flow graph colours.
        stack: Call-stack table colours.
        credential_sources: Provider credential-source colours.
        hex_marks: Default colours of marks stored in hex documents.
    """

    analysis: Callable[[], dict[str, QColor]]
    hex_editor: Callable[[], HexEditorColors]
    charts: Callable[[], ChartColors]
    graph: Callable[[], GraphColors]
    stack: Callable[[], StackColors]
    credential_sources: Callable[[], CredentialSourceColors]
    hex_marks: Callable[[], HexMarkColors]


_DARK_PALETTE: Final[_ThemePalette] = _ThemePalette(
    analysis=_dark_analysis_colors,
    hex_editor=_dark_hex_editor_colors,
    charts=_dark_chart_colors,
    graph=_dark_graph_colors,
    stack=_dark_stack_colors,
    credential_sources=_dark_credential_source_colors,
    hex_marks=_dark_hex_mark_colors,
)
_LIGHT_PALETTE: Final[_ThemePalette] = _ThemePalette(
    analysis=_light_analysis_colors,
    hex_editor=_light_hex_editor_colors,
    charts=_light_chart_colors,
    graph=_light_graph_colors,
    stack=_light_stack_colors,
    credential_sources=_light_credential_source_colors,
    hex_marks=_light_hex_mark_colors,
)

_THEME_PALETTES: Final[dict[str, _ThemePalette]] = {
    THEME_DARK: _DARK_PALETTE,
    THEME_LIGHT: _LIGHT_PALETTE,
    THEME_DARK2: replace(_DARK_PALETTE),
    THEME_LIGHT2: replace(_LIGHT_PALETTE),
}
"""One palette per concrete theme id.

``dark2`` and ``light2`` are entries of their own that start as copies of ``dark`` and ``light``. Giving a restyled theme its own painted
colours means replacing a field of its entry here (``replace(_DARK_PALETTE, graph=_dark2_graph_colors)``); no widget needs to change.
"""


class ThemeManager:
    """Singleton theme manager for application styling.

    Manages theme loading, switching, and application-wide stylesheet management.
    """

    _instance: ClassVar[ThemeManager | None] = None

    def __init__(self) -> None:
        """Initialize the ThemeManager instance."""
        self._current_theme: str = DEFAULT_THEME
        self._requested_theme: str = DEFAULT_THEME
        self._notifier: _ThemeNotifier = _ThemeNotifier()
        self._system_watch_connected: bool = False
        self._styled_generation: int = 0
        self.theme_cache: dict[str, str] = {}
        self.styles_available: bool = self._check_styles_available()

    @classmethod
    def get_instance(cls) -> ThemeManager:
        """Get the singleton instance of ThemeManager.

        Returns:
            ThemeManager: The ThemeManager singleton instance.
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (primarily for testing)."""
        if cls._instance is not None:
            cls._instance.release()
        cls._instance = None

    def release(self) -> None:
        """Release live OS color-scheme tracking held by this manager.

        Disconnects the ``colorSchemeChanged`` subscription created for the ``"system"`` theme. Safe to call when no subscription is active.
        """
        hints = QGuiApplication.styleHints()
        if not self._system_watch_connected or hints is None:
            self._system_watch_connected = False
            return
        try:
            hints.colorSchemeChanged.disconnect(self._on_system_color_scheme_changed)
        except (TypeError, RuntimeError):
            _logger.debug("system_watch_teardown_noop", exc_info=True)
        self._system_watch_connected = False

    @staticmethod
    def _check_styles_available() -> bool:
        """Check if the styles directory is available.

        Returns:
            bool: True if styles directory exists.
        """
        try:
            styles_dir = get_assets_path() / "styles"
            available = styles_dir.exists()
            _logger.debug("styles_availability_check", available=available, path=str(styles_dir))
        except FileNotFoundError:
            _logger.exception("styles_availability_check_failed")
            return False
        return available

    @property
    def theme_changed(self) -> pyqtBoundSignal:
        """Signal emitted with the resolved theme name on every theme change.

        Connect to this to refresh widgets that cannot be styled purely
        through the application stylesheet (custom-painted views, cached icon
        colors, syntax highlighters). The payload is the resolved theme name
        (:data:`THEME_DARK` or :data:`THEME_LIGHT`), never ``"system"``.

        Returns:
            pyqtBoundSignal: The bound ``theme_changed`` signal.
        """
        return self._notifier.theme_changed

    @staticmethod
    def _scheme_to_theme(scheme: Qt.ColorScheme) -> str:
        """Map a Qt color scheme to a concrete theme name.

        Args:
            scheme: The color scheme reported by Qt's style hints.

        Returns:
            str: :data:`THEME_LIGHT` or :data:`THEME_DARK`. When Qt reports
            an unknown scheme, the Windows registry is consulted and
            :data:`DEFAULT_THEME` is used as the final fallback.
        """
        if scheme == Qt.ColorScheme.Light:
            return THEME_LIGHT
        if scheme == Qt.ColorScheme.Dark:
            return THEME_DARK
        return _detect_windows_system_theme() or DEFAULT_THEME

    @classmethod
    def detect_system_theme(cls) -> str:
        """Detect the operating system's active light/dark preference.

        Prefers Qt's cross-platform :meth:`QStyleHints.colorScheme`, which on
        Windows tracks the system app color mode. Falls back to a direct
        Windows registry read and finally to :data:`DEFAULT_THEME`.

        Returns:
            str: :data:`THEME_LIGHT` or :data:`THEME_DARK`.
        """
        hints = QGuiApplication.styleHints()
        if QApplication.instance() is not None and hints is not None:
            return cls._scheme_to_theme(hints.colorScheme())
        return _detect_windows_system_theme() or DEFAULT_THEME

    @classmethod
    def resolve_theme(cls, theme: str) -> str:
        """Resolve a requested theme name to a concrete theme.

        Args:
            theme: Requested theme name (``"dark"``, ``"light"``, ``"dark2"``,
                ``"light2"`` or ``"system"``).

        Returns:
            str: The concrete theme to render: one of :data:`THEME_DARK`,
            :data:`THEME_LIGHT`, :data:`THEME_DARK2` or :data:`THEME_LIGHT2`.
            ``"system"`` resolves to dark or light; unknown names resolve to
            :data:`DEFAULT_THEME`.
        """
        if theme == THEME_SYSTEM:
            return cls.detect_system_theme()
        return theme if theme in _CONCRETE_THEMES else DEFAULT_THEME

    def apply_theme(self, theme: str = DEFAULT_THEME) -> bool:
        r"""Apply a theme to the application.

        Args:
            theme: Requested theme name (``"dark"``, ``"light"``, ``"dark2"``,
                ``"light2"`` or ``"system"``). ``"system"`` follows the OS
                light/dark preference and keeps tracking live OS changes.

        Returns:
            bool: True if theme was applied successfully.
        """
        if theme not in _SELECTABLE_THEMES:
            _logger.warning("unknown_theme", theme=theme, default=DEFAULT_THEME)
            theme = DEFAULT_THEME

        resolved = self.resolve_theme(theme)
        stylesheet = self.get_stylesheet(resolved)
        app_instance = QApplication.instance()

        if isinstance(app_instance, QApplication):
            app_instance.setStyleSheet(stylesheet)
            self._repolish_chrome(app_instance)
            self._requested_theme = theme
            self._current_theme = resolved
            self._update_system_watch()
            _logger.info("theme_applied", requested=theme, resolved=resolved)
            self._notifier.theme_changed.emit(resolved)
            return True

        _logger.warning("no_qapplication_instance")
        return False

    def _repolish_chrome(self, app_instance: QApplication) -> None:
        """Force visible chrome and content viewports to repaint after a live stylesheet change.

        ``QApplication.setStyleSheet`` reliably restyles ordinary widgets on
        a live theme change, but on Windows a :class:`~PyQt6.QtWidgets.QMenuBar`
        or :class:`~PyQt6.QtWidgets.QToolBar` that has already been painted once
        keeps rendering with the background it was first polished with: only
        newly constructed instances pick up the new stylesheet automatically.
        The same staleness affects content viewports built on
        :class:`~PyQt6.QtWidgets.QAbstractScrollArea` -- the hex grid's table,
        the disassembly table, the chat scroll area, and the markdown text
        browsers inside chat message bubbles -- along with the role-propertied
        :class:`~PyQt6.QtWidgets.QFrame` widgets (e.g. chat message bubbles
        styled via a ``role`` dynamic property selector) that never subscribe
        to :attr:`theme_changed` and instead depend entirely on the global
        stylesheet restyling an already-polished widget. Explicitly
        unpolishing and repolishing every such instance -- and, for scroll
        areas, their viewport widget as well, since the viewport is what
        actually paints the content background -- forces Qt to recompute
        style from the new stylesheet immediately, instead of leaving them
        visually stuck on the previous theme until the next resize or window
        recreation.

        Sweeping every live widget in the whole application
        (``QApplication.allWidgets()``) to find these instances blocks the
        event loop for seconds on a fully populated window, because it pays
        the unpolish/polish/update cost for hundreds of widgets nobody is
        looking at -- every scroll area and role-propertied frame in every
        inactive tab of every panel. Instead, this method walks only the
        currently *visible* top-level windows (the main window plus any
        shown, undocked panel windows) and repolishes only the chrome inside
        them that is itself visible right now. A chrome widget that exists
        but is hidden (an inactive tab page, a closed dock) is left alone
        here and instead gets a one-shot :class:`_LazyChromeRepolishFilter`
        that repolishes it the moment it is next shown, so the cost of
        styling a page nobody is viewing is deferred until someone actually
        views it.

        Args:
            app_instance: The active QApplication instance whose visible
                chrome and content-viewport widgets are repolished.
        """
        style = app_instance.style()
        if style is None:
            return
        self._styled_generation += 1
        for top_level in app_instance.topLevelWidgets():
            if not top_level.isVisible():
                continue
            top_level.setUpdatesEnabled(False)
            try:
                self._repolish_visible_chrome_in(style, top_level)
            finally:
                top_level.setUpdatesEnabled(True)

    def _repolish_visible_chrome_in(self, style: QStyle, top_level: QWidget) -> None:
        """Repolish the currently-visible chrome inside one visible top-level window.

        Any matching chrome widget that is not currently visible is left
        unstyled here and instead scheduled for a deferred repolish the next
        time it is shown, via :meth:`_schedule_lazy_repolish`.

        Args:
            style: The active application style used to unpolish/repolish.
            top_level: A visible top-level widget (the main window or a
                shown, undocked panel window) to search for chrome.
        """
        candidates: list[QWidget] = [
            *top_level.findChildren(QMenuBar),
            *top_level.findChildren(QToolBar),
            *top_level.findChildren(QAbstractScrollArea),
            *(frame for frame in top_level.findChildren(QFrame) if frame.property("role") is not None),
        ]
        for widget in candidates:
            if widget.isVisible():
                self._repolish_widget(style, widget)
                widget.setProperty(_STYLED_GENERATION_PROPERTY, self._styled_generation)
            else:
                self._schedule_lazy_repolish(widget)

    def _schedule_lazy_repolish(self, widget: QWidget) -> None:
        """Install a one-shot lazy repolish filter on a hidden chrome widget.

        A no-op if the widget already carries a
        :class:`_LazyChromeRepolishFilter` from a previous theme apply --
        that filter re-checks staleness against the current generation on
        every subsequent Show event, so a single installation covers every
        future theme change for the widget's lifetime.

        Args:
            widget: The hidden chrome widget to watch.
        """
        if widget.property(_LAZY_REPOLISH_FILTER_PROPERTY) is True:
            return
        _LazyChromeRepolishFilter(self, widget)
        filter_installed = True
        widget.setProperty(_LAZY_REPOLISH_FILTER_PROPERTY, filter_installed)

    def repolish_if_stale(self, widget: QWidget) -> None:
        """Repolish a chrome widget if it predates the current styled generation.

        Called from :class:`_LazyChromeRepolishFilter` when a previously
        hidden chrome widget is shown. A widget already tagged with the
        current generation (because it was visible and eagerly repolished
        during the most recent ``apply_theme``, or already lazily repolished
        on an earlier Show within the same generation) is left untouched.

        Args:
            widget: The chrome widget that was just shown.
        """
        app_instance = QApplication.instance()
        if not isinstance(app_instance, QApplication):
            return
        style = app_instance.style()
        if style is None:
            return
        stored_generation = widget.property(_STYLED_GENERATION_PROPERTY)
        if isinstance(stored_generation, int) and stored_generation >= self._styled_generation:
            return
        self._repolish_widget(style, widget)
        widget.setProperty(_STYLED_GENERATION_PROPERTY, self._styled_generation)

    @staticmethod
    def _repolish_widget(style: QStyle, widget: QWidget) -> None:
        """Unpolish and repolish one chrome widget, and its viewport if it has one.

        Args:
            style: The active application style used to unpolish/repolish.
            widget: The chrome widget to repolish.
        """
        style.unpolish(widget)
        style.polish(widget)
        widget.update()
        if isinstance(widget, QAbstractScrollArea):
            viewport = widget.viewport()
            if viewport is not None:
                style.unpolish(viewport)
                style.polish(viewport)
                viewport.update()

    def _update_system_watch(self) -> None:
        """Connect or disconnect live OS color-scheme tracking.

        When the requested theme is ``"system"``, subscribe to Qt's ``colorSchemeChanged`` signal so the application restyles itself the
        moment the OS light/dark preference changes. For explicit dark/light selections, the subscription is torn down.
        """
        hints = QGuiApplication.styleHints()
        if QApplication.instance() is None or hints is None:
            return
        signal = hints.colorSchemeChanged
        want_watch = self._requested_theme == THEME_SYSTEM
        if want_watch and not self._system_watch_connected:
            signal.connect(self._on_system_color_scheme_changed)
            self._system_watch_connected = True
        elif not want_watch and self._system_watch_connected:
            signal.disconnect(self._on_system_color_scheme_changed)
            self._system_watch_connected = False

    def _on_system_color_scheme_changed(self, scheme: Qt.ColorScheme) -> None:
        """Restyle the application when the OS color scheme changes.

        Args:
            scheme: The new color scheme reported by Qt's style hints.
        """
        if self._requested_theme != THEME_SYSTEM:
            return
        resolved = self._scheme_to_theme(scheme)
        if resolved == self._current_theme:
            return
        app_instance = QApplication.instance()
        if isinstance(app_instance, QApplication):
            app_instance.setStyleSheet(self.get_stylesheet(resolved))
            self._repolish_chrome(app_instance)
            self._current_theme = resolved
            _logger.info("system_color_scheme_changed", resolved=resolved)
            self._notifier.theme_changed.emit(resolved)

    def get_stylesheet(self, theme: str) -> str:
        """Get the stylesheet for a theme.

        Args:
            theme: Theme name.

        Returns:
            str: CSS stylesheet string.
        """
        if theme in self.theme_cache:
            _logger.debug("theme_cache_hit", theme=theme)
            return self.theme_cache[theme]

        _logger.debug("theme_cache_miss", theme=theme)
        stylesheet = self._load_stylesheet(theme)
        self.theme_cache[theme] = stylesheet
        return stylesheet

    def _load_stylesheet(self, theme: str) -> str:
        """Load a stylesheet from file or use fallback.

        Args:
            theme: Theme name.

        Returns:
            str: CSS stylesheet string.
        """
        if self.styles_available:
            filename = f"{theme}_theme.qss"
            try:
                if loaded := self._read_stylesheet_file(filename):
                    return loaded
            except OSError as e:
                _logger.warning(
                    "stylesheet_load_failed",
                    style_file=filename,
                    error=str(e),
                )

        _logger.debug("using_fallback_stylesheet", theme=theme)
        return _load_family_fallback_stylesheet(theme)

    @staticmethod
    def _read_stylesheet_file(filename: str) -> str | None:
        """Read a bundled QSS stylesheet by file name.

        Args:
            filename: Stylesheet file name, e.g. ``"dark_theme.qss"``.

        Returns:
            str | None: The stylesheet contents when the file exists and is
            non-empty, otherwise ``None``.
        """
        style_path = get_style_path(filename)
        if style_path.exists():
            with style_path.open(encoding="utf-8") as f:
                content = f.read()
            if content.strip():
                _logger.debug("stylesheet_loaded", path=str(style_path))
                return content
        return None

    def toggle_theme(self) -> str:
        """Toggle between light and dark within the current theme family.

        Flips ``dark`` <-> ``light`` and the restyled ``dark2`` <-> ``light2``,
        so a user who selected a restyled variant stays in that family instead
        of dropping back to the base themes.

        Returns:
            str: The new theme name.
        """
        old_theme = self._current_theme
        new_theme = _TOGGLE_PARTNER.get(old_theme, THEME_LIGHT if old_theme == THEME_DARK else THEME_DARK)
        _logger.debug("theme_toggling", from_theme=old_theme, to_theme=new_theme)
        self.apply_theme(new_theme)
        return new_theme

    @property
    def current_theme(self) -> str:
        """The resolved theme name currently rendered.

        Returns:
            str: The concrete theme being displayed (:data:`THEME_DARK` or
            :data:`THEME_LIGHT`), never ``"system"``.
        """
        return self._current_theme

    @property
    def requested_theme(self) -> str:
        """The theme the user requested.

        Returns:
            str: The requested theme name, which may be ``"system"`` when the
            theme follows the OS preference.
        """
        return self._requested_theme

    def is_dark_theme(self) -> bool:
        """Check if current theme is dark.

        Returns:
            bool: True if dark theme is active.
        """
        return self._current_theme in _DARK_FAMILY

    def _palette(self, theme: str | None) -> _ThemePalette:
        """Select the palette of a theme.

        Args:
            theme: Theme name to resolve, or ``None`` for the theme currently rendered. ``"system"`` and unknown names resolve the same way
                :meth:`resolve_theme` resolves them.

        Returns:
            _ThemePalette: The palette entry of the resolved theme.
        """
        resolved = self._current_theme if theme is None else self.resolve_theme(theme)
        return _THEME_PALETTES.get(resolved, _THEME_PALETTES[DEFAULT_THEME])

    def get_analysis_colors(self, theme: str | None = None) -> dict[str, QColor]:
        """Get the general semantic colors and disassembly token colors of a theme.

        Args:
            theme: Theme name, or ``None`` for the theme currently rendered.

        Returns:
            dict[str, QColor]: Mapping of semantic color names to QColor instances.
        """
        return self._palette(theme).analysis()

    def get_hex_editor_colors(self, theme: str | None = None) -> HexEditorColors:
        """Get the colors the hex editor grid, minimap and color modes paint with.

        Args:
            theme: Theme name, or ``None`` for the theme currently rendered.

        Returns:
            HexEditorColors: Colors for every hex editor role.
        """
        return self._palette(theme).hex_editor()

    def get_chart_colors(self, theme: str | None = None) -> ChartColors:
        """Get the colors of the entropy graph, byte histogram and digram heat map.

        Args:
            theme: Theme name, or ``None`` for the theme currently rendered.

        Returns:
            ChartColors: Colors for every chart role.
        """
        return self._palette(theme).charts()

    def get_graph_colors(self, theme: str | None = None) -> GraphColors:
        """Get the colors of the control-flow graph view.

        Args:
            theme: Theme name, or ``None`` for the theme currently rendered.

        Returns:
            GraphColors: Colors for every graph role.
        """
        return self._palette(theme).graph()

    def get_stack_colors(self, theme: str | None = None) -> StackColors:
        """Get the text colors of the call-stack table.

        Args:
            theme: Theme name, or ``None`` for the theme currently rendered.

        Returns:
            StackColors: Colors for every stack-table role.
        """
        return self._palette(theme).stack()

    def get_credential_source_colors(self, theme: str | None = None) -> CredentialSourceColors:
        """Get the colors that say where a provider credential comes from.

        Args:
            theme: Theme name, or ``None`` for the theme currently rendered.

        Returns:
            CredentialSourceColors: Colors for every credential-source role.
        """
        return self._palette(theme).credential_sources()

    def get_hex_mark_colors(self, theme: str | None = None) -> HexMarkColors:
        """Get the default colors of marks the hex editor stores in a document.

        Args:
            theme: Theme name, or ``None`` for the theme currently rendered.

        Returns:
            HexMarkColors: Default ``#RRGGBB`` strings for every kind of mark.
        """
        return self._palette(theme).hex_marks()

    @staticmethod
    def get_splash_colors() -> SplashColors:
        """Get the colors of the startup splash screen.

        The splash always renders on its own dark background, so these are the dark theme's entries whatever theme is active. It needs no
        :class:`ThemeManager` instance and no applied theme, so the splash can call it before the application is styled.

        Returns:
            SplashColors: Colors for every splash role.
        """
        dark = _THEME_PALETTES[THEME_DARK].analysis()
        version_text = QColor(dark["foreground"])
        version_text.setAlpha(_SPLASH_VERSION_ALPHA)
        return {
            "accent": dark["accent"],
            "glow": QColor(dark["accent"]),
            "text": dark["foreground"],
            "subtitle": dark["muted"],
            "track": dark["border"],
            "stage_pending": QColor(85, 85, 85),
            "stage_error": QColor(204, 51, 51),
            "version_text": version_text,
        }

    @staticmethod
    def contrasting_text_color(background: QColor) -> QColor:
        """Return black or white, whichever reads better on a solid background.

        Args:
            background: Solid color the text is painted over.

        Returns:
            QColor: Black for light backgrounds and white for dark ones, chosen by perceived (Rec. 601) relative luminance.
        """
        luminance = (
            _LUMINANCE_RED_WEIGHT * background.red()
            + _LUMINANCE_GREEN_WEIGHT * background.green()
            + _LUMINANCE_BLUE_WEIGHT * background.blue()
        ) / 255.0
        if luminance > _LUMINANCE_MIDPOINT:
            return QColor(0, 0, 0)
        return QColor(255, 255, 255)

    def clear_cache(self) -> None:
        """Clear the stylesheet cache."""
        cache_count = len(self.theme_cache)
        self.theme_cache.clear()
        _logger.info("theme_cache_cleared", entries_cleared=cache_count)

    @staticmethod
    def get_available_themes() -> list[str]:
        """Get list of available theme names.

        Returns:
            list[str]: List of theme names, including the restyled ``"dark2"``
            and ``"light2"`` variants and the ``"system"`` option that follows
            the OS light/dark preference.
        """
        return [THEME_DARK, THEME_LIGHT, THEME_DARK2, THEME_LIGHT2, THEME_SYSTEM]
