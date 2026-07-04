# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Custom hex editor widget using QPainter rendering.

Provides a high-performance hex editor view with virtual scrolling, keyboard editing, mouse selection, and column-based display for offset,
hex, and ASCII data.
"""

from __future__ import annotations

import base64
import math
import string
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, Literal, cast, override

from PyQt6.QtCore import QPoint, QRect, Qt, pyqtSignal
from PyQt6.QtGui import (
    QColor,
    QContextMenuEvent,
    QFontMetrics,
    QKeyEvent,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QPen,
    QResizeEvent,
    QWheelEvent,
)
from PyQt6.QtWidgets import QAbstractScrollArea, QApplication, QMenu, QWidget

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import GenericCallableWorker
from intellicrack.ui.panels.qt_compat import key_event_key, qt_key_page_down, qt_key_page_up, wheel_angle_delta_y
from intellicrack.ui.resources.font_manager import FontManager
from intellicrack.ui.resources.theme_manager import ThemeManager


if TYPE_CHECKING:
    from collections.abc import Callable, Iterable


_logger = get_logger(__name__)

_BYTES_PER_ROW = 16
_OFFSET_MIN_HEX_DIGITS = 8
_OFFSET_PREFIX_CHARS = 2
_GAP_PX = 12
_MARGIN_PX = 4
_SCROLL_LINES = 3
_PRINTABLE_MIN = 0x20
_PRINTABLE_MAX = 0x7E
_MINIMAP_WIDTH = 32

_ENTROPY_LOW_THRESH = 3.5
_ENTROPY_HIGH_THRESH = 6.5
_ENTROPY_MIN_BLOCK = 256
_ENTROPY_TARGET_BUCKETS = 2048

_ERR_UNKNOWN_MODE = "Unknown display mode"

_SIGNED_BYTE_THRESHOLD = 128
_MIN_RGB_BYTES = 3
_MIN_RGBA_BYTES = 4
_ASCII_MAX = 0x7F
_MAX_BYTE_VALUE = 255

_CONTENT_CLASS_BLOCK_SIZE = 256

_CONTENT_CLASS_COLOR_KEYS: dict[int, str] = {
    0: "content_null",
    1: "content_text",
    2: "content_generic",
    3: "content_compressed",
    4: "content_code",
}


def _entropy_value_to_color(
    entropy: float,
    low_color: QColor,
    mid_color: QColor,
    high_color: QColor,
) -> QColor:
    """Interpolate an entropy value to a color between low, mid, and high.

    Args:
        entropy: Shannon entropy value (0.0-8.0).
        low_color: Color for low entropy regions.
        mid_color: Color for mid entropy regions.
        high_color: Color for high entropy regions.

    Returns:
        QColor: Interpolated color for the given entropy value.
    """
    if entropy < _ENTROPY_LOW_THRESH:
        return low_color
    if entropy < _ENTROPY_HIGH_THRESH:
        t = (entropy - _ENTROPY_LOW_THRESH) / (_ENTROPY_HIGH_THRESH - _ENTROPY_LOW_THRESH)
        r = int(low_color.red() + t * (mid_color.red() - low_color.red()))
        g = int(low_color.green() + t * (mid_color.green() - low_color.green()))
        b = int(low_color.blue() + t * (mid_color.blue() - low_color.blue()))
        return QColor(r, g, b)
    t = min(1.0, (entropy - _ENTROPY_HIGH_THRESH) / (8.0 - _ENTROPY_HIGH_THRESH))
    r = int(mid_color.red() + t * (high_color.red() - mid_color.red()))
    g = int(mid_color.green() + t * (high_color.green() - mid_color.green()))
    b = int(mid_color.blue() + t * (high_color.blue() - mid_color.blue()))
    return QColor(r, g, b)


def _get_hex_editor_colors() -> dict[str, QColor]:
    """Get theme-aware colors for hex editor rendering.

    Returns:
        dict[str, QColor]: Mapping of semantic color names to QColor values.
    """
    if ThemeManager.get_instance().is_dark_theme():
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


@dataclass
class HighlightRule:
    """A conditional byte highlighting rule.

    Attributes:
        rule_id: Unique identifier for the rule.
        condition_type: One of "byte_value", "byte_range", or "pattern".
        condition_params: Parameters for the condition check.
        color: Background color as a hex string (e.g. "#FF0000").
        priority: Higher values take precedence when rules conflict.
    """

    rule_id: str
    condition_type: str
    condition_params: dict[str, Any]
    color: str
    priority: int = 0


class EntropyMiniMap(QWidget):
    """Scaled overview widget showing file entropy by region.

    Paints a compact vertical strip colored by Shannon entropy with a
    semi-transparent rectangle indicating the currently visible viewport.
    Clicking the minimap navigates the attached hex editor to that
    file position.

    Attributes:
        navigation_requested: Signal emitted with the target byte offset
            when the user clicks the minimap.
    """

    navigation_requested: pyqtSignal = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the EntropyMiniMap widget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._entropy_values: list[float] = []
        self._total_size: int = 0
        self._viewport_start: int = 0
        self._viewport_end: int = 0
        self._colors = _get_hex_editor_colors()
        self.setFixedWidth(_MINIMAP_WIDTH)
        self.setToolTip("Entropy minimap - click to navigate")

    def refresh_colors(self) -> None:
        """Refresh cached theme colors after theme change."""
        self._colors = _get_hex_editor_colors()
        self.update()

    def set_entropy_data(self, values: list[float], total_size: int) -> None:
        """Load entropy values for a file.

        Args:
            values: List of per-chunk Shannon entropy values (0.0-8.0).
            total_size: Total file size in bytes.
        """
        self._entropy_values = values
        self._total_size = total_size
        self.update()

    def set_viewport(self, start: int, end: int) -> None:
        """Update the visible-region indicator.

        Args:
            start: First visible byte offset.
            end: Last visible byte offset (exclusive).
        """
        self._viewport_start = start
        self._viewport_end = end
        self.update()

    @override
    def paintEvent(self, a0: QPaintEvent | None) -> None:
        """Paint the entropy overview and viewport indicator.

        Args:
            a0: Paint event (unused).
        """
        _ = a0
        painter = QPainter(self)
        try:
            self._draw_minimap(painter)
        finally:
            painter.end()

    def _draw_minimap(self, painter: QPainter) -> None:
        """Render the minimap content.

        Args:
            painter: Active QPainter instance.
        """
        colors = self._colors
        rect = self.rect()
        painter.fillRect(rect, colors["minimap_bg"])

        if not self._entropy_values or self._total_size == 0:
            return

        h = rect.height()
        w = rect.width()
        count = len(self._entropy_values)

        self._draw_entropy_bars(painter, w, h, count, colors)
        self._draw_viewport_indicator(painter, w, h, colors)

    def _draw_entropy_bars(
        self,
        painter: QPainter,
        w: int,
        h: int,
        count: int,
        colors: dict[str, QColor],
    ) -> None:
        """Paint per-chunk entropy bars onto the minimap.

        Args:
            painter: Active QPainter instance.
            w: Widget width in pixels.
            h: Widget height in pixels.
            count: Number of entropy chunks.
            colors: Theme color mapping.
        """
        entropy_low = colors["entropy_low"]
        entropy_mid = colors["entropy_mid"]
        entropy_high = colors["entropy_high"]

        for i, entropy in enumerate(self._entropy_values):
            y0 = int(i * h / count)
            y1 = int((i + 1) * h / count)
            segment_h = max(1, y1 - y0)
            color = _entropy_value_to_color(entropy, entropy_low, entropy_mid, entropy_high)
            painter.fillRect(QRect(0, y0, w, segment_h), color)

    def _draw_viewport_indicator(
        self,
        painter: QPainter,
        w: int,
        h: int,
        colors: dict[str, QColor],
    ) -> None:
        """Draw the semi-transparent viewport position indicator.

        Args:
            painter: Active QPainter instance.
            w: Widget width in pixels.
            h: Widget height in pixels.
            colors: Theme color mapping.
        """
        if self._viewport_end > self._viewport_start and self._total_size > 0:
            vp_y0 = int(self._viewport_start * h / self._total_size)
            vp_y1 = int(self._viewport_end * h / self._total_size)
            vp_h = max(2, vp_y1 - vp_y0)
            painter.fillRect(QRect(0, vp_y0, w, vp_h), colors["minimap_indicator"])
            painter.setPen(QPen(colors["minimap_indicator_border"]))
            painter.drawRect(0, vp_y0, w - 1, vp_h - 1)

    @override
    def mousePressEvent(self, a0: QMouseEvent | None) -> None:
        """Navigate to the clicked file position.

        Args:
            a0: Mouse event.
        """
        if a0 is None or self._total_size == 0:
            return
        fraction = a0.pos().y() / max(1, self.height())
        target = int(fraction * self._total_size)
        target = max(0, min(target, self._total_size - 1))
        self.navigation_requested.emit(target)


_MODE_PARAMS: dict[str, tuple[int, int]] = {
    "hex8": (1, 3),
    "hex16_le": (2, 5),
    "hex16_be": (2, 5),
    "hex32_le": (4, 9),
    "hex32_be": (4, 9),
    "hex64_le": (8, 17),
    "hex64_be": (8, 17),
    "dec_u8": (1, 4),
    "dec_u16": (2, 6),
    "dec_u32": (4, 11),
    "dec_s8": (1, 5),
    "dec_s16": (2, 7),
    "dec_s32": (4, 12),
    "float32": (4, 14),
    "float64": (8, 22),
    "rgba8": (4, 9),
    "hexii": (1, 3),
    "binary": (1, 9),
}

DISPLAY_MODES: list[str] = list(_MODE_PARAMS.keys())


class HexEditorWidget(QAbstractScrollArea):
    """Custom hex editor widget with QPainter rendering.

    Renders hex data in three columns (offset, hex, ASCII) with
    virtual scrolling for large file support, keyboard editing,
    mouse selection, and customizable display options.

    Attributes:
        DISPLAY_MODES: Available display mode names.
        cursor_moved: Signal emitted when the cursor position changes.
        selection_changed: Signal emitted when the selection range changes.
        data_changed: Signal emitted when data is modified.
        edit_mode_changed: Signal emitted when the edit mode changes.
        about_to_modify: Signal emitted before data modification at offset.
        status_message: Signal emitted with a status-bar message string
            (e.g. EOF clamp notifications from ``_move_cursor``).
    """

    DISPLAY_MODES: ClassVar[list[str]] = list(_MODE_PARAMS.keys())

    cursor_moved: pyqtSignal = pyqtSignal(int)
    selection_changed: pyqtSignal = pyqtSignal(int, int)
    data_changed: pyqtSignal = pyqtSignal()
    edit_mode_changed: pyqtSignal = pyqtSignal(str)
    about_to_modify: pyqtSignal = pyqtSignal(int)
    status_message: pyqtSignal = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the HexEditorWidget instance.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._document: Any | None = None
        self._bytes_per_row: int = _BYTES_PER_ROW
        self._cursor_offset: int = 0
        self._selection_start: int = -1
        self._selection_end: int = -1
        self._edit_mode: Literal["overwrite", "insert"] = "overwrite"
        self._active_column: Literal["hex", "ascii"] = "hex"
        self._nibble_index: int = 0
        self._pending_nibble: int = 0
        self._modified_offsets: set[int] = set()
        self._marks_undo: list[set[int]] = []
        self._marks_redo: list[set[int]] = []
        self._offset_hex_digits: int = _OFFSET_MIN_HEX_DIGITS
        self._highlights: list[tuple[int, int, str]] = []
        self._highlight_sources: dict[str, list[tuple[int, int, str]]] = {}
        self._selecting: bool = False
        self._display_mode: str = "hex8"
        self.encoding: str = "ascii"
        self._highlight_rules: list[HighlightRule] = []
        self._color_mode: str = "none"
        self._alignment_grid_size: int = 0
        self._va_mappings: list[tuple[int, int, int]] = []
        self._show_va: bool = False
        self._entropy_cache: list[float] = []
        self._content_class_cache: list[int] = []
        self._entropy_scan_active: bool = False
        self._entropy_scan_generation: int = 0
        self._entropy_scan_request_generation: int = -1
        self._content_class_scan_active: bool = False
        self._content_class_scan_generation: int = 0
        self._content_class_scan_request_generation: int = -1

        self._setup_font()
        self._colors = _get_hex_editor_colors()
        self._calculate_layout()

        focus_policy = getattr(Qt.FocusPolicy, "StrongFocus", Qt.FocusPolicy(11))
        self.setFocusPolicy(focus_policy)
        vp = self.viewport()
        if vp is not None:
            vp.setCursor(Qt.CursorShape.IBeamCursor)

        vbar = self.verticalScrollBar()
        if vbar is not None:
            vbar.setSingleStep(1)
            vbar.setPageStep(self._visible_row_count())
            vbar.valueChanged.connect(self._on_scroll_changed)

        self._minimap = EntropyMiniMap(self)
        self._minimap.navigation_requested.connect(self.goto_offset)
        self._minimap.hide()

        self.data_changed.connect(self._invalidate_color_caches)
        self.data_changed.connect(self._refresh_minimap_if_visible)
        ThemeManager.get_instance().theme_changed.connect(self._on_theme_changed)

    def _setup_font(self) -> None:
        """Configure monospace font for rendering."""
        font = FontManager.get_instance().get_code_font(10)
        self.setFont(font)
        metrics = QFontMetrics(font)
        self._char_width: int = metrics.horizontalAdvance("0")
        self._char_height: int = metrics.height()
        self._line_height: int = self._char_height + 2
        self._font_ascent: int = metrics.ascent()

    def refresh_colors(self) -> None:
        """Refresh cached theme colors after theme change."""
        self._colors = _get_hex_editor_colors()
        self._minimap.refresh_colors()
        self._update_viewport()

    def _on_theme_changed(self, resolved_theme: str) -> None:
        """Re-resolve cached theme colors when the active theme changes.

        Connected to :attr:`ThemeManager.theme_changed` so the custom-painted
        offset, separator, selection, and minimap colors track live theme
        switches without relying on the host to call
        :meth:`refresh_colors` manually.

        Args:
            resolved_theme: The concrete theme now active ("dark" or "light").
        """
        _ = resolved_theme
        self.refresh_colors()

    def _get_mode_params(self) -> tuple[int, int]:
        """Return (group_size, chars_per_group) for the current display mode.

        Returns:
            tuple[int, int]: Bytes per group and character width per group.
        """
        return _MODE_PARAMS.get(self._display_mode, (1, 3))

    def _calculate_layout(self) -> None:
        """Calculate column positions based on font metrics and display mode."""
        cw = self._char_width
        group_size, chars_per_group = self._get_mode_params()
        groups_per_row = max(1, _BYTES_PER_ROW // group_size)

        self._offset_col_x: int = _MARGIN_PX
        self._offset_col_width: int = (self._offset_hex_digits + _OFFSET_PREFIX_CHARS) * cw
        self._hex_col_x: int = self._offset_col_x + self._offset_col_width + _GAP_PX
        self._hex_col_width: int = (groups_per_row * (chars_per_group + 1) - 1) * cw
        self._ascii_col_x: int = self._hex_col_x + self._hex_col_width + _GAP_PX
        self._ascii_col_width: int = _BYTES_PER_ROW * cw
        self._total_width: int = self._ascii_col_x + self._ascii_col_width + _MARGIN_PX
        self.setMinimumWidth(self._total_width + 20)

    def set_display_mode(self, mode: str) -> None:
        """Change the hex column display format.

        Args:
            mode: One of the supported display mode names from DISPLAY_MODES.

        Raises:
            ValueError: If the mode string is not a recognised display mode.
        """
        if mode not in _MODE_PARAMS:
            _logger.warning(
                "hex_editor_invalid_display_mode",
                requested_mode=mode,
                valid_modes=list(_MODE_PARAMS),
            )
            msg = f"{_ERR_UNKNOWN_MODE}: {mode!r}. Valid modes: {list(_MODE_PARAMS)}"
            raise ValueError(msg)
        self._display_mode = mode
        self._calculate_layout()
        self._update_viewport()

    def set_alignment_grid_size(self, size: int) -> None:
        """Set the alignment grid column width and refresh the viewport.

        Args:
            size: Grid alignment size in bytes. Use 0 to disable alignment grid.
        """
        self._alignment_grid_size = size
        self.update()

    def set_color_mode(self, mode: str) -> None:
        """Change the byte color-mapping mode.

        Invalidates any cached per-byte colour data so that the next paint
        recomputes from the current document. Entropy and content-type data
        are recomputed lazily on a background worker thread the first time a
        paint handler needs them for the newly selected mode, so switching
        modes never blocks the GUI thread.

        Args:
            mode: Color mode string (``"none"``, ``"entropy"``,
                ``"byte_value"``, ``"content_type"``).
        """
        self._color_mode = mode
        self._invalidate_color_caches()
        self.update()

    def _invalidate_color_caches(self) -> None:
        """Drop cached entropy/content-type data and invalidate in-flight scans.

        Bumps the entropy and content-class scan generation counters so a background scan already running for now-stale data is discarded
        (and automatically retried) when it completes, instead of overwriting the cache with values computed before this edit.
        """
        self._entropy_cache = []
        self._content_class_cache = []
        self._entropy_scan_generation += 1
        self._content_class_scan_generation += 1

    def _entropy_block_size(self) -> int:
        """Choose an entropy block size bounding the bucket count for any file.

        Uses a fixed minimum block for small documents (fine detail) and grows
        the block size for large documents so the returned entropy list never
        exceeds :data:`_ENTROPY_TARGET_BUCKETS` entries, keeping the minimap
        render cost bounded regardless of file size.

        Returns:
            int: Block size in bytes for ``document.entropy_map``.
        """
        doc_len = self._doc_length()
        if doc_len <= 0:
            return _ENTROPY_MIN_BLOCK
        return max(_ENTROPY_MIN_BLOCK, math.ceil(doc_len / _ENTROPY_TARGET_BUCKETS))

    def _ensure_entropy_cache(self) -> list[float]:
        """Return the cached entropy values, starting a background scan if empty.

        Returns:
            list[float]: Per-block entropy values currently cached. May be
            empty immediately after an edit while a background scan
            (started by this call when needed) is still computing; the
            scan's completion callback triggers a follow-up repaint once
            real data is available.
        """
        if not self._entropy_cache:
            self._request_entropy_scan()
        return self._entropy_cache

    def _request_entropy_scan(self) -> None:
        """Start a background worker that populates the entropy cache.

        No-ops when no document is attached, the cache is already populated, or a scan is already in flight. Running
        ``document.entropy_map`` on a :class:`GenericCallableWorker` background thread keeps a full-document entropy scan from blocking the
        GUI thread on every edit while the entropy minimap or the entropy color mode is active.
        """
        if self._document is None or self._entropy_cache or self._entropy_scan_active:
            return
        entropy_fn = getattr(self._document, "entropy_map", None)
        if not callable(entropy_fn):
            return
        self._entropy_scan_active = True
        self._entropy_scan_request_generation = self._entropy_scan_generation
        worker = GenericCallableWorker(entropy_fn, self._entropy_block_size(), parent=self)
        _: object = worker.call_finished.connect(self._on_entropy_scan_finished)
        _ = worker.call_error.connect(self._on_entropy_scan_failed)
        worker.start()

    def _on_entropy_scan_finished(self, result: object) -> None:
        """Store a completed background entropy scan and refresh dependent views.

        Discards the result and immediately re-requests a fresh scan when
        the document was edited (generation bumped) while this scan was
        running, so the cache never settles on stale pre-edit data.

        Args:
            result: Per-block entropy values returned by the worker.
        """
        self._entropy_scan_active = False
        if self._entropy_scan_request_generation != self._entropy_scan_generation:
            self._request_entropy_scan()
            return
        try:
            self._entropy_cache = [float(v) for v in cast("Iterable[float]", result)]
        except (TypeError, ValueError):
            self._entropy_cache = []
        self._refresh_minimap_if_visible()
        self._update_viewport()

    def _on_entropy_scan_failed(self, exc: object) -> None:
        """Log a failed background entropy scan and reset scan state.

        Args:
            exc: Exception raised on the worker thread.
        """
        self._entropy_scan_active = False
        _logger.warning("entropy_map_failed", error=str(exc))
        self._entropy_cache = []

    def _refresh_minimap_entropy(self) -> None:
        """Compute file entropy and push it to the entropy minimap.

        Populates the entropy cache from the current document, forwards the per-block Shannon entropy values together with the document
        length to the minimap so it renders entropy bars sized to the whole file, then syncs the viewport indicator to the current scroll
        position.
        """
        doc_len = self._doc_length()
        if self._document is None or doc_len == 0:
            self._minimap.set_entropy_data([], 0)
            return
        values = self._ensure_entropy_cache()
        self._minimap.set_entropy_data(values, doc_len)
        vbar = self.verticalScrollBar()
        self._on_scroll_changed(vbar.value() if vbar is not None else 0)

    def _refresh_minimap_if_visible(self) -> None:
        """Recompute and push entropy to the minimap when it is visible."""
        if self._minimap.isVisible():
            self._refresh_minimap_entropy()

    def _ensure_content_class_cache(self) -> list[int]:
        """Return the cached content-class codes, starting a background scan if empty.

        Returns:
            list[int]: Per-bucket content-class codes currently cached. May
            be empty immediately after an edit while a background scan
            (started by this call when needed) is still computing.
        """
        if not self._content_class_cache:
            self._request_content_class_scan()
        return self._content_class_cache

    def _request_content_class_scan(self) -> None:
        """Start a background worker that populates the content-class cache.

        No-ops when no document is attached, the cache is already populated, or a scan is already in flight. Running
        ``document.content_classification`` on a :class:`GenericCallableWorker` background thread keeps a full-document classification scan
        from blocking the GUI thread.
        """
        if self._document is None or self._content_class_cache or self._content_class_scan_active:
            return
        class_fn = getattr(self._document, "content_classification", None)
        if not callable(class_fn):
            return
        self._content_class_scan_active = True
        self._content_class_scan_request_generation = self._content_class_scan_generation
        worker = GenericCallableWorker(class_fn, _CONTENT_CLASS_BLOCK_SIZE, parent=self)
        _: object = worker.call_finished.connect(self._on_content_class_scan_finished)
        _ = worker.call_error.connect(self._on_content_class_scan_failed)
        worker.start()

    def _on_content_class_scan_finished(self, result: object) -> None:
        """Store a completed background content-classification scan.

        Discards the result and immediately re-requests a fresh scan when
        the document was edited (generation bumped) while this scan was
        running, so the cache never settles on stale pre-edit data.

        Args:
            result: Per-block content-class codes returned by the worker.
        """
        self._content_class_scan_active = False
        if self._content_class_scan_request_generation != self._content_class_scan_generation:
            self._request_content_class_scan()
            return
        try:
            self._content_class_cache = [int(v) for v in cast("Iterable[int]", result)]
        except (TypeError, ValueError):
            self._content_class_cache = []
        self._update_viewport()

    def _on_content_class_scan_failed(self, exc: object) -> None:
        """Log a failed background content-classification scan and reset scan state.

        Args:
            exc: Exception raised on the worker thread.
        """
        self._content_class_scan_active = False
        _logger.warning("content_classification_failed", error=str(exc))
        self._content_class_cache = []

    def _color_mode_background(self, offset: int, byte_val: int) -> QColor | None:
        """Resolve the color-mode background for a byte at the given offset.

        Args:
            offset: Absolute byte offset used to index the block-level
                entropy and content-classification caches.
            byte_val: Raw byte value used by the byte-value heat map.

        Returns:
            QColor | None: Background color for the active color mode, or
            ``None`` when color mode is disabled or the relevant cached
            data is not yet available for this offset.
        """
        if self._color_mode == "entropy":
            return self._entropy_color_at(offset)
        if self._color_mode == "byte_value":
            return self._byte_value_color(byte_val)
        if self._color_mode == "content_type":
            return self._content_class_color_at(offset)
        return None

    def _entropy_color_at(self, offset: int) -> QColor | None:
        """Look up the entropy heat-map color for the block containing ``offset``.

        Args:
            offset: Absolute byte offset to resolve.

        Returns:
            QColor | None: Interpolated entropy color, or ``None`` when the
            entropy cache has no data for this offset yet.
        """
        values = self._ensure_entropy_cache()
        if not values:
            return None
        index = offset // self._entropy_block_size()
        if index >= len(values):
            return None
        return _entropy_value_to_color(
            values[index],
            self._colors["entropy_low"],
            self._colors["entropy_mid"],
            self._colors["entropy_high"],
        )

    def _byte_value_color(self, byte_val: int) -> QColor:
        """Map a raw byte value onto the low/mid/high entropy heat-map gradient.

        Args:
            byte_val: Raw byte value in the range 0-255.

        Returns:
            QColor: Heat-map color proportional to the byte's magnitude.
        """
        pseudo_entropy = (byte_val / _MAX_BYTE_VALUE) * 8.0
        return _entropy_value_to_color(
            pseudo_entropy,
            self._colors["entropy_low"],
            self._colors["entropy_mid"],
            self._colors["entropy_high"],
        )

    def _content_class_color_at(self, offset: int) -> QColor | None:
        """Look up the content-classification color for the block containing ``offset``.

        Args:
            offset: Absolute byte offset to resolve.

        Returns:
            QColor | None: Color for the block's classified content type,
            or ``None`` when the classification cache has no data for this
            offset yet or the class code is unrecognised.
        """
        values = self._ensure_content_class_cache()
        if not values:
            return None
        index = offset // _CONTENT_CLASS_BLOCK_SIZE
        if index >= len(values):
            return None
        color_key = _CONTENT_CLASS_COLOR_KEYS.get(values[index])
        if color_key is None:
            return None
        return self._colors[color_key]

    def _visible_row_count(self) -> int:
        """Calculate the number of rows visible in the viewport.

        Returns:
            int: Number of visible rows.
        """
        vp = self.viewport()
        return 1 if vp is None else max(1, vp.height() // self._line_height)

    def _doc_length(self) -> int:
        """Get the document length safely.

        Returns:
            int: Document length in bytes, or 0 if no document.
        """
        if self._document is None:
            return 0
        length_fn = getattr(self._document, "length", None)
        if callable(length_fn):
            result = length_fn()
            if isinstance(result, int):
                return result
        return 0

    def _total_rows(self) -> int:
        """Calculate total number of rows in the document.

        Returns:
            int: Total row count.
        """
        doc_len = self._doc_length()
        if doc_len == 0:
            return 0
        return (doc_len + self._bytes_per_row - 1) // self._bytes_per_row

    def set_document(self, document: object) -> None:
        """Attach a HexDocument to this widget.

        Args:
            document: HexDocument instance from the Rust core.
        """
        self._document = document
        self._cursor_offset = 0
        self._selection_start = -1
        self._selection_end = -1
        self._modified_offsets.clear()
        self._marks_undo.clear()
        self._marks_redo.clear()
        self._highlights.clear()
        self._highlight_sources.clear()
        self._nibble_index = 0
        self._invalidate_color_caches()

        self._offset_hex_digits = self._compute_offset_digits()
        self._calculate_layout()

        total = self._total_rows()
        vbar = self.verticalScrollBar()
        if vbar is not None:
            vbar.setRange(0, max(0, total - self._visible_row_count()))
            vbar.setValue(0)
            vbar.setPageStep(self._visible_row_count())

        vp = self.viewport()
        if vp is not None:
            vp.update()
        if self._minimap.isVisible():
            self._refresh_minimap_entropy()
            self._position_minimap()
        _logger.debug("document_set", doc_length=self._doc_length())

    def _compute_offset_digits(self) -> int:
        """Compute the hex-digit width needed to render the largest offset.

        Sizes the offset column to the current document length so offsets in
        files larger than 4 GiB (which need more than eight hex digits) render
        fully instead of overrunning into the hex column.

        Returns:
            int: Number of hex digits, at least :data:`_OFFSET_MIN_HEX_DIGITS`.
        """
        doc_len = self._doc_length()
        if doc_len <= 0:
            return _OFFSET_MIN_HEX_DIGITS
        max_offset = doc_len - 1
        needed = (max_offset.bit_length() + 3) // 4
        return max(_OFFSET_MIN_HEX_DIGITS, needed)

    def _on_scroll_changed(self, value: int) -> None:
        """Update the minimap viewport indicator on scroll.

        Args:
            value: New scrollbar row value.
        """
        doc_len = self._doc_length()
        if doc_len == 0:
            return
        start_byte = value * self._bytes_per_row
        end_byte = (value + self._visible_row_count()) * self._bytes_per_row
        self._minimap.set_viewport(start_byte, min(end_byte, doc_len))

    @override
    def paintEvent(self, a0: QPaintEvent | None) -> None:
        """Render the hex editor display.

        Args:
            a0: Paint event.
        """
        _ = a0
        vp = self.viewport()
        if vp is None:
            return
        painter = QPainter(vp)
        try:
            self._paint_content(painter, vp.rect())
        finally:
            painter.end()

    def _paint_content(self, painter: QPainter, clip_rect: QRect) -> None:
        """Paint all hex editor content.

        Args:
            painter: Active QPainter instance.
            clip_rect: Clipping rectangle for the viewport.
        """
        painter.fillRect(clip_rect, self._colors["editor_bg"])

        if self._document is None:
            painter.setPen(self._colors["offset_text"])
            painter.drawText(50, 50, "No file loaded")
            return

        vbar = self.verticalScrollBar()
        first_row = vbar.value() if vbar is not None else 0
        visible_rows = self._visible_row_count()

        self._paint_separators(painter, clip_rect.height())
        self._paint_data_rows(painter, first_row, visible_rows)
        self._paint_alignment_grid(painter, first_row, visible_rows)
        self._paint_highlight_overlays(painter, first_row, visible_rows)

    def _paint_alignment_grid(self, painter: QPainter, first_row: int, visible_rows: int) -> None:
        """Draw dashed marker lines at alignment-grid byte boundaries.

        No-ops when the alignment grid is disabled (size 0). Draws one
        dashed horizontal line across the offset, hex, and ASCII columns
        at the top of every visible row whose starting byte offset falls
        on an alignment-grid boundary.

        Args:
            painter: Active QPainter instance.
            first_row: First visible row index from scrollbar.
            visible_rows: Number of visible rows in the viewport.
        """
        grid_size = self._alignment_grid_size
        if grid_size <= 0:
            return
        doc_len = self._doc_length()
        right_edge = self._ascii_col_x + self._ascii_col_width
        painter.setPen(QPen(self._colors["alignment_grid"], 1, Qt.PenStyle.DashLine))
        for row_idx in range(visible_rows + 1):
            row_offset = (first_row + row_idx) * self._bytes_per_row
            if row_offset > doc_len:
                break
            if row_offset % grid_size != 0:
                continue
            y = row_idx * self._line_height
            painter.drawLine(self._offset_col_x, y, right_edge, y)

    def _paint_separators(self, painter: QPainter, vp_height: int) -> None:
        """Draw column separator lines.

        Args:
            painter: Active QPainter instance.
            vp_height: Viewport height in pixels.
        """
        painter.setPen(QPen(self._colors["separator"]))
        sep1_x = self._hex_col_x - _GAP_PX // 2
        sep2_x = self._ascii_col_x - _GAP_PX // 2
        painter.drawLine(sep1_x, 0, sep1_x, vp_height)
        painter.drawLine(sep2_x, 0, sep2_x, vp_height)

    def _paint_data_rows(self, painter: QPainter, first_row: int, visible_rows: int) -> None:
        """Paint offset, hex, and ASCII columns for visible rows.

        Args:
            painter: Active QPainter instance.
            first_row: First visible row index from scrollbar.
            visible_rows: Number of visible rows in the viewport.
        """
        doc_len = self._doc_length()
        sel_start = min(self._selection_start, self._selection_end) if self._selection_start >= 0 else -1
        sel_end = max(self._selection_start, self._selection_end) if self._selection_start >= 0 else -1
        read_fn = getattr(self._document, "read", None)
        group_size, _ = self._get_mode_params()

        for row_idx in range(visible_rows + 1):
            row_offset = (first_row + row_idx) * self._bytes_per_row
            if row_offset >= doc_len:
                break

            y = row_idx * self._line_height + self._font_ascent
            bytes_in_row = min(self._bytes_per_row, doc_len - row_offset)
            row_data = self._read_row_data(read_fn, row_offset, bytes_in_row)

            painter.setPen(QPen(self._colors["offset_text"]))
            painter.drawText(self._offset_col_x, y, f"0x{row_offset:0{self._offset_hex_digits}X}")

            self._paint_row_hex_groups(
                painter,
                row_idx,
                y,
                row_data,
                bytes_in_row,
                row_offset,
                group_size,
                sel_start,
                sel_end,
            )

            row_chars = self._decode_row_chars(row_offset, bytes_in_row, row_data)
            for col in range(bytes_in_row):
                byte_val = row_data[col] if col < len(row_data) else 0
                byte_offset = row_offset + col
                ascii_ch = row_chars[col] if col < len(row_chars) else "."
                self._paint_ascii_byte(
                    painter,
                    row_idx,
                    y,
                    col,
                    byte_val,
                    byte_offset,
                    sel_start,
                    sel_end,
                    ascii_ch,
                )

    def _paint_row_hex_groups(
        self,
        painter: QPainter,
        row_idx: int,
        y: int,
        row_data: bytes,
        bytes_in_row: int,
        row_offset: int,
        group_size: int,
        sel_start: int,
        sel_end: int,
    ) -> None:
        """Paint all hex groups for a single row.

        Args:
            painter: Active QPainter instance.
            row_idx: Visual row index in viewport.
            y: Y coordinate for text baseline.
            row_data: Raw bytes for the entire row.
            bytes_in_row: Number of valid bytes in the row.
            row_offset: Absolute byte offset of the first byte in this row.
            group_size: Bytes per display group.
            sel_start: Selection start offset (-1 if none).
            sel_end: Selection end offset (-1 if none).
        """
        groups_per_row = max(1, _BYTES_PER_ROW // group_size)
        for group_idx in range(groups_per_row):
            group_start_col = group_idx * group_size
            if group_start_col >= bytes_in_row:
                break
            actual_group_size = min(group_size, bytes_in_row - group_start_col)
            group_bytes = row_data[group_start_col : group_start_col + actual_group_size]
            group_offset = row_offset + group_start_col
            self._paint_hex_group(
                painter,
                row_idx,
                y,
                group_idx,
                group_bytes,
                actual_group_size,
                group_size,
                group_offset,
                sel_start,
                sel_end,
            )

    @staticmethod
    def _read_row_data(read_fn: Callable[[int, int], object] | None, offset: int, length: int) -> bytes:
        """Read a row of bytes from the document.

        Args:
            read_fn: Document read callable.
            offset: Start offset.
            length: Number of bytes to read.

        Returns:
            bytes: Bytes data for the row.
        """
        if read_fn is None:
            return b""
        raw = read_fn(offset, length)
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw)
        return bytes(cast("list[int]", raw)) if isinstance(raw, list) else b""

    def _format_group(self, group_bytes: bytes, padded_size: int) -> str:
        """Format a byte group as a display string for the current mode.

        Args:
            group_bytes: Actual bytes for this group (may be less than padded_size).
            padded_size: Expected group size in bytes (for multi-byte modes).

        Returns:
            str: Formatted string representation.
        """
        mode = self._display_mode
        n = len(group_bytes)

        if mode == "hex8":
            return f"{group_bytes[0]:02X}" if n > 0 else ".."
        if mode == "hexii":
            b = group_bytes[0] if n > 0 else 0
            return chr(b) if _PRINTABLE_MIN <= b <= _PRINTABLE_MAX else f"{b:02X}"
        if mode == "binary":
            b = group_bytes[0] if n > 0 else 0
            return f"{b:08b}"
        if mode == "dec_u8":
            b = group_bytes[0] if n > 0 else 0
            return f"{b:3d}"
        if mode == "dec_s8":
            b = group_bytes[0] if n > 0 else 0
            signed = b if b < _SIGNED_BYTE_THRESHOLD else b - 256
            return f"{signed:4d}"

        padded = group_bytes + bytes(max(0, padded_size - n))

        if mode == "hex16_le":
            return f"{cast('int', struct.unpack_from('<H', padded)[0]):04X}"
        if mode == "hex16_be":
            return f"{cast('int', struct.unpack_from('>H', padded)[0]):04X}"
        if mode in {"hex32_le", "rgba8"}:
            return f"{cast('int', struct.unpack_from('<I', padded)[0]):08X}"
        if mode == "hex32_be":
            return f"{cast('int', struct.unpack_from('>I', padded)[0]):08X}"
        if mode == "hex64_le":
            return f"{cast('int', struct.unpack_from('<Q', padded)[0]):016X}"
        if mode == "hex64_be":
            return f"{cast('int', struct.unpack_from('>Q', padded)[0]):016X}"
        if mode == "dec_u16":
            return f"{cast('int', struct.unpack_from('<H', padded)[0]):5d}"
        if mode == "dec_u32":
            return f"{cast('int', struct.unpack_from('<I', padded)[0]):10d}"
        if mode == "dec_s16":
            return f"{cast('int', struct.unpack_from('<h', padded)[0]):6d}"
        if mode == "dec_s32":
            return f"{cast('int', struct.unpack_from('<i', padded)[0]):11d}"
        if mode == "float32":
            try:
                val_f = cast("float", struct.unpack_from("<f", padded)[0])
            except struct.error:
                _logger.warning(
                    "hex_editor_float32_unpack_failed",
                    byte_count=len(padded),
                    expected=padded_size,
                )
                return "         ?"
            if math.isnan(val_f):
                return "       NaN"
            if math.isinf(val_f):
                return "       Inf" if val_f > 0 else "      -Inf"
            return f"{val_f:13.6g}"
        if mode == "float64":
            try:
                val_d = cast("float", struct.unpack_from("<d", padded)[0])
            except struct.error:
                _logger.warning(
                    "hex_editor_float64_unpack_failed",
                    byte_count=len(padded),
                    expected=padded_size,
                )
                return "                     ?"
            if math.isnan(val_d):
                return "                   NaN"
            if math.isinf(val_d):
                return "                   Inf" if val_d > 0 else "                  -Inf"
            return f"{val_d:21.10g}"
        return f"{group_bytes[0]:02X}" if n > 0 else ".."

    def _paint_hex_group(
        self,
        painter: QPainter,
        row_idx: int,
        y: int,
        group_idx: int,
        group_bytes: bytes,
        actual_size: int,
        group_size: int,
        group_offset: int,
        sel_start: int,
        sel_end: int,
    ) -> None:
        """Paint a group of bytes in the hex column.

        Args:
            painter: Active QPainter instance.
            row_idx: Visual row index in viewport.
            y: Y coordinate for text baseline.
            group_idx: Index of this group within the row.
            group_bytes: Raw bytes for this group.
            actual_size: Actual number of bytes (may be less than group_size at row end).
            group_size: Expected bytes per group for the current mode.
            group_offset: Absolute byte offset of the first byte in this group.
            sel_start: Selection start offset (-1 if none).
            sel_end: Selection end offset (-1 if none).
        """
        _, chars_per_group = self._get_mode_params()
        cell_chars = chars_per_group + 1
        hex_x = self._hex_col_x + group_idx * cell_chars * self._char_width
        cell_w = chars_per_group * self._char_width
        cell_rect = QRect(hex_x - 1, row_idx * self._line_height, cell_w + 2, self._line_height)

        any_selected = self._is_group_selected(group_offset, actual_size, sel_start, sel_end)
        any_modified = any((group_offset + bi) in self._modified_offsets for bi in range(actual_size))

        highlight_color = self._find_group_highlight(
            group_bytes,
            actual_size,
            group_offset,
            any_selected=any_selected,
        )

        self._paint_hex_group_background(
            painter,
            cell_rect,
            group_bytes,
            actual_size,
            highlight_color,
            group_offset,
            any_selected=any_selected,
        )
        self._set_hex_group_pen(
            painter,
            group_bytes,
            actual_size,
            any_selected=any_selected,
            any_modified=any_modified,
        )

        text = self._format_group(group_bytes, group_size)
        painter.drawText(hex_x, y, text)

        is_cursor = group_offset <= self._cursor_offset < group_offset + group_size
        if is_cursor and self._active_column == "hex" and self.hasFocus():
            painter.setPen(QPen(self._colors["cursor_text"]))
            caret_x, caret_w = self._hex_caret_geometry(hex_x, group_size, chars_per_group, group_offset)
            painter.drawRect(caret_x - 1, row_idx * self._line_height, caret_w, self._line_height - 1)

    def _hex_caret_geometry(self, hex_x: int, group_size: int, chars_per_group: int, group_offset: int) -> tuple[int, int]:
        """Compute the hex-column caret x-position and width for the cursor byte.

        For single-byte modes the caret tracks the active nibble. For
        multi-byte modes (16/32/64-bit hex, decimal and float) it tracks the
        cursor's byte position within the group, sized proportionally to the
        group's character width so the caret follows ``_cursor_offset`` instead
        of pinning to the group's first glyph.

        Args:
            hex_x: X coordinate of the group's first glyph.
            group_size: Bytes per display group for the current mode.
            chars_per_group: Character width of the group's formatted text.
            group_offset: Absolute byte offset of the group's first byte.

        Returns:
            tuple[int, int]: The caret x-position and width in pixels.
        """
        if group_size <= 1:
            return hex_x + self._nibble_index * self._char_width, self._char_width
        byte_in_group = max(0, min(group_size - 1, self._cursor_offset - group_offset))
        chars_per_byte = chars_per_group / group_size
        caret_x = hex_x + round(byte_in_group * chars_per_byte * self._char_width)
        caret_w = max(self._char_width, round(chars_per_byte * self._char_width))
        return caret_x, caret_w

    @staticmethod
    def _is_group_selected(group_offset: int, actual_size: int, sel_start: int, sel_end: int) -> bool:
        """Check whether any byte in the group falls within the selection.

        Args:
            group_offset: Absolute byte offset of the first byte in the group.
            actual_size: Number of bytes in the group.
            sel_start: Selection start offset (-1 if none).
            sel_end: Selection end offset (-1 if none).

        Returns:
            bool: True if at least one byte is selected.
        """
        if sel_start < 0:
            return False
        return any(sel_start <= group_offset + bi <= sel_end for bi in range(actual_size))

    def _find_group_highlight(
        self,
        group_bytes: bytes,
        actual_size: int,
        group_offset: int,
        *,
        any_selected: bool,
    ) -> str | None:
        """Find the first matching highlight color for a byte group.

        Args:
            group_bytes: Raw bytes for the group.
            actual_size: Number of valid bytes in the group.
            group_offset: Absolute byte offset of the first byte.
            any_selected: Whether any byte in the group is selected.

        Returns:
            str | None: Hex color string, or None if no highlight applies.
        """
        if any_selected:
            return None
        for bi in range(actual_size):
            bv = group_bytes[bi] if bi < len(group_bytes) else 0
            hc = self._get_highlight_color(bv, group_offset + bi)
            if hc is not None:
                return hc
        return None

    def _paint_hex_group_background(
        self,
        painter: QPainter,
        cell_rect: QRect,
        group_bytes: bytes,
        actual_size: int,
        highlight_color: str | None,
        group_offset: int,
        *,
        any_selected: bool,
    ) -> None:
        """Paint RGBA, color-mode, highlight, and selection backgrounds for a hex group.

        Args:
            painter: Active QPainter instance.
            cell_rect: Bounding rectangle for this hex group cell.
            group_bytes: Raw bytes for the group.
            actual_size: Number of valid bytes in the group.
            highlight_color: Optional hex color string from highlight rules.
            group_offset: Absolute byte offset of the first byte in the group.
            any_selected: Whether any byte in the group is selected.
        """
        if self._display_mode == "rgba8" and actual_size >= _MIN_RGB_BYTES:
            r_ch = group_bytes[0]
            g_ch = group_bytes[1]
            b_ch = group_bytes[2]
            a_ch = group_bytes[3] if actual_size >= _MIN_RGBA_BYTES else 255
            painter.fillRect(cell_rect, QColor(r_ch, g_ch, b_ch, max(40, a_ch)))
        elif actual_size > 0:
            mode_color = self._color_mode_background(group_offset, group_bytes[0])
            if mode_color is not None:
                painter.fillRect(cell_rect, mode_color)

        if highlight_color is not None:
            hc_obj = QColor(highlight_color)
            hc_obj.setAlpha(120)
            painter.fillRect(cell_rect, hc_obj)

        if any_selected:
            painter.fillRect(cell_rect, self._colors["selection_bg"])

    def _set_hex_group_pen(
        self,
        painter: QPainter,
        group_bytes: bytes,
        actual_size: int,
        *,
        any_selected: bool,
        any_modified: bool,
    ) -> None:
        """Set the painter pen color for hex group text.

        Args:
            painter: Active QPainter instance.
            group_bytes: Raw bytes for the group.
            actual_size: Number of valid bytes in the group.
            any_selected: Whether any byte in the group is selected.
            any_modified: Whether any byte in the group has been modified.
        """
        if any_selected:
            painter.setPen(QPen(self._colors["cursor_text"]))
        elif any_modified:
            painter.setPen(QPen(self._colors["hex_modified"]))
        elif all(b == 0 for b in group_bytes[:actual_size]):
            painter.setPen(QPen(self._colors["hex_zero"]))
        else:
            painter.setPen(QPen(self._colors["hex_normal"]))

    def _paint_hex_byte(
        self,
        painter: QPainter,
        row_idx: int,
        y: int,
        col: int,
        byte_val: int,
        byte_offset: int,
        sel_start: int,
        sel_end: int,
    ) -> None:
        """Paint a single byte in the hex column (hex8 mode only, kept for compatibility).

        Args:
            painter: Active QPainter instance.
            row_idx: Visual row index in viewport.
            y: Y coordinate for text baseline.
            col: Column index within the row.
            byte_val: Byte value to render.
            byte_offset: Absolute byte offset in document.
            sel_start: Selection start offset (-1 if none).
            sel_end: Selection end offset (-1 if none).
        """
        self._paint_hex_group(
            painter,
            row_idx,
            y,
            col,
            bytes([byte_val]),
            1,
            1,
            byte_offset,
            sel_start,
            sel_end,
        )

    def _decode_row_chars(self, row_offset: int, bytes_in_row: int, row_data: bytes) -> list[str]:
        """Decode one row's worth of bytes into printable ASCII-column characters.

        For ASCII encoding, produces a fast printable-byte mapping without
        calling into the document.  For every other encoding, delegates to
        the hexcore ``document.decode_text(offset, length, encoding)`` RPC
        (falling back to Python's codec only when the document does not
        expose that method) so the UI honours the document's canonical
        decoder.  Multi-byte codepoints are anchored at their leading byte
        and subsequent byte positions are padded with ``'.'`` to preserve
        column alignment.

        Args:
            row_offset: Absolute byte offset of the first byte in this row.
            bytes_in_row: Number of valid bytes in this row.
            row_data: Raw bytes already read for the row (fallback source).

        Returns:
            list[str]: Exactly ``bytes_in_row`` single-character strings.
        """
        if self.encoding == "ascii" or bytes_in_row <= 0:
            return [chr(b) if _PRINTABLE_MIN <= b <= _PRINTABLE_MAX else "." for b in row_data[:bytes_in_row]]
        chars: list[str] = ["." for _ in range(bytes_in_row)]
        decode_fn = getattr(self._document, "decode_text", None) if self._document is not None else None
        decoded: str | None = None
        if callable(decode_fn):
            try:
                raw_decoded: object = decode_fn(row_offset, bytes_in_row, self.encoding)
            except (RuntimeError, OSError, ValueError, LookupError, AttributeError):
                decoded = None
            else:
                decoded = raw_decoded if isinstance(raw_decoded, str) else None
        if decoded is None:
            try:
                decoded = bytes(row_data[:bytes_in_row]).decode(self.encoding, errors="replace")
            except (UnicodeDecodeError, LookupError):
                return chars
        per_byte = len(decoded) == bytes_in_row
        if per_byte:
            for i in range(bytes_in_row):
                ch = decoded[i]
                chars[i] = ch if ch.isprintable() else "."
            return chars
        ratio = max(1, bytes_in_row // max(1, len(decoded)))
        for glyph_index, ch in enumerate(decoded):
            col_index = glyph_index * ratio
            if col_index >= bytes_in_row:
                break
            chars[col_index] = ch if ch.isprintable() else "."
        return chars

    def _paint_ascii_byte(
        self,
        painter: QPainter,
        row_idx: int,
        y: int,
        col: int,
        byte_val: int,
        byte_offset: int,
        sel_start: int,
        sel_end: int,
        ascii_ch: str,
    ) -> None:
        """Paint a single byte in the ASCII column.

        Args:
            painter: Active QPainter instance.
            row_idx: Visual row index in viewport.
            y: Y coordinate for text baseline.
            col: Column index within the row.
            byte_val: Byte value to render.
            byte_offset: Absolute byte offset in document.
            sel_start: Selection start offset (-1 if none).
            sel_end: Selection end offset (-1 if none).
            ascii_ch: Pre-decoded character for this column from the row's
                decoded string (anchored at leading byte for multi-byte codecs).
        """
        ascii_x = self._ascii_col_x + col * self._char_width
        is_selected = sel_start >= 0 and sel_start <= byte_offset <= sel_end
        cell_rect = QRect(ascii_x - 1, row_idx * self._line_height, self._char_width + 1, self._line_height)

        highlight_color: str | None = None
        if not is_selected:
            highlight_color = self._get_highlight_color(byte_val, byte_offset)

        if not is_selected and highlight_color is None:
            mode_color = self._color_mode_background(byte_offset, byte_val)
            if mode_color is not None:
                painter.fillRect(cell_rect, mode_color)

        if highlight_color is not None:
            hc_obj = QColor(highlight_color)
            hc_obj.setAlpha(120)
            painter.fillRect(cell_rect, hc_obj)

        if is_selected:
            painter.fillRect(cell_rect, self._colors["selection_bg"])
            painter.setPen(QPen(self._colors["cursor_text"]))
        elif byte_offset in self._modified_offsets:
            painter.setPen(QPen(self._colors["hex_modified"]))
        elif byte_val == 0:
            painter.setPen(QPen(self._colors["ascii_nonprintable"]))
        else:
            painter.setPen(QPen(self._colors["ascii_printable"]))

        painter.drawText(ascii_x, y, ascii_ch)

        if byte_offset == self._cursor_offset and self._active_column == "ascii" and self.hasFocus():
            painter.setPen(QPen(self._colors["cursor_text"]))
            painter.drawRect(ascii_x - 1, row_idx * self._line_height, self._char_width, self._line_height - 1)

    def _paint_highlight_overlays(self, painter: QPainter, first_row: int, visible_rows: int) -> None:
        """Paint highlight overlays for bookmarks and templates.

        Args:
            painter: Active QPainter instance.
            first_row: First visible row index from scrollbar.
            visible_rows: Number of visible rows in the viewport.
        """
        group_size, chars_per_group = self._get_mode_params()
        cell_chars = chars_per_group + 1

        for h_offset, h_length, h_color_str in self._highlights:
            h_color = QColor(h_color_str)
            h_color.setAlpha(60)
            for i in range(h_length):
                byte_off = h_offset + i
                vis_row = byte_off // self._bytes_per_row - first_row
                if 0 <= vis_row <= visible_rows:
                    col_idx = byte_off % self._bytes_per_row
                    group_idx = col_idx // group_size
                    hx = self._hex_col_x + group_idx * cell_chars * self._char_width
                    hy = vis_row * self._line_height
                    painter.fillRect(QRect(hx - 1, hy, chars_per_group * self._char_width + 2, self._line_height), h_color)

    def _get_highlight_color(self, byte_val: int, offset: int) -> str | None:
        """Return the background color for a byte based on highlight rules.

        Evaluates all active highlight rules in priority order and returns
        the color from the highest-priority matching rule.

        Args:
            byte_val: The byte value at the given offset.
            offset: The absolute file offset of the byte.

        Returns:
            str | None: Hex color string, or None if no rule matches.
        """
        if not self._highlight_rules:
            return None

        best_priority = -1
        best_color: str | None = None

        for rule in self._highlight_rules:
            if rule.priority < best_priority:
                continue
            matched = False
            if rule.condition_type == "byte_value":
                matched = byte_val == cast("int", rule.condition_params.get("value", -1))
            elif rule.condition_type == "byte_range":
                lo = cast("int", rule.condition_params.get("min", 0))
                hi = cast("int", rule.condition_params.get("max", 255))
                matched = lo <= byte_val <= hi
            elif rule.condition_type == "pattern":
                offsets_set = cast("set[int]", rule.condition_params.get("offsets", set()))
                matched = offset in offsets_set
            if matched:
                best_priority = rule.priority
                best_color = rule.color

        return best_color

    def add_highlight_rule(self, rule: HighlightRule) -> None:
        """Add a conditional byte highlight rule.

        Args:
            rule: The highlight rule to add.
        """
        self._highlight_rules.append(rule)
        self._highlight_rules.sort(key=lambda r: r.priority, reverse=True)
        self._update_viewport()

    def remove_highlight_rule(self, rule_id: str) -> bool:
        """Remove a highlight rule by its identifier.

        Args:
            rule_id: The unique rule identifier to remove.

        Returns:
            bool: True if a rule was removed, False if not found.
        """
        before = len(self._highlight_rules)
        self._highlight_rules = [r for r in self._highlight_rules if r.rule_id != rule_id]
        removed = len(self._highlight_rules) < before
        if removed:
            self._update_viewport()
        return removed

    def clear_highlight_rules(self) -> None:
        """Remove all conditional highlight rules."""
        self._highlight_rules.clear()
        self._update_viewport()

    def get_highlight_rules(self) -> list[HighlightRule]:
        """Return a copy of the current highlight rule list.

        Returns:
            list[HighlightRule]: Active highlight rules ordered by priority descending.
        """
        return list(self._highlight_rules)

    @override
    def keyPressEvent(self, a0: QKeyEvent | None) -> None:
        """Handle keyboard input for editing and navigation.

        Args:
            a0: Key event.
        """
        event = a0
        if event is None:
            return

        key = key_event_key(event)
        modifiers = event.modifiers()
        ctrl = bool(modifiers & Qt.KeyboardModifier.ControlModifier)
        shift = bool(modifiers & Qt.KeyboardModifier.ShiftModifier)
        doc_len = self._doc_length()

        if doc_len == 0:
            return

        if ctrl and key == Qt.Key.Key_Z:
            self._do_undo()
            return
        if ctrl and key == Qt.Key.Key_Y:
            self._do_redo()
            return
        if ctrl and key == Qt.Key.Key_C:
            self._do_copy()
            return
        if ctrl and key == Qt.Key.Key_V:
            self._do_paste()
            return
        if ctrl and key == Qt.Key.Key_A:
            self._selection_start = 0
            self._selection_end = doc_len - 1
            self.selection_changed.emit(0, doc_len - 1)
            self._update_viewport()
            return

        if key == Qt.Key.Key_Left:
            self._move_cursor(self._cursor_offset - 1, extend_selection=shift)
        elif key == Qt.Key.Key_Right:
            self._move_cursor(self._cursor_offset + 1, extend_selection=shift)
        elif key == Qt.Key.Key_Up:
            self._move_cursor(self._cursor_offset - self._bytes_per_row, extend_selection=shift)
        elif key == Qt.Key.Key_Down:
            self._move_cursor(self._cursor_offset + self._bytes_per_row, extend_selection=shift)
        elif key == Qt.Key.Key_Home:
            if ctrl:
                self._move_cursor(0, extend_selection=shift)
            else:
                row_start = (self._cursor_offset // self._bytes_per_row) * self._bytes_per_row
                self._move_cursor(row_start, extend_selection=shift)
        elif key == Qt.Key.Key_End:
            if ctrl:
                self._move_cursor(doc_len - 1, extend_selection=shift)
            else:
                row_start = (self._cursor_offset // self._bytes_per_row) * self._bytes_per_row
                row_end = min(row_start + self._bytes_per_row - 1, doc_len - 1)
                self._move_cursor(row_end, extend_selection=shift)
        elif key in {qt_key_page_up(), qt_key_page_down()}:
            delta = self._visible_row_count() * self._bytes_per_row
            if key == qt_key_page_up():
                delta = -delta
            self._move_cursor(self._cursor_offset + delta, extend_selection=shift)
        elif key == Qt.Key.Key_Tab:
            self._active_column = "ascii" if self._active_column == "hex" else "hex"
            self._nibble_index = 0
            self._update_viewport()
        elif key == Qt.Key.Key_Insert:
            self._edit_mode = "insert" if self._edit_mode == "overwrite" else "overwrite"
            self.edit_mode_changed.emit(self._edit_mode)
            self._update_viewport()
        elif key in {Qt.Key.Key_Delete, Qt.Key.Key_Backspace}:
            self._do_delete(backspace=key == Qt.Key.Key_Backspace)
        elif text := event.text():
            if self._active_column == "hex":
                if text in string.hexdigits:
                    self._handle_hex_input(text)
            elif self._active_column == "ascii" and len(text) == 1 and _PRINTABLE_MIN <= ord(text) <= _PRINTABLE_MAX:
                self._handle_ascii_input(text)

    def _move_cursor(self, new_offset: int, *, extend_selection: bool = False) -> None:
        """Move the cursor to a new offset, clamping to the document range.

        Emits ``status_message`` when the requested offset fell outside the
        document so callers can surface the condition to the user.

        Args:
            new_offset: Target offset.
            extend_selection: Whether to extend the current selection.
        """
        doc_len = self._doc_length()
        requested = new_offset
        new_offset = max(0, min(new_offset, doc_len - 1)) if doc_len > 0 else 0
        if requested != new_offset:
            self.status_message.emit(f"Offset 0x{requested:X} is beyond EOF (0x{max(0, doc_len - 1):X}); clamped.")

        if extend_selection:
            if self._selection_start < 0:
                self._selection_start = self._cursor_offset
            self._selection_end = new_offset
            self.selection_changed.emit(
                min(self._selection_start, self._selection_end),
                max(self._selection_start, self._selection_end),
            )
        else:
            self._selection_start = -1
            self._selection_end = -1

        self._cursor_offset = new_offset
        self._nibble_index = 0
        self._ensure_visible(new_offset)
        self.cursor_moved.emit(new_offset)
        self._update_viewport()

    def _push_marks_undo(self) -> None:
        """Snapshot the current modified-byte marks before a fresh edit.

        Pushes a copy of the current marks onto the undo stack and clears the redo stack, mirroring the document's own undo history so a
        later undo can restore exactly the marks that preceded this edit.
        """
        self._marks_undo.append(set(self._modified_offsets))
        self._marks_redo.clear()

    def _restore_marks_undo(self) -> None:
        """Revert the modified-byte marks to the state before the last edit.

        Restores the snapshot recorded by :meth:`_push_marks_undo`, pushing the current marks onto the redo stack. Falls back to clearing
        all marks when no snapshot exists (edits made before mark tracking began).
        """
        if self._marks_undo:
            self._marks_redo.append(set(self._modified_offsets))
            self._modified_offsets = self._marks_undo.pop()
        else:
            self._modified_offsets.clear()

    def _restore_marks_redo(self) -> None:
        """Reapply the modified-byte marks removed by the last undo.

        Restores the snapshot recorded on the redo stack by
        :meth:`_restore_marks_undo`, pushing the current marks back onto the
        undo stack. Falls back to clearing all marks when no snapshot exists.
        """
        if self._marks_redo:
            self._marks_undo.append(set(self._modified_offsets))
            self._modified_offsets = self._marks_redo.pop()
        else:
            self._modified_offsets.clear()

    def _shift_modified_offsets_for_insert(self, offset: int, count: int) -> None:
        """Shift modified-byte marks to track an insertion.

        Args:
            offset: Byte offset where bytes were inserted.
            count: Number of bytes inserted.
        """
        if count <= 0 or not self._modified_offsets:
            return
        self._modified_offsets = {o + count if o >= offset else o for o in self._modified_offsets}

    def _shift_modified_offsets_for_delete(self, offset: int, count: int) -> None:
        """Shift modified-byte marks to track a deletion.

        Marks within the deleted range are dropped and marks after it move
        left by the deleted byte count so highlights keep tracking the correct
        bytes.

        Args:
            offset: First deleted byte offset.
            count: Number of bytes deleted.
        """
        if count <= 0 or not self._modified_offsets:
            return
        remapped: set[int] = set()
        for o in self._modified_offsets:
            if o < offset:
                remapped.add(o)
            elif o >= offset + count:
                remapped.add(o - count)
        self._modified_offsets = remapped

    def _handle_hex_input(self, char: str) -> None:
        """Process a hex digit input character.

        Args:
            char: Single hex character (0-9, a-f, A-F).
        """
        if self._document is None:
            return

        nibble_val = int(char, 16)

        if self._nibble_index == 0:
            self._pending_nibble = nibble_val
            self._nibble_index = 1
            self._update_viewport()
        else:
            byte_val = (self._pending_nibble << 4) | nibble_val
            data = bytes([byte_val])
            _logger.debug("hex_editor_hex_input_started", offset=self._cursor_offset, mode=self._edit_mode)
            self.about_to_modify.emit(self._cursor_offset)

            if self._edit_mode == "overwrite":
                write_fn = getattr(self._document, "write_bytes", None)
                if callable(write_fn):
                    try:
                        write_fn(self._cursor_offset, data)
                        self._push_marks_undo()
                        self._modified_offsets.add(self._cursor_offset)
                        _logger.info("hex_editor_overwrite_completed", offset=self._cursor_offset)
                    except (RuntimeError, ValueError, IndexError, OSError):
                        _logger.warning("hex_editor_overwrite_failed", offset=self._cursor_offset, exc_info=True)
            else:
                insert_fn = getattr(self._document, "insert_bytes", None)
                if callable(insert_fn):
                    try:
                        insert_fn(self._cursor_offset, data)
                        self._push_marks_undo()
                        self._shift_modified_offsets_for_insert(self._cursor_offset, len(data))
                        self._modified_offsets.add(self._cursor_offset)
                        _logger.debug("hex_editor_insert_completed", offset=self._cursor_offset)
                    except (RuntimeError, ValueError, IndexError, OSError):
                        _logger.warning("hex_editor_insert_failed", offset=self._cursor_offset, exc_info=True)

            self._nibble_index = 0
            self._pending_nibble = 0
            self.data_changed.emit()
            self._move_cursor(self._cursor_offset + 1)

    def _handle_ascii_input(self, char: str) -> None:
        """Process an ASCII character input.

        Args:
            char: Single printable ASCII character.
        """
        if self._document is None:
            return

        data = char.encode("ascii")
        _logger.debug("hex_editor_ascii_input_started", offset=self._cursor_offset, mode=self._edit_mode)
        self.about_to_modify.emit(self._cursor_offset)

        if self._edit_mode == "overwrite":
            write_fn = getattr(self._document, "write_bytes", None)
            if callable(write_fn):
                try:
                    write_fn(self._cursor_offset, data)
                    self._push_marks_undo()
                    self._modified_offsets.add(self._cursor_offset)
                    _logger.info("hex_editor_ascii_overwrite_completed", offset=self._cursor_offset)
                except (RuntimeError, ValueError, IndexError, OSError):
                    _logger.warning("hex_editor_ascii_overwrite_failed", offset=self._cursor_offset, exc_info=True)
        else:
            insert_fn = getattr(self._document, "insert_bytes", None)
            if callable(insert_fn):
                try:
                    insert_fn(self._cursor_offset, data)
                    self._push_marks_undo()
                    self._shift_modified_offsets_for_insert(self._cursor_offset, len(data))
                    self._modified_offsets.add(self._cursor_offset)
                    _logger.debug("hex_editor_ascii_insert_completed", offset=self._cursor_offset)
                except (RuntimeError, ValueError, IndexError, OSError):
                    _logger.warning("hex_editor_ascii_insert_failed", offset=self._cursor_offset, exc_info=True)

        self.data_changed.emit()
        self._move_cursor(self._cursor_offset + 1)

    def _delete_selection_impl(self, delete_fn: Callable[[int, int], object], start: int, length: int) -> None:
        """Delete ``length`` bytes starting at ``start`` and refresh selection state.

        Args:
            delete_fn: The document's ``delete_bytes`` callable.
            start: First byte offset of the selection.
            length: Number of bytes to delete.
        """
        delete_fn(start, length)
        self._push_marks_undo()
        self._shift_modified_offsets_for_delete(start, length)
        self._selection_start = -1
        self._selection_end = -1
        self.data_changed.emit()
        self._move_cursor(start)
        _logger.info("hex_editor_delete_selection_completed", start=start, length=length)

    def _delete_byte_impl(self, delete_fn: Callable[[int, int], object], offset: int) -> None:
        """Delete a single byte at ``offset`` and refresh cursor and mark state.

        Args:
            delete_fn: The document's ``delete_bytes`` callable.
            offset: The byte offset to delete.
        """
        delete_fn(offset, 1)
        self._push_marks_undo()
        self._shift_modified_offsets_for_delete(offset, 1)
        self.data_changed.emit()
        self._move_cursor(offset)
        _logger.info("hex_editor_delete_byte_completed", offset=offset)

    def _do_delete(self, *, backspace: bool) -> None:
        """Delete byte(s) at cursor or selection.

        Args:
            backspace: True if backspace key, False if delete key.
        """
        if self._document is None:
            return

        delete_fn = getattr(self._document, "delete_bytes", None)
        if not callable(delete_fn):
            return

        if self._selection_start >= 0:
            start = min(self._selection_start, self._selection_end)
            end = max(self._selection_start, self._selection_end)
            length = end - start + 1
            _logger.info("hex_editor_delete_selection_started", start=start, length=length)
            for i in range(length):
                self.about_to_modify.emit(start + i)
            try:
                self._delete_selection_impl(delete_fn, start, length)
            except (RuntimeError, ValueError, IndexError, OSError):
                _logger.warning("hex_editor_delete_selection_failed", exc_info=True)
        else:
            offset = self._cursor_offset
            if backspace and offset > 0:
                offset -= 1
            _logger.info("hex_editor_delete_byte_started", offset=offset, backspace=backspace)
            self.about_to_modify.emit(offset)
            try:
                self._delete_byte_impl(delete_fn, offset)
            except (RuntimeError, ValueError, IndexError, OSError):
                _logger.warning("hex_editor_delete_byte_failed", offset=offset, exc_info=True)

        self._update_scrollbar()

    def _do_undo(self) -> None:
        """Perform undo operation."""
        if self._document is None:
            return
        undo_fn = getattr(self._document, "undo", None)
        if callable(undo_fn):
            _logger.info("hex_editor_undo_started")
            if undo_fn():
                self._restore_marks_undo()
                self.data_changed.emit()
                self._update_viewport()
                _logger.info("hex_editor_undo_completed")
            else:
                _logger.debug("hex_editor_undo_noop")

    def _do_redo(self) -> None:
        """Perform redo operation."""
        if self._document is None:
            return
        redo_fn = getattr(self._document, "redo", None)
        if callable(redo_fn):
            _logger.info("hex_editor_redo_started")
            if redo_fn():
                self._restore_marks_redo()
                self.data_changed.emit()
                self._update_viewport()
                _logger.info("hex_editor_redo_completed")
            else:
                _logger.debug("hex_editor_redo_noop")

    def _do_copy(self) -> None:
        """Copy selection to clipboard as hex string."""
        if text := self.copy_as("hex"):
            clipboard = QApplication.clipboard()
            if clipboard is not None:
                clipboard.setText(text)

    def _do_paste(self) -> None:
        """Paste clipboard content at cursor position.

        Attempts to parse clipboard text as a hex string first (e.g. "4D 5A 90"). Falls back to encoding the raw text as UTF-8 bytes.
        """
        if self._document is None:
            return
        clipboard = QApplication.clipboard()
        if clipboard is None:
            return
        text = clipboard.text()
        if not text:
            return
        _logger.info("hex_editor_paste_started", offset=self._cursor_offset, clipboard_length=len(text), mode=self._edit_mode)

        data: bytes = b""
        stripped = text.replace(" ", "").replace("\n", "").replace("\r", "")
        if all(c in string.hexdigits for c in stripped) and len(stripped) % 2 == 0:
            try:
                data = bytes.fromhex(stripped)
            except ValueError:
                _logger.warning("hex_editor_paste_hex_parse_failed_fallback_utf8", length=len(text), exc_info=True)
                data = text.encode("utf-8")
        else:
            data = text.encode("utf-8")

        if not data:
            return

        for i in range(len(data)):
            self.about_to_modify.emit(self._cursor_offset + i)

        if self._edit_mode == "overwrite":
            write_fn = getattr(self._document, "write_bytes", None)
            if callable(write_fn):
                try:
                    write_fn(self._cursor_offset, data)
                    self._push_marks_undo()
                    for i in range(len(data)):
                        self._modified_offsets.add(self._cursor_offset + i)
                    _logger.info("hex_editor_paste_overwrite_completed", offset=self._cursor_offset, length=len(data))
                except (RuntimeError, ValueError, IndexError, OSError):
                    _logger.warning("hex_editor_paste_overwrite_failed", offset=self._cursor_offset, exc_info=True)
        else:
            insert_fn = getattr(self._document, "insert_bytes", None)
            if callable(insert_fn):
                try:
                    insert_fn(self._cursor_offset, data)
                    self._push_marks_undo()
                    self._shift_modified_offsets_for_insert(self._cursor_offset, len(data))
                    for i in range(len(data)):
                        self._modified_offsets.add(self._cursor_offset + i)
                    _logger.debug("hex_editor_paste_insert_completed", offset=self._cursor_offset, length=len(data))
                except (RuntimeError, ValueError, IndexError, OSError):
                    _logger.warning("hex_editor_paste_insert_failed", offset=self._cursor_offset, exc_info=True)

        self.data_changed.emit()
        self._update_scrollbar()
        self._move_cursor(self._cursor_offset + len(data))

    @override
    def mousePressEvent(self, a0: QMouseEvent | None) -> None:
        """Handle mouse press for cursor positioning.

        Args:
            a0: Mouse event.
        """
        event = a0
        if event is None or self._document is None:
            return

        pos = event.pos()
        offset = self._offset_from_point(pos)
        if offset is None:
            return

        if bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier):
            if self._selection_start < 0:
                self._selection_start = self._cursor_offset
            self._selection_end = offset
            self.selection_changed.emit(
                min(self._selection_start, self._selection_end),
                max(self._selection_start, self._selection_end),
            )
        else:
            self._selection_start = offset
            self._selection_end = offset
            self._selecting = True

        self._cursor_offset = offset
        self._nibble_index = 0
        self.cursor_moved.emit(offset)
        self._update_viewport()

    @override
    def mouseMoveEvent(self, a0: QMouseEvent | None) -> None:
        """Handle mouse drag for selection.

        Args:
            a0: Mouse event.
        """
        event = a0
        if event is None or not self._selecting or self._document is None:
            return

        pos = event.pos()
        offset = self._offset_from_point(pos)
        if offset is None:
            return

        self._selection_end = offset
        self._cursor_offset = offset
        self.selection_changed.emit(
            min(self._selection_start, self._selection_end),
            max(self._selection_start, self._selection_end),
        )
        self.cursor_moved.emit(offset)
        self._update_viewport()

    @override
    def mouseReleaseEvent(self, a0: QMouseEvent | None) -> None:
        """Handle mouse release to finalize selection.

        Args:
            a0: Mouse event.
        """
        if a0 is None:
            return
        self._selecting = False
        if self._selection_start >= 0 and self._selection_start == self._selection_end:
            self._selection_start = -1
            self._selection_end = -1

    @override
    def wheelEvent(self, a0: QWheelEvent | None) -> None:
        """Handle mouse wheel for scrolling.

        Args:
            a0: Wheel event.
        """
        if a0 is None:
            return

        delta = wheel_angle_delta_y(a0)
        lines = _SCROLL_LINES if delta < 0 else -_SCROLL_LINES

        vbar = self.verticalScrollBar()
        if vbar is not None:
            vbar.setValue(vbar.value() + lines)

    @override
    def resizeEvent(self, a0: QResizeEvent | None) -> None:
        """Handle widget resize and reposition the minimap.

        Args:
            a0: Resize event.
        """
        super().resizeEvent(a0)
        self._update_scrollbar()
        self._position_minimap()

    def _position_minimap(self) -> None:
        """Position the entropy minimap inside the reserved right viewport margin.

        The minimap occupies the margin carved by :meth:`show_minimap` between the viewport's right edge and the vertical scrollbar, so it
        stays within the widget bounds instead of being clipped past the scrollbar.
        """
        vp = self.viewport()
        if vp is None or not self._minimap.isVisible():
            return
        vp_geom = vp.geometry()
        mm_x = vp_geom.right() + 1
        self._minimap.setGeometry(mm_x, vp_geom.top(), _MINIMAP_WIDTH, vp_geom.height())

    def show_minimap(self, *, visible: bool = True) -> None:
        """Show or hide the entropy minimap.

        When shown, reserves a right viewport margin the width of the minimap
        so it renders within the widget, computes and pushes file entropy into
        it, then positions it. When hidden, the reserved margin is released.

        Args:
            visible: True to show the minimap, False to hide it.
        """
        if visible:
            self.setViewportMargins(0, 0, _MINIMAP_WIDTH, 0)
            self._minimap.show()
            self._refresh_minimap_entropy()
            self._position_minimap()
        else:
            self._minimap.hide()
            self.setViewportMargins(0, 0, 0, 0)
        self._update_scrollbar()
        self._update_viewport()

    def _update_scrollbar(self) -> None:
        """Update scrollbar range based on document size and viewport."""
        total = self._total_rows()
        visible = self._visible_row_count()
        vbar = self.verticalScrollBar()
        if vbar is not None:
            vbar.setRange(0, max(0, total - visible))
            vbar.setPageStep(visible)

    def _offset_from_point(self, pos: QPoint) -> int | None:
        """Determine the byte offset from a screen position.

        Args:
            pos: Point in viewport coordinates.

        Returns:
            int | None: Byte offset, or None if the point is outside the data area.
        """
        x = pos.x()
        y = pos.y()

        vbar = self.verticalScrollBar()
        first_row = vbar.value() if vbar is not None else 0
        row = first_row + y // self._line_height

        col: int | None = None

        if self._hex_col_x <= x < self._hex_col_x + self._hex_col_width:
            group_size, chars_per_group = self._get_mode_params()
            cell_chars = chars_per_group + 1
            pixel_in_hex = x - self._hex_col_x
            group_idx = pixel_in_hex // (cell_chars * self._char_width)
            col = group_idx * group_size
            self._active_column = "hex"
        elif self._ascii_col_x <= x < self._ascii_col_x + self._ascii_col_width:
            col = (x - self._ascii_col_x) // self._char_width
            self._active_column = "ascii"

        if col is None or col < 0 or col >= self._bytes_per_row:
            return None

        offset = row * self._bytes_per_row + col
        doc_len = self._doc_length()
        if offset >= doc_len:
            return doc_len - 1 if doc_len > 0 else None

        return offset

    def _ensure_visible(self, offset: int) -> None:
        """Scroll to ensure the given offset is visible.

        Args:
            offset: Byte offset to make visible.
        """
        row = offset // self._bytes_per_row
        vbar = self.verticalScrollBar()
        if vbar is None:
            return

        first_row = vbar.value()
        visible = self._visible_row_count()

        if row < first_row:
            vbar.setValue(row)
        elif row >= first_row + visible:
            vbar.setValue(row - visible + 1)

    def _update_viewport(self) -> None:
        """Trigger a viewport repaint."""
        vp = self.viewport()
        if vp is not None:
            vp.update()

    def goto_offset(self, offset: int) -> None:
        """Navigate to a specific byte offset.

        Args:
            offset: Target byte offset.
        """
        self._move_cursor(offset, extend_selection=False)

    def set_selection_range(self, start: int, end: int) -> None:
        """Set the selection range programmatically.

        Clamps both offsets to the document range and emits
        :attr:`selection_changed` so downstream consumers (data inspector,
        selection hash, scripting API, bridge) stay in sync instead of holding
        stale or out-of-range values. When the document is empty the selection
        is cleared and a cleared range is emitted.

        Args:
            start: Start byte offset of the selection.
            end: End byte offset of the selection.
        """
        doc_len = self._doc_length()
        if doc_len <= 0:
            self._selection_start = -1
            self._selection_end = -1
            self.selection_changed.emit(-1, -1)
            self._update_viewport()
            return
        max_offset = doc_len - 1
        clamped_start = max(0, min(start, max_offset))
        clamped_end = max(0, min(end, max_offset))
        self._selection_start = clamped_start
        self._selection_end = clamped_end
        self.selection_changed.emit(min(clamped_start, clamped_end), max(clamped_start, clamped_end))
        self._update_viewport()

    def get_selection_bytes(self) -> bytes:
        """Get the bytes in the current selection.

        Returns:
            bytes: Selected bytes, or empty bytes if no selection.
        """
        if self._document is None or self._selection_start < 0:
            return b""

        start = min(self._selection_start, self._selection_end)
        end = max(self._selection_start, self._selection_end)
        length = end - start + 1

        read_fn = getattr(self._document, "read", None)
        if callable(read_fn):
            raw = read_fn(start, length)
            if isinstance(raw, (bytes, bytearray)):
                return bytes(raw)
            if isinstance(raw, list):
                return bytes(cast("list[int]", raw))
        return b""

    def copy_as(self, fmt: str = "hex") -> str:
        """Format the current selection as a string.

        Args:
            fmt: Output format identifier. Supported values are "hex",
                "c_array", "python", "base64", "rust_array",
                "csharp_array", "java_array", "javascript_array",
                "go_slice", "hex_string_no_spaces", "nasm_db", and
                "markdown_table".

        Returns:
            str: Formatted string representation of the selected bytes.
        """
        data = self.get_selection_bytes()
        if not data and (self._document is not None and self._cursor_offset < self._doc_length()):
            read_fn = getattr(self._document, "read", None)
            if callable(read_fn):
                raw = read_fn(self._cursor_offset, 1)
                if isinstance(raw, (bytes, bytearray)):
                    data = bytes(raw)
                elif isinstance(raw, list):
                    data = bytes(cast("list[int]", raw))
        return self.copy_as_format(fmt, data) if data else ""

    def copy_as_format(self, fmt: str, data: bytes | None = None) -> str:
        """Format bytes as a string in the specified language format.

        Args:
            fmt: Output format identifier. Supported values are "hex",
                "c_array", "python", "base64", "rust_array",
                "csharp_array", "java_array", "javascript_array",
                "go_slice", "hex_string_no_spaces", "nasm_db", and
                "markdown_table".
            data: Bytes to format. Uses the current selection if None.

        Returns:
            str: Formatted string representation.
        """
        if data is None:
            data = self.get_selection_bytes()
        if not data:
            return ""

        if fmt == "hex":
            return " ".join(f"{b:02X}" for b in data)
        if fmt == "c_array":
            inner = ", ".join(f"0x{b:02X}" for b in data)
            return f"{{{inner}}}"
        if fmt == "python":
            inner = "".join(f"\\x{b:02x}" for b in data)
            return f'b"{inner}"'
        if fmt == "base64":
            return base64.b64encode(data).decode("ascii")
        if fmt == "rust_array":
            parts: list[str] = []
            for i, b in enumerate(data):
                suffix = "_u8" if i == 0 else ""
                parts.append(f"0x{b:02X}{suffix}")
            return f"[{', '.join(parts)}]"
        if fmt == "csharp_array":
            inner = ", ".join(f"0x{b:02X}" for b in data)
            return f"new byte[] {{ {inner} }}"
        if fmt == "java_array":
            java_parts: list[str] = []
            for b in data:
                if b > _ASCII_MAX:
                    java_parts.append(f"(byte)0x{b:02X}")
                else:
                    java_parts.append(f"0x{b:02X}")
            return f"new byte[] {{ {', '.join(java_parts)} }}"
        if fmt == "javascript_array":
            inner = ", ".join(f"0x{b:02X}" for b in data)
            return f"new Uint8Array([{inner}])"
        if fmt == "go_slice":
            inner = ", ".join(f"0x{b:02X}" for b in data)
            return f"[]byte{{{inner}}}"
        if fmt == "hex_string_no_spaces":
            return "".join(f"{b:02X}" for b in data)
        if fmt == "nasm_db":
            inner = ", ".join(f"0x{b:02X}" for b in data)
            return f"db {inner}"
        return self._format_markdown_table(data) if fmt == "markdown_table" else ""

    def _format_markdown_table(self, data: bytes) -> str:
        """Format bytes as a Markdown table with Offset, Hex, and ASCII columns.

        Args:
            data: Bytes to format.

        Returns:
            str: Markdown table string with 16 bytes per row.
        """
        row_size = 16
        lines: list[str] = ["| Offset | Hex | ASCII |", "|--------|-----|-------|"]
        sel_start = min(self._selection_start, self._selection_end) if self._selection_start >= 0 else 0

        for row_start in range(0, len(data), row_size):
            chunk = data[row_start : row_start + row_size]
            offset = sel_start + row_start
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if _PRINTABLE_MIN <= b <= _PRINTABLE_MAX else "." for b in chunk)
            lines.append(f"| 0x{offset:08X} | {hex_part} | {ascii_part} |")

        return "\n".join(lines)

    @override
    def contextMenuEvent(self, a0: QContextMenuEvent | None) -> None:
        """Show the right-click context menu.

        Args:
            a0: Context menu event.
        """
        if a0 is None:
            return

        menu = QMenu(self)

        has_selection = self._selection_start >= 0
        has_data = self._document is not None and self._doc_length() > 0

        copy_as_menu = menu.addMenu("Copy As")
        if copy_as_menu is not None and has_data:
            formats: list[tuple[str, str]] = [
                ("hex", "Hex (4D 5A 90)"),
                ("hex_string_no_spaces", "Hex no spaces (4D5A90)"),
                ("c_array", "C array ({0x4D, 0x5A})"),
                ("python", 'Python (b"\\x4d\\x5a")'),
                ("base64", "Base64"),
                ("rust_array", "Rust array ([0x4D_u8, ...])"),
                ("csharp_array", "C# array (new byte[] {...})"),
                ("java_array", "Java array (new byte[] {...})"),
                ("javascript_array", "JavaScript (new Uint8Array([...]))"),
                ("go_slice", "Go slice ([]byte{...})"),
                ("nasm_db", "NASM db (db 0x4D, 0x5A)"),
                ("markdown_table", "Markdown table"),
            ]
            for fmt_key, fmt_label in formats:
                action = copy_as_menu.addAction(fmt_label)
                if action is not None:
                    action.setEnabled(has_selection or has_data)

                    def _copy_as_slot(_checked: int, k: str = fmt_key) -> None:
                        self._copy_as_action(k)

                    action.triggered.connect(_copy_as_slot)

        display_menu = menu.addMenu("Display Mode")
        if display_menu is not None:
            mode_labels: dict[str, str] = {
                "hex8": "Hex 8-bit",
                "hex16_le": "Hex 16-bit LE",
                "hex16_be": "Hex 16-bit BE",
                "hex32_le": "Hex 32-bit LE",
                "hex32_be": "Hex 32-bit BE",
                "hex64_le": "Hex 64-bit LE",
                "hex64_be": "Hex 64-bit BE",
                "dec_u8": "Decimal u8",
                "dec_u16": "Decimal u16",
                "dec_u32": "Decimal u32",
                "dec_s8": "Decimal s8",
                "dec_s16": "Decimal s16",
                "dec_s32": "Decimal s32",
                "float32": "Float 32-bit",
                "float64": "Float 64-bit",
                "rgba8": "RGBA color",
                "hexii": "HexII",
                "binary": "Binary",
            }
            for mode_key, mode_label in mode_labels.items():
                action = display_menu.addAction(mode_label)
                if action is not None:
                    action.setCheckable(True)
                    action.setChecked(self._display_mode == mode_key)

                    def _mode_slot(_checked: int, m: str = mode_key) -> None:
                        self.set_display_mode(m)

                    action.triggered.connect(_mode_slot)

        minimap_action = menu.addAction("Show Entropy Minimap")
        if minimap_action is not None:
            minimap_action.setCheckable(True)
            minimap_action.setChecked(self._minimap.isVisible())

            def _minimap_slot(v: int) -> None:
                self.show_minimap(visible=bool(v))

            minimap_action.triggered.connect(_minimap_slot)

        menu.exec(a0.globalPos())

    def _copy_as_action(self, fmt: str) -> None:
        """Execute a copy-as action and put the result on the clipboard.

        Args:
            fmt: Format key string passed to copy_as_format.
        """
        if text := self.copy_as(fmt):
            clipboard = QApplication.clipboard()
            if clipboard is not None:
                clipboard.setText(text)

    def highlight_offsets(
        self,
        highlights: list[tuple[int, int, str]],
        source: str = "default",
    ) -> None:
        """Set highlight regions for template/bookmark visualization.

        Each source maintains its own set of highlights. The merged result
        of all sources is used for rendering.

        Args:
            highlights: List of (offset, length, color_hex_string) tuples.
            source: Identifier for the highlight source (e.g. "search",
                "yara", "template", "bookmark").
        """
        self._highlight_sources[source] = highlights
        self._rebuild_highlights()
        self._update_viewport()

    def clear_highlights(self, source: str) -> None:
        """Remove all highlights from a specific source.

        Args:
            source: The source identifier whose highlights should be cleared.
        """
        if source in self._highlight_sources:
            del self._highlight_sources[source]
            self._rebuild_highlights()
            self._update_viewport()

    def _rebuild_highlights(self) -> None:
        """Merge all per-source highlights into the flat rendering list."""
        merged: list[tuple[int, int, str]] = []
        for source_highlights in self._highlight_sources.values():
            merged.extend(source_highlights)
        self._highlights = merged

    def set_encoding(self, encoding: str) -> None:
        """Set the text encoding used for the ASCII column display.

        Args:
            encoding: Encoding name (e.g. "ascii", "utf-8", "latin-1").
        """
        self.encoding = encoding
        self._update_viewport()
