# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Custom hex editor widget using QPainter rendering.

Provides a high-performance hex editor view with virtual scrolling,
keyboard editing, mouse selection, and column-based display for
offset, hex, and ASCII data.
"""

from __future__ import annotations

import base64
import math
import struct
from dataclasses import dataclass
from typing import Any, Literal, cast, override

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
from intellicrack.ui.resources.font_manager import FontManager


_logger = get_logger("ui.panels.hex_editor_widget")

_BYTES_PER_ROW = 16
_OFFSET_CHARS = 10
_GAP_PX = 12
_MARGIN_PX = 4
_SCROLL_LINES = 3
_PRINTABLE_MIN = 0x20
_PRINTABLE_MAX = 0x7E
_MINIMAP_WIDTH = 32

_ENTROPY_LOW_COLOR = QColor("#4CAF50")
_ENTROPY_MED_COLOR = QColor("#FFC107")
_ENTROPY_HIGH_COLOR = QColor("#F44336")
_ENTROPY_LOW_THRESH = 3.5
_ENTROPY_HIGH_THRESH = 6.5


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

    Args:
        parent: Parent widget.

    Attributes:
        navigation_requested: Signal emitted with the target byte offset
            when the user clicks the minimap.
    """

    navigation_requested: pyqtSignal = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._entropy_values: list[float] = []
        self._total_size: int = 0
        self._viewport_start: int = 0
        self._viewport_end: int = 0
        self.setFixedWidth(_MINIMAP_WIDTH)
        self.setToolTip("Entropy minimap – click to navigate")

    def set_entropy_data(self, values: list[float], total_size: int) -> None:
        """Load entropy values for a file.

        Args:
            values: List of per-chunk Shannon entropy values (0.0–8.0).
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
        rect = self.rect()
        painter.fillRect(rect, QColor(25, 25, 25))

        if not self._entropy_values or self._total_size == 0:
            return

        h = rect.height()
        w = rect.width()
        count = len(self._entropy_values)

        for i, entropy in enumerate(self._entropy_values):
            y0 = int(i * h / count)
            y1 = int((i + 1) * h / count)
            segment_h = max(1, y1 - y0)

            if entropy < _ENTROPY_LOW_THRESH:
                color = _ENTROPY_LOW_COLOR
            elif entropy < _ENTROPY_HIGH_THRESH:
                t = (entropy - _ENTROPY_LOW_THRESH) / (_ENTROPY_HIGH_THRESH - _ENTROPY_LOW_THRESH)
                r = int(_ENTROPY_LOW_COLOR.red() + t * (_ENTROPY_MED_COLOR.red() - _ENTROPY_LOW_COLOR.red()))
                g = int(_ENTROPY_LOW_COLOR.green() + t * (_ENTROPY_MED_COLOR.green() - _ENTROPY_LOW_COLOR.green()))
                b = int(_ENTROPY_LOW_COLOR.blue() + t * (_ENTROPY_MED_COLOR.blue() - _ENTROPY_LOW_COLOR.blue()))
                color = QColor(r, g, b)
            else:
                t = min(1.0, (entropy - _ENTROPY_HIGH_THRESH) / (8.0 - _ENTROPY_HIGH_THRESH))
                r = int(_ENTROPY_MED_COLOR.red() + t * (_ENTROPY_HIGH_COLOR.red() - _ENTROPY_MED_COLOR.red()))
                g = int(_ENTROPY_MED_COLOR.green() + t * (_ENTROPY_HIGH_COLOR.green() - _ENTROPY_MED_COLOR.green()))
                b = int(_ENTROPY_MED_COLOR.blue() + t * (_ENTROPY_HIGH_COLOR.blue() - _ENTROPY_MED_COLOR.blue()))
                color = QColor(r, g, b)

            painter.fillRect(QRect(0, y0, w, segment_h), color)

        if self._viewport_end > self._viewport_start and self._total_size > 0:
            vp_y0 = int(self._viewport_start * h / self._total_size)
            vp_y1 = int(self._viewport_end * h / self._total_size)
            vp_h = max(2, vp_y1 - vp_y0)
            indicator = QColor(100, 150, 255, 100)
            painter.fillRect(QRect(0, vp_y0, w, vp_h), indicator)
            painter.setPen(QPen(QColor(150, 190, 255)))
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

    Args:
        parent: Parent widget.

    Attributes:
        cursor_moved: Signal emitted when the cursor position changes.
        selection_changed: Signal emitted when the selection range changes.
        data_changed: Signal emitted when data is modified.
        edit_mode_changed: Signal emitted when the edit mode changes.
    """

    DISPLAY_MODES: list[str] = list(_MODE_PARAMS.keys())

    cursor_moved: pyqtSignal = pyqtSignal(int)
    selection_changed: pyqtSignal = pyqtSignal(int, int)
    data_changed: pyqtSignal = pyqtSignal()
    edit_mode_changed: pyqtSignal = pyqtSignal(str)
    about_to_modify: pyqtSignal = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
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
        self._highlights: list[tuple[int, int, str]] = []
        self._highlight_sources: dict[str, list[tuple[int, int, str]]] = {}
        self._selecting: bool = False
        self._display_mode: str = "hex8"
        self._encoding: str = "ascii"
        self._highlight_rules: list[HighlightRule] = []

        self._setup_font()
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

    def _setup_font(self) -> None:
        """Configure monospace font for rendering."""
        font = FontManager.get_instance().get_code_font(10)
        self.setFont(font)
        metrics = QFontMetrics(font)
        self._char_width: int = metrics.horizontalAdvance("0")
        self._char_height: int = metrics.height()
        self._line_height: int = self._char_height + 2
        self._font_ascent: int = metrics.ascent()

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
        self._offset_col_width: int = _OFFSET_CHARS * cw
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
            raise ValueError(f"Unknown display mode: {mode!r}. Valid modes: {list(_MODE_PARAMS)}")
        self._display_mode = mode
        self._calculate_layout()
        self._update_viewport()

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

    def set_document(self, document: Any) -> None:
        """Attach a HexDocument to this widget.

        Args:
            document: HexDocument instance from the Rust core.
        """
        self._document = document
        self._cursor_offset = 0
        self._selection_start = -1
        self._selection_end = -1
        self._modified_offsets.clear()
        self._highlights.clear()
        self._highlight_sources.clear()
        self._nibble_index = 0

        total = self._total_rows()
        vbar = self.verticalScrollBar()
        if vbar is not None:
            vbar.setRange(0, max(0, total - self._visible_row_count()))
            vbar.setValue(0)
            vbar.setPageStep(self._visible_row_count())

        vp = self.viewport()
        if vp is not None:
            vp.update()
        _logger.debug("document_set", doc_length=self._doc_length())

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
        painter.fillRect(clip_rect, QColor(30, 30, 30))

        if self._document is None:
            painter.setPen(QColor(128, 128, 128))
            painter.drawText(50, 50, "No file loaded")
            return

        vbar = self.verticalScrollBar()
        first_row = vbar.value() if vbar is not None else 0
        visible_rows = self._visible_row_count()

        self._paint_separators(painter, clip_rect.height())
        self._paint_data_rows(painter, first_row, visible_rows)
        self._paint_highlight_overlays(painter, first_row, visible_rows)

    def _paint_separators(self, painter: QPainter, vp_height: int) -> None:
        """Draw column separator lines.

        Args:
            painter: Active QPainter instance.
            vp_height: Viewport height in pixels.
        """
        painter.setPen(QPen(QColor(60, 60, 60)))
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

            painter.setPen(QPen(QColor(100, 149, 237)))
            painter.drawText(self._offset_col_x, y, f"0x{row_offset:08X}")

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

            for col in range(bytes_in_row):
                byte_val = row_data[col] if col < len(row_data) else 0
                byte_offset = row_offset + col
                self._paint_ascii_byte(painter, row_idx, y, col, byte_val, byte_offset, sel_start, sel_end)

    @staticmethod
    def _read_row_data(read_fn: Any, offset: int, length: int) -> bytes:
        """Read a row of bytes from the document.

        Args:
            read_fn: Document read callable.
            offset: Start offset.
            length: Number of bytes to read.

        Returns:
            bytes: Bytes data for the row.
        """
        if not callable(read_fn):
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
            signed = b if b < 128 else b - 256
            return f"{signed:4d}"

        padded = group_bytes + bytes(max(0, padded_size - n))

        if mode == "hex16_le":
            return f"{cast('int', struct.unpack_from('<H', padded)[0]):04X}"
        if mode == "hex16_be":
            return f"{cast('int', struct.unpack_from('>H', padded)[0]):04X}"
        if mode in ["hex32_le", "rgba8"]:
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

        any_selected = False
        if sel_start >= 0:
            for bi in range(actual_size):
                if sel_start <= group_offset + bi <= sel_end:
                    any_selected = True
                    break

        any_modified = any((group_offset + bi) in self._modified_offsets for bi in range(actual_size))

        is_cursor = group_offset <= self._cursor_offset < group_offset + group_size

        highlight_color: str | None = None
        if not any_selected:
            for bi in range(actual_size):
                bv = group_bytes[bi] if bi < len(group_bytes) else 0
                hc = self._get_highlight_color(bv, group_offset + bi)
                if hc is not None:
                    highlight_color = hc
                    break

        if self._display_mode == "rgba8" and actual_size >= 3:
            r_ch = group_bytes[0]
            g_ch = group_bytes[1]
            b_ch = group_bytes[2]
            a_ch = group_bytes[3] if actual_size >= 4 else 255
            rgba_bg = QColor(r_ch, g_ch, b_ch, max(40, a_ch))
            painter.fillRect(QRect(hex_x - 1, row_idx * self._line_height, cell_w + 2, self._line_height), rgba_bg)

        if highlight_color is not None:
            hc_obj = QColor(highlight_color)
            hc_obj.setAlpha(120)
            painter.fillRect(QRect(hex_x - 1, row_idx * self._line_height, cell_w + 2, self._line_height), hc_obj)

        if any_selected:
            painter.fillRect(
                QRect(hex_x - 1, row_idx * self._line_height, cell_w + 2, self._line_height),
                QColor(51, 153, 255),
            )
            painter.setPen(QPen(QColor(255, 255, 255)))
        elif any_modified:
            painter.setPen(QPen(QColor(255, 80, 80)))
        elif all(b == 0 for b in group_bytes[:actual_size]):
            painter.setPen(QPen(QColor(80, 80, 80)))
        else:
            painter.setPen(QPen(QColor(212, 212, 212)))

        text = self._format_group(group_bytes, group_size)
        painter.drawText(hex_x, y, text)

        if is_cursor and self._active_column == "hex" and self.hasFocus():
            painter.setPen(QPen(QColor(255, 255, 255)))
            nibble_x = hex_x + self._nibble_index * self._char_width
            painter.drawRect(nibble_x - 1, row_idx * self._line_height, self._char_width, self._line_height - 1)

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
        """
        ascii_x = self._ascii_col_x + col * self._char_width
        if self._encoding == "ascii":
            ascii_ch = chr(byte_val) if _PRINTABLE_MIN <= byte_val <= _PRINTABLE_MAX else "."
        else:
            try:
                ascii_ch = bytes([byte_val]).decode(self._encoding, errors="replace")
                if len(ascii_ch) != 1 or not ascii_ch.isprintable():
                    ascii_ch = "."
            except (UnicodeDecodeError, LookupError):
                ascii_ch = "."
        is_selected = sel_start >= 0 and sel_start <= byte_offset <= sel_end

        highlight_color: str | None = None
        if not is_selected:
            highlight_color = self._get_highlight_color(byte_val, byte_offset)

        if highlight_color is not None:
            hc_obj = QColor(highlight_color)
            hc_obj.setAlpha(120)
            painter.fillRect(
                QRect(ascii_x - 1, row_idx * self._line_height, self._char_width + 1, self._line_height),
                hc_obj,
            )

        if is_selected:
            painter.fillRect(
                QRect(ascii_x - 1, row_idx * self._line_height, self._char_width + 1, self._line_height),
                QColor(51, 153, 255),
            )
            painter.setPen(QPen(QColor(255, 255, 255)))
        elif byte_offset in self._modified_offsets:
            painter.setPen(QPen(QColor(255, 80, 80)))
        elif byte_val == 0:
            painter.setPen(QPen(QColor(80, 80, 80)))
        else:
            painter.setPen(QPen(QColor(180, 200, 180)))

        painter.drawText(ascii_x, y, ascii_ch)

        if byte_offset == self._cursor_offset and self._active_column == "ascii" and self.hasFocus():
            painter.setPen(QPen(QColor(255, 255, 255)))
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

        key = event.key()
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
            self._move_cursor(self._cursor_offset - 1, shift)
        elif key == Qt.Key.Key_Right:
            self._move_cursor(self._cursor_offset + 1, shift)
        elif key == Qt.Key.Key_Up:
            self._move_cursor(self._cursor_offset - self._bytes_per_row, shift)
        elif key == Qt.Key.Key_Down:
            self._move_cursor(self._cursor_offset + self._bytes_per_row, shift)
        elif key == Qt.Key.Key_Home:
            if ctrl:
                self._move_cursor(0, shift)
            else:
                row_start = (self._cursor_offset // self._bytes_per_row) * self._bytes_per_row
                self._move_cursor(row_start, shift)
        elif key == Qt.Key.Key_End:
            if ctrl:
                self._move_cursor(doc_len - 1, shift)
            else:
                row_start = (self._cursor_offset // self._bytes_per_row) * self._bytes_per_row
                row_end = min(row_start + self._bytes_per_row - 1, doc_len - 1)
                self._move_cursor(row_end, shift)
        elif key in {Qt.Key.Key_PageUp, Qt.Key.Key_PageDown}:
            delta = self._visible_row_count() * self._bytes_per_row
            if key == Qt.Key.Key_PageUp:
                delta = -delta
            self._move_cursor(self._cursor_offset + delta, shift)
        elif key == Qt.Key.Key_Tab:
            self._active_column = "ascii" if self._active_column == "hex" else "hex"
            self._nibble_index = 0
            self._update_viewport()
        elif key == Qt.Key.Key_Insert:
            self._edit_mode = "insert" if self._edit_mode == "overwrite" else "overwrite"
            self.edit_mode_changed.emit(self._edit_mode)
            self._update_viewport()
        elif key in {Qt.Key.Key_Delete, Qt.Key.Key_Backspace}:
            self._do_delete(key == Qt.Key.Key_Backspace)
        elif text := event.text():
            if self._active_column == "hex":
                if text in "0123456789abcdefABCDEF":
                    self._handle_hex_input(text)
            elif (
                self._active_column == "ascii"
                and len(text) == 1
                and _PRINTABLE_MIN <= ord(text) <= _PRINTABLE_MAX
            ):
                self._handle_ascii_input(text)

    def _move_cursor(self, new_offset: int, extend_selection: bool = False) -> None:
        """Move the cursor to a new offset.

        Args:
            new_offset: Target offset.
            extend_selection: Whether to extend the current selection.
        """
        doc_len = self._doc_length()
        new_offset = max(0, min(new_offset, doc_len - 1)) if doc_len > 0 else 0

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
            self.about_to_modify.emit(self._cursor_offset)

            if self._edit_mode == "overwrite":
                write_fn = getattr(self._document, "write_bytes", None)
                if callable(write_fn):
                    try:
                        write_fn(self._cursor_offset, data)
                        self._modified_offsets.add(self._cursor_offset)
                    except (RuntimeError, ValueError, IndexError, OSError):
                        _logger.debug("write_failed", offset=self._cursor_offset)
            else:
                insert_fn = getattr(self._document, "insert_bytes", None)
                if callable(insert_fn):
                    try:
                        insert_fn(self._cursor_offset, data)
                        self._modified_offsets.add(self._cursor_offset)
                    except (RuntimeError, ValueError, IndexError, OSError):
                        _logger.debug("insert_failed", offset=self._cursor_offset)

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
        self.about_to_modify.emit(self._cursor_offset)

        if self._edit_mode == "overwrite":
            write_fn = getattr(self._document, "write_bytes", None)
            if callable(write_fn):
                try:
                    write_fn(self._cursor_offset, data)
                    self._modified_offsets.add(self._cursor_offset)
                except (RuntimeError, ValueError, IndexError, OSError):
                    _logger.debug("ascii_write_failed", offset=self._cursor_offset)
        else:
            insert_fn = getattr(self._document, "insert_bytes", None)
            if callable(insert_fn):
                try:
                    insert_fn(self._cursor_offset, data)
                    self._modified_offsets.add(self._cursor_offset)
                except (RuntimeError, ValueError, IndexError, OSError):
                    _logger.debug("ascii_insert_failed", offset=self._cursor_offset)

        self.data_changed.emit()
        self._move_cursor(self._cursor_offset + 1)

    def _do_delete(self, backspace: bool) -> None:
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
            for i in range(length):
                self.about_to_modify.emit(start + i)
            try:
                delete_fn(start, length)
                self._selection_start = -1
                self._selection_end = -1
                self.data_changed.emit()
                self._move_cursor(start)
            except (RuntimeError, ValueError, IndexError, OSError):
                _logger.debug("delete_selection_failed")
        else:
            offset = self._cursor_offset
            if backspace and offset > 0:
                offset -= 1
            self.about_to_modify.emit(offset)
            try:
                delete_fn(offset, 1)
                self.data_changed.emit()
                self._move_cursor(offset)
            except (RuntimeError, ValueError, IndexError, OSError):
                _logger.debug("delete_byte_failed", offset=offset)

        self._update_scrollbar()

    def _do_undo(self) -> None:
        """Perform undo operation."""
        if self._document is None:
            return
        undo_fn = getattr(self._document, "undo", None)
        if callable(undo_fn) and undo_fn():
            self._modified_offsets.clear()
            self.data_changed.emit()
            self._update_viewport()

    def _do_redo(self) -> None:
        """Perform redo operation."""
        if self._document is None:
            return
        redo_fn = getattr(self._document, "redo", None)
        if callable(redo_fn) and redo_fn():
            self._modified_offsets.clear()
            self.data_changed.emit()
            self._update_viewport()

    def _do_copy(self) -> None:
        """Copy selection to clipboard as hex string."""
        if text := self.copy_as("hex"):
            clipboard = QApplication.clipboard()
            if clipboard is not None:
                clipboard.setText(text)

    def _do_paste(self) -> None:
        """Paste clipboard content at cursor position.

        Attempts to parse clipboard text as a hex string first
        (e.g. "4D 5A 90"). Falls back to encoding the raw text
        as UTF-8 bytes.
        """
        if self._document is None:
            return
        clipboard = QApplication.clipboard()
        if clipboard is None:
            return
        text = clipboard.text()
        if not text:
            return

        data: bytes = b""
        stripped = text.replace(" ", "").replace("\n", "").replace("\r", "")
        if all(c in "0123456789abcdefABCDEF" for c in stripped) and len(stripped) % 2 == 0:
            try:
                data = bytes.fromhex(stripped)
            except ValueError:
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
                    for i in range(len(data)):
                        self._modified_offsets.add(self._cursor_offset + i)
                except (RuntimeError, ValueError, IndexError, OSError):
                    _logger.debug("paste_write_failed", offset=self._cursor_offset)
        else:
            insert_fn = getattr(self._document, "insert_bytes", None)
            if callable(insert_fn):
                try:
                    insert_fn(self._cursor_offset, data)
                    for i in range(len(data)):
                        self._modified_offsets.add(self._cursor_offset + i)
                except (RuntimeError, ValueError, IndexError, OSError):
                    _logger.debug("paste_insert_failed", offset=self._cursor_offset)

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

        delta = a0.angleDelta().y()
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
        """Position the entropy minimap to the right of the vertical scrollbar."""
        vbar = self.verticalScrollBar()
        vp = self.viewport()
        if vbar is None or vp is None:
            return
        vbar_geom = vbar.geometry()
        mm_x = vbar_geom.right() + 1
        mm_y = vp.geometry().top()
        mm_h = vp.geometry().height()
        self._minimap.setGeometry(mm_x, mm_y, _MINIMAP_WIDTH, mm_h)

    def show_minimap(self, visible: bool = True) -> None:
        """Show or hide the entropy minimap.

        Args:
            visible: True to show the minimap, False to hide it.
        """
        if visible:
            self._minimap.show()
            self._position_minimap()
        else:
            self._minimap.hide()

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
            parts = []
            for i, b in enumerate(data):
                suffix = "_u8" if i == 0 else ""
                parts.append(f"0x{b:02X}{suffix}")
            return f"[{', '.join(parts)}]"
        if fmt == "csharp_array":
            inner = ", ".join(f"0x{b:02X}" for b in data)
            return f"new byte[] {{ {inner} }}"
        if fmt == "java_array":
            parts = []
            for b in data:
                if b > 0x7F:
                    parts.append(f"(byte)0x{b:02X}")
                else:
                    parts.append(f"0x{b:02X}")
            return f"new byte[] {{ {', '.join(parts)} }}"
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
                    action.triggered.connect(lambda _checked, k=fmt_key: self._copy_as_action(k))

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
                    action.triggered.connect(lambda _checked, m=mode_key: self.set_display_mode(m))

        minimap_action = menu.addAction("Show Entropy Minimap")
        if minimap_action is not None:
            minimap_action.setCheckable(True)
            minimap_action.setChecked(self._minimap.isVisible())
            minimap_action.triggered.connect(self.show_minimap)

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
        self._encoding = encoding
        self._update_viewport()
