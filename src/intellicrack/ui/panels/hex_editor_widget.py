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
from typing import TYPE_CHECKING, Any, Literal, cast, override

from PyQt6.QtCore import QPoint, QRect, Qt, pyqtSignal
from PyQt6.QtGui import (
    QColor,
    QFont,
    QFontDatabase,
    QFontMetrics,
    QKeyEvent,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QPen,
    QResizeEvent,
    QWheelEvent,
)
from PyQt6.QtWidgets import QAbstractScrollArea, QApplication

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

_logger = get_logger("ui.panels.hex_editor_widget")

_BYTES_PER_ROW = 16
_OFFSET_CHARS = 10
_GAP_PX = 12
_MARGIN_PX = 4
_HEX_CHARS_PER_BYTE = 3
_SCROLL_LINES = 3
_PRINTABLE_MIN = 0x20
_PRINTABLE_MAX = 0x7E


class HexEditorWidget(QAbstractScrollArea):
    """Custom hex editor widget with QPainter rendering.

    Renders hex data in three columns (offset, hex, ASCII) with
    virtual scrolling for large file support, keyboard editing,
    mouse selection, and customizable display options.

    Attributes:
        _document: The HexDocument instance from the Rust core.
        _bytes_per_row: Number of bytes displayed per row.
        _cursor_offset: Current cursor position in the document.
        _selection_start: Start offset of the current selection.
        _selection_end: End offset of the current selection.
        _edit_mode: Current editing mode (overwrite or insert).
        _active_column: Which column is active for input.
        _nibble_index: Current nibble position during hex input.
        _modified_offsets: Set of byte offsets that have been modified.
        _highlights: List of highlight regions for templates/bookmarks.
    """

    cursor_moved: pyqtSignal = pyqtSignal(int)
    selection_changed: pyqtSignal = pyqtSignal(int, int)
    data_changed: pyqtSignal = pyqtSignal()
    edit_mode_changed: pyqtSignal = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the hex editor widget.

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
        self._highlights: list[tuple[int, int, str]] = []
        self._selecting: bool = False

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

    def _setup_font(self) -> None:
        """Configure monospace font for rendering."""
        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        families = QFontDatabase.families()
        if "Consolas" not in families:
            if "Courier New" in families:
                font = QFont("Courier New", 10)
            else:
                font.setFamily("monospace")
        font.setFixedPitch(True)
        self.setFont(font)
        metrics = QFontMetrics(font)
        self._char_width: int = metrics.horizontalAdvance("0")
        self._char_height: int = metrics.height()
        self._line_height: int = self._char_height + 2
        self._font_ascent: int = metrics.ascent()

    def _calculate_layout(self) -> None:
        """Calculate column positions based on font metrics."""
        cw = self._char_width
        self._offset_col_x: int = _MARGIN_PX
        self._offset_col_width: int = _OFFSET_CHARS * cw
        self._hex_col_x: int = self._offset_col_x + self._offset_col_width + _GAP_PX
        self._hex_col_width: int = (_BYTES_PER_ROW * _HEX_CHARS_PER_BYTE - 1) * cw
        self._ascii_col_x: int = self._hex_col_x + self._hex_col_width + _GAP_PX
        self._ascii_col_width: int = _BYTES_PER_ROW * cw
        self._total_width: int = self._ascii_col_x + self._ascii_col_width + _MARGIN_PX
        self.setMinimumWidth(self._total_width + 20)

    def _visible_row_count(self) -> int:
        """Calculate the number of rows visible in the viewport.

        Returns:
            Number of visible rows.
        """
        vp = self.viewport()
        if vp is None:
            return 1
        return max(1, vp.height() // self._line_height)

    def _doc_length(self) -> int:
        """Get the document length safely.

        Returns:
            Document length in bytes, or 0 if no document.
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
            Total row count.
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

        for row_idx in range(visible_rows + 1):
            row_offset = (first_row + row_idx) * self._bytes_per_row
            if row_offset >= doc_len:
                break

            y = row_idx * self._line_height + self._font_ascent
            bytes_in_row = min(self._bytes_per_row, doc_len - row_offset)
            row_data = self._read_row_data(read_fn, row_offset, bytes_in_row)

            painter.setPen(QPen(QColor(100, 149, 237)))
            painter.drawText(self._offset_col_x, y, f"0x{row_offset:08X}")

            for col in range(bytes_in_row):
                byte_val = row_data[col] if col < len(row_data) else 0
                byte_offset = row_offset + col
                self._paint_hex_byte(painter, row_idx, y, col, byte_val, byte_offset, sel_start, sel_end)
                self._paint_ascii_byte(painter, row_idx, y, col, byte_val, byte_offset, sel_start, sel_end)

    @staticmethod
    def _read_row_data(read_fn: Any, offset: int, length: int) -> bytes:
        """Read a row of bytes from the document.

        Args:
            read_fn: Document read callable.
            offset: Start offset.
            length: Number of bytes to read.

        Returns:
            Bytes data for the row.
        """
        if not callable(read_fn):
            return b""
        raw = read_fn(offset, length)
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw)
        if isinstance(raw, list):
            return bytes(cast("list[int]", raw))
        return b""

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
        """Paint a single byte in the hex column.

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
        hex_x = self._hex_col_x + col * _HEX_CHARS_PER_BYTE * self._char_width
        is_selected = sel_start >= 0 and sel_start <= byte_offset <= sel_end

        if is_selected:
            painter.fillRect(
                QRect(hex_x - 1, row_idx * self._line_height, self._char_width * 2 + 2, self._line_height),
                QColor(51, 153, 255),
            )
            painter.setPen(QPen(QColor(255, 255, 255)))
        elif byte_offset in self._modified_offsets:
            painter.setPen(QPen(QColor(255, 80, 80)))
        elif byte_val == 0:
            painter.setPen(QPen(QColor(80, 80, 80)))
        else:
            painter.setPen(QPen(QColor(212, 212, 212)))

        painter.drawText(hex_x, y, f"{byte_val:02X}")

        if byte_offset == self._cursor_offset and self._active_column == "hex" and self.hasFocus():
            painter.setPen(QPen(QColor(255, 255, 255)))
            nibble_x = hex_x + self._nibble_index * self._char_width
            painter.drawRect(nibble_x - 1, row_idx * self._line_height, self._char_width, self._line_height - 1)

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
        ascii_ch = chr(byte_val) if _PRINTABLE_MIN <= byte_val <= _PRINTABLE_MAX else "."
        is_selected = sel_start >= 0 and sel_start <= byte_offset <= sel_end

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
        for h_offset, h_length, h_color_str in self._highlights:
            h_color = QColor(h_color_str)
            h_color.setAlpha(60)
            for i in range(h_length):
                byte_off = h_offset + i
                vis_row = byte_off // self._bytes_per_row - first_row
                if 0 <= vis_row <= visible_rows:
                    col_idx = byte_off % self._bytes_per_row
                    hx = self._hex_col_x + col_idx * _HEX_CHARS_PER_BYTE * self._char_width
                    hy = vis_row * self._line_height
                    painter.fillRect(QRect(hx - 1, hy, self._char_width * 2 + 2, self._line_height), h_color)

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
        else:
            text = event.text()
            if text and self._active_column == "hex":
                if text in "0123456789abcdefABCDEF":
                    self._handle_hex_input(text)
            elif text and self._active_column == "ascii" and len(text) == 1 and _PRINTABLE_MIN <= ord(text) <= _PRINTABLE_MAX:
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

            if self._edit_mode == "overwrite":
                write_fn = getattr(self._document, "write_bytes", None)
                if callable(write_fn):
                    try:
                        write_fn(self._cursor_offset, data)
                        self._modified_offsets.add(self._cursor_offset)
                    except Exception:
                        _logger.debug("write_failed", offset=self._cursor_offset)
            else:
                insert_fn = getattr(self._document, "insert_bytes", None)
                if callable(insert_fn):
                    try:
                        insert_fn(self._cursor_offset, data)
                        self._modified_offsets.add(self._cursor_offset)
                    except Exception:
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

        if self._edit_mode == "overwrite":
            write_fn = getattr(self._document, "write_bytes", None)
            if callable(write_fn):
                try:
                    write_fn(self._cursor_offset, data)
                    self._modified_offsets.add(self._cursor_offset)
                except Exception:
                    _logger.debug("ascii_write_failed", offset=self._cursor_offset)
        else:
            insert_fn = getattr(self._document, "insert_bytes", None)
            if callable(insert_fn):
                try:
                    insert_fn(self._cursor_offset, data)
                    self._modified_offsets.add(self._cursor_offset)
                except Exception:
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
            try:
                delete_fn(start, length)
                self._selection_start = -1
                self._selection_end = -1
                self.data_changed.emit()
                self._move_cursor(start)
            except Exception:
                _logger.debug("delete_selection_failed")
        else:
            offset = self._cursor_offset
            if backspace and offset > 0:
                offset -= 1
            try:
                delete_fn(offset, 1)
                self.data_changed.emit()
                self._move_cursor(offset)
            except Exception:
                _logger.debug("delete_byte_failed", offset=offset)

        self._update_scrollbar()

    def _do_undo(self) -> None:
        """Perform undo operation."""
        if self._document is None:
            return
        undo_fn = getattr(self._document, "undo", None)
        if callable(undo_fn) and undo_fn():
            self.data_changed.emit()
            self._update_viewport()

    def _do_redo(self) -> None:
        """Perform redo operation."""
        if self._document is None:
            return
        redo_fn = getattr(self._document, "redo", None)
        if callable(redo_fn) and redo_fn():
            self.data_changed.emit()
            self._update_viewport()

    def _do_copy(self) -> None:
        """Copy selection to clipboard as hex string."""
        text = self.copy_as("hex")
        if text:
            clipboard = QApplication.clipboard()
            if clipboard is not None:
                clipboard.setText(text)

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
        """Handle widget resize.

        Args:
            a0: Resize event.
        """
        super().resizeEvent(a0)
        self._update_scrollbar()

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
            Byte offset, or None if the point is outside the data area.
        """
        x = pos.x()
        y = pos.y()

        vbar = self.verticalScrollBar()
        first_row = vbar.value() if vbar is not None else 0
        row = first_row + y // self._line_height

        col: int | None = None

        if self._hex_col_x <= x < self._hex_col_x + self._hex_col_width:
            pixel_in_hex = x - self._hex_col_x
            byte_width = _HEX_CHARS_PER_BYTE * self._char_width
            col = pixel_in_hex // byte_width
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
            Selected bytes, or empty bytes if no selection.
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
            fmt: Output format - "hex", "c_array", "python", or "base64".

        Returns:
            Formatted string representation of the selected bytes.
        """
        data = self.get_selection_bytes()
        if not data:
            if self._document is not None and self._cursor_offset < self._doc_length():
                read_fn = getattr(self._document, "read", None)
                if callable(read_fn):
                    raw = read_fn(self._cursor_offset, 1)
                    if isinstance(raw, (bytes, bytearray)):
                        data = bytes(raw)
                    elif isinstance(raw, list):
                        data = bytes(cast("list[int]", raw))
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
        return ""

    def highlight_offsets(self, highlights: list[tuple[int, int, str]]) -> None:
        """Set highlight regions for template/bookmark visualization.

        Args:
            highlights: List of (offset, length, color_hex_string) tuples.
        """
        self._highlights = highlights
        self._update_viewport()
