# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the GUI audit findings in ``hex_editor_widget``.

Each test class targets one audit finding and fails against the pre-fix
behaviour:

* ``TestOffsetColor`` (M20): offsets must be painted with the opaque
  ``offset_text`` colour, never the (partly transparent / blue) selection
  colour, and the cached colour must re-resolve on a live theme switch.
* ``TestEntropyMinimap`` (M21): enabling the minimap must push real entropy
  into it and keep its geometry inside the widget, with a reserved viewport
  margin so it is actually visible.
* ``TestCursorRect``: in multi-byte display modes the hex caret must track the
  cursor's byte within the group instead of pinning to the group's first
  glyph.
* ``TestOffsetOverrun``: offsets in files larger than 4 GiB must not overrun
  the offset column into the hex column.
* ``TestModifiedOffsetRemap``: modified-byte marks must follow insert/delete
  edits, and a single undo must revert only that step's marks.
* ``TestSelectionRange``: ``set_selection_range`` must clamp to the document
  and emit ``selection_changed``.

All tests drive a real :class:`HexEditorWidget` bound to a real
``intellicrack_hexcore`` document (no mocks) under an offscreen QApplication.
"""

from __future__ import annotations

import pytest
from PyQt6.QtGui import QColor, QFontMetrics, QImage, QPainter
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget
from intellicrack.ui.resources.theme_manager import THEME_DARK, THEME_LIGHT, ThemeManager


hexcore = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore backend required for real hex documents",
)


pytestmark = pytest.mark.integration


_SAMPLE_BYTES: bytes = bytes((i * 7 + 3) & 0xFF for i in range(4096))


def _make_widget(qapp: QApplication, data: bytes = _SAMPLE_BYTES) -> HexEditorWidget:
    """Build a shown, real-document-backed hex widget for painting tests.

    Args:
        qapp: The shared QApplication instance.
        data: Bytes to load into the backing document.

    Returns:
        HexEditorWidget: A sized, visible widget with a real document.
    """
    _ = qapp
    widget = HexEditorWidget()
    document = hexcore.HexDocument.open_bytes(data)
    widget.set_document(document)
    widget.resize(760, 320)
    widget.show()
    QApplication.processEvents()
    return widget


def _restore_theme() -> None:
    """Restore the shared theme manager to the default dark theme."""
    ThemeManager.get_instance().apply_theme(THEME_DARK)


class TestOffsetColor:
    """M20: offsets are painted with the opaque offset_text colour."""

    @staticmethod
    def _most_inked_offset_pixel(widget: HexEditorWidget) -> QColor:
        """Render the viewport and return the offset column's most-inked pixel.

        Args:
            widget: The hex widget to render.

        Returns:
            QColor: The offset-column pixel furthest from the background.
        """
        vp = widget.viewport()
        assert vp is not None
        image = QImage(vp.width(), vp.height(), QImage.Format.Format_ARGB32)
        image.fill(0)
        painter = QPainter(image)
        vp.render(painter)
        painter.end()

        bg = widget._colors["editor_bg"]
        x0 = widget._offset_col_x
        x1 = min(vp.width(), widget._offset_col_x + widget._offset_col_width)
        best = bg
        best_dist = -1.0
        for y in range(min(vp.height(), widget._line_height * 4)):
            for x in range(x0, x1):
                pixel = image.pixelColor(x, y)
                dist = (pixel.red() - bg.red()) ** 2 + (pixel.green() - bg.green()) ** 2 + (pixel.blue() - bg.blue()) ** 2
                if dist > best_dist:
                    best_dist = float(dist)
                    best = pixel
        return best

    def test_offset_ink_is_achromatic_not_selection_blue(self, qapp: QApplication) -> None:
        """The offset ink must be grey (offset_text), never the blue selection colour.

        Antialiasing blends ink toward the achromatic background, so the
        falsifiable invariant is chroma: offset_text is grey (R approximately
        B) while ``selection_bg`` is blue (B noticeably greater than R). The
        pre-fix code used ``selection_bg`` and would fail this in both themes.

        Args:
            qapp: The shared QApplication fixture.
        """
        try:
            for theme in (THEME_DARK, THEME_LIGHT):
                ThemeManager.get_instance().apply_theme(theme)
                widget = _make_widget(qapp)
                try:
                    assert widget._colors["offset_text"].alpha() == 255, "offset_text must be opaque"
                    selection = widget._colors["selection_bg"]
                    assert selection.blue() - selection.red() > 40, "test premise: selection colour is blue"

                    inked = self._most_inked_offset_pixel(widget)
                    bg = widget._colors["editor_bg"]
                    differs = abs(inked.red() - bg.red()) + abs(inked.green() - bg.green()) + abs(inked.blue() - bg.blue())
                    assert differs > 20, f"no offset text rendered in {theme} theme"
                    assert abs(inked.blue() - inked.red()) <= 30, (
                        f"offset ink in {theme} theme is chromatic {inked.getRgb()}; "
                        "offsets are painted with the blue selection colour, not offset_text"
                    )
                finally:
                    widget.deleteLater()
        finally:
            _restore_theme()

    def test_offset_text_contrast_adequate_both_themes(self, qapp: QApplication) -> None:
        """offset_text must contrast with the editor background in both themes.

        Args:
            qapp: The shared QApplication fixture.
        """
        try:
            for theme in (THEME_DARK, THEME_LIGHT):
                ThemeManager.get_instance().apply_theme(theme)
                widget = _make_widget(qapp)
                try:
                    fg = widget._colors["offset_text"]
                    bg = widget._colors["editor_bg"]
                    fg_lum = 0.299 * fg.red() + 0.587 * fg.green() + 0.114 * fg.blue()
                    bg_lum = 0.299 * bg.red() + 0.587 * bg.green() + 0.114 * bg.blue()
                    assert abs(fg_lum - bg_lum) > 40, f"offset_text/{theme} contrast too low"
                finally:
                    widget.deleteLater()
        finally:
            _restore_theme()

    def test_theme_change_re_resolves_offset_color(self, qapp: QApplication) -> None:
        """A live theme switch must re-resolve the cached offset colour.

        Proves the widget subscribes to ``ThemeManager.theme_changed``: without
        the subscription the cached ``_colors`` would not update on
        ``apply_theme`` and the two themes would report identical colours.

        Args:
            qapp: The shared QApplication fixture.
        """
        try:
            ThemeManager.get_instance().apply_theme(THEME_DARK)
            widget = _make_widget(qapp)
            try:
                dark_offset = widget._colors["offset_text"].getRgb()
                ThemeManager.get_instance().apply_theme(THEME_LIGHT)
                light_offset = widget._colors["offset_text"].getRgb()
                assert dark_offset != light_offset, "offset colour did not re-resolve on theme_changed"
                ThemeManager.get_instance().apply_theme(THEME_DARK)
                assert widget._colors["offset_text"].getRgb() == dark_offset
            finally:
                widget.deleteLater()
        finally:
            _restore_theme()


class TestEntropyMinimap:
    """M21: the minimap receives entropy and stays within the widget."""

    def test_minimap_receives_entropy_and_fits_within_widget(self, qapp: QApplication) -> None:
        """Enabling the minimap pushes entropy and keeps geometry inside the widget.

        Pre-fix: entropy was never pushed (empty bars) and the minimap was
        placed past the scrollbar with no reserved margin, so its right edge
        overran the widget and the viewport width did not shrink.

        Args:
            qapp: The shared QApplication fixture.
        """
        try:
            _restore_theme()
            widget = _make_widget(qapp)
            try:
                vp = widget.viewport()
                assert vp is not None
                width_before = vp.width()

                widget.show_minimap(visible=True)
                QApplication.processEvents()

                minimap = widget._minimap
                assert minimap.isVisible()
                assert minimap._entropy_values, "entropy was not pushed into the minimap"
                assert minimap._total_size == widget._doc_length()

                geom = minimap.geometry()
                assert geom.left() >= 0
                assert geom.right() <= widget.width(), "minimap overruns the widget right edge"
                assert geom.left() >= vp.geometry().right(), "minimap overlaps the viewport"

                assert vp.width() < width_before, "no viewport margin was reserved for the minimap"

                widget.show_minimap(visible=False)
                QApplication.processEvents()
                assert not minimap.isVisible()
                assert vp.width() >= width_before, "viewport margin not released on hide"
            finally:
                widget.deleteLater()
        finally:
            _restore_theme()


class TestCursorRect:
    """The hex caret must track the cursor's byte within a multi-byte group."""

    def test_caret_tracks_byte_within_group_hex32(self, qapp: QApplication) -> None:
        """In hex32 mode the caret x for byte 2 differs from byte 0.

        Args:
            qapp: The shared QApplication fixture.
        """
        widget = _make_widget(qapp)
        try:
            widget.set_display_mode("hex32_le")
            group_size, chars_per_group = widget._get_mode_params()
            hex_x = 200
            group_offset = 0

            widget._cursor_offset = 0
            x0, w0 = widget._hex_caret_geometry(hex_x, group_size, chars_per_group, group_offset)
            widget._cursor_offset = 2
            x2, w2 = widget._hex_caret_geometry(hex_x, group_size, chars_per_group, group_offset)

            assert x2 > x0, "caret does not move to byte 2 within the hex32 group"
            expected_step = round(2 * (chars_per_group / group_size) * widget._char_width)
            assert x2 - hex_x == expected_step
            assert w0 == w2 == max(widget._char_width, round((chars_per_group / group_size) * widget._char_width))
        finally:
            widget.deleteLater()

    def test_caret_uses_nibble_in_hex8(self, qapp: QApplication) -> None:
        """In single-byte hex8 mode the caret follows the active nibble.

        Args:
            qapp: The shared QApplication fixture.
        """
        widget = _make_widget(qapp)
        try:
            widget.set_display_mode("hex8")
            group_size, chars_per_group = widget._get_mode_params()
            hex_x = 200
            widget._cursor_offset = 5
            widget._nibble_index = 0
            x_first, _ = widget._hex_caret_geometry(hex_x, group_size, chars_per_group, 5)
            widget._nibble_index = 1
            x_second, _ = widget._hex_caret_geometry(hex_x, group_size, chars_per_group, 5)
            assert x_second - x_first == widget._char_width
        finally:
            widget.deleteLater()


class _HugeDoc:
    """Minimal document exposing a >4 GiB length for offset-column sizing.

    A real 4 GiB document cannot be allocated in a test, so this stand-in
    exercises the pure offset-width layout math with a genuine byte reader.
    """

    def __init__(self, length: int) -> None:
        """Initialize the stand-in with a fixed length.

        Args:
            length: Reported document length in bytes.
        """
        self._length = length

    def length(self) -> int:
        """Return the document length.

        Returns:
            int: The reported length in bytes.
        """
        return self._length

    def read(self, offset: int, length: int) -> bytes:
        """Return zero bytes for any requested span.

        Args:
            offset: Start offset (ignored).
            length: Number of bytes to return.

        Returns:
            bytes: ``length`` zero bytes.
        """
        _ = offset
        return bytes(max(0, length))


class TestOffsetOverrun:
    """Offsets in files larger than 4 GiB must not overrun the offset column."""

    def test_offset_field_widens_for_large_files(self, qapp: QApplication) -> None:
        """A >4 GiB document widens the offset field so 0x1_0000_0000 fits.

        Pre-fix ``_OFFSET_CHARS`` was a fixed 10 (``0x`` + 8 digits), so a
        9-digit offset overran into the hex column. The field must now size to
        the document length.

        Args:
            qapp: The shared QApplication fixture.
        """
        _ = qapp
        widget = HexEditorWidget()
        try:
            widget.set_document(_HugeDoc(0x1_0000_0100))
            assert widget._offset_hex_digits >= 9, "offset field not widened for >4 GiB document"

            fm = QFontMetrics(widget.font())
            max_text = f"0x{widget._doc_length() - 1:0{widget._offset_hex_digits}X}"
            assert fm.horizontalAdvance(max_text) <= widget._offset_col_width, "large offset overruns the offset column"
            assert widget._offset_col_x + widget._offset_col_width <= widget._hex_col_x, "offset column crosses into hex column"
        finally:
            widget.deleteLater()

    def test_small_file_keeps_minimum_width(self, qapp: QApplication) -> None:
        """Small documents keep the 8-digit minimum offset width.

        Args:
            qapp: The shared QApplication fixture.
        """
        widget = _make_widget(qapp, data=bytes(64))
        try:
            assert widget._offset_hex_digits == 8
        finally:
            widget.deleteLater()


class TestModifiedOffsetRemap:
    """Modified marks must follow edits, and undo must revert only one step."""

    @staticmethod
    def _type_byte(widget: HexEditorWidget, offset: int, hexstr: str) -> None:
        """Type a full byte via two hex-nibble key handlers at ``offset``.

        Args:
            widget: The hex widget under test.
            offset: Byte offset to place the cursor before typing.
            hexstr: Two-character hex string, e.g. ``"AA"``.
        """
        widget._cursor_offset = offset
        widget._nibble_index = 0
        widget._handle_hex_input(hexstr[0])
        widget._handle_hex_input(hexstr[1])

    def test_marks_shift_on_insert(self, qapp: QApplication) -> None:
        """Inserting before a mark shifts it; a new mark is added at the edit.

        Args:
            qapp: The shared QApplication fixture.
        """
        widget = _make_widget(qapp, data=bytes(range(16)))
        try:
            widget._edit_mode = "overwrite"
            self._type_byte(widget, 8, "AA")
            assert widget._modified_offsets == {8}

            widget._edit_mode = "insert"
            self._type_byte(widget, 2, "BB")
            assert widget._modified_offsets == {2, 9}, "mark at 8 did not shift to 9 after insert at 2"
        finally:
            widget.deleteLater()

    def test_marks_shift_on_delete(self, qapp: QApplication) -> None:
        """Deleting before a mark shifts it left by the deleted count.

        Args:
            qapp: The shared QApplication fixture.
        """
        widget = _make_widget(qapp, data=bytes(range(16)))
        try:
            widget._edit_mode = "overwrite"
            self._type_byte(widget, 10, "AA")
            assert widget._modified_offsets == {10}

            widget._selection_start = -1
            widget._selection_end = -1
            widget._cursor_offset = 3
            widget._do_delete(backspace=False)
            assert widget._modified_offsets == {9}, "mark at 10 did not shift to 9 after delete at 3"
        finally:
            widget.deleteLater()

    def test_single_undo_reverts_only_that_steps_marks(self, qapp: QApplication) -> None:
        """One undo reverts only the last edit's mark, preserving earlier marks.

        Pre-fix ``_do_undo`` cleared every mark; a single-step undo must leave
        the earlier mark intact and redo must restore the reverted mark.

        Args:
            qapp: The shared QApplication fixture.
        """
        widget = _make_widget(qapp, data=bytes(range(16)))
        try:
            widget._edit_mode = "overwrite"
            self._type_byte(widget, 3, "AA")
            self._type_byte(widget, 7, "BB")
            assert widget._modified_offsets == {3, 7}

            widget._do_undo()
            assert widget._modified_offsets == {3}, "undo cleared all marks instead of only the last step"

            widget._do_redo()
            assert widget._modified_offsets == {3, 7}, "redo did not restore the reverted mark"
        finally:
            widget.deleteLater()


class TestSelectionRange:
    """set_selection_range must clamp to the document and emit the signal."""

    def test_out_of_range_end_clamps_and_emits(self, qapp: QApplication) -> None:
        """An out-of-range end clamps to the last byte and emits selection_changed.

        Args:
            qapp: The shared QApplication fixture.
        """
        widget = _make_widget(qapp, data=bytes(range(16)))
        try:
            emitted: list[tuple[int, int]] = []
            widget.selection_changed.connect(lambda s, e: emitted.append((s, e)))

            widget.set_selection_range(2, 999)
            doc_max = widget._doc_length() - 1
            assert widget._selection_start == 2
            assert widget._selection_end == doc_max, "selection end was not clamped to the document"
            assert emitted, "selection_changed was not emitted"
            assert emitted[-1] == (2, doc_max), "selection_changed not emitted with clamped range"
        finally:
            widget.deleteLater()

    def test_negative_start_clamps_to_zero(self, qapp: QApplication) -> None:
        """A negative start clamps to offset zero.

        Args:
            qapp: The shared QApplication fixture.
        """
        widget = _make_widget(qapp, data=bytes(range(16)))
        try:
            emitted: list[tuple[int, int]] = []
            widget.selection_changed.connect(lambda s, e: emitted.append((s, e)))
            widget.set_selection_range(-5, 4)
            assert widget._selection_start == 0
            assert widget._selection_end == 4
            assert emitted[-1] == (0, 4)
        finally:
            widget.deleteLater()


class TestDisplayModes:
    """The widget exposes its display modes as a class constant."""

    def test_display_modes_available(self) -> None:
        """The hex32 display mode is registered."""
        assert "hex32_le" in HexEditorWidget.DISPLAY_MODES
