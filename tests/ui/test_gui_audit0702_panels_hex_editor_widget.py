# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for GUI audit findings C5, H9, and M25 in ``hex_editor_widget``.

* ``TestC5ColorModeBackground`` (C5): the Entropy/Byte-Value/Content-Type
  color-mode combo box must visibly recolor hex-view cell backgrounds
  instead of being wired to a mode flag no paint routine reads.
* ``TestH9EntropyScanOffGuiThread`` (H9): full-document entropy scans
  triggered by the minimap and entropy color mode must run on a
  background worker thread rather than blocking the GUI thread inline on
  every keystroke edit.
* ``TestM25AlignmentGrid`` (M25): a non-zero alignment-grid size must draw
  dashed marker lines at grid-boundary rows instead of only affecting
  invisible cursor-snap math.

C5 and M25 drive a real :class:`HexEditorWidget` bound to a real
``intellicrack_hexcore`` document under an offscreen QApplication. H9
attaches a lightweight in-process document stand-in exposing the minimal
read/write/entropy_map interface so the exact OS thread performing the
(simulated) full-document entropy scan can be observed deterministically.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtGui import QColor, QImage, QPainter
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget
from intellicrack.ui.resources.theme_manager import THEME_DARK, THEME_LIGHT, ThemeManager


if TYPE_CHECKING:
    from pytestqt.qtbot import QtBot


hexcore = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore backend required for real hex documents",
)


pytestmark = pytest.mark.integration


def _render_viewport(widget: HexEditorWidget) -> QImage:
    """Render the widget's viewport to an offscreen image.

    Args:
        widget: The hex widget to render.

    Returns:
        QImage: ARGB32 snapshot of the current viewport paint output.
    """
    vp = widget.viewport()
    assert vp is not None
    image = QImage(vp.width(), vp.height(), QImage.Format.Format_ARGB32)
    image.fill(0)
    painter = QPainter(image)
    vp.render(painter)
    painter.end()
    return image


def _restore_theme() -> None:
    """Restore the shared theme manager to the default dark theme."""
    ThemeManager.get_instance().apply_theme(THEME_DARK)


class TestC5ColorModeBackground:
    """C5: the color-mode combo actually recolors hex-view cell backgrounds."""

    @staticmethod
    def _sample_hex_cell_color(image: QImage, widget: HexEditorWidget, row_idx: int) -> QColor:
        """Sample the glyph-free trailing region of a hex-column cell.

        Args:
            image: Rendered viewport snapshot.
            widget: The hex widget the image was rendered from.
            row_idx: Visual row index (0-based) of the byte group to sample.

        Returns:
            QColor: Pixel color to the right of the two hex-digit glyphs,
            reflecting the cell's background fill rather than text ink.
        """
        char_width = widget._char_width
        sample_x = widget._hex_col_x + 2 * char_width + 2
        sample_y = row_idx * widget._line_height + widget._line_height // 2
        return image.pixelColor(sample_x, sample_y)

    def test_c5_byte_value_mode_recolors_hex_cells_by_byte_magnitude(self, qapp: QApplication) -> None:
        """byte_value color mode paints visibly different backgrounds for 0x00 vs 0xFF rows.

        Pre-fix, ``set_color_mode`` only stored ``_color_mode`` and
        invalidated caches; no paint routine ever read it, so every hex
        cell rendered identically regardless of the selected mode -- both
        the all-zero and the all-0xFF row would sample as the plain editor
        background. Post-fix, ``_paint_hex_group_background`` resolves
        ``_color_mode_background``, which for ``"byte_value"`` fills each
        cell with a color proportional to the byte's magnitude.

        Args:
            qapp: The shared QApplication fixture.
        """
        _ = qapp
        try:
            ThemeManager.get_instance().apply_theme(THEME_LIGHT)
            data = bytes([0x00] * 16 + [0xFF] * 16 + [0x00] * 16)
            widget = HexEditorWidget()
            document = hexcore.HexDocument.open_bytes(data)
            widget.set_document(document)
            widget.set_display_mode("hex8")
            widget.resize(760, 320)
            widget.show()
            QApplication.processEvents()
            try:
                widget.set_color_mode("byte_value")
                QApplication.processEvents()
                image = _render_viewport(widget)

                bg = widget._colors["editor_bg"]
                low_row_color = self._sample_hex_cell_color(image, widget, row_idx=0)
                high_row_color = self._sample_hex_cell_color(image, widget, row_idx=1)

                low_dist = (
                    abs(low_row_color.red() - bg.red()) + abs(low_row_color.green() - bg.green()) + abs(low_row_color.blue() - bg.blue())
                )
                high_dist = (
                    abs(high_row_color.red() - bg.red()) + abs(high_row_color.green() - bg.green()) + abs(high_row_color.blue() - bg.blue())
                )
                assert low_dist > 40, "0x00 row hex cell was not recolored by byte_value color mode"
                assert high_dist > 40, "0xFF row hex cell was not recolored by byte_value color mode"

                row_dist = (
                    abs(low_row_color.red() - high_row_color.red())
                    + abs(low_row_color.green() - high_row_color.green())
                    + abs(low_row_color.blue() - high_row_color.blue())
                )
                assert row_dist > 60, "0x00 and 0xFF rows rendered identically under byte_value color mode"
            finally:
                widget.deleteLater()
        finally:
            _restore_theme()

    def test_c5_none_mode_leaves_hex_cells_at_plain_background(self, qapp: QApplication) -> None:
        """color_mode "none" must not tint hex cells.

        Sanity check for the pixel-sampling method used by the byte_value
        gate above: with the default "none" mode the sampled cell must
        remain the plain editor background, confirming the earlier
        recoloring assertion is attributable to the color mode and not to
        some other unconditional paint path.

        Args:
            qapp: The shared QApplication fixture.
        """
        _ = qapp
        try:
            ThemeManager.get_instance().apply_theme(THEME_LIGHT)
            data = bytes([0xFF] * 16)
            widget = HexEditorWidget()
            document = hexcore.HexDocument.open_bytes(data)
            widget.set_document(document)
            widget.set_display_mode("hex8")
            widget.resize(760, 320)
            widget.show()
            QApplication.processEvents()
            try:
                image = _render_viewport(widget)
                bg = widget._colors["editor_bg"]
                sampled = self._sample_hex_cell_color(image, widget, row_idx=0)
                dist = abs(sampled.red() - bg.red()) + abs(sampled.green() - bg.green()) + abs(sampled.blue() - bg.blue())
                assert dist <= 10, "hex cell was tinted even though color_mode is 'none'"
            finally:
                widget.deleteLater()
        finally:
            _restore_theme()


class _ThreadRecordingDocument:
    """Document stand-in that records the OS thread of each entropy scan.

    Exposes only the subset of the HexDocument interface
    :class:`HexEditorWidget` needs to drive a keyboard edit
    (``length``/``read``/``write_bytes``) and a full-document entropy scan
    (``entropy_map``), so the exact thread performing the scan can be
    observed without depending on the native hexcore backend's own
    threading behaviour.

    Attributes:
        entropy_map_call_count: Number of times ``entropy_map`` was invoked.
        entropy_map_thread_ids: OS thread identifier recorded on each call.
    """

    entropy_map_call_count: int
    entropy_map_thread_ids: list[int]

    def __init__(self, data: bytes, *, scan_delay_seconds: float = 0.15) -> None:
        """Initialize the document with backing bytes and an artificial scan delay.

        Args:
            data: Initial byte content.
            scan_delay_seconds: Time ``entropy_map`` sleeps before
                returning, simulating a slow full-document scan so the
                test can observe the GUI thread proceeding before the
                scan completes.
        """
        self._data = bytearray(data)
        self._scan_delay_seconds = scan_delay_seconds
        self.entropy_map_call_count = 0
        self.entropy_map_thread_ids = []

    def length(self) -> int:
        """Return the document length in bytes.

        Returns:
            int: Number of bytes currently held.
        """
        return len(self._data)

    def read(self, offset: int, length: int) -> bytes:
        """Read a slice of bytes from the document.

        Args:
            offset: Start offset in bytes.
            length: Number of bytes to read.

        Returns:
            bytes: The requested byte slice.
        """
        return bytes(self._data[offset : offset + length])

    def write_bytes(self, offset: int, data: bytes) -> None:
        """Overwrite bytes at the given offset.

        Args:
            offset: Start offset in bytes.
            data: Replacement byte content.
        """
        self._data[offset : offset + len(data)] = data

    def entropy_map(self, block_size: int) -> list[float]:
        """Simulate a slow full-document entropy scan and record its thread.

        Args:
            block_size: Requested entropy block size (unused by the stand-in).

        Returns:
            list[float]: A single constant entropy value.
        """
        _ = block_size
        self.entropy_map_call_count += 1
        self.entropy_map_thread_ids.append(threading.get_ident())
        time.sleep(self._scan_delay_seconds)
        return [4.0]


@pytest.mark.usefixtures("qapp")
class TestH9EntropyScanOffGuiThread:
    """H9: full-document entropy scans must not run synchronously on the GUI thread."""

    @staticmethod
    def test_h9_entropy_scan_dispatches_to_background_thread(qtbot: QtBot) -> None:
        """Showing the minimap starts the entropy scan on a non-GUI thread.

        Pre-fix, ``_ensure_entropy_cache`` called ``document.entropy_map``
        directly inline, so the scan ran on whatever thread called
        ``show_minimap`` -- the GUI/test thread -- and the recorded thread
        id would equal the main thread id. Post-fix, ``_ensure_entropy_cache``
        starts a ``GenericCallableWorker`` background ``QThread`` instead.

        Args:
            qtbot: pytest-qt bot fixture used to poll for async completion.
        """
        main_thread_id = threading.get_ident()
        widget = HexEditorWidget()
        document = _ThreadRecordingDocument(bytes(64))
        widget.set_document(document)
        try:
            widget.show_minimap(visible=True)
            qtbot.waitUntil(
                lambda: document.entropy_map_call_count >= 1 and not widget._entropy_scan_active,
                timeout=3000,
            )
            assert document.entropy_map_call_count == 1
            assert document.entropy_map_thread_ids[-1] != main_thread_id, "entropy_map ran on the GUI thread"
            assert widget._entropy_cache, "background scan did not populate the entropy cache"
        finally:
            widget.deleteLater()

    @staticmethod
    def test_h9_keystroke_edit_does_not_block_on_synchronous_rescan(qtbot: QtBot) -> None:
        """A hex-digit edit while the minimap is visible must not block for a full rescan.

        Pre-fix, ``data_changed`` -> ``_invalidate_color_caches`` ->
        ``_refresh_minimap_if_visible`` -> ``_refresh_minimap_entropy`` ->
        ``_ensure_entropy_cache`` called ``document.entropy_map`` inline
        and synchronously, so ``_entropy_cache`` would already be
        repopulated (non-empty) and ``entropy_map`` already called a
        second time the instant the keystroke handler returned. Post-fix
        the rescan is dispatched to a background worker and the cache
        stays empty on the GUI thread until that worker's completion
        signal fires.

        Args:
            qtbot: pytest-qt bot fixture used to poll for async completion.
        """
        main_thread_id = threading.get_ident()
        widget = HexEditorWidget()
        document = _ThreadRecordingDocument(bytes(64))
        widget.set_document(document)
        try:
            widget.show()
            QApplication.processEvents()
            widget.show_minimap(visible=True)
            qtbot.waitUntil(
                lambda: document.entropy_map_call_count >= 1 and not widget._entropy_scan_active,
                timeout=3000,
            )
            assert widget._entropy_cache, "setup: initial background scan did not populate the cache"

            widget._cursor_offset = 0
            widget._nibble_index = 0
            widget._handle_hex_input("A")
            widget._handle_hex_input("B")

            assert widget._entropy_cache == [], (
                "entropy cache was already repopulated immediately after the keystroke; "
                "the rescan ran synchronously on the GUI thread instead of a background worker"
            )
            assert document.entropy_map_call_count == 1, "entropy_map was invoked synchronously during the keystroke handler"

            qtbot.waitUntil(
                lambda: document.entropy_map_call_count >= 2 and not widget._entropy_scan_active,
                timeout=3000,
            )
            assert widget._entropy_cache, "background rescan never repopulated the entropy cache"
            assert document.entropy_map_thread_ids[-1] != main_thread_id, "rescan after edit ran on the GUI thread"
        finally:
            widget.deleteLater()


class TestM25AlignmentGrid:
    """M25: a non-zero alignment-grid size draws dashed marker lines at boundary rows."""

    @staticmethod
    def _row_has_grid_tint(image: QImage, y: int, x0: int, x1: int, bg: QColor) -> bool:
        """Check whether any pixel in a horizontal band deviates from the background.

        Args:
            image: Rendered viewport snapshot.
            y: Pixel row to scan.
            x0: Inclusive left bound of the scan range.
            x1: Exclusive right bound of the scan range.
            bg: Editor background color to compare against.

        Returns:
            bool: True if some pixel in ``[x0, x1)`` at row ``y`` differs
            noticeably from ``bg``, indicating a painted marker line.
        """
        for x in range(x0, min(image.width(), x1)):
            pixel = image.pixelColor(x, y)
            dist = abs(pixel.red() - bg.red()) + abs(pixel.green() - bg.green()) + abs(pixel.blue() - bg.blue())
            if dist > 15:
                return True
        return False

    def test_m25_alignment_grid_draws_lines_at_boundary_rows_only(self, qapp: QApplication) -> None:
        """A non-zero grid size draws marker lines only at rows on a grid boundary.

        Pre-fix, ``set_alignment_grid_size`` stored the value and called
        ``self.update()`` but no paint routine ever referenced
        ``_alignment_grid_size``, so the offset-column pixels at every
        row's top edge stayed pure background regardless of the
        configured grid size. Post-fix, ``_paint_alignment_grid`` draws a
        dashed line at the top of every row whose absolute byte offset is
        a multiple of the grid size, and no line otherwise.

        Args:
            qapp: The shared QApplication fixture.
        """
        _ = qapp
        try:
            ThemeManager.get_instance().apply_theme(THEME_LIGHT)
            data = bytes(range(256)) * 4
            widget = HexEditorWidget()
            document = hexcore.HexDocument.open_bytes(data)
            widget.set_document(document)
            widget.resize(760, 400)
            widget.show()
            QApplication.processEvents()
            try:
                bg = widget._colors["editor_bg"]
                x0 = widget._offset_col_x
                x1 = widget._offset_col_x + widget._offset_col_width

                widget.set_alignment_grid_size(0)
                QApplication.processEvents()
                image_disabled = _render_viewport(widget)
                assert not self._row_has_grid_tint(image_disabled, 0, x0, x1, bg), "grid line drawn while disabled (size 0)"

                widget.set_alignment_grid_size(32)
                QApplication.processEvents()
                image_enabled = _render_viewport(widget)

                assert self._row_has_grid_tint(image_enabled, 0, x0, x1, bg), "no grid line at boundary row (offset 0)"
                assert not self._row_has_grid_tint(image_enabled, widget._line_height, x0, x1, bg), (
                    "grid line drawn at non-boundary row (offset 16)"
                )
                assert self._row_has_grid_tint(image_enabled, widget._line_height * 2, x0, x1, bg), (
                    "no grid line at boundary row (offset 32)"
                )
            finally:
                widget.deleteLater()
        finally:
            _restore_theme()
