# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for the hex toolbar Search field.

The Search ``QLineEdit`` in the hex editor toolbar must not clip glyph
bottoms. The general vertical-clipping mechanism is handled system-wide
(see ``tests/ui/test_input_field_vertical_clipping_r02_r03.py``): every
``AnalysisPanelBase._add_toolbar_input`` line edit gets its minimum height
from :func:`intellicrack.ui.panels.base_panel.compute_control_min_height`,
which derives a font-metric-based floor tall enough to avoid clipping.
``TestSearchFieldHeightNoGlyphClip`` confirms that this covers the hex
Search field specifically.

The field's max width is ``_SEARCH_INPUT_MAX_WIDTH = 200``
(``HexEditorPanel._populate_toolbar``, ``ui/panels/hex_editor/panel.py``).
A max width of 180 is too narrow for a realistic byte-pattern search query
(e.g. an 11-byte hex signature such as ``"48 8B 05 21 10 00 00 48 8B 40 08"``)
to display without horizontal scrolling. The width must also cover the styled
``QLineEdit``'s horizontal chrome (``padding: 6px 8px`` + ``1px`` border each
side, from the theme QSS). ``TestSearchFieldWidthFitsRepresentativeQuery``
gates the width: a max width below the representative query's required pixel
width (measured against the real field's own font) fails the test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtGui import QFontMetrics

from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


# A realistic hex-editor search query: an 11-byte instruction-sequence
# signature, the kind of byte pattern a reverse engineer commonly searches
# for. Deliberately longer than a short offset or single opcode so the gate
# is not vacuously satisfied by any field width.
_REPRESENTATIVE_QUERY: Final[str] = "48 8B 05 21 10 00 00 48 8B 40 08"

# QSS QLineEdit rule (dark_theme.qss / light_theme.qss): `padding: 6px 8px;`
# (8px left + 8px right) plus a 1px border on each side.
_LINE_EDIT_HORIZONTAL_CHROME: Final[int] = 2 * 8 + 2 * 1

# Margin for the no-glyph-clip check: rendered height must cover the font's
# own line height plus slack for the styled QLineEdit's vertical padding and
# border.
_NO_CLIP_HEIGHT_MARGIN: Final[int] = 14


class TestSearchFieldHeightNoGlyphClip:
    """The Search field's rendered height must not clip the font's own glyphs."""

    @staticmethod
    def test_search_field_height_covers_font_metrics(qapp: QApplication) -> None:
        """Rendered height must be at least the font's line height plus clip margin.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        try:
            panel.resize(1600, 900)
            panel.show()
            panel.ensurePolished()
            qapp.processEvents()

            field = panel._search_input
            assert field is not None, "panel search input was not built"

            metrics = QFontMetrics(field.font())
            required_height = metrics.height() + _NO_CLIP_HEIGHT_MARGIN
            assert field.height() >= required_height, (
                f"Search field height {field.height()}px is below the no-glyph-clip floor "
                f"{required_height}px (font line height {metrics.height()}px) -- glyph bottoms "
                "would be clipped"
            )
        finally:
            panel.close()


class TestSearchFieldWidthFitsRepresentativeQuery:
    """The Search field must be able to display a realistic query without truncation."""

    @staticmethod
    def test_max_width_fits_representative_byte_pattern_query(qapp: QApplication) -> None:
        """The field's configured max width must fit the representative query plus chrome.

        A max width of 180 makes the required pixel width
        (measured against the field's own real font) exceed the configured
        maximum, so this assertion fails.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        try:
            field = panel._search_input
            assert field is not None, "panel search input was not built"

            metrics = QFontMetrics(field.font())
            required_width = metrics.horizontalAdvance(_REPRESENTATIVE_QUERY) + _LINE_EDIT_HORIZONTAL_CHROME

            assert field.maximumWidth() >= required_width, (
                f"Search field max width {field.maximumWidth()}px cannot fit the representative "
                f"query {_REPRESENTATIVE_QUERY!r} (needs {required_width}px including chrome) "
                "without horizontal truncation/scrolling"
            )
        finally:
            panel.close()

    @staticmethod
    def test_max_width_exceeds_prior_180px_default(qapp: QApplication) -> None:
        """The field's max width must exceed 180px.

        A direct pin on the 180px boundary, independent of the query-fit
        measurement above.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        try:
            field = panel._search_input
            assert field is not None, "panel search input was not built"
            assert field.maximumWidth() > 180, (
                f"Search field max width {field.maximumWidth()}px was not widened past the pre-fix 180px value"
            )
        finally:
            panel.close()
