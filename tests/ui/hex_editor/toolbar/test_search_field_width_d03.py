# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for S19-D03: the hex toolbar Search field.

The re-live audit reported the Search ``QLineEdit`` in the hex editor
toolbar clipping glyph bottoms. The general vertical-clipping mechanism was
already fixed system-wide (R03,
``tests/ui/test_input_field_vertical_clipping_r02_r03.py``): every
``AnalysisPanelBase._add_toolbar_input`` line edit gets its minimum height
from :func:`intellicrack.ui.panels.base_panel.compute_control_min_height`,
which derives a font-metric-based floor tall enough to avoid clipping.
``TestSearchFieldHeightNoGlyphClip`` re-confirms that this already-landed
fix covers the hex Search field specifically.

Separately, the field's ``max_width=180`` (``HexEditorPanel._populate_toolbar``,
``ui/panels/hex_editor/panel.py``) was too narrow to fit a realistic
byte-pattern search query (e.g. an 11-byte hex signature such as
``"48 8B 05 21 10 00 00 48 8B 40 08"``) without horizontal scrolling --
the query never fit inside the field's own maximum width, let alone its
live, toolbar-constrained rendered width. The fix widens the Search
field's max width to ``_SEARCH_INPUT_MAX_WIDTH = 200``
(``panel.py``), just enough to cover that query plus the styled
``QLineEdit``'s horizontal chrome (``padding: 6px 8px`` + ``1px`` border
each side, from the theme QSS). ``TestSearchFieldWidthFitsRepresentativeQuery``
gates that fix: reverting ``_SEARCH_INPUT_MAX_WIDTH`` back to ``180`` turns
it RED because the representative query's required pixel width (measured
against the real field's own font) then exceeds the field's configured
maximum width.
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

# Mirrors the "no glyph clip" margin used by the R02/R03 vertical-clipping
# gates: rendered height must cover the font's own line height plus slack
# for the styled QLineEdit's vertical padding/border.
_NO_CLIP_HEIGHT_MARGIN: Final[int] = 14


class TestSearchFieldHeightNoGlyphClip:
    """The Search field's rendered height must not clip the font's own glyphs (R03 coverage)."""

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
    """The Search field must be able to display a realistic query without truncation (D03)."""

    @staticmethod
    def test_max_width_fits_representative_byte_pattern_query(qapp: QApplication) -> None:
        """The field's configured max width must fit the representative query plus chrome.

        Falsifiable: reverting ``_SEARCH_INPUT_MAX_WIDTH`` to its pre-fix
        value of 180 makes the required pixel width (measured against the
        field's own real font) exceed the configured maximum, so this
        assertion fails.

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
        """The field's max width must exceed the pre-fix 180px value.

        A direct, minimal regression pin on the specific constant this
        finding widened, independent of the query-fit measurement above.

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
