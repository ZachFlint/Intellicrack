# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the ``cutter_search_tab`` results table resize modes and tooltips.

* ``SearchTab`` must configure its results table header. Without a ``setSectionResizeMode`` call
  (``setHorizontalHeaderLabels``/``setSelectionBehavior``/``setSelectionMode`` alone do not size columns), the
  header keeps Qt's default ``Interactive`` resize mode with a small fixed default section width for both columns.
  Crypto-constant and magic-signature matches populate the Detail column from ``_apply_dict_results``,
  which falls back to ``str(entry)`` (a full dict repr) when none of ``name``/``type``/``info``/``comment`` are
  present, so that text would be clipped with no way to recover it. The Address column uses
  ``ResizeToContents`` and the Detail column uses ``Stretch``, and every Detail cell carries a full-text tooltip.

All tests drive a real :class:`SearchTab` widget and real
``_apply_addresses``/``_apply_dict_results`` calls under an offscreen
``QApplication`` -- no mocks stand in for the Qt header-resize machinery or
the result-population logic being verified.
"""

from __future__ import annotations

from PyQt6.QtWidgets import QApplication, QHeaderView

from intellicrack.ui.panels.cutter_search_tab import SearchTab


def test_h35_header_resize_modes_are_resize_to_contents_and_stretch(qapp: QApplication) -> None:
    """The results table header must configure per-column resize modes.

    ``SearchTab.__init__`` must call ``setSectionResizeMode`` (or
    any other width-configuring API) on ``self._results_table``'s header, or
    both columns stay at Qt's default ``Interactive`` resize mode. This
    asserts the concrete Qt mechanism the fix installs: the Address column
    is ``ResizeToContents`` and the Detail column is ``Stretch``.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    tab = SearchTab()
    try:
        header = tab._results_table.horizontalHeader()
        assert header is not None
        assert header.sectionResizeMode(0) == QHeaderView.ResizeMode.ResizeToContents, (
            "Address column is not ResizeToContents; it stays at the Interactive default width"
        )
        assert header.sectionResizeMode(1) == QHeaderView.ResizeMode.Stretch, (
            "Detail column is not Stretch; long crypto/magic match text will be clipped at the Interactive default width"
        )
    finally:
        tab.deleteLater()


def test_h35_detail_column_width_tracks_panel_resize(qapp: QApplication) -> None:
    """The Detail column width must grow when the panel is widened.

    With ``Interactive`` mode both columns stay pinned at Qt's fixed
    default section width regardless of how much space was available, so
    widening the panel never widens the Detail column. With
    ``Stretch``, the rendered column width tracks the available panel
    width, so a much wider tab must produce a measurably wider Detail
    column.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    tab = SearchTab()
    try:
        tab.resize(420, 300)
        tab.show()
        QApplication.processEvents()
        header = tab._results_table.horizontalHeader()
        assert header is not None
        narrow_width = header.sectionSize(1)

        tab.resize(1800, 300)
        QApplication.processEvents()
        wide_width = header.sectionSize(1)

        assert wide_width > narrow_width + 300, (
            f"Detail column did not widen with the panel (narrow={narrow_width}, wide={wide_width}); "
            "column is not stretching to fill available width"
        )
    finally:
        tab.deleteLater()


def test_h35_detail_column_stretches_far_beyond_address_column(qapp: QApplication) -> None:
    """A wide panel must give the Detail column far more width than Address.

    With both columns on the same small fixed ``Interactive`` default width, a wide panel left most of the table's width unused
    rather than handing it to the Detail column. With ``Stretch``, the Detail column absorbs all freed width while
    ``ResizeToContents`` keeps Address tight to its own short ``0x...`` text.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    tab = SearchTab()
    try:
        tab.resize(1600, 300)
        tab.show()
        QApplication.processEvents()
        tab._apply_addresses([0xDEADBEEF])
        QApplication.processEvents()

        header = tab._results_table.horizontalHeader()
        assert header is not None
        address_width = header.sectionSize(0)
        detail_width = header.sectionSize(1)

        assert detail_width > address_width * 3, (
            f"Detail column ({detail_width}px) did not absorb the width freed from Address ({address_width}px); Detail is not stretching"
        )
    finally:
        tab.deleteLater()


def test_h35_dict_fallback_detail_text_and_tooltip_preserve_full_repr(qapp: QApplication) -> None:
    """A crypto/magic match without name/type/info/comment must keep full text.

    ``_apply_dict_results`` falls back to ``str(entry)`` (the whole dict
    repr) when none of the ``name``/``type``/``info``/``comment`` keys are
    present. That text would be placed in a plain ``QTableWidgetItem``
    with no tooltip, so a visually clipped cell had no way to recover the
    full description. The Detail item must set ``setToolTip`` to the
    same full text, so it asserts both the cell text and the tooltip carry
    the complete, unclipped dict repr.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    tab = SearchTab()
    try:
        entry = {
            "offset": 4198400,
            "algo": "aes-sbox-fwd",
            "size": 256,
            "extra": "matched forward AES substitution box constants",
        }
        tab._apply_dict_results([entry])

        assert tab._results_table.rowCount() == 1
        item = tab._results_table.item(0, 1)
        assert item is not None
        expected = str(entry)
        assert item.text() == expected, "Detail cell does not carry the full dict repr fallback text"
        assert item.toolTip() == expected, "Detail cell tooltip does not carry the full dict repr fallback text"

        addr_item = tab._results_table.item(0, 0)
        assert addr_item is not None
        assert addr_item.text() == "0x401000"
    finally:
        tab.deleteLater()


def test_h35_named_match_still_gets_full_text_tooltip(qapp: QApplication) -> None:
    """A match that does carry a ``name``/``type``/``info``/``comment`` key also gets a tooltip.

    Confirms the tooltip is unconditional on the Detail item (not only
    applied to the ``str(entry)`` fallback branch), so every populated match
    -- named or not -- keeps its full description recoverable via tooltip.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    tab = SearchTab()
    try:
        entry = {"offset": 0x2000, "name": "MZ/PE magic signature"}
        tab._apply_dict_results([entry])

        item = tab._results_table.item(0, 1)
        assert item is not None
        assert item.text() == "MZ/PE magic signature"
        assert item.toolTip() == "MZ/PE magic signature", "named-match Detail cell has no tooltip"
    finally:
        tab.deleteLater()
