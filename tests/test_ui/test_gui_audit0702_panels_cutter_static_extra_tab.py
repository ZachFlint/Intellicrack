# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the GUI audit findings in ``cutter_static_extra_tab``.

Each test targets one audit finding and fails against the pre-fix behaviour:

* ``H36``: ``ClassesTab`` builds a ``QTreeWidget`` with no header resize
  configuration at all, so long RTTI/C++ class names (from rizin's ``icj``)
  are clipped by the header's default ``Interactive`` width. The fix applies
  ``ResizeToContents`` to the Class/Address/Methods columns, stretches the
  last column, and sets a full-name tooltip on the top-level row.
* ``M43``: ``CallGraphTab`` builds its table through ``_make_table``, which
  applies uniform ``Stretch`` to every column, wasting width on the short
  fixed-format Address column while squeezing the Caller/Callee name
  columns. The fix keeps Caller/Callee ``Stretch`` but sets Address to
  ``ResizeToContents``.

All tests drive real :class:`ClassesTab` / :class:`CallGraphTab` widgets and
real ``_apply_data`` calls under an offscreen ``QApplication`` -- no mocks
stand in for the Qt header-resize machinery being verified.
"""

from __future__ import annotations

from PyQt6.QtGui import QFontMetrics
from PyQt6.QtWidgets import QApplication, QHeaderView

from intellicrack.core.types import ClassInfo
from intellicrack.ui.panels.cutter_static_extra_tab import CallGraphTab, ClassesTab


def test_h36_tree_header_uses_resize_to_contents(qapp: QApplication) -> None:
    """``ClassesTab``'s tree header must configure per-column resize modes.

    Pre-fix, ``ClassesTab.__init__`` never called ``setSectionResizeMode``
    (or any other width-configuring API) on ``self._tree.header()``, so
    every column stayed at Qt's default ``Interactive`` resize mode. This
    asserts the concrete Qt mechanism the fix installs: the Class, Address,
    and Methods columns are ``ResizeToContents`` and the last (Fields)
    column is stretched.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    tab = ClassesTab()
    try:
        header = tab._tree.header()
        assert header is not None
        for column in (0, 1, 2):
            assert header.sectionResizeMode(column) == QHeaderView.ResizeMode.ResizeToContents, (
                f"column {column} is not ResizeToContents; long class/method names will be clipped at the Interactive default width"
            )
        assert header.stretchLastSection() is True, "last column does not stretch to fill remaining space"
    finally:
        tab.deleteLater()


def test_h36_long_class_name_widens_column_and_is_not_clipped(qapp: QApplication) -> None:
    """A long RTTI class name must widen the Class column to fit, not clip.

    Pre-fix the Class column stayed at its fixed default width regardless of
    content (``Interactive`` mode does not auto-grow on data changes), so a
    long demangled/templated/namespaced class name would render clipped.
    Post-fix, ``ResizeToContents`` makes the rendered column width track the
    actual content, so populating a long name must measurably widen column 0
    beyond what a short name produces, and the resulting width must be able
    to hold the full name's rendered text.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    tab = ClassesTab()
    try:
        tab.resize(900, 500)
        tab.show()
        QApplication.processEvents()

        short_cls = ClassInfo(name="A", address=0x1000, methods=[], fields=[])
        tab._apply_data([short_cls])
        QApplication.processEvents()
        header = tab._tree.header()
        assert header is not None
        short_width = header.sectionSize(0)

        long_name = "Acme::Licensing::Protection::ValidationEngine<std::__1::basic_string<char>>"
        long_cls = ClassInfo(name=long_name, address=0x2000, methods=[], fields=[])
        tab._apply_data([long_cls])
        QApplication.processEvents()
        long_width = header.sectionSize(0)

        assert long_width > short_width, (
            f"Class column did not widen for a long name (short={short_width}, long={long_width}); column is not tracking content width"
        )
        fm = QFontMetrics(tab._tree.font())
        needed = fm.horizontalAdvance(long_name)
        assert long_width >= needed, (
            f"Class column width {long_width}px is narrower than the rendered name width {needed}px; the class name would be clipped"
        )
    finally:
        tab.deleteLater()


def test_h36_class_row_tooltip_carries_full_name(qapp: QApplication) -> None:
    """The top-level class row must carry a tooltip with the full class name.

    Pre-fix no tooltip was set on the Class column, so an analyst with a
    still-narrow or manually-shrunk column had no way to recover a clipped
    name without dragging the column wider. The fix sets ``setToolTip(0,
    cls.name)`` on every top-level row.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    tab = ClassesTab()
    try:
        long_name = "Acme::Licensing::Protection::ValidationEngine<std::__1::basic_string<char>>"
        tab._apply_data([ClassInfo(name=long_name, address=0x2000, methods=[], fields=[])])
        top = tab._tree.topLevelItem(0)
        assert top is not None
        assert top.toolTip(0) == long_name, "top-level class row tooltip does not carry the full class name"
    finally:
        tab.deleteLater()


def test_m43_address_column_is_resize_to_contents_while_names_stretch(qapp: QApplication) -> None:
    """``CallGraphTab`` must resize Address to contents, keeping names stretched.

    Pre-fix, ``_make_table`` applied uniform ``Stretch`` to all three
    columns via ``_stretch_headers``, so the short fixed-format Address
    column claimed an equal share of the table width as the free-text
    Caller/Callee name columns. This asserts the concrete per-column
    override the fix installs: Caller/Callee stay ``Stretch`` and Address
    becomes ``ResizeToContents``.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    tab = CallGraphTab()
    try:
        header = tab._table.horizontalHeader()
        assert header is not None
        assert header.sectionResizeMode(0) == QHeaderView.ResizeMode.Stretch, "Caller column must remain Stretch"
        assert header.sectionResizeMode(1) == QHeaderView.ResizeMode.Stretch, "Callee column must remain Stretch"
        assert header.sectionResizeMode(2) == QHeaderView.ResizeMode.ResizeToContents, (
            "Address column is still Stretch; it will claim as much width as the long Caller/Callee name columns"
        )
    finally:
        tab.deleteLater()


def test_m43_long_names_get_far_more_width_than_short_address(qapp: QApplication) -> None:
    """Long mangled Caller/Callee names must consume far more width than Address.

    Pre-fix, uniform ``Stretch`` split the table width roughly evenly across
    all three columns, so a short address like ``0xDEADBEEF`` would occupy
    nearly the same width as a long mangled C++ symbol, squeezing the name
    columns. Post-fix, Address is ``ResizeToContents`` (sized tightly to its
    own text) while Caller/Callee absorb the freed width via ``Stretch``.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    tab = CallGraphTab()
    try:
        tab.resize(900, 400)
        tab.show()
        QApplication.processEvents()

        caller = "_ZN4Acme9Licensing17ValidationEngine18verifyLicenseKeyEPKcS3_"
        callee = "_ZN4Acme6Crypto11AesDecryptorC1Ev"
        edge = {"name": caller, "addr": 0xDEADBEEF, "imports": [callee]}
        tab._apply_data([edge])
        QApplication.processEvents()

        header = tab._table.horizontalHeader()
        assert header is not None
        caller_width = header.sectionSize(0)
        callee_width = header.sectionSize(1)
        address_width = header.sectionSize(2)

        fm = QFontMetrics(tab._table.font())
        address_text_width = fm.horizontalAdvance("0xDEADBEEF")
        assert address_width < address_text_width + 40, (
            f"Address column ({address_width}px) is far wider than its own text ({address_text_width}px); "
            "it is still stretching like a name column"
        )
        assert caller_width > address_width * 2, (
            f"Caller column ({caller_width}px) did not absorb the width freed from Address ({address_width}px)"
        )
        assert callee_width > address_width * 2, (
            f"Callee column ({callee_width}px) did not absorb the width freed from Address ({address_width}px)"
        )

        row_address_text = tab._table.item(0, 2)
        assert row_address_text is not None
        assert row_address_text.text() == "0xDEADBEEF"
    finally:
        tab.deleteLater()
