# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the 2026-07-02 GUI audit findings in ``cutter_tabs``.

* ``M19``: ``FlagsTab`` add-flag validation and RPC-error status text must be
  written to the dedicated ``_add_result_label`` next to the Add Flag row,
  never to ``_resolve_result_label`` (which belongs to the unrelated Resolve
  Address row), and a successful add must clear any stale add-flag message.
* ``L6``: ``TypeBrowserTab``'s tree header must resize the Name column with
  ``ResizeToContents`` so long type/struct/enum names are not squeezed by the
  stretched Details column.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from PyQt6.QtGui import QFontMetrics
from PyQt6.QtWidgets import QApplication, QHeaderView, QTreeWidgetItem

from intellicrack.ui.panels.cutter_tabs import FlagsTab, TypeBrowserTab


if TYPE_CHECKING:
    import pytest

    from intellicrack.bridges.cutter import CutterBridge


def _make_flags_tab(qapp: QApplication) -> FlagsTab:
    """Build a ``FlagsTab`` with a non-``None`` bridge attached.

    The bridge only needs to satisfy the ``is None`` guard in
    ``_on_add_flag``; none of the tests exercised here reach an actual RPC
    call on it.

    Args:
        qapp: The shared QApplication fixture.

    Returns:
        FlagsTab: A tab instance with ``_bridge`` set to a placeholder.
    """
    _ = qapp
    tab = FlagsTab()
    tab._bridge = cast("CutterBridge", object())
    return tab


class TestM19AddFlagStatusLabel:
    """M19: add-flag status text must land on the Add row's own label."""

    def test_m19_empty_name_writes_to_add_label_not_resolve_label(self, qapp: QApplication) -> None:
        """Empty-name validation failure updates ``_add_result_label`` only.

        Pre-fix this wrote "Enter a name and a valid address" into
        ``_resolve_result_label`` (the Resolve Address row's label), so this
        assertion on ``_add_result_label`` would fail before the fix.

        Args:
            qapp: The shared QApplication fixture.
        """
        tab = _make_flags_tab(qapp)
        try:
            tab._resolve_result_label.setText("")
            tab._add_name_input.setText("")
            tab._add_addr_input.setText("0x401000")

            tab._on_add_flag()

            assert tab._add_result_label.text() == "Enter a name and a valid address"
            assert not tab._resolve_result_label.text(), "resolve label must not receive add-flag status"
        finally:
            tab.deleteLater()

    def test_m19_invalid_address_writes_to_add_label_not_resolve_label(self, qapp: QApplication) -> None:
        """Invalid-address validation failure updates ``_add_result_label`` only.

        Args:
            qapp: The shared QApplication fixture.
        """
        tab = _make_flags_tab(qapp)
        try:
            tab._resolve_result_label.setText("")
            tab._add_name_input.setText("my_flag")
            tab._add_addr_input.setText("not-an-address")

            tab._on_add_flag()

            assert tab._add_result_label.text() == "Enter a name and a valid address"
            assert not tab._resolve_result_label.text()
        finally:
            tab.deleteLater()

    def test_m19_invalid_size_writes_to_add_label_not_resolve_label(self, qapp: QApplication) -> None:
        """Invalid-size validation failure updates ``_add_result_label`` only.

        Pre-fix this branch also wrote into ``_resolve_result_label``.

        Args:
            qapp: The shared QApplication fixture.
        """
        tab = _make_flags_tab(qapp)
        try:
            tab._resolve_result_label.setText("")
            tab._add_name_input.setText("my_flag")
            tab._add_addr_input.setText("0x401000")
            tab._add_size_input.setText("not-a-size")

            tab._on_add_flag()

            assert tab._add_result_label.text() == "Invalid size"
            assert not tab._resolve_result_label.text()
        finally:
            tab.deleteLater()

    def test_m19_add_flag_error_writes_to_add_label_and_leaves_resolve_label_untouched(self, qapp: QApplication) -> None:
        """An RPC failure updates ``_add_result_label`` and leaves the resolve label alone.

        Pre-fix, ``_on_add_flag_error`` overwrote whatever was in
        ``_resolve_result_label`` (e.g. a genuine resolve-address result),
        which is exactly the cross-contamination this test forbids.

        Args:
            qapp: The shared QApplication fixture.
        """
        tab = _make_flags_tab(qapp)
        try:
            tab._resolve_result_label.setText("resolved: some_other_flag")

            tab._on_add_flag_error(RuntimeError("rpc timeout"))

            assert tab._add_result_label.text() == "Add failed: rpc timeout"
            assert tab._resolve_result_label.text() == "resolved: some_other_flag", (
                "add-flag error overwrote an unrelated resolve-address result"
            )
            assert tab._add_btn.isEnabled()
        finally:
            tab.deleteLater()

    def test_m19_add_flag_success_clears_stale_add_label_and_leaves_resolve_label_untouched(
        self,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A successful add clears a stale add-flag message from its own label.

        Pre-fix, ``_on_add_flag_success`` never cleared any label (the error
        path wrote into ``_resolve_result_label``, and success touched
        neither), so a stale "Add failed: ..." message would persist
        indefinitely. This asserts the now-owned ``_add_result_label`` is
        cleared, and that the unrelated resolve label is left as-is.

        ``_on_add_flag_success`` unconditionally ends with a call to
        ``self._fetch_flags()``, which issues a live RPC through
        ``self._bridge.get_flags()``. That refresh call is incidental to the
        label-clearing behaviour this test targets, so the instance's
        ``_fetch_flags`` is monkeypatched to a no-op: this keeps the
        placeholder ``_bridge`` (which satisfies only the ``is None`` guards
        exercised elsewhere in this class) usable here too, without spinning
        up a real background RPC worker thread whose async completion could
        race the test's own teardown.

        Args:
            qapp: The shared QApplication fixture.
            monkeypatch: Fixture used to stub out the live flag-refresh call.
        """
        tab = _make_flags_tab(qapp)
        try:
            monkeypatch.setattr(tab, "_fetch_flags", lambda: None)
            tab._add_result_label.setText("Add failed: previous attempt")
            tab._resolve_result_label.setText("resolved: unrelated")
            tab._add_name_input.setText("my_flag")
            tab._add_addr_input.setText("0x401000")

            tab._on_add_flag_success()

            assert not tab._add_result_label.text()
            assert tab._resolve_result_label.text() == "resolved: unrelated"
            assert not tab._add_name_input.text()
            assert not tab._add_addr_input.text()
            assert tab._add_btn.isEnabled()
        finally:
            tab.deleteLater()


class TestL6TypeBrowserHeaderResize:
    """L6: the Name column resizes to fit content instead of being squeezed."""

    def test_l6_name_column_uses_resize_to_contents_mode(self, qapp: QApplication) -> None:
        """The tree header's Name column (0) is in ``ResizeToContents`` mode.

        Pre-fix no resize mode was ever set, so column 0 stayed at the
        header's default ``Interactive`` mode; this assertion fails against
        that pre-fix code.

        Args:
            qapp: The shared QApplication fixture.
        """
        _ = qapp
        tab = TypeBrowserTab()
        try:
            header = tab._tree.header()
            assert header is not None
            assert header.sectionResizeMode(0) == QHeaderView.ResizeMode.ResizeToContents
            assert header.stretchLastSection() is True
        finally:
            tab.deleteLater()

    def test_l6_long_name_is_not_squeezed_by_stretched_details_column(self, qapp: QApplication) -> None:
        """A long type name widens column 0 instead of being clipped to a fixed width.

        Pre-fix, column 0 stayed at the header's fixed default section width
        (roughly 100px) regardless of content because no resize mode was set
        and the trailing "Details" column absorbed all remaining space via
        ``stretchLastSection``; the long name would be squeezed/elided. Post
        fix, ``ResizeToContents`` grows column 0 to fit the widest item, so
        its rendered width tracks the actual text width.

        Args:
            qapp: The shared QApplication fixture.
        """
        _ = qapp
        long_name = "TemplatedStructWithAVeryLongQualifiedTypeName<Foo, Bar, Baz, Qux>::NestedMember"
        tab = TypeBrowserTab()
        try:
            tab.resize(320, 240)
            tab.show()
            QTreeWidgetItem(tab._tree, [long_name, "size=4"])
            QApplication.processEvents()
            tab._tree.doItemsLayout()
            QApplication.processEvents()

            header = tab._tree.header()
            assert header is not None
            fm = QFontMetrics(tab._tree.font())
            text_width = fm.horizontalAdvance(long_name)

            assert header.sectionSize(0) >= text_width * 0.9, (
                f"Name column width {header.sectionSize(0)} does not track the long "
                f"item text width {text_width}; the column is being squeezed"
            )
            assert header.sectionSize(0) == tab._tree.sizeHintForColumn(0)
        finally:
            tab.deleteLater()
