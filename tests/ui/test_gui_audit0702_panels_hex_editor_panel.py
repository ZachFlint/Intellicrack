# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the GUI audit findings in ``hex_editor.panel``.

Each test targets one audit finding and fails against the pre-fix behaviour:

* ``test_c2_*`` (C2): ``HexEditorPanel.set_state_holder`` must register the
  ``_state_event_received`` pyqtSignal's ``emit`` as the ``HexDocumentState``
  callback, not the GUI-mutating handler directly. Invoking a
  ``HexDocumentState.notify_*`` call from a background thread -- exactly as
  ``HexEditorBridge``'s async RPC methods do from a non-GUI event-loop thread
  -- must not mutate any Qt widget synchronously on that thread; the mutation
  must only happen once the GUI thread's event loop delivers the queued
  signal.
* ``test_m51_*`` (M51): the toolbar encoding combo box must use
  ``AdjustToContents`` sizing (not a fixed 120px width) and must expose the
  full, untruncated codec description via tooltips, both per-item and for
  the current selection.
* ``test_m52_*`` (M52): ``_make_tree`` must configure every header section to
  ``ResizeToContents`` with the last section stretched, so variable-length
  columns (e.g. the Imports tree's "Function" column) actually grow to fit
  long content instead of clipping it at Qt's default section width.

All tests drive a real :class:`HexEditorPanel` and a real
:class:`HexDocumentState` under an offscreen QApplication; no panel or
state-holder behaviour is mocked or stubbed.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFontMetrics
from PyQt6.QtWidgets import QApplication, QComboBox, QHeaderView, QTreeWidgetItem

from intellicrack.bridges.hex_state import HexDocumentState
from intellicrack.ui.panels.hex_editor.panel import _ENCODING_COMBO_WIDTH, HexEditorPanel


if TYPE_CHECKING:
    from collections.abc import Callable


_MAX_WAIT_S: Final[float] = 3.0
_POLL_INTERVAL_S: Final[float] = 0.01
_JOIN_TIMEOUT_S: Final[float] = 5.0


def _pump_until(qapp: QApplication, predicate: Callable[[], bool]) -> bool:
    """Pump the Qt event loop until ``predicate`` is satisfied or time runs out.

    Args:
        qapp: The shared QApplication whose event loop is pumped.
        predicate: Zero-argument callable polled after each pump.

    Returns:
        bool: True if ``predicate`` became truthy before the deadline.
    """
    deadline = time.monotonic() + _MAX_WAIT_S
    while time.monotonic() < deadline:
        if predicate():
            return True
        qapp.processEvents()
        time.sleep(_POLL_INTERVAL_S)
    return bool(predicate())


class TestC2StateEventCrossThreadMarshalling:
    """C2: bridge-thread state notifications must be marshalled to the GUI thread."""

    def test_c2_background_thread_highlight_added_does_not_mutate_widget_synchronously(
        self,
        qapp: QApplication,
    ) -> None:
        """A background-thread ``HIGHLIGHT_RULE_ADDED`` notification must not run in-place.

        Simulates exactly what ``HexEditorBridge.add_highlight_rule`` does
        when its coroutine runs on the bridge's background event-loop
        thread: it calls ``state_holder.notify_highlight_rule_added(...)``,
        which ``HexDocumentState._dispatch_one`` delivers by invoking every
        registered callback synchronously on the calling thread.

        Pre-fix, the registered callback was the ``on_state_event`` closure
        itself, so ``_apply_bridge_highlight_rule_added`` -- and its
        ``QListWidget.addItem`` / ``HexEditorWidget.update`` calls -- would
        run synchronously on this background thread. This test asserts the
        list widget has not been touched immediately after the background
        thread finishes, and only gains the new row once the GUI thread's
        event loop is pumped.

        Args:
            qapp: The shared QApplication fixture.
        """
        panel = HexEditorPanel()
        try:
            state_holder = HexDocumentState()
            panel.set_state_holder(state_holder)
            assert panel._highlight_rules_list is not None
            assert panel._highlight_rules_list.count() == 0

            rule = {
                "id": "rule-bg-added",
                "condition_type": "byte_equals",
                "condition_params": {"value": 65},
                "color": "#00FF00",
            }
            caller_thread_id: list[int] = []

            def _invoke_from_background() -> None:
                """Invoke the bridge notification from a non-GUI background thread."""
                caller_thread_id.append(threading.get_ident())
                state_holder.notify_highlight_rule_added(rule, source="bridge")

            worker = threading.Thread(target=_invoke_from_background, name="fake-bridge-event-loop")
            worker.start()
            worker.join(timeout=_JOIN_TIMEOUT_S)

            assert not worker.is_alive(), "background notification thread did not finish"
            assert caller_thread_id, "background thread never invoked the state-holder notification"
            assert caller_thread_id[0] != threading.get_ident(), "test setup error: notification ran on the GUI thread"

            assert panel._highlight_rules_list.count() == 0, (
                "QListWidget.addItem executed synchronously on the background notification thread "
                "instead of being queued through the _state_event_received signal"
            )
            assert panel._active_highlight_ids == [], "highlight rule state was applied off the GUI thread"

            delivered = _pump_until(qapp, lambda: panel._highlight_rules_list.count() > 0)
            assert delivered, "the queued HIGHLIGHT_RULE_ADDED event was never delivered to the GUI thread"
            assert panel._active_highlight_ids == ["rule-bg-added"]
            assert str(rule["id"])[:8] in panel._highlight_rules_list.item(0).text()
        finally:
            panel.deleteLater()

    def test_c2_background_thread_highlight_removed_does_not_mutate_widget_synchronously(
        self,
        qapp: QApplication,
    ) -> None:
        """A background-thread ``HIGHLIGHT_RULE_REMOVED`` notification must not run in-place.

        Seeds a rule on the GUI thread via the real
        ``_apply_bridge_highlight_rule_added`` method, then removes it from
        a background thread via ``state_holder.notify_highlight_rule_removed``.
        Pre-fix this would call ``QListWidget.takeItem`` synchronously on the
        background thread; post-fix the row must survive until the GUI
        thread processes the queued signal.

        Args:
            qapp: The shared QApplication fixture.
        """
        panel = HexEditorPanel()
        try:
            state_holder = HexDocumentState()
            panel.set_state_holder(state_holder)
            assert panel._highlight_rules_list is not None

            seed_rule = {
                "id": "rule-bg-removed",
                "condition_type": "byte_equals",
                "condition_params": {"value": 66},
                "color": "#0000FF",
            }
            panel._apply_bridge_highlight_rule_added(seed_rule)
            assert panel._highlight_rules_list.count() == 1
            assert panel._active_highlight_ids == ["rule-bg-removed"]

            caller_thread_id: list[int] = []

            def _invoke_from_background() -> None:
                """Invoke the removal notification from a non-GUI background thread."""
                caller_thread_id.append(threading.get_ident())
                state_holder.notify_highlight_rule_removed("rule-bg-removed", source="bridge")

            worker = threading.Thread(target=_invoke_from_background, name="fake-bridge-event-loop")
            worker.start()
            worker.join(timeout=_JOIN_TIMEOUT_S)

            assert not worker.is_alive(), "background notification thread did not finish"
            assert caller_thread_id, "background thread never invoked the state-holder notification"
            assert caller_thread_id[0] != threading.get_ident(), "test setup error: notification ran on the GUI thread"

            assert panel._highlight_rules_list.count() == 1, (
                "QListWidget.takeItem executed synchronously on the background notification thread "
                "instead of being queued through the _state_event_received signal"
            )
            assert panel._active_highlight_ids == ["rule-bg-removed"]

            delivered = _pump_until(qapp, lambda: panel._highlight_rules_list.count() == 0)
            assert delivered, "the queued HIGHLIGHT_RULE_REMOVED event was never delivered to the GUI thread"
            assert panel._active_highlight_ids == []
        finally:
            panel.deleteLater()


class TestM51EncodingComboFitsLongDescriptions:
    """M51: the toolbar encoding combo must grow to fit and tooltip long codec names."""

    def test_m51_encoding_combo_uses_adjust_to_contents_and_not_fixed_width(self, qapp: QApplication) -> None:
        """The combo must resize to its contents instead of a fixed 120px box.

        Pre-fix, ``setFixedWidth(_ENCODING_COMBO_WIDTH)`` pinned both the
        minimum and maximum width to 120px, so no long codec description
        could ever widen the closed combo box beyond a truncated fragment.
        The fix switches to ``setMinimumWidth`` plus ``AdjustToContents``,
        leaving the maximum width unconstrained.

        Args:
            qapp: The shared QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        try:
            combo = panel._encoding_combo
            assert combo is not None
            assert combo.sizeAdjustPolicy() == QComboBox.SizeAdjustPolicy.AdjustToContents
            assert combo.minimumWidth() == _ENCODING_COMBO_WIDTH
            assert combo.maximumWidth() > _ENCODING_COMBO_WIDTH, (
                "the combo box is still pinned to a fixed maximum width and cannot grow past 120px"
            )
        finally:
            panel.deleteLater()

    def test_m51_encoding_combo_items_carry_full_description_as_tooltip_role(self, qapp: QApplication) -> None:
        """Every combo item's ToolTipRole must mirror its full display text.

        Pre-fix, no per-item tooltip was ever set, so a user could not
        recover a truncated description without reopening the popup. This
        iterates every populated item and asserts the tooltip role equals
        the item's exact text.

        Args:
            qapp: The shared QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        try:
            combo = panel._encoding_combo
            assert combo is not None
            assert combo.count() > 0
            for index in range(combo.count()):
                text = combo.itemText(index)
                tooltip = combo.itemData(index, Qt.ItemDataRole.ToolTipRole)
                assert tooltip == text, f"item {index} tooltip {tooltip!r} does not mirror its display text {text!r}"
        finally:
            panel.deleteLater()

    def test_m51_selecting_encoding_updates_combo_tooltip_via_real_signal_wiring(self, qapp: QApplication) -> None:
        """Changing the current selection must refresh the combo's own tooltip.

        Drives the real ``currentTextChanged`` -> ``_on_encoding_changed``
        connection (not a direct method call), proving the signal wiring
        itself keeps the combo's tooltip in sync. Pre-fix the combo carried
        no tooltip at all, so the closed box gave no way to confirm a long
        selection.

        Args:
            qapp: The shared QApplication fixture.
        """
        panel = HexEditorPanel()
        try:
            combo = panel._encoding_combo
            assert combo is not None
            assert combo.count() >= 2, "need at least two encodings to exercise a selection change"
            combo.setCurrentIndex(combo.count() - 1)
            qapp.processEvents()
            assert combo.toolTip() == combo.currentText()
        finally:
            panel.deleteLater()

    def test_m51_long_codec_description_is_fully_recoverable_via_tooltip(self, qapp: QApplication) -> None:
        """A genuinely long hexcore codec description must be fully recoverable via tooltip.

        Uses ``intellicrack_hexcore``'s real ``list_encodings()`` registry
        (which includes descriptions such as "ISO-8859-16 (Latin-10,
        South-Eastern European)") to find an entry wider than the old fixed
        120px box, then asserts its tooltip and combo-box size adjustment
        expose it in full.

        Args:
            qapp: The shared QApplication fixture.
        """
        pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore backend required for the real codec registry")

        panel = HexEditorPanel()
        try:
            combo = panel._encoding_combo
            assert combo is not None
            fm = QFontMetrics(combo.font())
            candidates = [
                (index, combo.itemText(index))
                for index in range(combo.count())
                if fm.horizontalAdvance(combo.itemText(index)) > _ENCODING_COMBO_WIDTH
            ]
            assert candidates, "expected hexcore's registry to include descriptions wider than the old fixed 120px box"
            index, long_text = max(candidates, key=lambda pair: len(pair[1]))

            combo.setCurrentIndex(index)
            qapp.processEvents()

            assert combo.itemData(index, Qt.ItemDataRole.ToolTipRole) == long_text
            assert combo.toolTip() == long_text
            assert combo.sizeHint().width() >= fm.horizontalAdvance(long_text), (
                "AdjustToContents did not grow the combo box to fit the long description"
            )
        finally:
            panel.deleteLater()


class TestM52SharedTreeFactoryResizesColumns:
    """M52: ``_make_tree`` must configure resize-to-contents column behaviour."""

    def test_m52_make_tree_configures_header_resize_mode_and_stretch(self, qapp: QApplication) -> None:
        """``_make_tree`` must set every section to ``ResizeToContents`` and stretch the last one.

        Pre-fix, ``_make_tree`` only called
        ``setHeaderLabels``/``setRootIsDecorated``/``setAlternatingRowColors``
        and never touched ``setSectionResizeMode`` or
        ``setStretchLastSection``, leaving every header section at Qt's
        default ``Interactive`` resize mode.

        Args:
            qapp: The shared QApplication fixture.
        """
        del qapp
        tree = HexEditorPanel._make_tree(["Library", "Function", "Address"])
        try:
            header = tree.header()
            assert header is not None
            assert header.stretchLastSection() is True
            for section in range(tree.columnCount()):
                assert header.sectionResizeMode(section) == QHeaderView.ResizeMode.ResizeToContents, (
                    f"column {section} is not configured to resize to its contents"
                )
        finally:
            tree.deleteLater()

    def test_m52_imports_tree_function_column_grows_to_fit_long_mangled_name(self, qapp: QApplication) -> None:
        """A long mangled import name must widen the Function column instead of clipping.

        Uses the real ``_imports_tree`` built by ``_make_tree`` inside a
        live ``HexEditorPanel`` and feeds it a genuinely long C++ mangled
        import name -- the exact scenario M52 describes. Pre-fix, the
        default ``Interactive`` resize mode left the column pinned near
        Qt's small default section width regardless of content length.

        Args:
            qapp: The shared QApplication fixture.
        """
        panel = HexEditorPanel()
        try:
            tree = panel._imports_tree
            assert tree is not None
            tree.resize(600, 400)
            tree.show()

            long_name = "?CreateInstanceWithExtraLongMangledDecorationForTestingPurposesOnly@@YAXXZ"
            item = QTreeWidgetItem(["kernel32.dll", long_name, "0x00401000"])
            tree.addTopLevelItem(item)
            qapp.processEvents()

            header = tree.header()
            assert header is not None
            fm = QFontMetrics(tree.font())
            text_width = fm.horizontalAdvance(long_name)
            function_column_width = header.sectionSize(1)
            assert function_column_width >= text_width, (
                f"Function column ({function_column_width}px) did not grow to fit the "
                f"{text_width}px-wide import name; long names remain clipped"
            )
        finally:
            panel.deleteLater()

    def test_m52_exports_tree_name_column_grows_to_fit_long_mangled_symbol(self, qapp: QApplication) -> None:
        """A long mangled export symbol must widen the Name column instead of clipping.

        Mirrors the imports-tree gate for the exports tree's first "Name"
        column, which the finding also calls out by name.

        Args:
            qapp: The shared QApplication fixture.
        """
        panel = HexEditorPanel()
        try:
            tree = panel._exports_tree
            assert tree is not None
            tree.resize(600, 400)
            tree.show()

            long_symbol = "?VeryLongMangledExportedSymbolNameForColumnResizeTesting@@YAHXZ"
            item = QTreeWidgetItem([long_symbol, "0x00402000", "17"])
            tree.addTopLevelItem(item)
            qapp.processEvents()

            header = tree.header()
            assert header is not None
            fm = QFontMetrics(tree.font())
            text_width = fm.horizontalAdvance(long_symbol)
            name_column_width = header.sectionSize(0)
            assert name_column_width >= text_width, (
                f"Name column ({name_column_width}px) did not grow to fit the {text_width}px-wide export symbol; long names remain clipped"
            )
        finally:
            panel.deleteLater()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
