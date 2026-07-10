# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression test for the YARA goto finding: double-click must select the match range.

Pre-fix, ``YaraMixin.goto_offset`` was an empty stub and the match byte length
was not stored, so double-clicking a YARA result performed no selection of the
matched bytes. The fix (1) stores each match's byte length on the result item's
user data, (2) has ``_on_yara_result_double_clicked`` pass that length through,
and (3) makes ``goto_offset`` move the cursor and select the ``length``-byte
span. This test exercises all three: the panel ``goto_offset`` selection call,
the double-click dispatch of ``(offset, length)``, and the length storage.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QTreeWidgetItem

from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel
from intellicrack.ui.panels.hex_editor.yara import YaraMixin


if TYPE_CHECKING:
    from collections.abc import Iterator


_MATCH_OFFSET: Final[int] = 16
_MATCH_LENGTH: Final[int] = 8
_MATCH_DATA_HEX: Final[str] = "deadbeefcafe1234"
_EXPECTED_LEN_FROM_HEX: Final[int] = len(_MATCH_DATA_HEX) // 2


@pytest.fixture(scope="module")
def qapp() -> Iterator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt item construction.

    Yields:
        QApplication: The active Qt application for the test process.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class _RecordingWidget:
    """Hex-widget stub recording navigation, selection, and repaint calls."""

    def __init__(self) -> None:
        """Initialise with empty navigation and selection call logs."""
        self.goto_calls: list[int] = []
        self.selection_calls: list[tuple[int, int]] = []
        self.update_calls: int = 0

    def goto_offset(self, offset: int) -> None:
        """Record a cursor navigation to ``offset``.

        Args:
            offset: Target byte offset.
        """
        self.goto_calls.append(offset)

    def set_selection_range(self, start: int, end: int) -> None:
        """Record a selection-range assignment.

        Args:
            start: Inclusive selection start offset.
            end: Inclusive selection end offset.
        """
        self.selection_calls.append((start, end))

    def update(self) -> None:
        """Record a repaint request."""
        self.update_calls += 1


class _GotoHarness:
    """Harness invoking the real ``HexEditorPanel.goto_offset`` over a stub widget."""

    def __init__(self, widget: _RecordingWidget | None) -> None:
        """Initialise the harness with the hex-widget stub to drive.

        Args:
            widget: Recording widget stub installed as ``self._hex_widget``.
        """
        self._hex_widget: _RecordingWidget | None = widget

    def goto_offset(self, offset: int, length: int = 0) -> None:
        """Invoke the production ``goto_offset`` implementation.

        Args:
            offset: Target byte offset.
            length: Number of bytes to select starting at ``offset``.
        """
        getattr(HexEditorPanel, "goto_offset")(self, offset, length)


class _DoubleClickHarness:
    """Harness invoking the real YARA double-click handler and recording goto args."""

    def __init__(self) -> None:
        """Initialise with an empty goto-call log."""
        self.goto_calls: list[tuple[int, int]] = []

    def goto_offset(self, offset: int, length: int = 0) -> None:
        """Record the offset and length the handler forwards.

        Args:
            offset: Target byte offset extracted from the result item.
            length: Match byte length extracted from the result item's user data.
        """
        self.goto_calls.append((offset, length))

    def handle_double_click(self, item: QTreeWidgetItem, column: int) -> None:
        """Invoke the production ``_on_yara_result_double_clicked`` handler.

        Args:
            item: The double-clicked result tree item.
            column: The double-clicked column index.
        """
        getattr(YaraMixin, "_on_yara_result_double_clicked")(self, item, column)


@pytest.mark.usefixtures("qapp")
class TestPanelGotoOffsetSelection:
    """goto_offset must move the cursor and select the requested span."""

    @staticmethod
    def test_goto_with_length_selects_inclusive_range(qapp: QApplication) -> None:
        """Assert a positive length selects ``[offset, offset+length-1]`` and repaints.

        Args:
            qapp: Qt application fixture (kept alive for item construction).
        """
        del qapp
        widget = _RecordingWidget()
        _GotoHarness(widget).goto_offset(_MATCH_OFFSET, _MATCH_LENGTH)

        assert widget.goto_calls == [_MATCH_OFFSET], f"cursor must move to {_MATCH_OFFSET}, got {widget.goto_calls}"
        assert widget.selection_calls == [(_MATCH_OFFSET, _MATCH_OFFSET + _MATCH_LENGTH - 1)], (
            f"selection must cover the match span, got {widget.selection_calls}"
        )
        assert widget.update_calls >= 1, "widget must repaint after selecting the match range"

    @staticmethod
    def test_goto_without_length_does_not_select(qapp: QApplication) -> None:
        """Assert length<=0 moves the cursor only and makes no selection.

        Args:
            qapp: Qt application fixture (kept alive for item construction).
        """
        del qapp
        widget = _RecordingWidget()
        _GotoHarness(widget).goto_offset(_MATCH_OFFSET, 0)

        assert widget.goto_calls == [_MATCH_OFFSET], f"cursor must still move to {_MATCH_OFFSET}, got {widget.goto_calls}"
        assert widget.selection_calls == [], f"no selection must be made when length is 0, got {widget.selection_calls}"


@pytest.mark.usefixtures("qapp")
class TestYaraDoubleClickDispatch:
    """Double-clicking a YARA match must forward its offset and stored length."""

    @staticmethod
    def test_double_click_forwards_offset_and_length(qapp: QApplication) -> None:
        """Assert the handler passes the item offset and user-data length to goto_offset.

        Args:
            qapp: Qt application fixture (kept alive for item construction).
        """
        del qapp
        parent = QTreeWidgetItem(["rule"])
        child = QTreeWidgetItem(["", f"0x{_MATCH_OFFSET:08X}", "$a", "DE AD"])
        child.setData(1, Qt.ItemDataRole.UserRole, _MATCH_LENGTH)
        parent.addChild(child)

        harness = _DoubleClickHarness()
        harness.handle_double_click(child, 1)

        assert harness.goto_calls == [(_MATCH_OFFSET, _MATCH_LENGTH)], (
            f"double-click must forward ({_MATCH_OFFSET}, {_MATCH_LENGTH}), got {harness.goto_calls}"
        )

    @staticmethod
    def test_double_click_on_rule_row_does_nothing(qapp: QApplication) -> None:
        """Assert double-clicking a top-level rule row (no parent) is a no-op.

        Args:
            qapp: Qt application fixture (kept alive for item construction).
        """
        del qapp
        parent = QTreeWidgetItem(["rule"])

        harness = _DoubleClickHarness()
        harness.handle_double_click(parent, 0)

        assert harness.goto_calls == [], f"a rule row double-click must not navigate, got {harness.goto_calls}"


@pytest.mark.usefixtures("qapp")
class TestYaraMatchLengthStorage:
    """Match rows must persist the match byte length for range selection."""

    @staticmethod
    def test_append_stores_match_length_in_user_data(qapp: QApplication) -> None:
        """Assert ``_append_yara_match_strings`` stores the byte length on the row.

        Args:
            qapp: Qt application fixture (kept alive for item construction).
        """
        del qapp
        rule_item = QTreeWidgetItem(["rule"])
        match: dict[str, Any] = {
            "rule": "rule",
            "strings": [{"identifier": "$a", "offset": _MATCH_OFFSET, "data": _MATCH_DATA_HEX}],
        }

        offsets: list[tuple[int, int]] = getattr(YaraMixin, "_append_yara_match_strings")(rule_item, match)

        assert offsets == [(_MATCH_OFFSET, _EXPECTED_LEN_FROM_HEX)], (
            f"append must report ({_MATCH_OFFSET}, {_EXPECTED_LEN_FROM_HEX}), got {offsets}"
        )
        child = rule_item.child(0)
        assert child is not None, "a child row must be appended for the match"
        stored = child.data(1, Qt.ItemDataRole.UserRole)
        assert stored == _EXPECTED_LEN_FROM_HEX, f"child must store match length {_EXPECTED_LEN_FROM_HEX} in user data, got {stored!r}"
