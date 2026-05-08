# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for audit4 B4 - MemoryTab findings F-0003, F-0005, F-0006, F-0007, F-0008, F-0009.

Each test documents the finding it covers and is written to fail before the
fix and pass after it.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest
from PyQt6.QtWidgets import QApplication, QMessageBox, QTableWidgetItem

import intellicrack.ui.panels.process_panel._memory_tab as _mem_mod
from intellicrack.ui.panels.process_panel._memory_tab import MemoryTab


if TYPE_CHECKING:
    from collections.abc import Iterator

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def qapp() -> Iterator[QApplication]:
    """Provide a session-scoped QApplication.

    Qt requires exactly one QApplication per process.

    Yields:
        QApplication: A live QApplication for widget construction.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


@pytest.fixture
def tab(qapp: QApplication) -> MemoryTab:  # noqa: ARG001
    """Create a MemoryTab instance for testing.

    Args:
        qapp: QApplication fixture — required to ensure Qt is initialised.

    Returns:
        MemoryTab: A fresh MemoryTab widget.
    """
    return MemoryTab()


def _noop_warning(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
    """Return Ok without showing a dialog.

    Args:
        *_args: Positional arguments (ignored).
        **_kwargs: Keyword arguments (ignored).

    Returns:
        QMessageBox.StandardButton: Ok button constant.
    """
    return QMessageBox.StandardButton.Ok


def _noop_warning_yes(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
    """Return Yes without showing a dialog.

    Args:
        *_args: Positional arguments (ignored).
        **_kwargs: Keyword arguments (ignored).

    Returns:
        QMessageBox.StandardButton: Yes button constant.
    """
    return QMessageBox.StandardButton.Yes


class TestRegionFilterFiltersTable:
    """F-0003: _region_filter textChanged is wired and filters the region table."""

    def test_region_filter_filters_table(self, tab: MemoryTab) -> None:
        """Filter input shows/hides rows based on case-insensitive substring.

        The filter slot is connected to textChanged; this test also verifies the
        slot logic works end-to-end via direct invocation so row ordering from
        Qt's sort model does not affect row-index assertions.

        Args:
            tab: MemoryTab fixture.
        """
        table = tab._region_table
        table.setSortingEnabled(False)
        table.setRowCount(3)
        table.setItem(0, 0, QTableWidgetItem("0x7FF600000000"))
        table.setItem(0, 2, QTableWidgetItem("rwx"))
        table.setItem(0, 5, QTableWidgetItem("ntdll.dll"))
        table.setItem(1, 0, QTableWidgetItem("0x00007FFE0000"))
        table.setItem(1, 2, QTableWidgetItem("r"))
        table.setItem(1, 5, QTableWidgetItem("kernel32.dll"))
        table.setItem(2, 0, QTableWidgetItem("0xABCD00000000"))
        table.setItem(2, 2, QTableWidgetItem("rw"))
        table.setItem(2, 5, QTableWidgetItem(""))

        tab._on_region_filter_changed("ntdll")

        assert not table.isRowHidden(0)
        assert table.isRowHidden(1)
        assert table.isRowHidden(2)

    def test_region_filter_wired_to_text_changed(self, tab: MemoryTab) -> None:
        """_region_filter.textChanged is connected to the filter slot.

        Verifies the signal wire-up required by F-0003 by checking that typing
        into the field updates row visibility without manually calling the slot.

        Args:
            tab: MemoryTab fixture.
        """
        table = tab._region_table
        table.setSortingEnabled(False)
        table.setRowCount(2)
        table.setItem(0, 5, QTableWidgetItem("ntdll.dll"))
        table.setItem(1, 5, QTableWidgetItem("kernel32.dll"))

        tab._region_filter.clear()
        tab._region_filter.insert("ntdll")

        assert not table.isRowHidden(0)
        assert table.isRowHidden(1)

    def test_region_filter_case_insensitive(self, tab: MemoryTab) -> None:
        """Filter match is case-insensitive.

        Args:
            tab: MemoryTab fixture.
        """
        table = tab._region_table
        table.setSortingEnabled(False)
        table.setRowCount(2)
        table.setItem(0, 5, QTableWidgetItem("KERNEL32.DLL"))
        table.setItem(1, 5, QTableWidgetItem("ntdll.dll"))

        tab._on_region_filter_changed("kernel32")

        assert not table.isRowHidden(0)
        assert table.isRowHidden(1)

    def test_region_filter_empty_shows_all(self, tab: MemoryTab) -> None:
        """Empty filter text reveals all rows.

        Args:
            tab: MemoryTab fixture.
        """
        table = tab._region_table
        table.setSortingEnabled(False)
        table.setRowCount(3)
        for row in range(3):
            table.setItem(row, 0, QTableWidgetItem(f"0x{row:016X}"))
            table.setRowHidden(row, True)  # noqa: FBT003

        tab._on_region_filter_changed("")

        for row in range(3):
            assert not table.isRowHidden(row)


class TestActionsDisabledWhenUnattached:
    """F-0005: Memory action buttons are disabled when no process is attached."""

    def test_buttons_disabled_on_init(self, tab: MemoryTab) -> None:
        """All action buttons are disabled immediately after construction.

        Args:
            tab: MemoryTab fixture.
        """
        assert tab._action_buttons, "Expected at least one action button registered"
        for btn in tab._action_buttons:
            assert not btn.isEnabled(), f"Button '{btn.text()}' should be disabled when unattached"

    def test_buttons_enabled_after_set_attached_pid(self, tab: MemoryTab) -> None:
        """Action buttons become enabled once set_attached_pid is called with a PID.

        Args:
            tab: MemoryTab fixture.
        """
        tab.set_attached_pid(1234)
        for btn in tab._action_buttons:
            assert btn.isEnabled(), f"Button '{btn.text()}' should be enabled after attach"

    def test_buttons_disabled_after_detach(self, tab: MemoryTab) -> None:
        """Action buttons become disabled again after set_attached_pid(None).

        Args:
            tab: MemoryTab fixture.
        """
        tab.set_attached_pid(1234)
        tab.set_attached_pid(None)
        for btn in tab._action_buttons:
            assert not btn.isEnabled(), f"Button '{btn.text()}' should be disabled after detach"


class TestActionsDisabledHandlerNoDispatch:
    """F-0005: Handler preconditions block dispatch when not attached."""

    def test_on_read_no_dispatch_when_unattached(self, tab: MemoryTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """_on_read does not call bridge when _attached_pid is None.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab._bridge = MagicMock()
        tab._attached_pid = None

        dispatch_mock = MagicMock()
        monkeypatch.setattr(_mem_mod, "run_bridge_coroutine_async", dispatch_mock)
        monkeypatch.setattr(QMessageBox, "warning", _noop_warning)

        tab._read_addr.setText("0x1000")
        tab._on_read()

        dispatch_mock.assert_not_called()

    def test_on_write_no_dispatch_when_unattached(self, tab: MemoryTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """_on_write does not call bridge when _attached_pid is None.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab._bridge = MagicMock()
        tab._attached_pid = None

        dispatch_mock = MagicMock()
        monkeypatch.setattr(_mem_mod, "run_bridge_coroutine_async", dispatch_mock)
        monkeypatch.setattr(QMessageBox, "warning", _noop_warning)

        tab._write_addr.setText("0x1000")
        tab._write_input.setPlainText("90 90")
        tab._on_write()

        dispatch_mock.assert_not_called()

    def test_on_search_no_dispatch_when_unattached(self, tab: MemoryTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """_on_search does not call bridge when _attached_pid is None.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab._bridge = MagicMock()
        tab._attached_pid = None

        dispatch_mock = MagicMock()
        monkeypatch.setattr(_mem_mod, "run_bridge_coroutine_async", dispatch_mock)
        monkeypatch.setattr(QMessageBox, "warning", _noop_warning)

        tab._search_pattern.setText("90 90")
        tab._on_search()

        dispatch_mock.assert_not_called()


class TestSearchStatusResetsOnFailure:
    """F-0006: _on_search 'Searching...' status resets on failure via _on_error."""

    def test_search_status_resets_on_failure(self, tab: MemoryTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """When the bridge search fails, _search_status is set to an error string.

        The status must not remain 'Searching...' after the error callback fires.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab._bridge = MagicMock()
        tab.set_attached_pid(1234)

        captured_on_error: list[object] = []

        def fake_dispatch(
            _coro: object,
            _on_success: object,
            on_error: object,
            _parent: object,
        ) -> None:
            captured_on_error.append(on_error)

        monkeypatch.setattr(_mem_mod, "run_bridge_coroutine_async", fake_dispatch)
        monkeypatch.setattr(QMessageBox, "critical", _noop_warning)

        tab._search_pattern.setText("48 8B")
        tab._on_search()

        assert tab._search_status.text() == "Searching..."
        assert captured_on_error, "Expected an on_error callback to be registered"

        error_cb = captured_on_error[0]
        assert callable(error_cb)
        error_cb(RuntimeError("bridge error"))

        assert tab._search_status.text() != "Searching...", "_search_status was left as 'Searching...' after error — F-0006 not fixed"


class TestFreeRemovesAllocationRow:
    """F-0007: _on_free removes the matching Allocated row instead of adding a Freed row."""

    def test_free_removes_allocation_row(self, tab: MemoryTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """After a successful free, the matching Allocated row is removed from _alloc_log.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab._bridge = MagicMock()
        tab.set_attached_pid(1234)

        table = tab._alloc_log
        table.setRowCount(2)
        table.setItem(0, 0, QTableWidgetItem("0x7FF600000000"))
        table.setItem(0, 1, QTableWidgetItem("4096"))
        table.setItem(0, 2, QTableWidgetItem("rwx"))
        table.setItem(0, 3, QTableWidgetItem("Allocated"))
        table.setItem(1, 0, QTableWidgetItem("0xABCD00001000"))
        table.setItem(1, 1, QTableWidgetItem("4096"))
        table.setItem(1, 2, QTableWidgetItem("rw"))
        table.setItem(1, 3, QTableWidgetItem("Allocated"))

        captured_on_success: list[object] = []

        def fake_dispatch(
            _coro: object,
            on_success: object,
            _on_error: object,
            _parent: object,
        ) -> None:
            captured_on_success.append(on_success)

        monkeypatch.setattr(_mem_mod, "run_bridge_coroutine_async", fake_dispatch)
        monkeypatch.setattr(QMessageBox, "warning", _noop_warning_yes)

        tab._free_addr.setText("0x7FF600000000")
        tab._on_free()

        assert captured_on_success, "Expected an on_success callback"
        success_cb = captured_on_success[0]
        assert callable(success_cb)
        success_cb(None)

        assert table.rowCount() == 1, f"Expected 1 row remaining after free, got {table.rowCount()} — F-0007 not fixed"
        remaining_item = table.item(0, 0)
        assert remaining_item is not None
        assert remaining_item.text() == "0xABCD00001000"

        for row in range(table.rowCount()):
            action_item = table.item(row, 3)
            assert action_item is None or action_item.text() != "Freed", "Found a 'Freed' row in _alloc_log — F-0007 not fixed"

    def test_free_does_not_add_freed_row(self, tab: MemoryTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """_on_free success callback never adds a new row to _alloc_log.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab._bridge = MagicMock()
        tab.set_attached_pid(1234)

        table = tab._alloc_log
        table.setRowCount(1)
        table.setItem(0, 0, QTableWidgetItem("0x1000"))
        table.setItem(0, 1, QTableWidgetItem("4096"))
        table.setItem(0, 2, QTableWidgetItem("rw"))
        table.setItem(0, 3, QTableWidgetItem("Allocated"))

        captured_on_success: list[object] = []

        def fake_dispatch(
            _coro: object,
            on_success: object,
            _on_error: object,
            _parent: object,
        ) -> None:
            captured_on_success.append(on_success)

        monkeypatch.setattr(_mem_mod, "run_bridge_coroutine_async", fake_dispatch)
        monkeypatch.setattr(QMessageBox, "warning", _noop_warning_yes)

        tab._free_addr.setText("0x1000")
        tab._on_free()

        assert captured_on_success
        captured_on_success[0](None)

        row_count_after = table.rowCount()
        assert row_count_after == 0, f"Expected 0 rows after free, got {row_count_after}"


class TestInvalidAddressSurfacesError:
    """F-0008: _on_protect and _on_free surface user-visible error on invalid address."""

    def test_invalid_protect_address_shows_messagebox(
        self,
        tab: MemoryTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_protect shows a QMessageBox.critical for an unparseable address.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab._bridge = MagicMock()
        tab.set_attached_pid(1234)

        critical_calls: list[tuple[object, ...]] = []

        def capture_critical(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            critical_calls.append(args)
            return QMessageBox.StandardButton.Ok

        monkeypatch.setattr(QMessageBox, "critical", capture_critical)

        tab._prot_addr.setText("not_a_hex_address")
        tab._on_protect()

        assert critical_calls, "Expected QMessageBox.critical for invalid address — F-0008 not fixed"

    def test_invalid_free_address_shows_messagebox(
        self,
        tab: MemoryTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_free shows a QMessageBox.critical for an unparseable address.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab._bridge = MagicMock()
        tab.set_attached_pid(1234)

        critical_calls: list[tuple[object, ...]] = []

        def capture_critical(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            critical_calls.append(args)
            return QMessageBox.StandardButton.Ok

        monkeypatch.setattr(QMessageBox, "critical", capture_critical)

        tab._free_addr.setText("ZZZNOTANADDR")
        tab._on_free()

        assert critical_calls, "Expected QMessageBox.critical for invalid free address — F-0008 not fixed"

    def test_invalid_protect_address_message_contains_input(
        self,
        tab: MemoryTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The error message for an invalid protect address contains the bad input text.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab._bridge = MagicMock()
        tab.set_attached_pid(1234)

        messages: list[str] = []

        def capture_critical(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            messages.append(str(args[2]))
            return QMessageBox.StandardButton.Ok

        monkeypatch.setattr(QMessageBox, "critical", capture_critical)

        tab._prot_addr.setText("bad_input_xyz")
        tab._on_protect()

        assert any("bad_input_xyz" in m for m in messages), "Error message does not contain the invalid address text — F-0008 not fixed"


class TestAddressFieldHasPlaceholder:
    """F-0009: _build_protect_tab address field has a setPlaceholderText hint."""

    def test_prot_addr_has_placeholder(self, tab: MemoryTab) -> None:
        """_prot_addr placeholder text shows the expected address format.

        Args:
            tab: MemoryTab fixture.
        """
        placeholder = tab._prot_addr.placeholderText()
        assert placeholder, "Expected placeholder text on _prot_addr — F-0009 not fixed"
        assert "0x" in placeholder.lower() or "7FF" in placeholder, (
            f"Placeholder '{placeholder}' does not indicate hex address format — F-0009 not fixed"
        )

    def test_prot_addr_placeholder_matches_expected_format(self, tab: MemoryTab) -> None:
        """_prot_addr placeholder shows an example with a realistic 64-bit address format.

        Args:
            tab: MemoryTab fixture.
        """
        placeholder = tab._prot_addr.placeholderText()
        assert "0x7FF600000000" in placeholder or ("0x" in placeholder and len(placeholder) > 4), (
            f"Placeholder '{placeholder}' does not match expected format — F-0009 not fixed"
        )
