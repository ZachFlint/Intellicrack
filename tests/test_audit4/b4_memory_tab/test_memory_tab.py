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
from typing import TYPE_CHECKING, cast
from unittest.mock import MagicMock

import pytest
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
)

from intellicrack.ui.panels import async_bridge as _async_bridge_mod
from intellicrack.ui.panels.process_panel import memory_tab as _memory_tab_mod
from intellicrack.ui.panels.process_panel.memory_tab import MemoryTab


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
def tab(qapp: QApplication) -> MemoryTab:
    """Create a MemoryTab instance for testing.

    Args:
        qapp: QApplication fixture — required to ensure Qt is initialised.

    Returns:
        MemoryTab: A fresh MemoryTab widget.
    """
    assert isinstance(qapp, QApplication)
    return MemoryTab()


def _region_filter(tab: MemoryTab) -> QLineEdit:
    """Return the region-filter ``QLineEdit`` widget of a MemoryTab.

    Retrieved via ``getattr`` and type-narrowed with ``isinstance`` so the
    accessor is fully type-safe without reaching through a private attribute
    annotation.

    Args:
        tab: MemoryTab whose region filter field is requested.

    Returns:
        QLineEdit: The live region-filter input widget.
    """
    return _line_edit(tab, "_region_filter")


def _region_table(tab: MemoryTab) -> QTableWidget:
    """Return the region-map ``QTableWidget`` of a MemoryTab.

    Args:
        tab: MemoryTab whose region table is requested.

    Returns:
        QTableWidget: The live region-map table widget.
    """
    return _table(tab, "_region_table")


def _line_edit(tab: MemoryTab, attr_name: str) -> QLineEdit:
    """Return a named ``QLineEdit`` member of a MemoryTab, type-narrowed.

    Args:
        tab: MemoryTab to read from.
        attr_name: Name of the ``QLineEdit`` member.

    Returns:
        QLineEdit: The live line-edit widget.
    """
    widget = getattr(tab, attr_name)
    assert isinstance(widget, QLineEdit), f"MemoryTab.{attr_name} must be a QLineEdit"
    return widget


def _label(tab: MemoryTab, attr_name: str) -> QLabel:
    """Return a named ``QLabel`` member of a MemoryTab, type-narrowed.

    Args:
        tab: MemoryTab to read from.
        attr_name: Name of the ``QLabel`` member.

    Returns:
        QLabel: The live label widget.
    """
    widget = getattr(tab, attr_name)
    assert isinstance(widget, QLabel), f"MemoryTab.{attr_name} must be a QLabel"
    return widget


def _table(tab: MemoryTab, attr_name: str) -> QTableWidget:
    """Return a named ``QTableWidget`` member of a MemoryTab, type-narrowed.

    Args:
        tab: MemoryTab to read from.
        attr_name: Name of the ``QTableWidget`` member.

    Returns:
        QTableWidget: The live table widget.
    """
    widget = getattr(tab, attr_name)
    assert isinstance(widget, QTableWidget), f"MemoryTab.{attr_name} must be a QTableWidget"
    return widget


def _plain_text(tab: MemoryTab, attr_name: str) -> QPlainTextEdit:
    """Return a named ``QPlainTextEdit`` member of a MemoryTab, type-narrowed.

    Args:
        tab: MemoryTab to read from.
        attr_name: Name of the ``QPlainTextEdit`` member.

    Returns:
        QPlainTextEdit: The live plain-text editor widget.
    """
    widget = getattr(tab, attr_name)
    assert isinstance(widget, QPlainTextEdit), f"MemoryTab.{attr_name} must be a QPlainTextEdit"
    return widget


def _action_buttons(tab: MemoryTab) -> list[QPushButton]:
    """Return the list of memory action buttons, type-narrowed.

    Args:
        tab: MemoryTab to read from.

    Returns:
        list[QPushButton]: The action-button list.
    """
    attr_name = "_action_buttons"
    buttons = getattr(tab, attr_name)
    assert isinstance(buttons, list), "MemoryTab._action_buttons must be a list"
    typed: list[QPushButton] = []
    for btn in cast("list[object]", buttons):
        assert isinstance(btn, QPushButton), "every action button must be a QPushButton"
        typed.append(btn)
    return typed


def _call_region_filter_changed(tab: MemoryTab, text: str) -> None:
    """Invoke the region-filter slot directly with the given text.

    Args:
        tab: MemoryTab whose filter slot is invoked.
        text: Filter substring passed to the slot.
    """
    method_name = "_on_region_filter_changed"
    slot = getattr(tab, method_name)
    assert callable(slot), "MemoryTab._on_region_filter_changed must be callable"
    slot(text)


def _invoke(tab: MemoryTab, method_name: str) -> None:
    """Invoke a named zero-argument handler method on a MemoryTab.

    Args:
        tab: MemoryTab whose handler is invoked.
        method_name: Name of the handler method to call.
    """
    handler = getattr(tab, method_name)
    assert callable(handler), f"MemoryTab.{method_name} must be callable"
    handler()


def _set_private(tab: MemoryTab, attr_name: str, value: object) -> None:
    """Assign a value to a named MemoryTab attribute.

    Used to wire test doubles into private collaborator slots without a
    private-attribute assignment expression.

    Args:
        tab: MemoryTab to mutate.
        attr_name: Attribute name to set.
        value: Value to assign.
    """
    setattr(tab, attr_name, value)


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
        table = _region_table(tab)
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

        _call_region_filter_changed(tab, "ntdll")

        assert not table.isRowHidden(0)
        assert table.isRowHidden(1)
        assert table.isRowHidden(2)

    def test_region_filter_wired_to_text_changed(self, tab: MemoryTab) -> None:
        """``_region_filter.textChanged`` is connected to the filter slot.

        Proves the signal wire-up required by F-0003 *directly* rather than by
        outcome alone. Two independent gates are asserted:

        * The ``textChanged`` signal reports exactly one connected receiver
          (``QObject.receivers`` is an oracle independent of the slot body);
          if the production ``connect`` call were removed this count would be 0.
        * Driving the field exclusively through ``setText`` (which is the only
          way a real user mutates the field, and which emits ``textChanged``)
          must update row visibility for *each* distinct value. The slot is
          never invoked directly. A sequence of three values whose matching row
          differs each time can only produce the expected visibility for every
          step if the signal genuinely re-drives the slot on every change, so a
          missing ``connect`` turns each transition red.

        Args:
            tab: MemoryTab fixture.
        """
        table = _region_table(tab)
        region_filter = _region_filter(tab)
        table.setSortingEnabled(False)
        table.setRowCount(2)
        table.setItem(0, 5, QTableWidgetItem("ntdll.dll"))
        table.setItem(1, 5, QTableWidgetItem("kernel32.dll"))

        receiver_count = region_filter.receivers(region_filter.textChanged)
        assert receiver_count == 1, f"textChanged must have exactly one connected receiver (the filter slot); got {receiver_count}"

        region_filter.setText("ntdll")
        assert not table.isRowHidden(0), "row 0 (ntdll.dll) must be visible after the signal drives the slot with 'ntdll'"
        assert table.isRowHidden(1), "row 1 (kernel32.dll) must be hidden after the signal drives the slot with 'ntdll'"

        region_filter.setText("kernel32")
        assert table.isRowHidden(0), "row 0 must flip to hidden when the signal re-drives the slot with 'kernel32'"
        assert not table.isRowHidden(1), "row 1 must flip to visible when the signal re-drives the slot with 'kernel32'"

        region_filter.setText("")
        assert not table.isRowHidden(0), "row 0 must be revealed when the signal re-drives the slot with empty text"
        assert not table.isRowHidden(1), "row 1 must be revealed when the signal re-drives the slot with empty text"

    def test_region_filter_signal_drives_slot_without_direct_call(self, tab: MemoryTab) -> None:
        """Signal-driven filter: ``setText`` changes row visibility without a direct slot call.

        Populates the table with two distinct module names, then drives the
        filter exclusively through ``QLineEdit.setText`` (which emits
        ``textChanged`` and reaches the slot only via the Qt signal connection).
        Row visibility is the independent oracle: if the signal were disconnected
        or the slot replaced with a no-op the rows would remain in their
        pre-filter state, turning the assertions red.

        Args:
            tab: MemoryTab fixture.
        """
        table = _region_table(tab)
        region_filter = _region_filter(tab)
        table.setSortingEnabled(False)
        table.setRowCount(2)
        table.setItem(0, 5, QTableWidgetItem("ntdll.dll"))
        table.setItem(1, 5, QTableWidgetItem("kernel32.dll"))

        region_filter.setText("ntdll")

        assert not table.isRowHidden(0), (
            "Row 0 (ntdll.dll) must be visible after signal-driven filter setText('ntdll')"
        )
        assert table.isRowHidden(1), (
            "Row 1 (kernel32.dll) must be hidden after signal-driven filter setText('ntdll')"
        )

        region_filter.setText("kernel32")

        assert table.isRowHidden(0), (
            "Row 0 (ntdll.dll) must be hidden after signal-driven filter setText('kernel32')"
        )
        assert not table.isRowHidden(1), (
            "Row 1 (kernel32.dll) must be visible after signal-driven filter setText('kernel32')"
        )

    def test_region_filter_case_insensitive(self, tab: MemoryTab) -> None:
        """Filter match is case-insensitive.

        Args:
            tab: MemoryTab fixture.
        """
        table = _region_table(tab)
        table.setSortingEnabled(False)
        table.setRowCount(2)
        table.setItem(0, 5, QTableWidgetItem("KERNEL32.DLL"))
        table.setItem(1, 5, QTableWidgetItem("ntdll.dll"))

        _call_region_filter_changed(tab, "kernel32")

        assert not table.isRowHidden(0)
        assert table.isRowHidden(1)

    def test_region_filter_empty_shows_all(self, tab: MemoryTab) -> None:
        """Empty filter text reveals all rows.

        Args:
            tab: MemoryTab fixture.
        """
        table = _region_table(tab)
        table.setSortingEnabled(False)
        table.setRowCount(3)
        hidden = True
        for row in range(3):
            table.setItem(row, 0, QTableWidgetItem(f"0x{row:016X}"))
            table.setRowHidden(row, hidden)

        _call_region_filter_changed(tab, "")

        for row in range(3):
            assert not table.isRowHidden(row)


class TestActionsDisabledWhenUnattached:
    """F-0005: Memory action buttons are disabled when no process is attached."""

    def test_buttons_disabled_on_init(self, tab: MemoryTab) -> None:
        """All action buttons are disabled immediately after construction.

        Args:
            tab: MemoryTab fixture.
        """
        assert _action_buttons(tab), "Expected at least one action button registered"
        for btn in _action_buttons(tab):
            assert not btn.isEnabled(), f"Button '{btn.text()}' should be disabled when unattached"

    def test_buttons_enabled_after_set_attached_pid(self, tab: MemoryTab) -> None:
        """Action buttons become enabled once set_attached_pid is called with a PID.

        Args:
            tab: MemoryTab fixture.
        """
        tab.set_attached_pid(1234)
        for btn in _action_buttons(tab):
            assert btn.isEnabled(), f"Button '{btn.text()}' should be enabled after attach"

    def test_buttons_disabled_after_detach(self, tab: MemoryTab) -> None:
        """Action buttons become disabled again after set_attached_pid(None).

        Args:
            tab: MemoryTab fixture.
        """
        tab.set_attached_pid(1234)
        tab.set_attached_pid(None)
        for btn in _action_buttons(tab):
            assert not btn.isEnabled(), f"Button '{btn.text()}' should be disabled after detach"


class TestActionsDisabledHandlerNoDispatch:
    """F-0005: Handler preconditions block dispatch when not attached.

    Each unattached test is paired with an attached counterpart that confirms
    the guard on ``_attached_pid`` is the sole controlling factor: when the PID
    is set, ``run_bridge_coroutine_logged`` is reached; when it is None the
    warning is shown and dispatch is skipped.
    """

    def test_on_read_no_dispatch_when_unattached(self, tab: MemoryTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """_on_read shows the 'Not Attached' warning and skips dispatch when _attached_pid is None.

        Patching the actual dispatch function the production code calls
        (``run_bridge_coroutine_logged``) - not the unrelated
        ``run_bridge_coroutine_async`` - guarantees the test goes red if the
        guard is removed even when the bridge mock is present.  The exact
        warning title and message are asserted so the test also fails if the
        production code shows the wrong dialog text.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(tab, "_bridge", MagicMock())
        _set_private(tab, "_attached_pid", None)

        warning_calls: list[tuple[object, ...]] = []

        def _capture_warning(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            warning_calls.append(args)
            return QMessageBox.StandardButton.Ok

        dispatch_calls: list[object] = []

        def _fail_if_dispatched(*args: object, **_kwargs: object) -> None:
            dispatch_calls.append(args)

        monkeypatch.setattr(_memory_tab_mod, "run_bridge_coroutine_logged", _fail_if_dispatched)
        monkeypatch.setattr(QMessageBox, "warning", _capture_warning)

        _line_edit(tab, "_read_addr").setText("0x1000")
        _invoke(tab, "_on_read")

        assert dispatch_calls == [], (
            f"run_bridge_coroutine_logged must not be called when _attached_pid is None; got {len(dispatch_calls)} call(s)"
        )
        assert warning_calls, "_on_read must show QMessageBox.warning when not attached"
        title = str(warning_calls[0][1]) if len(warning_calls[0]) > 1 else ""
        message = str(warning_calls[0][2]) if len(warning_calls[0]) > 2 else ""
        assert title == "Not Attached", f"Expected warning title 'Not Attached', got {title!r}"
        assert "Not attached to any process" in message, f"Expected 'Not attached to any process' in message, got {message!r}"

    def test_on_read_dispatches_when_attached(self, tab: MemoryTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """_on_read dispatches the coroutine from bridge.read_memory with matching address kwarg.

        Asserts that (1) ``run_bridge_coroutine_logged`` is called with the
        coroutine returned by ``bridge.read_memory`` as its first positional
        argument, and (2) the ``address`` keyword argument equals ``hex(0x1000)``.
        These checks fail if ``_on_read`` dispatches the wrong bridge method or
        passes a wrong address, not merely when the ``_attached_pid`` guard is
        absent.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        _set_private(tab, "_bridge", mock_bridge)
        tab.set_attached_pid(1234)

        dispatch_args: list[tuple[object, ...]] = []
        dispatch_kwargs: list[dict[str, object]] = []

        def _capture_dispatch(*args: object, **kwargs: object) -> None:
            dispatch_args.append(args)
            dispatch_kwargs.append(kwargs)

        monkeypatch.setattr(_memory_tab_mod, "run_bridge_coroutine_logged", _capture_dispatch)

        _line_edit(tab, "_read_addr").setText("0x1000")
        _invoke(tab, "_on_read")

        assert dispatch_args, "run_bridge_coroutine_logged must be called when _attached_pid is set"
        assert dispatch_args[0][0] is mock_bridge.read_memory.return_value, (
            "First positional argument must be the coroutine returned by bridge.read_memory; "
            f"got {dispatch_args[0][0]!r}"
        )
        assert dispatch_kwargs[0].get("address") == hex(0x1000), (
            f"address kwarg must equal {hex(0x1000)!r}; "
            f"got {dispatch_kwargs[0].get('address')!r}"
        )

    def test_on_write_no_dispatch_when_unattached(self, tab: MemoryTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """_on_write shows the 'Not Attached' warning and skips dispatch when _attached_pid is None.

        Patching the production dispatch function proves the guard on
        ``_attached_pid`` — not an exception elsewhere — is what prevents the
        call.  Exact title and message are asserted so a wrong-text regression
        also fails.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(tab, "_bridge", MagicMock())
        _set_private(tab, "_attached_pid", None)

        warning_calls: list[tuple[object, ...]] = []

        def _capture_warning(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            warning_calls.append(args)
            return QMessageBox.StandardButton.Ok

        dispatch_calls: list[object] = []

        def _fail_if_dispatched(*args: object, **_kwargs: object) -> None:
            dispatch_calls.append(args)

        monkeypatch.setattr(_memory_tab_mod, "run_bridge_coroutine_logged", _fail_if_dispatched)
        monkeypatch.setattr(QMessageBox, "warning", _capture_warning)

        _line_edit(tab, "_write_addr").setText("0x1000")
        _plain_text(tab, "_write_input").setPlainText("90 90")
        _invoke(tab, "_on_write")

        assert dispatch_calls == [], (
            f"run_bridge_coroutine_logged must not be called when _attached_pid is None; got {len(dispatch_calls)} call(s)"
        )
        assert warning_calls, "_on_write must show QMessageBox.warning when not attached"
        title = str(warning_calls[0][1]) if len(warning_calls[0]) > 1 else ""
        message = str(warning_calls[0][2]) if len(warning_calls[0]) > 2 else ""
        assert title == "Not Attached", f"Expected warning title 'Not Attached', got {title!r}"
        assert "Not attached to any process" in message, f"Expected 'Not attached to any process' in message, got {message!r}"

    def test_on_write_dispatches_when_attached(self, tab: MemoryTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """_on_write dispatches the coroutine from bridge.write_memory with matching address kwarg.

        Asserts that (1) ``run_bridge_coroutine_logged`` is called with the
        coroutine returned by ``bridge.write_memory`` as its first positional
        argument, and (2) the ``address`` keyword argument equals ``hex(0x1000)``.
        These checks fail if ``_on_write`` dispatches the wrong bridge method or
        passes a wrong address, not merely when the ``_attached_pid`` guard is
        absent.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        _set_private(tab, "_bridge", mock_bridge)
        tab.set_attached_pid(1234)

        dispatch_args: list[tuple[object, ...]] = []
        dispatch_kwargs: list[dict[str, object]] = []

        def _capture_dispatch(*args: object, **kwargs: object) -> None:
            dispatch_args.append(args)
            dispatch_kwargs.append(kwargs)

        monkeypatch.setattr(_memory_tab_mod, "run_bridge_coroutine_logged", _capture_dispatch)
        monkeypatch.setattr(QMessageBox, "warning", _noop_warning_yes)

        _line_edit(tab, "_write_addr").setText("0x1000")
        _plain_text(tab, "_write_input").setPlainText("90 90")
        _invoke(tab, "_on_write")

        assert dispatch_args, "run_bridge_coroutine_logged must be called when _attached_pid is set"
        assert dispatch_args[0][0] is mock_bridge.write_memory.return_value, (
            "First positional argument must be the coroutine returned by bridge.write_memory; "
            f"got {dispatch_args[0][0]!r}"
        )
        assert dispatch_kwargs[0].get("address") == hex(0x1000), (
            f"address kwarg must equal {hex(0x1000)!r}; "
            f"got {dispatch_kwargs[0].get('address')!r}"
        )

    def test_on_search_no_dispatch_when_unattached(self, tab: MemoryTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """_on_search shows the 'Not Attached' warning and skips dispatch when _attached_pid is None.

        The test patches the actual ``run_bridge_coroutine_logged`` function
        (not ``run_bridge_coroutine_async``) so the assertion is a genuine gate
        against guard removal.  Exact title and message are verified.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(tab, "_bridge", MagicMock())
        _set_private(tab, "_attached_pid", None)

        warning_calls: list[tuple[object, ...]] = []

        def _capture_warning(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            warning_calls.append(args)
            return QMessageBox.StandardButton.Ok

        dispatch_calls: list[object] = []

        def _fail_if_dispatched(*args: object, **_kwargs: object) -> None:
            dispatch_calls.append(args)

        monkeypatch.setattr(_memory_tab_mod, "run_bridge_coroutine_logged", _fail_if_dispatched)
        monkeypatch.setattr(QMessageBox, "warning", _capture_warning)

        _line_edit(tab, "_search_pattern").setText("90 90")
        _invoke(tab, "_on_search")

        assert dispatch_calls == [], (
            f"run_bridge_coroutine_logged must not be called when _attached_pid is None; got {len(dispatch_calls)} call(s)"
        )
        assert warning_calls, "_on_search must show QMessageBox.warning when not attached"
        title = str(warning_calls[0][1]) if len(warning_calls[0]) > 1 else ""
        message = str(warning_calls[0][2]) if len(warning_calls[0]) > 2 else ""
        assert title == "Not Attached", f"Expected warning title 'Not Attached', got {title!r}"
        assert "Not attached to any process" in message, f"Expected 'Not attached to any process' in message, got {message!r}"

    def test_on_search_dispatches_when_attached(self, tab: MemoryTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """_on_search dispatches the coroutine from bridge.search_pattern with matching pattern_length kwarg.

        Asserts that (1) ``run_bridge_coroutine_logged`` is called with the
        coroutine returned by ``bridge.search_pattern`` as its first positional
        argument, and (2) the ``pattern_length`` keyword argument equals the
        length of the search pattern string ``'90 90'``.  These checks fail if
        ``_on_search`` dispatches the wrong bridge method or passes a mismatched
        pattern length, not merely when the ``_attached_pid`` guard is absent.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        _set_private(tab, "_bridge", mock_bridge)
        tab.set_attached_pid(1234)

        dispatch_args: list[tuple[object, ...]] = []
        dispatch_kwargs: list[dict[str, object]] = []

        def _capture_dispatch(*args: object, **kwargs: object) -> None:
            dispatch_args.append(args)
            dispatch_kwargs.append(kwargs)

        monkeypatch.setattr(_memory_tab_mod, "run_bridge_coroutine_logged", _capture_dispatch)

        pattern = "90 90"
        _line_edit(tab, "_search_pattern").setText(pattern)
        _invoke(tab, "_on_search")

        assert dispatch_args, "run_bridge_coroutine_logged must be called when _attached_pid is set"
        assert dispatch_args[0][0] is mock_bridge.search_pattern.return_value, (
            "First positional argument must be the coroutine returned by bridge.search_pattern; "
            f"got {dispatch_args[0][0]!r}"
        )
        assert dispatch_kwargs[0].get("pattern_length") == len(pattern), (
            f"pattern_length kwarg must equal {len(pattern)!r}; "
            f"got {dispatch_kwargs[0].get('pattern_length')!r}"
        )


class TestSearchStatusResetsOnFailure:
    """F-0006: _on_search 'Searching...' status resets on failure via _on_error."""

    def test_search_status_resets_on_failure(self, tab: MemoryTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """When the bridge search fails, _search_status is set to an error string.

        The status must not remain 'Searching...' after the error callback fires.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(tab, "_bridge", MagicMock())
        tab.set_attached_pid(1234)

        captured_on_error: list[object] = []

        def fake_dispatch(
            _coro: object,
            _on_success: object,
            on_error: object,
            _parent: object,
        ) -> None:
            captured_on_error.append(on_error)

        monkeypatch.setattr(_async_bridge_mod, "run_bridge_coroutine_async", fake_dispatch)
        monkeypatch.setattr(QMessageBox, "critical", _noop_warning)

        _line_edit(tab, "_search_pattern").setText("48 8B")
        _invoke(tab, "_on_search")

        assert _label(tab, "_search_status").text() == "Searching..."
        assert captured_on_error, "Expected an on_error callback to be registered"

        error_cb = captured_on_error[0]
        assert callable(error_cb)
        error_cb(RuntimeError("bridge error"))

        assert _label(tab, "_search_status").text() != "Searching...", (
            "_search_status was left as 'Searching...' after error — F-0006 not fixed"
        )


class TestFreeRemovesAllocationRow:
    """F-0007: _on_free removes the matching Allocated row instead of adding a Freed row."""

    def test_free_removes_allocation_row(self, tab: MemoryTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """After a successful free, the matching Allocated row is removed from _alloc_log.

        Args:
            tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(tab, "_bridge", MagicMock())
        tab.set_attached_pid(1234)

        table = _table(tab, "_alloc_log")
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

        monkeypatch.setattr(_async_bridge_mod, "run_bridge_coroutine_async", fake_dispatch)
        monkeypatch.setattr(QMessageBox, "warning", _noop_warning_yes)

        _line_edit(tab, "_free_addr").setText("0x7FF600000000")
        _invoke(tab, "_on_free")

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
        _set_private(tab, "_bridge", MagicMock())
        tab.set_attached_pid(1234)

        table = _table(tab, "_alloc_log")
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

        monkeypatch.setattr(_async_bridge_mod, "run_bridge_coroutine_async", fake_dispatch)
        monkeypatch.setattr(QMessageBox, "warning", _noop_warning_yes)

        _line_edit(tab, "_free_addr").setText("0x1000")
        _invoke(tab, "_on_free")

        assert captured_on_success
        success_cb = captured_on_success[0]
        assert callable(success_cb)
        success_cb(None)

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
        _set_private(tab, "_bridge", MagicMock())
        tab.set_attached_pid(1234)

        critical_calls: list[tuple[object, ...]] = []

        def capture_critical(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            critical_calls.append(args)
            return QMessageBox.StandardButton.Ok

        monkeypatch.setattr(QMessageBox, "critical", capture_critical)

        _line_edit(tab, "_prot_addr").setText("not_a_hex_address")
        _invoke(tab, "_on_protect")

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
        _set_private(tab, "_bridge", MagicMock())
        tab.set_attached_pid(1234)

        critical_calls: list[tuple[object, ...]] = []

        def capture_critical(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            critical_calls.append(args)
            return QMessageBox.StandardButton.Ok

        monkeypatch.setattr(QMessageBox, "critical", capture_critical)

        _line_edit(tab, "_free_addr").setText("ZZZNOTANADDR")
        _invoke(tab, "_on_free")

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
        _set_private(tab, "_bridge", MagicMock())
        tab.set_attached_pid(1234)

        messages: list[str] = []

        def capture_critical(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            messages.append(str(args[2]))
            return QMessageBox.StandardButton.Ok

        monkeypatch.setattr(QMessageBox, "critical", capture_critical)

        _line_edit(tab, "_prot_addr").setText("bad_input_xyz")
        _invoke(tab, "_on_protect")

        assert any("bad_input_xyz" in m for m in messages), "Error message does not contain the invalid address text — F-0008 not fixed"


class TestAddressFieldHasPlaceholder:
    """F-0009: _build_protect_tab address field has a setPlaceholderText hint."""

    def test_prot_addr_has_placeholder(self, tab: MemoryTab) -> None:
        """_prot_addr placeholder text is exactly the canonical 64-bit example address.

        The production constructor calls ``set_hint_p('0x7FF600000000')``.
        Asserting the exact value means any regression to a generic ``'0x...'``
        or empty string turns the test red immediately.

        Args:
            tab: MemoryTab fixture.
        """
        placeholder = _line_edit(tab, "_prot_addr").placeholderText()
        assert placeholder == "0x7FF600000000", (
            f"Expected placeholder '0x7FF600000000' on _prot_addr; got {placeholder!r} — F-0009 not fixed"
        )

    def test_prot_addr_placeholder_matches_expected_format(self, tab: MemoryTab) -> None:
        """_prot_addr placeholder contains the exact 64-bit example address string.

        Asserts ``'0x7FF600000000' in placeholder`` without a second disjunct,
        so any regression to a shorter or generic placeholder (e.g. ``'0x...'``)
        turns the test red.

        Args:
            tab: MemoryTab fixture.
        """
        placeholder = _line_edit(tab, "_prot_addr").placeholderText()
        assert "0x7FF600000000" in placeholder, (
            f"Placeholder '{placeholder}' does not contain the expected '0x7FF600000000' — F-0009 not fixed"
        )
