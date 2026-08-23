# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""GUI-audit regression gates for :mod:`intellicrack.ui.panels.process_panel.system_tab`.

Finding H25: reconnecting to a named pipe with the same name left a stale
table row that resolved to the wrong handle. ``_on_pipe_connect`` always
appends a new row and overwrites ``_pipe_handles[name]`` with the newest
handle, so two rows can legitimately display the same pipe name with
different handles. Pre-fix, ``_selected_pipe`` resolved the acting handle
by looking the row's *name* up in ``_pipe_handles`` -- always yielding the
newest handle regardless of which row was actually selected -- and
``_on_pipe_close`` removed the first table row matching the pipe name,
regardless of which handle was actually closed. The fix makes
``_selected_pipe`` read the handle directly from the selected row's own
handle cell, and makes ``_on_pipe_close`` remove the row whose own handle
cell matches the handle that was actually closed.

Finding L13: the Windows tab's "Class Name" column had no header resize
mode (stuck at the ``QHeaderView`` Interactive default) and no per-item
tooltip, so long/variable Win32 class names (WinForms, Chrome, UWP style)
rendered clipped with no way to read the full value without manually
dragging the column border. The fix sets column 2 to
``QHeaderView.ResizeMode.ResizeToContents`` and gives every class-name cell
a tooltip carrying its full text.

Each test drives the real :class:`SystemTab` widget and its production
callback closures with real result data. Only the async dispatch shim
(``run_bridge_coroutine_logged``) is replaced with a synchronous capture
stub, mirroring the project's established gate pattern (see
``test_gui_audit0702_panels_process_panel_modules_tab.py``), so the tests
stay deterministic and thread-free while exercising the actual production
UI-population and row-resolution code.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QHeaderView

from intellicrack.bridges.process import ProcessBridge
from intellicrack.ui.panels.process_panel import system_tab
from intellicrack.ui.panels.process_panel.system_tab import SystemTab


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from PyQt6.QtWidgets import QApplication


_PIPE_NAME: str = "\\\\.\\pipe\\MyPipe"
_LONG_CLASS_NAME: str = "WindowsForms10.Window.8.app.0.141b42a_r9_ad1"


@pytest.fixture
def tab(qapp: QApplication) -> Generator[SystemTab]:
    """Build a real :class:`SystemTab` bound to a live, unattached bridge.

    Args:
        qapp: Session ``QApplication`` fixture ensuring Qt is initialised.

    Yields:
        SystemTab: A ``SystemTab`` wired to a real
        :class:`ProcessBridge` instance.
    """
    del qapp
    widget = SystemTab()
    widget.set_bridge(ProcessBridge())
    yield widget
    widget.deleteLater()


def _install_fake_dispatch(monkeypatch: pytest.MonkeyPatch) -> dict[str, Callable[[object], None] | None]:
    """Replace the async bridge dispatcher with a synchronous capture stub.

    The real coroutine produced by the live bridge method is closed
    unawaited, and the real ``on_success``/``on_error`` closures defined
    inside the production method under test are captured so the test can
    invoke them directly with real result data.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        dict[str, Callable[[object], None] | None]: Mutable box populated
        with the captured ``on_success`` and ``on_error`` callables once the
        production method dispatches through the stub.
    """
    captured: dict[str, Callable[[object], None] | None] = {"on_success": None, "on_error": None}

    def _fake(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: object = None,
        *,
        event: str,
        logger: object,
        level: str = "debug",
        **context: object,
    ) -> None:
        del parent, event, logger, level, context
        coro.close()
        captured["on_success"] = on_success
        captured["on_error"] = on_error

    monkeypatch.setattr(system_tab, "run_bridge_coroutine_logged", _fake)
    return captured


def _connect_pipe(tab: SystemTab, captured: dict[str, Callable[[object], None] | None], handle: int) -> None:
    """Drive a real pipe-connect round trip that inserts one table row.

    Args:
        tab: The ``SystemTab`` under test.
        captured: The capture box populated by :func:`_install_fake_dispatch`.
        handle: The handle value the (stubbed) bridge call resolves to.
    """
    tab._pipe_name.setText(_PIPE_NAME)
    tab._on_pipe_connect()
    on_success = captured["on_success"]
    assert on_success is not None, "Connect must dispatch pipe_connect through the async worker"
    on_success(handle)


class TestH25PipeReconnectHandleResolution:
    """H25: reconnecting to a pipe with the same name must not mix up handles."""

    def test_h25_selected_pipe_reads_handle_from_own_row_not_stale_name_lookup(
        self,
        tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Selecting the older of two same-named rows resolves that row's own handle.

        Pre-fix ``_selected_pipe`` resolved the handle via
        ``self._pipe_handles.get(pipe_name)``, which after a reconnect
        always holds the *newest* handle for that name regardless of which
        row is selected. Reconnecting under the same pipe name produces a
        second row with a different handle, so selecting the first
        (older) row would incorrectly resolve to the second (newer)
        row's handle.

        Args:
            tab: The ``SystemTab`` under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        captured = _install_fake_dispatch(monkeypatch)
        _connect_pipe(tab, captured, 0x10)
        _connect_pipe(tab, captured, 0x14)

        assert tab._pipe_table.rowCount() == 2
        assert tab._pipe_handles[_PIPE_NAME] == 0x14, "test premise: dict holds only the newest handle"

        tab._pipe_table.selectRow(0)
        resolved = tab._selected_pipe()
        assert resolved == (_PIPE_NAME, 0x10), (
            f"selecting the older row (displayed handle 0x10) must resolve to 0x10, got {resolved!r}; "
            "pre-fix this would resolve to the stale name-keyed dict value 0x14"
        )

        tab._pipe_table.selectRow(1)
        resolved_second = tab._selected_pipe()
        assert resolved_second == (_PIPE_NAME, 0x14), "selecting the newer row must resolve to its own handle 0x14"

    def test_h25_pipe_close_removes_the_row_whose_handle_was_actually_closed(
        self,
        tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Closing the newer of two same-named rows removes that row, not the first name match.

        Pre-fix ``_on_pipe_close``'s row-removal loop matched only on pipe
        name and stopped at the first row found, so closing the row
        holding the *second* connection (handle 0x14) would instead
        remove the *first* row (handle 0x10, which is still live),
        leaving a stale-looking row displayed for the handle that was
        actually just closed.

        Args:
            tab: The ``SystemTab`` under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        captured = _install_fake_dispatch(monkeypatch)
        _connect_pipe(tab, captured, 0x10)
        _connect_pipe(tab, captured, 0x14)
        assert tab._pipe_table.rowCount() == 2

        tab._pipe_table.selectRow(1)
        tab._on_pipe_close()
        on_close_success = captured["on_success"]
        assert on_close_success is not None, "Close must dispatch pipe_close through the async worker"
        pipe_closed_successfully = True
        on_close_success(pipe_closed_successfully)

        assert tab._pipe_table.rowCount() == 1, "exactly one row (the closed one) must be removed"
        remaining_name = tab._pipe_table.item(0, 0)
        remaining_handle = tab._pipe_table.item(0, 1)
        assert remaining_name is not None
        assert remaining_handle is not None
        assert remaining_name.text() == _PIPE_NAME
        assert remaining_handle.text() == "0x10", (
            "the surviving row must be the still-open 0x10 connection; "
            "pre-fix the first-name-match removal would have deleted this row instead of the closed 0x14 row"
        )


class TestL13WindowsClassNameColumn:
    """L13: the Windows tab's Class Name column resizes to contents and tooltips."""

    def test_l13_class_name_header_resize_mode(self, tab: SystemTab) -> None:
        """Column 2 (Class Name) resizes to its content width.

        Pre-fix there was no ``setSectionResizeMode`` call for column 2 at
        all, so it stayed at the ``QHeaderView`` Interactive default.

        Args:
            tab: The ``SystemTab`` under test.
        """
        header = tab._win_table.horizontalHeader()
        assert header is not None
        assert header.sectionResizeMode(2) == QHeaderView.ResizeMode.ResizeToContents, (
            "Class Name column must resize to its content width, not stay at the Interactive default"
        )
        assert header.sectionResizeMode(1) == QHeaderView.ResizeMode.Stretch, "Title column must still stretch"

    def test_l13_refresh_windows_sets_class_name_tooltip_matching_long_text(
        self,
        tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Enumerating windows writes the full class name and a matching tooltip.

        Pre-fix ``_refresh_windows`` built the Class Name cell as a plain
        ``QTableWidgetItem`` with no ``setToolTip`` call, so
        ``QTableWidgetItem.toolTip()`` would return the empty string
        rather than the full class name.

        Args:
            tab: The ``SystemTab`` under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        captured = _install_fake_dispatch(monkeypatch)
        tab.set_attached_pid(4242)
        tab._refresh_windows()
        on_success = captured["on_success"]
        assert on_success is not None, "Enumerate Windows must dispatch get_windows through the async worker"

        window = {
            "hwnd": 0x00010234,
            "title": "Some Window",
            "class_name": _LONG_CLASS_NAME,
            "visible": True,
        }
        on_success([window])

        assert tab._win_table.rowCount() == 1
        class_item = tab._win_table.item(0, 2)
        assert class_item is not None
        assert class_item.text() == _LONG_CLASS_NAME, "Class Name column must show the full Win32 class name"
        assert class_item.toolTip() == _LONG_CLASS_NAME, (
            "Class Name cell must carry a full-value tooltip so a clipped ResizeToContents column stays readable on hover"
        )
