# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""GUI-audit regression gates for :mod:`intellicrack.ui.panels.process_panel.threads_tab`.

Finding M27: the register table's ``Register`` name column (0) was built with
a plain ``QTableWidgetItem`` and no ``setFlags`` restriction, so it kept Qt's
default ``ItemIsEditable`` flag even though ``_on_write_registers`` trusts
``name_item.text()`` verbatim as the dict key sent to
``bridge.set_thread_context``. A stray double-click edit could silently
corrupt the write-back key. The fix strips ``ItemIsEditable`` from the name
cell while leaving the Hex/Decimal value cells editable.

Finding M60: the wait-status ``QLabel`` had no word wrap and the time-wait
error handler's only user-visible surface was ``setText(f"Wait failed:
{exc}")`` with no tooltip and no ``QMessageBox`` fallback, so a long bridge
error message was silently clipped with no way to read the rest. The fix
adds ``setWordWrap(True)`` to the label, sets a matching tooltip on both the
success and failure paths, and pops a ``QMessageBox.warning`` with the full
exception text on failure.

Each test drives the real :class:`ThreadsTab` widget and its production
callback closures with real result data. Only the async dispatch shim
(``run_bridge_coroutine_logged``) is replaced with a synchronous capture
stub, mirroring the project's established gate pattern (see
``test_gui_audit0702_panels_process_panel_modules_tab.py``), so the tests
stay deterministic and thread-free while exercising the actual production
UI-population and error-surfacing code.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QMessageBox, QTableWidgetItem

from intellicrack.bridges.process import ProcessBridge
from intellicrack.ui.panels.process_panel import threads_tab
from intellicrack.ui.panels.process_panel.threads_tab import ThreadsTab


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from PyQt6.QtWidgets import QApplication

_LONG_WAIT_ERROR: str = (
    "WaitForSingleObject failed for thread handle 0x000002A8: "
    "the thread handle was invalid or the process detached mid-wait (WinError 6, ERROR_INVALID_HANDLE)"
)


@pytest.fixture
def tab(qapp: QApplication) -> Generator[ThreadsTab]:
    """Build a real :class:`ThreadsTab` bound to a live, unattached bridge.

    Args:
        qapp: Session ``QApplication`` fixture ensuring Qt is initialised.

    Yields:
        Generator[ThreadsTab]: A ``ThreadsTab`` wired to a real
        :class:`ProcessBridge` instance and a fake attached PID.
    """
    del qapp
    widget = ThreadsTab()
    widget.set_bridge(ProcessBridge())
    widget.set_attached_pid(4242)
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

    monkeypatch.setattr(threads_tab, "run_bridge_coroutine_logged", _fake)
    return captured


def _select_first_thread_row(tab: ThreadsTab, tid: int) -> None:
    """Insert one real row into the thread table and select it.

    Args:
        tab: The ``ThreadsTab`` under test.
        tid: Thread id to store in the row's ``DisplayRole`` data.
    """
    tab._thread_table.setRowCount(0)
    tab._thread_table.insertRow(0)
    tid_item = QTableWidgetItem()
    tid_item.setData(Qt.ItemDataRole.DisplayRole, tid)
    tab._thread_table.setItem(0, 0, tid_item)
    tab._thread_table.selectRow(0)


class TestM27RegisterNameNotEditable:
    """M27: the register table's name column must not be user-editable."""

    def test_m27_register_name_item_is_not_editable(
        self,
        tab: ThreadsTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Refreshing registers writes a name cell whose ``ItemIsEditable`` flag is stripped.

        Pre-fix ``_refresh_registers`` built column 0 with a bare
        ``QTableWidgetItem(str(reg_name))`` and never called ``setFlags``,
        so it kept Qt's default ``ItemIsEditable`` flag and a user could
        double-click the cell and retype the register name that
        ``_on_write_registers`` later trusts verbatim as the bridge
        dictionary key.

        Args:
            tab: The ``ThreadsTab`` under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        captured = _install_fake_dispatch(monkeypatch)
        tab._reg_combo.addItem("TID 4242", 4242)
        tab._refresh_registers()
        on_success = captured["on_success"]
        assert on_success is not None, "Refresh must dispatch get_thread_context through the async worker"

        on_success({"RAX": 0x1000, "RBX": 0x2000})

        assert tab._reg_table.rowCount() == 2
        for row in range(tab._reg_table.rowCount()):
            name_item = tab._reg_table.item(row, 0)
            assert name_item is not None
            assert not (name_item.flags() & Qt.ItemFlag.ItemIsEditable), (
                f"register name cell in row {row} must not carry ItemIsEditable; "
                "pre-fix a stray double-click could corrupt the register name used as the "
                "set_thread_context write-back key"
            )

    def test_m27_register_value_cells_remain_editable(
        self,
        tab: ThreadsTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Hex and Decimal value cells stay editable so register writes still work.

        The fix must only restrict column 0; columns 1 and 2 are the
        intended write-back editing surface for ``_on_write_registers`` and
        must not regress to read-only.

        Args:
            tab: The ``ThreadsTab`` under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        captured = _install_fake_dispatch(monkeypatch)
        tab._reg_combo.addItem("TID 4242", 4242)
        tab._refresh_registers()
        on_success = captured["on_success"]
        assert on_success is not None
        on_success({"RAX": 0x1000})

        hex_item = tab._reg_table.item(0, 1)
        dec_item = tab._reg_table.item(0, 2)
        assert hex_item is not None
        assert dec_item is not None
        assert hex_item.flags() & Qt.ItemFlag.ItemIsEditable, "Hex Value column must remain user-editable"
        assert dec_item.flags() & Qt.ItemFlag.ItemIsEditable, "Decimal column must remain user-editable"

    def test_m27_write_registers_uses_the_untampered_name(
        self,
        tab: ThreadsTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Writing registers sends the original register name as the bridge key.

        Drives the real ``_on_write_registers`` write-back path end to end
        against a populated, non-editable name column and asserts the
        dispatched register dict keys match the original register names
        exactly (proxy for the corruption the missing flag would have
        allowed).

        Args:
            tab: The ``ThreadsTab`` under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        refresh_captured = _install_fake_dispatch(monkeypatch)
        tab._reg_combo.addItem("TID 4242", 4242)
        tab._refresh_registers()
        on_success = refresh_captured["on_success"]
        assert on_success is not None
        on_success({"RAX": 0x1000, "RCX": 0x99})

        monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *_a, **_k: QMessageBox.StandardButton.Yes))
        write_captured = _install_fake_dispatch(monkeypatch)
        tab._on_write_registers()

        assert write_captured["on_success"] is not None, "Write must dispatch set_thread_context through the async worker"
        name_item_0 = tab._reg_table.item(0, 0)
        name_item_1 = tab._reg_table.item(1, 0)
        assert name_item_0 is not None
        assert name_item_1 is not None
        assert {name_item_0.text(), name_item_1.text()} == {"RAX", "RCX"}, (
            "register name cells must still hold their original, untampered names when writing"
        )


class TestM60WaitStatusErrorSurfacing:
    """M60: the wait-status label wraps and errors get a tooltip plus dialog."""

    def test_m60_wait_status_label_has_word_wrap_enabled(self, tab: ThreadsTab) -> None:
        """The wait-status ``QLabel`` wraps long text instead of clipping it.

        Pre-fix ``self._wait_status = QLabel("")`` never called
        ``setWordWrap(True)``, so a long single-line error string overflowed
        the label's fixed-in-place layout with no wrapping.

        Args:
            tab: The ``ThreadsTab`` under test.
        """
        assert tab._wait_status.wordWrap() is True, "wait-status label must wrap long text instead of clipping it"

    def test_m60_wait_failure_shows_full_text_in_tooltip_and_message_box(
        self,
        tab: ThreadsTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A time-wait failure surfaces the full exception text via tooltip and dialog.

        Pre-fix ``_on_error`` only did
        ``self._wait_status.setText(f"Wait failed: {exc}")`` with no
        ``setToolTip`` call and no ``QMessageBox``, so the label was the
        only (clippable) surface for a long bridge error message. The fix
        also sets a matching tooltip and pops a
        ``QMessageBox.warning`` carrying the full exception text.

        Args:
            tab: The ``ThreadsTab`` under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        message_boxes: list[tuple[object, ...]] = []

        def _fake_warning(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            message_boxes.append(args)
            return QMessageBox.StandardButton.Ok

        monkeypatch.setattr(QMessageBox, "warning", staticmethod(_fake_warning))
        captured = _install_fake_dispatch(monkeypatch)
        _select_first_thread_row(tab, 4242)
        tab._on_time_thread_wait()
        on_error = captured["on_error"]
        assert on_error is not None, "Time Wait must dispatch time_thread_wait through the async worker"

        on_error(RuntimeError(_LONG_WAIT_ERROR))

        expected_message = f"Wait failed: {_LONG_WAIT_ERROR}"
        assert tab._wait_status.text() == expected_message
        assert tab._wait_status.toolTip() == expected_message, (
            "wait-status label must carry a full-text tooltip so a clipped line stays readable on hover"
        )
        assert len(message_boxes) == 1, "a failed wait must pop exactly one QMessageBox with the full error"
        dialog_args = message_boxes[0]
        assert any(_LONG_WAIT_ERROR in str(arg) for arg in dialog_args), "the QMessageBox must carry the full, unwrapped exception text"

    def test_m60_wait_success_also_sets_a_matching_tooltip(
        self,
        tab: ThreadsTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A successful time-wait also sets a tooltip matching the status text.

        The success path was changed alongside the failure path so hovering
        over a long-but-successful status message also recovers the full
        text.

        Args:
            tab: The ``ThreadsTab`` under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        captured = _install_fake_dispatch(monkeypatch)
        _select_first_thread_row(tab, 4242)
        tab._on_time_thread_wait()
        on_success = captured["on_success"]
        assert on_success is not None, "Time Wait must dispatch time_thread_wait through the async worker"

        on_success({"result": "signaled", "elapsed_us": 1234})

        expected_message = "TID 4242: signaled (1234 us)"
        assert tab._wait_status.text() == expected_message
        assert tab._wait_status.toolTip() == expected_message, "wait-status label tooltip must match the displayed success text"
