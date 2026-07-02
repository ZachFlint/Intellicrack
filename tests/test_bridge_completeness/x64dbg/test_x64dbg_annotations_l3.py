# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Labels/Comments tables (rows 33, 35 of the state-manipulation slice).

``get_labels`` and ``get_comments`` were fully implemented and registered
bridge methods, and ``_lbl_table``/``_cmt_table`` widgets existed in the
Annotations tab, but neither table was ever populated (DEAD-CONTROL): no
code path called ``get_labels``/``get_comments`` or inserted rows. The
remediation wires a Refresh button (and an automatic refresh after a
successful ``set_label``/``set_comment``) that calls the bridge and
populates the table with the real returned rows, plus a row-click handler
that copies the selected entry back into the edit fields.

Also covers the closed conditional-breakpoint DEAD-CONTROL gap (row 19 of
the execution-control slice): the Breakpoints tab's Add-BP toolbar now
exposes a ``_bp_cond_input`` field, and ``_on_add_breakpoint`` forwards its
(stripped, empty-to-``None``) text as the ``condition`` kwarg to
``bridge.set_breakpoint``. ``TestConditionalBreakpointGuiWiring`` is the
positive replacement for the former residual-gap test, which asserted the
pre-remediation broken state.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QLineEdit, QPlainTextEdit, QPushButton, QTableWidget

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel

from .conftest import install_fake_pipe, ok, priv, pump_until


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger bridge")

_LABEL_ADDR = 0x402000
_LABEL_TEXT = "gate_test_label"
_COMMENT_ADDR = 0x402010
_COMMENT_TEXT = "gate test comment"

_RESIDUAL_REFRESH_RPCS = frozenset(
    {
        "reg_all",
        "reg_get",
        "register_list",
        "bp_list",
        "thread_list",
        "module_list",
        "memmap",
        "watch_list",
        "wp_list",
        "stack_trace",
        "status",
    },
)


@pytest.fixture
def wired_panel(qapp: QApplication) -> tuple[X64DbgPanel, X64DbgBridge]:
    """Build a panel with a real bridge attached (no live plugin pipe).

    Sets ``_x64dbg_path``/``_state.connected`` directly so
    ``plugin_status["ready"]`` is true once :meth:`install_fake_pipe` marks
    the plugin deployed and the pipe connected; without this,
    ``_update_controls_state`` leaves every toolbar debug button disabled
    and a ``.click()`` in these tests would be a silent no-op.

    Args:
        qapp: Session QApplication fixture.

    Returns:
        tuple[X64DbgPanel, X64DbgBridge]: The panel and its attached bridge.
    """
    del qapp
    panel = X64DbgPanel()
    bridge = X64DbgBridge()
    setattr(bridge, "_x64dbg_path", Path("C:/tmp/x64dbg.exe"))
    setattr(getattr(bridge, "_state"), "connected", True)
    panel.set_bridge(bridge)
    return panel, bridge


def _cell_text(table: QTableWidget, row: int, column: int) -> str:
    """Read the text of a table cell, failing loudly if the cell is empty.

    Args:
        table: The table widget to read from.
        row: Row index.
        column: Column index.

    Returns:
        str: The cell's text.
    """
    item = table.item(row, column)
    assert item is not None, f"expected an item at ({row}, {column})"
    return item.text()


def _residual_response(command: str) -> dict[str, Any]:
    """Build a canned response for a residual post-refresh RPC.

    ``_refresh_state()`` (triggered after several handlers succeed) polls a
    fixed set of auxiliary RPCs unrelated to the behavior a given test is
    gating; this helper answers all of them uniformly so responders only
    need to special-case the command under test.

    Args:
        command: The RPC command name.

    Returns:
        dict[str, Any]: A successful envelope with an empty/paused payload.
    """
    if command == "status":
        return ok({"paused": True, "debugging": True})
    return ok({})


class TestLabelsTableRefresh:
    """The Labels table must populate from a real ``get_labels`` round-trip."""

    @staticmethod
    def test_refresh_labels_populates_table_with_real_lbl_list_data(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking the Labels Refresh button must render the exact ``lbl_list`` entries.

        Falsifiable: if ``_on_refresh_labels`` were never wired (the
        pre-remediation DEAD-CONTROL state), the table would remain empty
        forever and this test would time out with zero rows. Broken
        production line: ``self._bridge.get_labels(0, end)`` in
        ``_on_refresh_labels`` and the field mapping in ``_apply_labels``
        (``ui/panels/x64dbg_panel.py``).

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        assert hasattr(panel, "_lbl_refresh_btn"), "Labels tab must expose a Refresh button (remediation of row 33)"

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "lbl_list":
                assert params is not None
                assert params.get("start") == 0
                return ok([{"address": hex(_LABEL_ADDR), "text": _LABEL_TEXT}])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        lbl_refresh_btn = priv(panel, "_lbl_refresh_btn", QPushButton)
        lbl_table = priv(panel, "_lbl_table", QTableWidget)

        try:
            lbl_refresh_btn.click()
            pump_until(qapp, lambda: lbl_table.rowCount() >= 1)

            assert lbl_table.rowCount() == 1
            assert _cell_text(lbl_table, 0, 0) == f"0x{_LABEL_ADDR:X}"
            assert _cell_text(lbl_table, 0, 1) == _LABEL_TEXT
        finally:
            panel.deleteLater()

    @staticmethod
    def test_setting_a_label_auto_refreshes_the_table(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A successful ``set_label`` must trigger an automatic ``get_labels`` refresh.

        Falsifiable: if ``_on_label_set`` did not call ``_on_refresh_labels``
        (reverting to the old bare console-append success callback), the
        table would stay empty after ``set_label`` succeeds. Broken
        production line: ``self._on_refresh_labels()`` inside
        ``_on_label_set`` (``ui/panels/x64dbg_panel.py``).

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert "lblset" in params.get("command", "")
                return ok(None)
            if command == "lbl_list":
                return ok([{"address": hex(_LABEL_ADDR), "text": _LABEL_TEXT}])
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        lbl_addr_input = priv(panel, "_lbl_addr_input", QLineEdit)
        lbl_text_input = priv(panel, "_lbl_text_input", QLineEdit)
        set_lbl_btn = priv(panel, "_set_lbl_btn", QPushButton)
        lbl_table = priv(panel, "_lbl_table", QTableWidget)

        try:
            lbl_addr_input.setText(hex(_LABEL_ADDR))
            lbl_text_input.setText(_LABEL_TEXT)
            set_lbl_btn.click()

            pump_until(qapp, lambda: lbl_table.rowCount() >= 1)
            assert _cell_text(lbl_table, 0, 1) == _LABEL_TEXT
        finally:
            panel.deleteLater()

    @staticmethod
    def test_clicking_a_label_row_populates_edit_fields(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking a populated label row must copy its address/text into the edit inputs.

        Falsifiable: if ``_on_label_row_selected`` were removed (or never
        connected to ``cellClicked``), the edit fields would remain empty
        after the click. Broken production line:
        ``self._lbl_table.cellClicked.connect(self._on_label_row_selected)``
        and the field assignment inside ``_on_label_row_selected``.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "lbl_list":
                return ok([{"address": hex(_LABEL_ADDR), "text": _LABEL_TEXT}])
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        lbl_refresh_btn = priv(panel, "_lbl_refresh_btn", QPushButton)
        lbl_table = priv(panel, "_lbl_table", QTableWidget)
        lbl_addr_input = priv(panel, "_lbl_addr_input", QLineEdit)
        lbl_text_input = priv(panel, "_lbl_text_input", QLineEdit)

        try:
            lbl_refresh_btn.click()
            pump_until(qapp, lambda: lbl_table.rowCount() >= 1)

            lbl_table.cellClicked.emit(0, 0)

            assert lbl_addr_input.text() == f"0x{_LABEL_ADDR:X}"
            assert lbl_text_input.text() == _LABEL_TEXT
        finally:
            panel.deleteLater()


class TestCommentsTableRefresh:
    """The Comments table must populate from a real ``get_comments`` round-trip."""

    @staticmethod
    def test_refresh_comments_populates_table_with_real_cmt_list_data(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking the Comments Refresh button must render the exact ``cmt_list`` entries.

        Falsifiable: if ``_on_refresh_comments`` were never wired (the
        pre-remediation DEAD-CONTROL state), the table would remain empty
        forever. Broken production line: ``self._bridge.get_comments(0,
        end)`` in ``_on_refresh_comments`` and the field mapping in
        ``_apply_comments`` (``ui/panels/x64dbg_panel.py``).

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        assert hasattr(panel, "_cmt_refresh_btn"), "Comments tab must expose a Refresh button (remediation of row 35)"

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "cmt_list":
                return ok([{"address": hex(_COMMENT_ADDR), "text": _COMMENT_TEXT}])
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        cmt_refresh_btn = priv(panel, "_cmt_refresh_btn", QPushButton)
        cmt_table = priv(panel, "_cmt_table", QTableWidget)

        try:
            cmt_refresh_btn.click()
            pump_until(qapp, lambda: cmt_table.rowCount() >= 1)

            assert cmt_table.rowCount() == 1
            assert _cell_text(cmt_table, 0, 0) == f"0x{_COMMENT_ADDR:X}"
            assert _cell_text(cmt_table, 0, 1) == _COMMENT_TEXT
        finally:
            panel.deleteLater()

    @staticmethod
    def test_setting_a_comment_auto_refreshes_the_table(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A successful ``set_comment`` must trigger an automatic ``get_comments`` refresh.

        Falsifiable: if ``_on_comment_set`` did not call
        ``_on_refresh_comments``, the table would stay empty after
        ``set_comment`` succeeds. Broken production line:
        ``self._on_refresh_comments()`` inside ``_on_comment_set``
        (``ui/panels/x64dbg_panel.py``).

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert "cmtset" in params.get("command", "")
                return ok(None)
            if command == "cmt_list":
                return ok([{"address": hex(_COMMENT_ADDR), "text": _COMMENT_TEXT}])
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        cmt_addr_input = priv(panel, "_cmt_addr_input", QLineEdit)
        cmt_text_input = priv(panel, "_cmt_text_input", QLineEdit)
        set_cmt_btn = priv(panel, "_set_cmt_btn", QPushButton)
        cmt_table = priv(panel, "_cmt_table", QTableWidget)

        try:
            cmt_addr_input.setText(hex(_COMMENT_ADDR))
            cmt_text_input.setText(_COMMENT_TEXT)
            set_cmt_btn.click()

            pump_until(qapp, lambda: cmt_table.rowCount() >= 1)
            assert _cell_text(cmt_table, 0, 1) == _COMMENT_TEXT
        finally:
            panel.deleteLater()


class TestConditionalBreakpointGuiWiring:
    """Positive gate for the conditional-breakpoint GUI (slice-1 row 19, now closed).

    The bridge (``set_breakpoint(condition=...)``) and tool-def
    (``x64dbg.set_breakpoint``'s ``condition`` parameter) layers support
    conditional breakpoints, and the Breakpoints tab's Add-BP toolbar now
    exposes a ``_bp_cond_input`` field whose (stripped) text
    ``_on_add_breakpoint`` forwards as the ``condition`` kwarg -- empty
    input maps to ``None``, non-empty input is passed through verbatim.
    """

    @staticmethod
    def test_breakpoint_toolbar_has_condition_input(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
    ) -> None:
        """The Add-BP toolbar must expose a dedicated condition ``QLineEdit``.

        Falsifiable: if ``_bp_cond_input`` were removed from
        ``_build_bp_tab``, ``hasattr`` would fail.

        Args:
            wired_panel: Panel/bridge pair fixture.
        """
        panel, _bridge = wired_panel
        try:
            assert hasattr(panel, "_bp_cond_input")
        finally:
            panel.deleteLater()

    @staticmethod
    def test_add_breakpoint_forwards_entered_condition(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """``_on_add_breakpoint`` must forward the exact entered condition text.

        Falsifiable: if ``_on_add_breakpoint`` stopped reading
        ``_bp_cond_input`` (or hardcoded ``condition=None``), the recorded
        ``bp_set`` params would not carry the entered condition string.
        Broken production line: ``condition =
        self._bp_cond_input.text().strip() or None`` /
        ``self._bridge.set_breakpoint(address, bp_type=bp_type,
        condition=condition)`` in ``_on_add_breakpoint``
        (``ui/panels/x64dbg_panel.py``).

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        addr = 0x403000
        condition_text = "eax == 1"

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "bp_set":
                return ok(hex(addr))
            if command == "bp_list":
                return ok([{"address": addr, "type": "software", "enabled": True}])
            if command == "exec":
                return ok("")
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        bp_addr_input = priv(panel, "_bp_addr_input", QLineEdit)
        bp_cond_input = priv(panel, "_bp_cond_input", QLineEdit)
        add_bp_btn = priv(panel, "_add_bp_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            bp_addr_input.setText(hex(addr))
            bp_cond_input.setText(condition_text)
            add_bp_btn.click()
            pump_until(qapp, lambda: "Breakpoint" in console_output.toPlainText())
        finally:
            panel.deleteLater()

        bp_set_params = [params for command, params in fake.sent if command == "bp_set"]
        assert bp_set_params, "expected a bp_set command to be dispatched"
        first_bp_set = bp_set_params[0]
        assert first_bp_set is not None
        assert first_bp_set.get("condition") == condition_text, (
            f"bp_set must carry the entered condition; got {first_bp_set.get('condition')!r}"
        )
        exec_commands = [
            params.get("command") for command, params in fake.sent if command == "exec" and params is not None
        ]
        assert f'bpcond {hex(addr)}, "{condition_text}"' in exec_commands, (
            "expected a bpcond exec carrying the entered condition to be dispatched"
        )

    @staticmethod
    def test_add_breakpoint_with_empty_condition_forwards_none(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """An empty condition field must forward ``condition=None`` and skip ``bpcond``.

        Falsifiable: if ``_on_add_breakpoint`` forwarded the raw (possibly
        whitespace-only) field text instead of ``.strip() or None``, the
        recorded ``bp_set`` params would carry an empty string rather than
        ``None``, and a spurious ``bpcond`` command would be sent. Broken
        production line: the same ``condition = ... or None`` / dispatch
        pair as above, plus ``if condition is not None:`` in
        ``X64DbgBridge.set_breakpoint`` (``bridges/x64dbg.py``).

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        addr = 0x403010

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "bp_set":
                assert params is not None
                assert params.get("condition") is None
                return ok(hex(addr))
            if command == "bp_list":
                return ok([{"address": addr, "type": "software", "enabled": True}])
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        bp_addr_input = priv(panel, "_bp_addr_input", QLineEdit)
        bp_cond_input = priv(panel, "_bp_cond_input", QLineEdit)
        add_bp_btn = priv(panel, "_add_bp_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            bp_addr_input.setText(hex(addr))
            bp_cond_input.setText("   ")
            add_bp_btn.click()
            pump_until(qapp, lambda: "Breakpoint" in console_output.toPlainText())

            assert not any(cmd == "exec" for cmd, _ in fake.sent), (
                "no bpcond exec command must be sent when the condition field is blank"
            )
        finally:
            panel.deleteLater()
