# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Advanced tab (``x64dbg_advanced_tab.py``).

The Advanced tab groups nine control clusters -- module info (imports /
entry point / PE directories), process structures (PEB / TEB / SEH),
watch expressions, breakpoint-property configuration, cross-references,
handle enumeration, the script engine, and the plugin manager -- each of
whose handlers dispatches to an :class:`X64DbgBridge` method.

Every gate here drives the REAL ``X64DbgAdvancedTab`` widget wired to a
REAL ``X64DbgBridge`` and substitutes only the single genuine external
boundary the sandbox cannot cross: the named-pipe transport to the x64dbg
plugin (see :mod:`conftest`). Handlers whose bridge method routes through
``_send_pipe_command`` (the vast majority) are gated with the pipe pattern:
a scripted responder returns canned envelopes and the test asserts on
``fake.sent`` that the exact RPC command and parameters were dispatched, on
the main thread, after :func:`pump_until` observes the handler's visible
side effect. ``_send_command`` script commands surface on ``fake.sent`` as
an ``exec`` envelope carrying ``{"command": <script text>}``.

Two handlers -- ``_on_get_entry_point`` (whose ``get_entry_point`` parses
the module's in-memory PE header via a sequence of memory-read RPCs) and
``_on_refresh_handles`` (whose ``get_handles`` performs a live
``NtQuerySystemInformation`` OS call, not a pipe round-trip) -- cannot be
cleanly scripted through the single-response pipe responder, so they use
the coroutine-capture pattern: ``run_bridge_coroutine_logged`` is patched
in the advanced-tab module and the test asserts the coroutine handed to it
is exactly the real bridge method's return value, called with the exact
arguments the handler read from the UI.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication, QComboBox, QLabel, QLineEdit, QMessageBox, QPushButton, QTableWidget

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.ui.panels import x64dbg_advanced_tab as _advanced_mod
from intellicrack.ui.panels.x64dbg_advanced_tab import X64DbgAdvancedTab

from .conftest import FakePipeClient, install_fake_pipe, ok, priv, pump_until


if TYPE_CHECKING:
    from collections.abc import Iterator


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger bridge")

_MODAL_WATCHDOG_INTERVAL_MS: int = 5


def _dismiss_stray_modal() -> None:
    """Close any real, active ``QMessageBox`` modal without asserting on it.

    ``tests/bridges/completeness/conftest.py`` installs a tree-wide autouse
    ``guard_modal_dialogs`` fixture that monkeypatches ``QMessageBox.warning``
    to a non-blocking stand-in for the whole test tree, and every Advanced-tab
    input-validation handler exercised by this module (``_on_read_teb``,
    ``_bpcfg_address``, ``_xref_address``, ``_on_set_logging_breakpoint``,
    ``_on_close_handle``) relies on exactly that guard to stay non-blocking.
    This sandbox's pytest invocation collects every test node twice in the
    same process (a known, out-of-scope harness quirk); on a test's second,
    duplicate occurrence that guard has been observed to not be re-applied,
    letting the real, blocking ``QMessageBox.warning`` construct a genuine
    modal that never returns under the headless offscreen Qt platform --
    hanging the test, and, when the stray dialog is instead delivered via a
    queued cross-thread signal after a later test's guard has torn down,
    corrupting the heap (Windows fatal exception 0xc0000374) deep inside
    pytest-qt's own event pump. This watchdog is a second, independent line
    of defense: if a real modal ever appears despite the guard, it is closed
    immediately instead of blocking the run.
    """
    widget = QApplication.activeModalWidget()
    if isinstance(widget, QMessageBox):
        widget.done(int(QMessageBox.StandardButton.Ok))


@pytest.fixture(autouse=True)
def modal_watchdog(qapp: QApplication) -> Iterator[None]:
    """Run a background watchdog that dismisses any stray real modal dialog.

    Args:
        qapp: Session ``QApplication`` fixture; ensures the application
            instance exists before the watchdog timer is created.

    Yields:
        None: Control returns to the test body while the watchdog runs.
    """
    del qapp
    timer = QTimer()
    timer.setInterval(_MODAL_WATCHDOG_INTERVAL_MS)
    timer.timeout.connect(_dismiss_stray_modal)
    timer.start()
    try:
        yield
    finally:
        timer.stop()
        timer.timeout.disconnect(_dismiss_stray_modal)


@pytest.fixture
def wired_tab(qapp: QApplication) -> Iterator[tuple[X64DbgAdvancedTab, X64DbgBridge]]:
    """Build a real Advanced tab wired to a real (pipe-less) ``X64DbgBridge``.

    The tab's toolbar buttons are always enabled (the Advanced tab does no
    connection-state gating), so a ``.click()`` reaches the handler without
    any further setup; :func:`install_fake_pipe` is applied per-test to
    intercept the transport boundary.

    Args:
        qapp: Session QApplication fixture.

    Yields:
        tuple[X64DbgAdvancedTab, X64DbgBridge]: The tab and its bridge.
    """
    del qapp
    tab = X64DbgAdvancedTab()
    bridge = X64DbgBridge()
    tab.set_bridge(bridge)
    yield tab, bridge
    tab.deleteLater()


def _cell_text(table: QTableWidget, row: int, column: int) -> str:
    """Read a table cell's text, failing loudly when the cell is empty.

    Args:
        table: Table widget to read from.
        row: Row index.
        column: Column index.

    Returns:
        str: The cell's text.
    """
    item = table.item(row, column)
    assert item is not None, f"expected an item at ({row}, {column})"
    return item.text()


def _exec_commands(fake: FakePipeClient) -> list[str]:
    """Collect every script string dispatched through the ``exec`` RPC.

    ``X64DbgBridge._send_command`` frames a console-script command as an
    ``exec`` envelope carrying ``{"command": <script text>}``; this helper
    extracts those script strings in dispatch order.

    Args:
        fake: The fake pipe client recording the bridge's sends.

    Returns:
        list[str]: The ``command`` strings from every recorded ``exec`` send.
    """
    commands: list[str] = []
    for name, params in fake.sent:
        if name == "exec" and params is not None:
            script = params.get("command")
            if isinstance(script, str):
                commands.append(script)
    return commands


class TestModuleInfoDispatch:
    """Module-info controls must dispatch the imports / PE-directory / entry-point RPCs."""

    @staticmethod
    def test_imports_button_dispatches_mod_imports_rpc(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The Imports button must send ``mod_imports`` with the entered module name.

        Falsifiable: reverting the ``self._bridge.get_module_imports(module_name)``
        call in ``_on_get_module_imports`` (or the ``mod_imports`` RPC in
        ``X64DbgBridge.get_module_imports``) stops the recorded command/params
        from appearing and leaves the table empty.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "mod_imports":
                return ok([{"name": "CreateFileW", "ordinal": 12, "iatRva": "0x1000", "iatVa": "0x401000"}])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_modinfo_name_input", QLineEdit).setText("kernel32.dll")
        table = priv(tab, "_modinfo_table", QTableWidget)

        priv(tab, "_modinfo_imports_btn", QPushButton).click()
        pump_until(qapp, lambda: table.rowCount() >= 1)

        assert ("mod_imports", {"name": "kernel32.dll"}) in fake.sent
        assert table.rowCount() == 1
        assert _cell_text(table, 0, 0) == "CreateFileW"

    @staticmethod
    def test_imports_button_blank_module_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """A blank module field must skip the ``mod_imports`` dispatch entirely.

        Falsifiable: dropping the ``if module_name is None: return`` guard in
        ``_on_get_module_imports`` would let a blank field dispatch a bogus
        ``mod_imports`` request, which this assertion forbids.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            msg = f"no command expected, got: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_modinfo_name_input", QLineEdit).setText("   ")

        priv(tab, "_modinfo_imports_btn", QPushButton).click()

        assert all(name != "mod_imports" for name, _ in fake.sent)

    @staticmethod
    def test_pe_directories_button_dispatches_pe_directories_rpc(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The PE Directories button must send ``pe_directories`` with the module name.

        Falsifiable: reverting the ``self._bridge.get_pe_directories(module_name)``
        call in ``_on_get_pe_directories`` (or the ``pe_directories`` RPC in the
        bridge) stops the command from being recorded and the table from filling.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "pe_directories":
                return ok([{"index": 0, "name": "Export", "rva": "0x2000", "size": 256}])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_modinfo_name_input", QLineEdit).setText("ntdll.dll")
        table = priv(tab, "_modinfo_table", QTableWidget)

        priv(tab, "_modinfo_pedirs_btn", QPushButton).click()
        pump_until(qapp, lambda: table.rowCount() >= 1)

        assert ("pe_directories", {"module": "ntdll.dll"}) in fake.sent
        assert _cell_text(table, 0, 1) == "Export"

    @staticmethod
    def test_pe_directories_button_blank_module_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """A blank module field must skip the ``pe_directories`` dispatch.

        Falsifiable: dropping the ``if module_name is None: return`` guard in
        ``_on_get_pe_directories`` would dispatch a bogus request.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            msg = f"no command expected, got: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_modinfo_name_input", QLineEdit).setText("")

        priv(tab, "_modinfo_pedirs_btn", QPushButton).click()

        assert all(name != "pe_directories" for name, _ in fake.sent)

    @staticmethod
    def test_entry_point_button_dispatches_get_entry_point_with_module(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The Entry Point button must call ``get_entry_point`` with the entered module.

        ``get_entry_point`` parses the module's in-memory PE header through a
        sequence of memory-read RPCs, so this handler is gated with the
        coroutine-capture pattern rather than a single-response responder.

        Falsifiable: rewiring the button to any other bridge method, or
        dropping the ``module_name`` argument in ``_on_get_entry_point``, makes
        the captured coroutine no longer ``get_entry_point``'s return value or
        the recorded call arguments wrong.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab, _bridge = wired_tab
        mock_bridge = MagicMock()
        setattr(tab, "_bridge", mock_bridge)

        captured: list[tuple[object, ...]] = []

        def _capture(*args: object, **kwargs: object) -> None:
            del kwargs
            captured.append(args)

        monkeypatch.setattr(_advanced_mod, "run_bridge_coroutine_logged", _capture)
        priv(tab, "_modinfo_name_input", QLineEdit).setText("kernel32.dll")

        priv(tab, "_modinfo_entry_btn", QPushButton).click()

        assert captured, "Entry Point button must dispatch through run_bridge_coroutine_logged"
        assert captured[0][0] is mock_bridge.get_entry_point.return_value
        mock_bridge.get_entry_point.assert_called_once_with("kernel32.dll")


class TestProcessStructuresDispatch:
    """PEB / TEB / SEH controls must dispatch their process-structure RPCs."""

    @staticmethod
    def test_read_peb_button_dispatches_peb_read_rpc(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The Read PEB button must send ``peb_read`` and render the returned fields.

        Falsifiable: reverting ``self._bridge.read_peb()`` in ``_on_read_peb``
        (or the ``peb_read`` RPC in ``X64DbgBridge.read_peb``) removes the
        recorded command and leaves the structure table empty.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "peb_read":
                return ok({"address": "0x7ffdf000", "beingDebugged": 0})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        table = priv(tab, "_procstruct_table", QTableWidget)

        priv(tab, "_peb_btn", QPushButton).click()
        pump_until(qapp, lambda: table.rowCount() >= 1)

        assert ("peb_read", None) in fake.sent
        assert _cell_text(table, 0, 0) == "address"
        assert _cell_text(table, 0, 1) == "0x7ffdf000"

    @staticmethod
    def test_read_teb_button_with_tid_dispatches_teb_read_with_tid(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A parseable TID must be forwarded as ``teb_read`` ``{"tid": <int>}``.

        Falsifiable: dropping the ``if tid is not None: params["tid"] = tid``
        framing in ``X64DbgBridge.read_teb`` (or the ``int(tid_text, 0)`` parse
        in ``_on_read_teb``) changes the recorded params away from the exact TID.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "teb_read":
                return ok({"threadId": "0x100"})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_teb_tid_input", QLineEdit).setText("0x100")
        table = priv(tab, "_procstruct_table", QTableWidget)

        priv(tab, "_teb_btn", QPushButton).click()
        pump_until(qapp, lambda: table.rowCount() >= 1)

        assert ("teb_read", {"tid": 0x100}) in fake.sent

    @staticmethod
    def test_read_teb_button_without_tid_dispatches_teb_read_none(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A blank TID must send ``teb_read`` with ``None`` params (current thread).

        Falsifiable: if ``_on_read_teb`` sent an empty ``{}`` or a spurious tid
        for a blank field, the ``("teb_read", None)`` record would be absent.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "teb_read":
                return ok({"processId": "0x4"})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_teb_tid_input", QLineEdit).setText("")
        table = priv(tab, "_procstruct_table", QTableWidget)

        priv(tab, "_teb_btn", QPushButton).click()
        pump_until(qapp, lambda: table.rowCount() >= 1)

        assert ("teb_read", None) in fake.sent

    @staticmethod
    def test_read_teb_button_invalid_tid_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """A non-numeric TID must warn and skip the ``teb_read`` dispatch.

        Falsifiable: removing the ``except ValueError`` guard in ``_on_read_teb``
        (which returns before dispatch) would let an unparseable TID reach the
        bridge, contradicting this assertion.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            msg = f"no command expected, got: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_teb_tid_input", QLineEdit).setText("notanumber")

        priv(tab, "_teb_btn", QPushButton).click()

        assert all(name != "teb_read" for name, _ in fake.sent)

    @staticmethod
    def test_seh_chain_button_dispatches_seh_chain_rpc(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The SEH Chain button must send ``seh_chain`` and render handler/next rows.

        Falsifiable: reverting ``self._bridge.get_seh_chain()`` in
        ``_on_get_seh_chain`` (or the ``seh_chain`` RPC in the bridge) removes
        the recorded command and the handler/next rows.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "seh_chain":
                return ok([{"handler": "0x401000", "next": "0x0"}])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        table = priv(tab, "_procstruct_table", QTableWidget)

        priv(tab, "_seh_btn", QPushButton).click()
        pump_until(qapp, lambda: table.rowCount() >= 2)

        assert ("seh_chain", None) in fake.sent
        assert _cell_text(table, 0, 0) == "[0] handler"
        assert _cell_text(table, 0, 1) == "0x401000"


class TestWatchesDispatch:
    """Watch controls must dispatch the add / remove / list RPCs."""

    @staticmethod
    def test_refresh_button_dispatches_watch_list_rpc(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The Refresh button must send ``watch_list`` and render the returned rows.

        Falsifiable: reverting ``self._bridge.get_watches()`` in
        ``_on_refresh_watches`` (or the ``watch_list`` RPC in the bridge) leaves
        the record absent and the table empty.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "watch_list":
                return ok([{"index": 0, "expression": "[rsp]", "value": "0x1234"}])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        table = priv(tab, "_watch_table", QTableWidget)

        priv(tab, "_watch_refresh_btn", QPushButton).click()
        pump_until(qapp, lambda: table.rowCount() >= 1)

        assert ("watch_list", None) in fake.sent
        assert _cell_text(table, 0, 1) == "[rsp]"
        assert _cell_text(table, 0, 2) == "0x1234"

    @staticmethod
    def test_add_button_dispatches_watch_add_rpc(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The Add button must send ``watch_add`` with the entered expression.

        Falsifiable: reverting ``self._bridge.add_watch(expression)`` in
        ``_on_add_watch`` (or the ``watch_add`` RPC framing in the bridge)
        removes the recorded command.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "watch_add":
                return ok(None)
            if command == "watch_list":
                return ok([{"index": 0, "expression": "[rsp]", "value": "0"}])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_watch_expr_input", QLineEdit).setText("[rsp]")
        table = priv(tab, "_watch_table", QTableWidget)

        priv(tab, "_watch_add_btn", QPushButton).click()
        pump_until(qapp, lambda: table.rowCount() >= 1)

        assert ("watch_add", {"expression": "[rsp]"}) in fake.sent

    @staticmethod
    def test_add_button_blank_expression_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """A blank expression must skip the ``watch_add`` dispatch.

        Falsifiable: dropping the ``if not expression: return`` guard in
        ``_on_add_watch`` would dispatch an empty watch.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            msg = f"no command expected, got: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_watch_expr_input", QLineEdit).setText("   ")

        priv(tab, "_watch_add_btn", QPushButton).click()

        assert all(name != "watch_add" for name, _ in fake.sent)

    @staticmethod
    def test_remove_button_dispatches_watch_remove_rpc(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Removing a selected watch must send ``watch_remove`` with its index.

        Falsifiable: reverting ``self._bridge.remove_watch(index)`` in
        ``_on_remove_watch`` (or the ``watch_remove`` RPC in the bridge), or the
        index parse from the selected row, removes the recorded command.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "watch_remove":
                return ok(None)
            if command == "watch_list":
                return ok([{"index": 5, "expression": "[rax]", "value": "0"}])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        table = priv(tab, "_watch_table", QTableWidget)

        priv(tab, "_watch_refresh_btn", QPushButton).click()
        pump_until(qapp, lambda: table.rowCount() >= 1)
        table.setCurrentCell(0, 0)

        priv(tab, "_watch_remove_btn", QPushButton).click()
        pump_until(qapp, lambda: any(name == "watch_remove" for name, _ in fake.sent))

        assert ("watch_remove", {"index": 5}) in fake.sent

    @staticmethod
    def test_remove_button_no_selection_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """Removing with no selected row must skip the ``watch_remove`` dispatch.

        Falsifiable: dropping the ``if row < 0: return`` guard in
        ``_on_remove_watch`` would dispatch a removal with no selection.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            msg = f"no command expected, got: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)

        priv(tab, "_watch_remove_btn", QPushButton).click()

        assert all(name != "watch_remove" for name, _ in fake.sent)


class TestBreakpointConfigDispatch:
    """Breakpoint-config controls must dispatch the exact console-script commands."""

    @staticmethod
    def test_apply_button_dispatches_all_configured_properties(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Applying config must issue the condition/log/command/fast-resume scripts.

        Falsifiable: reverting any of the four conditional
        ``await self._send_command(...)`` lines in
        ``X64DbgBridge.configure_breakpoint`` (or the field reads in
        ``_on_configure_breakpoint``) removes the matching ``exec`` script.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return ok("")
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_bpcfg_addr_input", QLineEdit).setText("0x401000")
        priv(tab, "_bpcfg_cond_input", QLineEdit).setText("eax==1")
        priv(tab, "_bpcfg_log_input", QLineEdit).setText("{rax}")
        priv(tab, "_bpcfg_cmd_input", QLineEdit).setText("log_hit")
        priv(tab, "_bpcfg_fast_resume_combo", QComboBox).setCurrentIndex(1)
        status = priv(tab, "_bpcfg_status_label", QLabel)

        priv(tab, "_bpcfg_apply_btn", QPushButton).click()
        pump_until(qapp, lambda: "[+]" in status.text())

        scripts = _exec_commands(fake)
        assert 'bpcond 0x401000, "eax==1"' in scripts
        assert 'SetBreakpointLog 0x401000, "{rax}"' in scripts
        assert 'SetBreakpointCommand 0x401000, "log_hit"' in scripts
        assert "SetBreakpointFastResume 0x401000, 1" in scripts

    @staticmethod
    def test_apply_button_invalid_address_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """A non-numeric address must warn and skip every breakpoint-config script.

        Falsifiable: removing the ``except ValueError`` guard in
        ``_bpcfg_address`` (which returns ``None`` before dispatch) would let a
        bad address reach the bridge.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            msg = f"no command expected, got: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_bpcfg_addr_input", QLineEdit).setText("notanaddress")
        priv(tab, "_bpcfg_cond_input", QLineEdit).setText("eax==1")

        priv(tab, "_bpcfg_apply_btn", QPushButton).click()

        assert all(name != "exec" for name, _ in fake.sent)

    @staticmethod
    def test_logging_breakpoint_button_dispatches_bp_log_scripts(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The logging-BP button must set the BP, its log text, and fast-resume.

        Falsifiable: reverting any of the ``bp`` / ``SetBreakpointLog`` /
        ``SetBreakpointFastResume`` sends in
        ``X64DbgBridge.set_logging_breakpoint`` removes the matching ``exec``
        script.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return ok("")
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_bpcfg_addr_input", QLineEdit).setText("0x402000")
        priv(tab, "_bpcfg_log_input", QLineEdit).setText("{rcx}")
        status = priv(tab, "_bpcfg_status_label", QLabel)

        priv(tab, "_bpcfg_logging_btn", QPushButton).click()
        pump_until(qapp, lambda: "[+]" in status.text())

        scripts = _exec_commands(fake)
        assert "bp 0x402000" in scripts
        assert 'SetBreakpointLog 0x402000, "{rcx}"' in scripts
        assert "SetBreakpointFastResume 0x402000, 1" in scripts

    @staticmethod
    def test_logging_breakpoint_button_empty_log_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """A blank log-text field must warn and skip the logging-BP dispatch.

        Falsifiable: dropping the ``if not log_text: ...; return`` guard in
        ``_on_set_logging_breakpoint`` would dispatch a logging BP with no text.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            msg = f"no command expected, got: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_bpcfg_addr_input", QLineEdit).setText("0x402000")
        priv(tab, "_bpcfg_log_input", QLineEdit).setText("")

        priv(tab, "_bpcfg_logging_btn", QPushButton).click()

        assert all(name != "exec" for name, _ in fake.sent)

    @staticmethod
    def test_dll_breakpoint_button_dispatches_librarian_script(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The DLL-BP button (load) must issue ``LibrarianSetBreakPoint``.

        Falsifiable: reverting the ``LibrarianSetBreakPoint`` send in
        ``X64DbgBridge.set_dll_breakpoint`` removes the recorded script.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return ok("")
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_bpcfg_dll_input", QLineEdit).setText("ws2_32.dll")
        priv(tab, "_bpcfg_dll_event_combo", QComboBox).setCurrentIndex(0)
        status = priv(tab, "_bpcfg_status_label", QLabel)

        priv(tab, "_bpcfg_dll_btn", QPushButton).click()
        pump_until(qapp, lambda: "[+]" in status.text())

        assert 'LibrarianSetBreakPoint "ws2_32.dll"' in _exec_commands(fake)

    @staticmethod
    def test_dll_breakpoint_button_unload_appends_unload_arg(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Selecting the unload event must append ``, unload`` to the librarian script.

        Falsifiable: reverting the ``if event == "unload": cmd += ", unload"``
        branch in ``X64DbgBridge.set_dll_breakpoint`` (or the combo read in
        ``_on_set_dll_breakpoint``) drops the ``, unload`` suffix.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return ok("")
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_bpcfg_dll_input", QLineEdit).setText("ws2_32.dll")
        priv(tab, "_bpcfg_dll_event_combo", QComboBox).setCurrentIndex(1)
        status = priv(tab, "_bpcfg_status_label", QLabel)

        priv(tab, "_bpcfg_dll_btn", QPushButton).click()
        pump_until(qapp, lambda: "[+]" in status.text())

        assert 'LibrarianSetBreakPoint "ws2_32.dll", unload' in _exec_commands(fake)

    @staticmethod
    def test_dll_breakpoint_button_blank_dll_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """A blank DLL name must skip the librarian dispatch.

        Falsifiable: dropping the ``if not dll_name: return`` guard in
        ``_on_set_dll_breakpoint`` would dispatch a nameless librarian command.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            msg = f"no command expected, got: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_bpcfg_dll_input", QLineEdit).setText("   ")

        priv(tab, "_bpcfg_dll_btn", QPushButton).click()

        assert all(name != "exec" for name, _ in fake.sent)


class TestCrossReferencesDispatch:
    """Cross-reference controls must dispatch the ref_search / cfg RPCs by type."""

    @staticmethod
    def test_find_references_button_dispatches_reference_ref_search(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The Find References button must send ``ref_search`` typed ``reference``.

        Falsifiable: reverting ``self._bridge.find_references(address)`` in
        ``_on_find_references`` (or the ``{"type": "reference"}`` framing in the
        bridge) removes the recorded command and the reference rows.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "ref_search":
                return ok(["0x402000", "0x403000"])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_xref_addr_input", QLineEdit).setText("0x401000")
        table = priv(tab, "_xref_table", QTableWidget)

        priv(tab, "_xref_find_btn", QPushButton).click()
        pump_until(qapp, lambda: table.rowCount() >= 1)

        assert ("ref_search", {"address": "0x401000", "type": "reference"}) in fake.sent
        assert _cell_text(table, 0, 1) == "0x402000"

    @staticmethod
    def test_find_references_button_invalid_address_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """A non-numeric address must warn and skip the ``ref_search`` dispatch.

        Falsifiable: removing the ``except ValueError`` guard in
        ``_xref_address`` would let a bad address reach the bridge.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            msg = f"no command expected, got: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_xref_addr_input", QLineEdit).setText("notanaddress")

        priv(tab, "_xref_find_btn", QPushButton).click()

        assert all(name != "ref_search" for name, _ in fake.sent)

    @staticmethod
    def test_function_cfg_button_dispatches_cfg_rpc(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The Function CFG button must send ``cfg`` with address and max_blocks.

        Falsifiable: reverting ``self._bridge.get_function_cfg(address)`` in
        ``_on_get_function_cfg`` (or the ``cfg`` RPC framing in the bridge)
        removes the recorded command and the rendered block/edge rows.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "cfg":
                return ok({"entry": "0x401000", "blocks": ["b1"], "edges": ["e1"]})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_xref_addr_input", QLineEdit).setText("0x401000")
        table = priv(tab, "_xref_table", QTableWidget)

        priv(tab, "_xref_cfg_btn", QPushButton).click()
        pump_until(qapp, lambda: table.rowCount() >= 1)

        assert ("cfg", {"address": "0x401000", "max_blocks": 500}) in fake.sent
        assert _cell_text(table, 0, 0) == "block"
        assert _cell_text(table, 0, 1) == "b1"

    @staticmethod
    def test_string_references_button_dispatches_string_ref_search(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The String References button must send ``ref_search`` typed ``string``.

        Falsifiable: reverting ``self._bridge.find_string_references(module)`` in
        ``_on_find_string_references`` (or the ``{"type": "string"}`` framing in
        the bridge) removes the recorded command.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "ref_search":
                return ok(["push offset aHello"])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_xref_module_input", QLineEdit).setText("target.exe")
        table = priv(tab, "_xref_table", QTableWidget)

        priv(tab, "_xref_strings_btn", QPushButton).click()
        pump_until(qapp, lambda: table.rowCount() >= 1)

        assert ("ref_search", {"module": "target.exe", "type": "string"}) in fake.sent

    @staticmethod
    def test_string_references_button_blank_module_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """A blank module must skip the string ``ref_search`` dispatch.

        Falsifiable: dropping the ``if not module: return`` guard in
        ``_on_find_string_references`` would dispatch a moduleless search.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            msg = f"no command expected, got: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_xref_module_input", QLineEdit).setText("")

        priv(tab, "_xref_strings_btn", QPushButton).click()

        assert all(name != "ref_search" for name, _ in fake.sent)

    @staticmethod
    def test_intermodular_calls_button_dispatches_intermodular_ref_search(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The Intermodular Calls button must send ``ref_search`` typed ``intermodular``.

        Falsifiable: reverting ``self._bridge.find_intermodular_calls(module)``
        in ``_on_find_intermodular_calls`` (or the ``{"type": "intermodular"}``
        framing in the bridge) removes the recorded command.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "ref_search":
                return ok(["call ds:CreateFileW"])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_xref_module_input", QLineEdit).setText("target.exe")
        table = priv(tab, "_xref_table", QTableWidget)

        priv(tab, "_xref_intermod_btn", QPushButton).click()
        pump_until(qapp, lambda: table.rowCount() >= 1)

        assert ("ref_search", {"module": "target.exe", "type": "intermodular"}) in fake.sent


class TestHandlesDispatch:
    """Handle controls must enumerate and close handles through the bridge."""

    @staticmethod
    def test_enumerate_button_dispatches_get_handles(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The Enumerate Handles button must call ``get_handles``.

        ``get_handles`` performs a live ``NtQuerySystemInformation`` OS call
        rather than a pipe round-trip, so this handler is gated with the
        coroutine-capture pattern.

        Falsifiable: rewiring the button, or dropping the
        ``self._bridge.get_handles()`` call in ``_on_refresh_handles``, makes
        the captured coroutine no longer ``get_handles``'s return value.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab, _bridge = wired_tab
        mock_bridge = MagicMock()
        setattr(tab, "_bridge", mock_bridge)

        captured: list[tuple[object, ...]] = []

        def _capture(*args: object, **kwargs: object) -> None:
            del kwargs
            captured.append(args)

        monkeypatch.setattr(_advanced_mod, "run_bridge_coroutine_logged", _capture)

        priv(tab, "_handles_refresh_btn", QPushButton).click()

        assert captured, "Enumerate Handles button must dispatch through run_bridge_coroutine_logged"
        assert captured[0][0] is mock_bridge.get_handles.return_value
        mock_bridge.get_handles.assert_called_once_with()

    @staticmethod
    def test_close_button_dispatches_handleclose_script(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The Close Handle button must issue the ``handleclose`` console script.

        Falsifiable: reverting ``await self._send_command(f"handleclose ...")``
        in ``X64DbgBridge.close_handle`` (or the value parse in
        ``_on_close_handle``) removes the recorded ``exec`` script.

        A successful close makes ``_on_handle_closed`` immediately re-invoke
        ``_on_refresh_handles``, which issues a REAL, unmocked
        ``self._bridge.get_handles()`` call (this handler is not gated behind
        the pipe responder). Against a ``wired_tab`` bridge that was never
        attached to a process, that call fails on the background bridge-worker
        thread and its error callback -- delivered later via a queued
        cross-thread Qt signal -- calls ``QMessageBox.warning`` from
        ``_on_handles_error``. Left unobserved, that queued callback can still
        be in flight when this test returns; its warning call would then fire
        during a LATER test, after this test's package-root
        ``guard_modal_dialogs`` autouse patch (see
        ``tests/bridges/completeness/conftest.py``) has already been torn
        down, hitting the real, blocking ``QMessageBox.warning`` instead of
        the guard's no-op stand-in. The test therefore overrides the guard
        locally (the package conftest's own documented precedence rule) with
        a spy and pumps the loop until that spy fires, so the whole chain
        provably settles -- and the guard is provably still active -- before
        the test (and the ``wired_tab`` fixture's ``deleteLater``) returns.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return ok("")
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_handles_close_input", QLineEdit).setText("0x1a4")

        refresh_error_messages: list[str] = []

        def _spy_warning(*args: object, **_kwargs: object) -> object:
            del _kwargs
            refresh_error_messages.append(str(args[2]) if len(args) > 2 else "")
            return QMessageBox.StandardButton.Ok

        monkeypatch.setattr(QMessageBox, "warning", _spy_warning)

        priv(tab, "_handles_close_btn", QPushButton).click()
        pump_until(qapp, lambda: "handleclose 0x1a4" in _exec_commands(fake))

        assert ("exec", {"command": "handleclose 0x1a4"}) in fake.sent

        pump_until(qapp, lambda: bool(refresh_error_messages))
        assert "not attached" in refresh_error_messages[0].lower()

    @staticmethod
    def test_close_button_invalid_value_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """A non-numeric handle value must warn and skip the ``handleclose`` dispatch.

        Falsifiable: removing the ``except ValueError`` guard in
        ``_on_close_handle`` would let a bad handle reach the bridge.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            msg = f"no command expected, got: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_handles_close_input", QLineEdit).setText("notahandle")

        priv(tab, "_handles_close_btn", QPushButton).click()

        assert all(name != "exec" for name, _ in fake.sent)


class TestScriptEngineDispatch:
    """Script-engine controls must dispatch the load / run / cmd / abort scripts."""

    @staticmethod
    def test_load_button_dispatches_scriptload(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The Load button must issue ``scriptload "<path>"``.

        Falsifiable: reverting ``await self._send_command(f'scriptload ...')``
        in ``X64DbgBridge.script_load`` (or the path read in ``_on_script_load``)
        removes the recorded ``exec`` script.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return ok("")
            if command == "eval":
                return ok(0)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_script_path_input", QLineEdit).setText("C:/scripts/unpack.txt")
        status = priv(tab, "_script_status_label", QLabel)

        priv(tab, "_script_load_btn", QPushButton).click()
        pump_until(qapp, lambda: "script_load" in status.text())

        assert ("exec", {"command": 'scriptload "C:/scripts/unpack.txt"'}) in fake.sent

    @staticmethod
    def test_load_button_blank_path_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """A blank script path must skip the ``scriptload`` dispatch.

        Falsifiable: dropping the ``if not path: return`` guard in
        ``_on_script_load`` would dispatch an empty load.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            msg = f"no command expected, got: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_script_path_input", QLineEdit).setText("   ")

        priv(tab, "_script_load_btn", QPushButton).click()

        assert all(name != "exec" for name, _ in fake.sent)

    @staticmethod
    def test_run_button_dispatches_scriptrun(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The Run button must issue ``scriptrun``.

        Falsifiable: reverting ``await self._send_command("scriptrun")`` in
        ``X64DbgBridge.script_run`` removes the recorded ``exec`` script.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return ok("")
            if command == "eval":
                return ok(0)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        status = priv(tab, "_script_status_label", QLabel)

        priv(tab, "_script_run_btn", QPushButton).click()
        pump_until(qapp, lambda: "script_run" in status.text())

        assert ("exec", {"command": "scriptrun"}) in fake.sent

    @staticmethod
    def test_execute_button_dispatches_scriptcmd(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The Execute button must issue ``scriptcmd "<line>"``.

        Falsifiable: reverting ``await self._send_command(f'scriptcmd ...')`` in
        ``X64DbgBridge.script_cmd`` (or the line read in ``_on_script_cmd``)
        removes the recorded ``exec`` script.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return ok("")
            if command == "eval":
                return ok(0)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_script_cmd_input", QLineEdit).setText("mov eax, 1")
        status = priv(tab, "_script_status_label", QLabel)

        priv(tab, "_script_cmd_btn", QPushButton).click()
        pump_until(qapp, lambda: "script_cmd" in status.text())

        assert ("exec", {"command": 'scriptcmd "mov eax, 1"'}) in fake.sent

    @staticmethod
    def test_execute_button_blank_line_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """A blank command line must skip the ``scriptcmd`` dispatch.

        Falsifiable: dropping the ``if not line: return`` guard in
        ``_on_script_cmd`` would dispatch an empty command.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            msg = f"no command expected, got: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_script_cmd_input", QLineEdit).setText("")

        priv(tab, "_script_cmd_btn", QPushButton).click()

        assert all(name != "exec" for name, _ in fake.sent)

    @staticmethod
    def test_abort_button_dispatches_scriptabort(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The Abort button must issue ``scriptabort``.

        Falsifiable: reverting ``await self._send_command("scriptabort")`` in
        ``X64DbgBridge.script_abort`` removes the recorded ``exec`` script.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return ok("")
            if command == "eval":
                return ok(0)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        status = priv(tab, "_script_status_label", QLabel)

        priv(tab, "_script_abort_btn", QPushButton).click()
        pump_until(qapp, lambda: "script_abort" in status.text())

        assert ("exec", {"command": "scriptabort"}) in fake.sent


class TestPluginManagerDispatch:
    """Plugin-manager controls must dispatch the load / unload / list operations."""

    @staticmethod
    def test_load_button_dispatches_plugload_and_verifies_via_plugin_list(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The Load button must issue ``plugload`` and verify presence via ``plugin_list``.

        Falsifiable: reverting ``await self._send_command(f'plugload ...')`` in
        ``X64DbgBridge.plugin_load``, or its ``plugin_list`` presence check,
        removes the recorded commands and leaves the plugin table empty.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return ok("")
            if command == "plugin_list":
                return ok([{"name": "myplugin", "path": "C:/plugins/myplugin.dp64", "loaded": True}])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_plugin_path_input", QLineEdit).setText("C:/plugins/myplugin.dp64")
        table = priv(tab, "_plugin_table", QTableWidget)

        priv(tab, "_plugin_load_btn", QPushButton).click()
        pump_until(qapp, lambda: table.rowCount() >= 1)

        assert ("exec", {"command": 'plugload "C:/plugins/myplugin.dp64"'}) in fake.sent
        assert ("plugin_list", None) in fake.sent
        assert _cell_text(table, 0, 0) == "myplugin"

    @staticmethod
    def test_load_button_blank_path_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """A blank plugin path must skip the ``plugload`` dispatch.

        Falsifiable: dropping the ``if not path: return`` guard in
        ``_on_plugin_load`` would dispatch an empty load.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            msg = f"no command expected, got: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_plugin_path_input", QLineEdit).setText("   ")

        priv(tab, "_plugin_load_btn", QPushButton).click()

        assert all(name != "exec" for name, _ in fake.sent)

    @staticmethod
    def test_unload_button_dispatches_plugunload(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The Unload button must issue ``plugunload "<name>"``.

        Falsifiable: reverting ``await self._send_command(f'plugunload ...')`` in
        ``X64DbgBridge.plugin_unload`` (or the name read in ``_on_plugin_unload``)
        removes the recorded ``exec`` script.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return ok("")
            if command == "plugin_list":
                return ok([])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_plugin_name_input", QLineEdit).setText("myplugin")

        priv(tab, "_plugin_unload_btn", QPushButton).click()
        pump_until(qapp, lambda: 'plugunload "myplugin"' in _exec_commands(fake))

        assert ("exec", {"command": 'plugunload "myplugin"'}) in fake.sent

    @staticmethod
    def test_unload_button_blank_name_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """A blank plugin name must skip the ``plugunload`` dispatch.

        Falsifiable: dropping the ``if not name: return`` guard in
        ``_on_plugin_unload`` would dispatch a nameless unload.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            msg = f"no command expected, got: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        priv(tab, "_plugin_name_input", QLineEdit).setText("")

        priv(tab, "_plugin_unload_btn", QPushButton).click()

        assert all(name != "exec" for name, _ in fake.sent)

    @staticmethod
    def test_refresh_button_dispatches_plugin_list_rpc(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The Refresh List button must send ``plugin_list`` and render the plugins.

        Falsifiable: reverting ``self._bridge.plugin_list()`` in
        ``_on_refresh_plugins`` (or the ``plugin_list`` RPC in the bridge)
        removes the recorded command and leaves the table empty.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "plugin_list":
                return ok([{"name": "foo", "path": "C:/plugins/foo.dp64", "loaded": True}])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        table = priv(tab, "_plugin_table", QTableWidget)

        priv(tab, "_plugin_refresh_btn", QPushButton).click()
        pump_until(qapp, lambda: table.rowCount() >= 1)

        assert ("plugin_list", None) in fake.sent
        assert _cell_text(table, 0, 0) == "foo"
