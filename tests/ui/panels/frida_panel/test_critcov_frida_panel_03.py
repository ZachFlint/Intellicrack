# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the memory-protection, symbol, function-call, child-gating and crash handlers of the Frida panel.

Every test drives a real ``FridaPanel``. Button handlers that reach the bridge run through the real asynchronous dispatch against a
genuine, unattached ``FridaBridge``: the bridge itself refuses the request with its own ``ToolError`` ("not attached to a process" or "no
Frida device available"), which travels through the real worker thread and comes back to the panel's error handler as a console line.
Result handlers are fed the real dataclasses (``MemoryRegion``, ``SymbolInfo``, ``ApiResolverMatch``, ``ChildProcessInfo``,
``CrashInfo``) that ``FridaBridge`` returns, and the expected table cells are written out by hand. No test attaches to a process.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, cast

import pytest
from PyQt6.QtWidgets import QApplication, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QTableWidget, QTableWidgetItem

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.types import ApiResolverMatch, ChildProcessInfo, CrashInfo, MemoryRegion, SymbolInfo, ToolError
from intellicrack.ui.panels.async_bridge import drain_bridge_workers_for
from intellicrack.ui.panels.frida_panel import FridaPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")

_WAIT_MS: Final[int] = 20_000
_NOT_ATTACHED: Final[str] = "not attached to a process"
_NO_DEVICE: Final[str] = "no Frida device available"
_INVALID_ADDRESS: Final[str] = "[-] Invalid address"
_CHILD_PID: Final[int] = 4321

_ARMED_FIELDS: Final[tuple[tuple[str, str], ...]] = (
    ("_mem_prot_addr", "0x1000"),
    ("_sym_module_input", "kernel32.dll"),
    ("_sym_addr_input", "0x1000"),
    ("_sym_func_input", "CreateFileW"),
    ("_sym_api_input", "exports:*!CreateFile*"),
    ("_adv_call_addr", "0x1000"),
)

_BRIDGE_HANDLERS: Final[tuple[str, ...]] = (
    "_on_set_protection",
    "_on_query_protection",
    "_on_find_base",
    "_on_resolve_symbol",
    "_on_find_functions",
    "_on_resolve_api",
    "_on_call_function",
    "_on_enable_child_gating",
    "_on_disable_child_gating",
    "_on_refresh_children",
    "_on_resume_child",
    "_on_enable_session_child_gating",
    "_on_disable_session_child_gating",
    "_on_refresh_session_children",
    "_on_resume_session_child",
    "_on_enable_crash_reporting",
    "_on_refresh_crashes",
)

_ADDRESS_HANDLERS: Final[tuple[tuple[str, str], ...]] = (
    ("_on_set_protection", "_mem_prot_addr"),
    ("_on_query_protection", "_mem_prot_addr"),
    ("_on_resolve_symbol", "_sym_addr_input"),
    ("_on_call_function", "_adv_call_addr"),
)

_DISPATCH_CASES: Final[tuple[tuple[str, tuple[tuple[str, str], ...], str], ...]] = (
    ("_on_set_protection", (("_mem_prot_addr", "0x1000"),), f"[-] Set protection failed: {_NOT_ATTACHED}"),
    ("_on_query_protection", (("_mem_prot_addr", "0x1000"),), f"[-] Query protection failed: {_NOT_ATTACHED}"),
    ("_on_find_base", (("_sym_module_input", "kernel32.dll"),), f"[-] Find base failed: {_NOT_ATTACHED}"),
    ("_on_resolve_symbol", (("_sym_addr_input", "401000"),), f"[-] Resolve failed: {_NOT_ATTACHED}"),
    ("_on_find_functions", (("_sym_func_input", "CreateFileW"),), f"[-] Find functions failed: {_NOT_ATTACHED}"),
    ("_on_resolve_api", (("_sym_api_input", "exports:*!CreateFile*"),), f"[-] API resolve failed: {_NOT_ATTACHED}"),
    ("_on_call_function", (("_adv_call_addr", "0x1000"),), f"[-] Call failed: {_NOT_ATTACHED}"),
    (
        "_on_call_function",
        (("_adv_call_addr", "0x1000"), ("_adv_call_args", "1, 0x2, 3"), ("_adv_arg_types", "pointer, int, int")),
        f"[-] Call failed: {_NOT_ATTACHED}",
    ),
    ("_on_enable_child_gating", (), f"[-] Enable child gating failed: {_NO_DEVICE}"),
    ("_on_disable_child_gating", (), f"[-] Disable child gating failed: {_NO_DEVICE}"),
    ("_on_refresh_children", (), f"[-] Refresh children failed: {_NO_DEVICE}"),
    ("_on_enable_session_child_gating", (), f"[-] Enable session child gating failed: {_NOT_ATTACHED}"),
    ("_on_disable_session_child_gating", (), f"[-] Disable session child gating failed: {_NOT_ATTACHED}"),
    ("_on_refresh_session_children", (), f"[-] Refresh session children failed: {_NOT_ATTACHED}"),
    ("_on_enable_crash_reporting", (), f"[-] Enable crash reporting failed: {_NO_DEVICE}"),
)
_DISPATCH_IDS: Final[tuple[str, ...]] = (
    "set_protection",
    "query_protection",
    "find_base",
    "resolve_symbol",
    "find_functions",
    "resolve_api",
    "call_function",
    "call_function_with_types",
    "enable_child_gating",
    "disable_child_gating",
    "refresh_children",
    "enable_session_child_gating",
    "disable_session_child_gating",
    "refresh_session_children",
    "enable_crash_reporting",
)

_EMPTY_INPUT_HANDLERS: Final[tuple[tuple[str, str], ...]] = (
    ("_on_find_base", "_sym_module_input"),
    ("_on_find_functions", "_sym_func_input"),
    ("_on_resolve_api", "_sym_api_input"),
)

_RESUME_HANDLERS: Final[tuple[tuple[str, str, str, str], ...]] = (
    (
        "_on_resume_child",
        "_populate_children_table",
        "_adv_children_table",
        f"[-] Resume child failed: {_NO_DEVICE}",
    ),
    (
        "_on_resume_session_child",
        "_populate_session_children_table",
        "_adv_session_children_table",
        f"[-] Resume session child failed: {_NOT_ATTACHED}",
    ),
)
_RESUME_IDS: Final[tuple[str, ...]] = ("device_wide", "session")

_ERROR_HANDLERS: Final[tuple[tuple[str, str], ...]] = (
    ("_on_call_function_error", "Call failed"),
    ("_on_enable_child_gating_error", "Enable child gating failed"),
    ("_on_enable_session_child_gating_error", "Enable session child gating failed"),
)
_ERROR_HANDLER_IDS: Final[tuple[str, ...]] = ("call_function", "enable_child_gating", "enable_session_child_gating")
_UNUSABLE_DETAILS: Final[tuple[dict[str, object] | None, ...]] = (None, {"reason": ""}, {"reason": 5}, {"other": "value"})
_UNUSABLE_DETAILS_IDS: Final[tuple[str, ...]] = ("none", "empty", "not_text", "no_reason")

_TABLE_POPULATORS: Final[tuple[tuple[str, str], ...]] = (
    ("_populate_regions_table", "_mem_regions_table"),
    ("_populate_sym_results_table", "_sym_results_table"),
    ("_populate_api_table", "_sym_api_table"),
    ("_populate_children_table", "_adv_children_table"),
    ("_populate_session_children_table", "_adv_session_children_table"),
    ("_populate_crashes_table", "_adv_crashes_table"),
)
_TABLE_IDS: Final[tuple[str, ...]] = ("regions", "symbols", "api", "children", "session_children", "crashes")


def priv[T](obj: object, name: str, typ: type[T]) -> T:
    """Read a private attribute with a known static type.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name, including its leading underscore.
        typ: Static type of the attribute, used only for typing.

    Returns:
        T: The attribute value.
    """
    del typ
    value: T = getattr(obj, name)
    return value


def method(obj: object, name: str) -> Callable[..., object]:
    """Look up a (possibly private) method by name.

    Args:
        obj: Object that owns the method.
        name: Method name.

    Returns:
        Callable[..., object]: The bound method.
    """
    return cast("Callable[..., object]", getattr(obj, name))


def _lines(panel: FridaPanel) -> list[str]:
    """Read the panel console as a list of lines.

    Args:
        panel: Panel whose console is read.

    Returns:
        list[str]: The console lines in order.
    """
    return priv(panel, "_console", QPlainTextEdit).toPlainText().splitlines()


def _set_text(panel: FridaPanel, name: str, text: str) -> None:
    """Type text into a line edit of the panel.

    Args:
        panel: Panel that owns the line edit.
        name: Attribute name of the line edit.
        text: Text to enter.
    """
    priv(panel, name, QLineEdit).setText(text)


def _table(panel: FridaPanel, name: str) -> QTableWidget:
    """Look up a table of the panel.

    Args:
        panel: Panel that owns the table.
        name: Attribute name of the table.

    Returns:
        QTableWidget: The table.
    """
    return priv(panel, name, QTableWidget)


def _row(table: QTableWidget, row: int) -> list[str]:
    """Read the cell texts of one table row.

    Args:
        table: Table to read.
        row: Zero-based row index.

    Returns:
        list[str]: The text of every cell of the row, left to right.
    """
    texts: list[str] = []
    for column in range(table.columnCount()):
        item = table.item(row, column)
        assert item is not None
        texts.append(item.text())
    return texts


def _rows(table: QTableWidget) -> list[list[str]]:
    """Read every row of a table.

    Args:
        table: Table to read.

    Returns:
        list[list[str]]: The cell texts of every row, top to bottom.
    """
    return [_row(table, row) for row in range(table.rowCount())]


def _settle(panel: FridaPanel) -> None:
    """Join the panel's bridge workers and deliver the results they queued.

    Args:
        panel: Panel whose workers are joined.
    """
    drain_bridge_workers_for(panel)
    QApplication.processEvents()


def _wait_for_line(qtbot: QtBot, panel: FridaPanel, line: str) -> None:
    """Wait until the panel console shows a given line.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        panel: Panel whose console is watched.
        line: Console line to wait for.
    """
    qtbot.waitUntil(lambda: line in _lines(panel), timeout=_WAIT_MS)


def _local_clock(timestamp: float) -> str:
    """Format a Unix timestamp as the hour, minute and second of the machine's local time zone.

    Args:
        timestamp: Seconds since the Unix epoch.

    Returns:
        str: The local time as ``HH:MM:SS``.
    """
    return datetime.fromtimestamp(timestamp, tz=UTC).astimezone().strftime("%H:%M:%S")


def _child(pid: int, path: str | None) -> ChildProcessInfo:
    """Build the child record a bridge reports for a gated process.

    Args:
        pid: Child process identifier.
        path: Executable path of the child, if known.

    Returns:
        ChildProcessInfo: A child record whose parent is process 1000.
    """
    return ChildProcessInfo(pid=pid, parent_pid=1000, origin="spawn", identifier=None, path=path, argv=[])


def _select_child(panel: FridaPanel, populate: str, table: str, pid: int) -> None:
    """Fill a children table with one child and select its row.

    Args:
        panel: Panel that owns the table.
        populate: Name of the panel method that fills the table.
        table: Attribute name of the table.
        pid: Identifier of the child shown in the row.
    """
    method(panel, populate)([_child(pid, None)])
    _table(panel, table).setCurrentCell(0, 0)


@pytest.fixture
def panel(qtbot: QtBot) -> Generator[FridaPanel]:
    """Provide a Frida panel with an empty console and no bridge.

    Args:
        qtbot: pytest-qt fixture that owns the widget.

    Yields:
        FridaPanel: The panel.
    """
    widget = FridaPanel()
    qtbot.addWidget(widget)
    priv(widget, "_console", QPlainTextEdit).clear()
    try:
        yield widget
    finally:
        drain_bridge_workers_for(widget)


@pytest.fixture
def bridged_panel(panel: FridaPanel) -> FridaPanel:
    """Give the panel a real bridge that is not attached to any process.

    Args:
        panel: Panel without a bridge.

    Returns:
        FridaPanel: The same panel, now holding an unattached ``FridaBridge``.
    """
    panel.set_bridge(FridaBridge())
    return panel


@pytest.mark.parametrize("handler", _BRIDGE_HANDLERS)
def test_handler_without_bridge_does_nothing(panel: FridaPanel, handler: str) -> None:
    """With no bridge set, a handler returns before it reads its inputs or touches the console.

    Every input is filled in and both child tables have a selected row, so a handler that skipped its bridge guard would go on to call a
    method of ``None`` instead of returning quietly.

    Args:
        panel: Panel without a bridge.
        handler: Name of the panel slot under test.
    """
    for name, text in _ARMED_FIELDS:
        _set_text(panel, name, text)
    _select_child(panel, "_populate_children_table", "_adv_children_table", _CHILD_PID)
    _select_child(panel, "_populate_session_children_table", "_adv_session_children_table", _CHILD_PID)

    method(panel, handler)()
    _settle(panel)

    assert panel.get_bridge() is None
    assert _lines(panel) == []
    assert not priv(panel, "_mem_prot_result", QLabel).text()


@pytest.mark.parametrize("text", ["zz", "", "   "])
@pytest.mark.parametrize(("handler", "field"), _ADDRESS_HANDLERS, ids=[handler for handler, _ in _ADDRESS_HANDLERS])
def test_handler_rejects_an_unparsable_address_without_dispatching(bridged_panel: FridaPanel, handler: str, field: str, text: str) -> None:
    """An address that is empty or not hexadecimal is reported once and nothing is sent to the bridge.

    Settling afterwards would show a second, bridge-generated error line if the handler had dispatched anyway.

    Args:
        bridged_panel: Panel holding an unattached bridge.
        handler: Name of the panel slot under test.
        field: Attribute name of the address input the slot reads.
        text: Address text typed into the input.
    """
    _set_text(bridged_panel, field, text)

    method(bridged_panel, handler)()
    _settle(bridged_panel)

    assert _lines(bridged_panel) == [_INVALID_ADDRESS]


def test_call_function_rejects_malformed_arguments_without_dispatching(bridged_panel: FridaPanel) -> None:
    """An argument list with a non-numeric entry is reported once and nothing is sent to the bridge.

    Args:
        bridged_panel: Panel holding an unattached bridge.
    """
    _set_text(bridged_panel, "_adv_call_addr", "0x1000")
    _set_text(bridged_panel, "_adv_call_args", "1, x")

    method(bridged_panel, "_on_call_function")()
    _settle(bridged_panel)

    assert _lines(bridged_panel) == ["[-] Invalid arguments"]


@pytest.mark.parametrize("text", ["", "   "])
@pytest.mark.parametrize(("handler", "field"), _EMPTY_INPUT_HANDLERS, ids=[handler for handler, _ in _EMPTY_INPUT_HANDLERS])
def test_lookup_with_blank_input_does_nothing(bridged_panel: FridaPanel, handler: str, field: str, text: str) -> None:
    """A lookup whose input is empty or only whitespace returns without dispatching or printing anything.

    Args:
        bridged_panel: Panel holding an unattached bridge.
        handler: Name of the panel slot under test.
        field: Attribute name of the input the slot reads.
        text: Text typed into the input.
    """
    _set_text(bridged_panel, field, text)

    method(bridged_panel, handler)()
    _settle(bridged_panel)

    assert _lines(bridged_panel) == []


@pytest.mark.parametrize(("handler", "fields", "expected"), _DISPATCH_CASES, ids=_DISPATCH_IDS)
def test_handler_reports_the_bridge_refusal_on_the_console(
    qtbot: QtBot,
    bridged_panel: FridaPanel,
    handler: str,
    fields: tuple[tuple[str, str], ...],
    expected: str,
) -> None:
    """A slot hands its request to the bridge and prints the bridge's own refusal when the bridge is not attached.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding an unattached bridge.
        handler: Name of the panel slot under test.
        fields: Input attribute names and the text typed into each.
        expected: Console line the failure must produce.
    """
    for name, text in fields:
        _set_text(bridged_panel, name, text)

    method(bridged_panel, handler)()

    _wait_for_line(qtbot, bridged_panel, expected)
    _settle(bridged_panel)
    assert _lines(bridged_panel) == [expected]


@pytest.mark.parametrize(("handler", "populate", "table", "expected"), _RESUME_HANDLERS, ids=_RESUME_IDS)
def test_resume_of_the_selected_child_reports_the_bridge_refusal(
    qtbot: QtBot,
    bridged_panel: FridaPanel,
    handler: str,
    populate: str,
    table: str,
    expected: str,
) -> None:
    """Resuming the selected child row dispatches the request and prints the bridge's refusal.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding an unattached bridge.
        handler: Name of the resume slot under test.
        populate: Name of the panel method that fills the children table.
        table: Attribute name of the children table.
        expected: Console line the failure must produce.
    """
    _select_child(bridged_panel, populate, table, _CHILD_PID)

    method(bridged_panel, handler)()

    _wait_for_line(qtbot, bridged_panel, expected)
    _settle(bridged_panel)
    assert _lines(bridged_panel) == [expected]


@pytest.mark.parametrize("scenario", ["unselected", "missing_item", "bad_pid"])
@pytest.mark.parametrize(("handler", "populate", "table", "expected"), _RESUME_HANDLERS, ids=_RESUME_IDS)
def test_resume_without_a_usable_selection_does_nothing(
    bridged_panel: FridaPanel,
    handler: str,
    populate: str,
    table: str,
    expected: str,
    scenario: str,
) -> None:
    """Resuming with no selected row, a row without a PID cell, or a PID cell that is not a number sends nothing to the bridge.

    A dispatched request would add the bridge's refusal line to the console, so an empty console after settling proves nothing was sent.

    Args:
        bridged_panel: Panel holding an unattached bridge.
        handler: Name of the resume slot under test.
        populate: Name of the panel method that fills the children table.
        table: Attribute name of the children table.
        expected: Console line a dispatched request would have produced.
        scenario: Which unusable selection to set up.
    """
    del expected
    children = _table(bridged_panel, table)
    if scenario == "unselected":
        method(bridged_panel, populate)([_child(_CHILD_PID, None)])
        children.setCurrentCell(-1, -1)
        assert children.currentRow() == -1
    else:
        children.setRowCount(0)
        children.insertRow(0)
        if scenario == "bad_pid":
            children.setItem(0, 0, QTableWidgetItem("abc"))
        children.setCurrentCell(0, 0)
        assert children.currentRow() == 0

    method(bridged_panel, handler)()
    _settle(bridged_panel)

    assert _lines(bridged_panel) == []


def test_refresh_crashes_replaces_the_table_with_the_bridge_crash_log(qtbot: QtBot, bridged_panel: FridaPanel) -> None:
    """Refreshing crashes clears stale rows and shows the crash log of a bridge that recorded none.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding an unattached bridge.
    """
    crashes = _table(bridged_panel, "_adv_crashes_table")
    crash = CrashInfo(pid=_CHILD_PID, process_name="target.exe", summary="access violation", report="r", parameters={}, timestamp=0.0)
    method(bridged_panel, "_populate_crashes_table")([crash])
    assert crashes.rowCount() == 1

    method(bridged_panel, "_on_refresh_crashes")()

    qtbot.waitUntil(lambda: crashes.rowCount() == 0, timeout=_WAIT_MS)
    _settle(bridged_panel)
    assert _lines(bridged_panel) == []


@pytest.mark.parametrize(("handler", "prefix"), _ERROR_HANDLERS, ids=_ERROR_HANDLER_IDS)
def test_failure_handler_prefers_the_reason_the_bridge_attached(panel: FridaPanel, handler: str, prefix: str) -> None:
    """A ``ToolError`` that carries a textual reason is shown by that reason instead of its generic message.

    Args:
        panel: Panel without a bridge.
        handler: Name of the failure handler under test.
        prefix: Text that opens the console line the handler prints.
    """
    method(panel, handler)(ToolError("generic message", details={"reason": "specific reason"}))

    assert _lines(panel) == [f"[-] {prefix}: specific reason"]


@pytest.mark.parametrize(("handler", "prefix"), _ERROR_HANDLERS, ids=_ERROR_HANDLER_IDS)
@pytest.mark.parametrize("details", _UNUSABLE_DETAILS, ids=_UNUSABLE_DETAILS_IDS)
def test_failure_handler_falls_back_to_the_error_message(
    panel: FridaPanel,
    handler: str,
    prefix: str,
    details: dict[str, object] | None,
) -> None:
    """A ``ToolError`` without a usable textual reason is shown by its message.

    Args:
        panel: Panel without a bridge.
        handler: Name of the failure handler under test.
        prefix: Text that opens the console line the handler prints.
        details: Details attached to the error.
    """
    method(panel, handler)(ToolError("generic message", details=details))

    assert _lines(panel) == [f"[-] {prefix}: generic message"]


@pytest.mark.parametrize(("handler", "prefix"), _ERROR_HANDLERS, ids=_ERROR_HANDLER_IDS)
def test_failure_handler_shows_a_plain_exception_by_its_text(panel: FridaPanel, handler: str, prefix: str) -> None:
    """An exception that is not a ``ToolError`` is shown by its own text.

    Args:
        panel: Panel without a bridge.
        handler: Name of the failure handler under test.
        prefix: Text that opens the console line the handler prints.
    """
    method(panel, handler)(RuntimeError("plain failure"))

    assert _lines(panel) == [f"[-] {prefix}: plain failure"]


def test_regions_table_shows_each_region_and_replaces_stale_rows(panel: FridaPanel) -> None:
    """Listed regions fill the table row by row with hex bases and empty module cells, and the list button is enabled again.

    Args:
        panel: Panel without a bridge.
    """
    table = _table(panel, "_mem_regions_table")
    button = priv(panel, "_mem_regions_btn", QPushButton)
    stale = MemoryRegion(base_address=0x10, size=1, protection="---", state="free", type="private", module_name=None)
    method(panel, "_populate_regions_table")([stale, stale, stale])
    assert table.rowCount() == 3
    button.setEnabled(False)
    regions = [
        MemoryRegion(
            base_address=0x7FFE0000A000,
            size=4096,
            protection="r-x",
            state="committed",
            type="image",
            module_name="C:\\Windows\\System32\\kernel32.dll",
        ),
        MemoryRegion(base_address=0x1F0000, size=65536, protection="rw-", state="committed", type="private", module_name=None),
    ]

    method(panel, "_populate_regions_table")(regions)

    assert _rows(table) == [
        ["0x7FFE0000A000", "4096", "r-x", "committed", "image", "C:\\Windows\\System32\\kernel32.dll"],
        ["0x1F0000", "65536", "rw-", "committed", "private", ""],
    ]
    assert button.isEnabled()


@pytest.mark.parametrize("result", [None, []], ids=["not_a_list", "empty_list"])
def test_regions_table_without_regions_is_cleared_and_the_button_enabled(panel: FridaPanel, result: list[MemoryRegion] | None) -> None:
    """A result with no regions empties the table and still re-enables the list button.

    Args:
        panel: Panel without a bridge.
        result: Result handed to the handler.
    """
    table = _table(panel, "_mem_regions_table")
    button = priv(panel, "_mem_regions_btn", QPushButton)
    table.setRowCount(2)
    button.setEnabled(False)

    method(panel, "_populate_regions_table")(result)

    assert table.rowCount() == 0
    assert button.isEnabled()


def test_regions_error_is_printed_and_the_button_enabled(panel: FridaPanel) -> None:
    """A failed region listing prints the error and re-enables the list button.

    Args:
        panel: Panel without a bridge.
    """
    button = priv(panel, "_mem_regions_btn", QPushButton)
    button.setEnabled(False)

    method(panel, "_on_regions_error")(ToolError(_NOT_ATTACHED))

    assert _lines(panel) == [f"[-] List regions failed: {_NOT_ATTACHED}"]
    assert button.isEnabled()


def test_symbol_results_table_shows_every_symbol_field(panel: FridaPanel) -> None:
    """Found functions fill the table with name, hex address, module, source file and line, using empty cells for missing parts.

    Args:
        panel: Panel without a bridge.
    """
    table = _table(panel, "_sym_results_table")
    stale = SymbolInfo(name="Old", address=1, module_name=None, file_name=None, line_number=None)
    method(panel, "_populate_sym_results_table")([stale, stale, stale])
    assert table.rowCount() == 3
    symbols = [
        SymbolInfo(name="CreateFileW", address=0x7FF812340000, module_name="kernel32.dll", file_name="C:\\src\\file.c", line_number=88),
        SymbolInfo(name="Sleep", address=0x401000, module_name=None, file_name=None, line_number=None),
        SymbolInfo(name="Zero", address=0x10, module_name="z.dll", file_name="z.c", line_number=0),
    ]

    method(panel, "_populate_sym_results_table")(symbols)

    assert _rows(table) == [
        ["CreateFileW", "0x7FF812340000", "kernel32.dll", "C:\\src\\file.c", "88"],
        ["Sleep", "0x401000", "", "", ""],
        ["Zero", "0x10", "z.dll", "z.c", "0"],
    ]


def test_api_table_shows_each_match_with_a_hex_address(panel: FridaPanel) -> None:
    """Resolved API matches fill the table with name and hex address, replacing stale rows.

    Args:
        panel: Panel without a bridge.
    """
    table = _table(panel, "_sym_api_table")
    method(panel, "_populate_api_table")([ApiResolverMatch(name="old", address=1)] * 2)
    assert table.rowCount() == 2
    matches = [
        ApiResolverMatch(name="kernel32.dll!CreateFileW", address=0x7FF812340000),
        ApiResolverMatch(name="ntdll.dll!NtCreateFile", address=0x7FF8ABCDEF00),
    ]

    method(panel, "_populate_api_table")(matches)

    assert _rows(table) == [
        ["kernel32.dll!CreateFileW", "0x7FF812340000"],
        ["ntdll.dll!NtCreateFile", "0x7FF8ABCDEF00"],
    ]


@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            SymbolInfo(name="kernel32.dll!Sleep", address=0x7FF812340100, module_name="kernel32.dll", file_name=None, line_number=None),
            "[+] Symbol: kernel32.dll!Sleep at 0x7FF812340100 (kernel32.dll)",
        ),
        (
            SymbolInfo(name="Foo", address=0x10, module_name=None, file_name=None, line_number=None),
            "[+] Symbol: Foo at 0x10 ()",
        ),
    ],
    ids=["with_module", "without_module"],
)
def test_resolved_symbol_is_printed_with_its_hex_address_and_module(panel: FridaPanel, symbol: SymbolInfo, expected: str) -> None:
    """A resolved symbol is printed with its name, uppercase hex address and module in parentheses.

    Args:
        panel: Panel without a bridge.
        symbol: Symbol the bridge resolved.
        expected: Console line the symbol must produce.
    """
    method(panel, "_on_symbol_resolved")(symbol)

    assert _lines(panel) == [expected]


def test_children_table_shows_each_pending_child(panel: FridaPanel) -> None:
    """Pending children fill the table with PID, parent PID, origin and path, using an empty cell for an unknown path.

    Args:
        panel: Panel without a bridge.
    """
    table = _table(panel, "_adv_children_table")
    method(panel, "_populate_children_table")([_child(1, None)] * 3)
    assert table.rowCount() == 3
    children = [
        ChildProcessInfo(
            pid=_CHILD_PID,
            parent_pid=1000,
            origin="spawn",
            identifier=None,
            path="C:\\Windows\\notepad.exe",
            argv=["notepad.exe"],
        ),
        ChildProcessInfo(pid=77, parent_pid=_CHILD_PID, origin="fork", identifier=None, path=None, argv=[]),
    ]

    method(panel, "_populate_children_table")(children)

    assert _rows(table) == [
        ["4321", "1000", "spawn", "C:\\Windows\\notepad.exe"],
        ["77", "4321", "fork", ""],
    ]


def test_session_children_table_shows_each_pending_child(panel: FridaPanel) -> None:
    """Session-gated children fill their own table with PID, parent PID, origin and path, using an empty cell for an unknown path.

    Args:
        panel: Panel without a bridge.
    """
    table = _table(panel, "_adv_session_children_table")
    method(panel, "_populate_session_children_table")([_child(1, None)] * 3)
    assert table.rowCount() == 3
    children = [
        ChildProcessInfo(
            pid=_CHILD_PID,
            parent_pid=1000,
            origin="spawn",
            identifier=None,
            path="C:\\Windows\\notepad.exe",
            argv=["notepad.exe"],
        ),
        ChildProcessInfo(pid=77, parent_pid=_CHILD_PID, origin="fork", identifier=None, path=None, argv=[]),
    ]

    method(panel, "_populate_session_children_table")(children)

    assert _rows(table) == [
        ["4321", "1000", "spawn", "C:\\Windows\\notepad.exe"],
        ["77", "4321", "fork", ""],
    ]
    assert _table(panel, "_adv_children_table").rowCount() == 0


def test_crashes_table_shows_each_crash_with_its_local_time(panel: FridaPanel) -> None:
    """Recorded crashes fill the table with PID, process, summary and the local clock time of the crash.

    Args:
        panel: Panel without a bridge.
    """
    table = _table(panel, "_adv_crashes_table")
    stale = CrashInfo(pid=1, process_name="old.exe", summary="old", report="", parameters={}, timestamp=0.0)
    method(panel, "_populate_crashes_table")([stale, stale])
    assert table.rowCount() == 2
    first_time = 1_700_000_000.0
    second_time = 86_400.0
    crashes = [
        CrashInfo(
            pid=_CHILD_PID,
            process_name="target.exe",
            summary="access violation at 0x401000",
            report="EXCEPTION_ACCESS_VIOLATION",
            parameters={"code": "c0000005"},
            timestamp=first_time,
        ),
        CrashInfo(pid=77, process_name="other.exe", summary="stack overflow", report="", parameters={}, timestamp=second_time),
    ]

    method(panel, "_populate_crashes_table")(crashes)

    assert _rows(table) == [
        ["4321", "target.exe", "access violation at 0x401000", _local_clock(first_time)],
        ["77", "other.exe", "stack overflow", _local_clock(second_time)],
    ]


@pytest.mark.parametrize("result", [None, []], ids=["not_a_list", "empty_list"])
@pytest.mark.parametrize(("populate", "table"), _TABLE_POPULATORS, ids=_TABLE_IDS)
def test_table_populator_clears_stale_rows_when_there_is_nothing_to_show(
    panel: FridaPanel,
    populate: str,
    table: str,
    result: list[object] | None,
) -> None:
    """A result that is not a list, or an empty one, leaves the table empty instead of keeping the previous rows.

    Args:
        panel: Panel without a bridge.
        populate: Name of the panel method that fills the table.
        table: Attribute name of the table.
        result: Result handed to the populate method.
    """
    target = _table(panel, table)
    target.setRowCount(2)

    method(panel, populate)(result)

    assert target.rowCount() == 0
