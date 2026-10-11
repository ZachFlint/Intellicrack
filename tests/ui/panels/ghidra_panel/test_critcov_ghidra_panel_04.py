# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the comment, symbol, namespace, equate, relocation, external-function, scripting and analysis handlers of the Ghidra panel.

Every test drives a real ``GhidraPanel`` under the offscreen ``QApplication`` by calling the slots its buttons trigger. Handlers that reach
the bridge run through the real asynchronous dispatch against ``ScriptedGhidraBridge``, a subclass of the real ``GhidraBridge`` that
replaces only the two methods that cross the process boundary to Ghidra (``_execute_remote`` and ``_execute_remote_eval``). Every bridge
method above them is the production code: it builds the Jython source, parses the reply and wraps failures, so the panel receives exactly
the payload shapes and error texts the real bridge produces. The scripted replies mirror the dictionaries the Jython snippets in
``bridges/ghidra.py`` build. Expected table cells and status texts are written out by hand; JSON error texts come from the standard
library's own parser. Panels with no bridge or with an unconnected bridge show the guard messages and never dispatch.
"""

from __future__ import annotations

import asyncio
import importlib
import json
from typing import TYPE_CHECKING, Final, cast, override

import pytest
from PyQt6.QtWidgets import QApplication, QCheckBox, QComboBox, QLineEdit, QPlainTextEdit, QPushButton, QSpinBox, QTableWidget
from structlog.testing import capture_logs

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError
from intellicrack.ui.panels.async_bridge import drain_bridge_workers_for
from intellicrack.ui.panels.ghidra_panel import GhidraPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping, Sequence

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")

_WAIT_MS: Final[int] = 20_000
_UNUSED_PORT: Final[int] = 1
_NO_BRIDGE: Final[str] = "No bridge configured"
_NOT_CONNECTED: Final[str] = "Ghidra not connected"

_GUARDED_HANDLERS: Final[tuple[str, ...]] = (
    "_on_search_symbols",
    "_on_create_namespace",
    "_on_refresh_namespaces",
    "_on_create_equate",
    "_on_refresh_equates",
    "_on_refresh_relocations",
    "_on_add_external_function",
    "_on_run_script",
    "_on_run_script_with_params",
    "_on_apply_decompiler_options",
    "_on_configure_analysis",
)

_ARMED_LINE_EDITS: Final[tuple[tuple[str, str], ...]] = (
    ("_sym_name_input", "main"),
    ("_ns_name_input", "Parser"),
    ("_eq_addr_input", "0x1000"),
    ("_eq_value_input", "5"),
    ("_eq_name_input", "FIVE"),
    ("_ext_lib_input", "kernel32.dll"),
    ("_ext_func_input", "CreateFileW"),
    ("_script_params_input", "{}"),
    ("_analyzer_name_input", "Decompiler Parameter ID"),
)

_SYMBOL_REPLY: Final[list[dict[str, object]]] = [
    {"name": "main", "address": 0x140001000, "type": "Function", "namespace": "Global"},
    {"name": "g_flag", "address": 0x140020010, "type": "Label", "namespace": "Settings"},
]
_NAMESPACE_REPLY: Final[list[dict[str, object]]] = [
    {"name": "Parser", "path": "Outer::Parser"},
    {"name": "Global", "path": "Global"},
]
_EQUATE_REPLY: Final[list[dict[str, object]]] = [
    {"name": "MAGIC", "value": 42, "references": 1},
    {"name": "COLOR_WHITE", "value": 16777215, "references": 3},
]
_RELOCATION_REPLY: Final[list[dict[str, object]]] = [
    {"address": 0x140030000, "type": 3, "symbol": "", "values": []},
    {"address": 0x140030008, "type": 10, "symbol": "ImportedFn", "values": [1]},
]
_COMMENT_REPLY: Final[list[dict[str, object]]] = [
    {"address": 0x140001000, "type": "EOL", "comment": "entry point"},
    {"address": 0x140001010, "type": "PLATE", "comment": "first line\nsecond line"},
]
_SCRIPT: Final[str] = "6 * 7"


class ScriptedGhidraBridge(GhidraBridge):
    """Real ``GhidraBridge`` whose Jython transport answers from a script.

    Only ``_execute_remote`` and ``_execute_remote_eval``, the two methods that hand Jython source to the Ghidra process, are replaced.
    Each looks through its list of ``(marker, reply)`` pairs for the first marker contained in the source and returns that reply, or
    raises it when it is an exception. A source with no matching marker raises a ``ToolError``. Every caller above those two methods is
    the production code under test. The instance lists ``exec_replies`` and ``eval_replies`` hold the marker and reply pairs, and
    ``scripts`` and ``evals`` record the source of every call, in order.
    """

    def __init__(self) -> None:
        """Create the bridge with no scripted replies."""
        super().__init__()
        self.exec_replies: list[tuple[str, object]] = []
        self.eval_replies: list[tuple[str, object]] = []
        self.scripts: list[str] = []
        self.evals: list[str] = []

    @override
    async def _execute_remote(self, code: str) -> object:
        """Record the source and return the scripted reply.

        Args:
            code: Jython source the production code wants to run.

        Returns:
            object: The scripted reply for the source.
        """
        await asyncio.sleep(0)
        self.scripts.append(code)
        return _route(self.exec_replies, code)

    @override
    async def _execute_remote_eval(self, expression: str) -> object:
        """Record the expression and return the scripted reply.

        Args:
            expression: Jython expression the production code wants to evaluate.

        Returns:
            object: The scripted reply for the expression.
        """
        await asyncio.sleep(0)
        self.evals.append(expression)
        return _route(self.eval_replies, expression)


def _route(replies: list[tuple[str, object]], source: str) -> object:
    """Pick the scripted reply whose marker occurs in the source.

    Args:
        replies: Marker and reply pairs, searched in order.
        source: Jython source or expression sent by the production code.

    Returns:
        object: The reply of the first matching marker.

    Raises:
        reply: The scripted reply itself, when it is an exception.
        ToolError: When no marker occurs in the source.
    """
    for marker, reply in replies:
        if marker in source:
            if isinstance(reply, BaseException):
                raise reply
            return reply
    msg = f"no scripted reply for: {source[:80]!r}"
    raise ToolError(msg)


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


def _status(panel: GhidraPanel) -> str:
    """Read the status text shown in the panel toolbar.

    Args:
        panel: Panel whose status label is read.

    Returns:
        str: The label text.
    """
    label = panel.status_label
    assert label is not None
    return label.text()


def _set_text(panel: GhidraPanel, name: str, text: str) -> None:
    """Type text into a line edit of the panel.

    Args:
        panel: Panel that owns the line edit.
        name: Attribute name of the line edit.
        text: Text to enter.
    """
    priv(panel, name, QLineEdit).setText(text)


def _set_plain(panel: GhidraPanel, name: str, text: str) -> None:
    """Type text into a multi-line editor of the panel.

    Args:
        panel: Panel that owns the editor.
        name: Attribute name of the editor.
        text: Text to enter.
    """
    priv(panel, name, QPlainTextEdit).setPlainText(text)


def _table(panel: GhidraPanel, name: str) -> QTableWidget:
    """Look up a table of the panel.

    Args:
        panel: Panel that owns the table.
        name: Attribute name of the table.

    Returns:
        QTableWidget: The table.
    """
    return priv(panel, name, QTableWidget)


def _rows(table: QTableWidget) -> list[list[str]]:
    """Read every row of a table.

    Args:
        table: Table to read.

    Returns:
        list[list[str]]: The cell texts of every row, top to bottom; a cell without an item reads as ``<none>``.
    """
    rows: list[list[str]] = []
    for row in range(table.rowCount()):
        texts: list[str] = []
        for column in range(table.columnCount()):
            item = table.item(row, column)
            texts.append("<none>" if item is None else item.text())
        rows.append(texts)
    return rows


def _settle(panel: GhidraPanel) -> None:
    """Join the panel's bridge workers and deliver their results, following chained requests.

    Args:
        panel: Panel whose workers are joined.
    """
    for _ in range(4):
        drain_bridge_workers_for(panel, timeout_ms=_WAIT_MS)
        QApplication.processEvents()


def _arm(panel: GhidraPanel) -> None:
    """Fill every input a handler reads so that a handler skipping its guard would go on to use the bridge.

    Args:
        panel: Panel whose inputs are filled.
    """
    for name, text in _ARMED_LINE_EDITS:
        _set_text(panel, name, text)
    _set_plain(panel, "_script_editor", _SCRIPT)


def _json_error(text: str) -> json.JSONDecodeError:
    """Obtain the error the standard library's JSON parser raises for malformed text.

    Args:
        text: Text that is not valid JSON.

    Returns:
        json.JSONDecodeError: The parser's own error.
    """
    with pytest.raises(json.JSONDecodeError) as info:
        json.loads(text)
    return info.value


def _events(logs: Sequence[Mapping[str, object]], name: str) -> list[Mapping[str, object]]:
    """Filter captured structlog entries by event name.

    Args:
        logs: Entries captured with ``structlog.testing.capture_logs``.
        name: Event name to keep.

    Returns:
        list[Mapping[str, object]]: The matching entries in emission order.
    """
    return [entry for entry in logs if entry["event"] == name]


@pytest.fixture(scope="module")
def rpc_client() -> object:
    """Provide a real ``ghidra_bridge`` RPC client that has never connected.

    The client connects lazily on its first remote call, and the scripted bridge never makes one, so nothing is opened.

    Returns:
        object: The ``ghidra_bridge.GhidraBridge`` client instance.
    """
    module = importlib.import_module("ghidra_bridge")
    factory = cast("Callable[..., object]", getattr(module, "GhidraBridge"))
    return factory(namespace=None, connect_to_host="127.0.0.1", connect_to_port=_UNUSED_PORT, response_timeout=5)


@pytest.fixture
def panel(qtbot: QtBot) -> Generator[GhidraPanel]:
    """Provide a Ghidra panel with no bridge.

    Args:
        qtbot: pytest-qt fixture that owns the widget.

    Yields:
        GhidraPanel: The panel.
    """
    widget = GhidraPanel()
    qtbot.addWidget(widget)
    try:
        yield widget
    finally:
        drain_bridge_workers_for(widget)


@pytest.fixture
def bridge(rpc_client: object) -> ScriptedGhidraBridge:
    """Provide a connected bridge whose Jython transport answers from a script.

    Args:
        rpc_client: Real RPC client attached to the bridge.

    Returns:
        ScriptedGhidraBridge: A bridge that reports itself ready and has no scripted replies.
    """
    scripted = ScriptedGhidraBridge()
    scripted.attach_remote_bridge(rpc_client)
    return scripted


@pytest.fixture
def bridged_panel(panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> GhidraPanel:
    """Give the panel the scripted bridge.

    Args:
        panel: Panel without a bridge.
        bridge: Connected scripted bridge.

    Returns:
        GhidraPanel: The same panel, now holding the bridge.
    """
    panel.set_bridge(bridge)
    return panel


@pytest.mark.parametrize("handler", _GUARDED_HANDLERS)
def test_handler_without_a_bridge_reports_it_and_does_nothing(panel: GhidraPanel, handler: str) -> None:
    """With no bridge set, a handler shows the missing-bridge message before it reads anything or touches a table.

    Every input is filled in, so a handler that skipped its guard would go on to call a method of ``None``.

    Args:
        panel: Panel without a bridge.
        handler: Name of the panel slot under test.
    """
    _arm(panel)
    assert _status(panel) != _NO_BRIDGE

    method(panel, handler)()
    _settle(panel)

    assert panel.get_bridge() is None
    assert _status(panel) == _NO_BRIDGE
    assert priv(panel, "_run_script_btn", QPushButton).isEnabled()
    assert priv(panel, "_run_script_params_btn", QPushButton).isEnabled()
    assert not priv(panel, "_script_output", QPlainTextEdit).toPlainText()
    for name in ("_symbols_table", "_namespaces_table", "_equates_table", "_relocations_table"):
        assert _table(panel, name).rowCount() == 0


@pytest.mark.parametrize("handler", _GUARDED_HANDLERS)
def test_handler_with_an_unconnected_bridge_reports_it_and_dispatches_nothing(panel: GhidraPanel, handler: str) -> None:
    """A real bridge that never connected makes a handler show the not-connected message and send nothing.

    A request that was dispatched anyway would be refused by the bridge and replace the message with a failure line.

    Args:
        panel: Panel without a bridge.
        handler: Name of the panel slot under test.
    """
    panel.set_bridge(GhidraBridge())
    _arm(panel)
    assert _status(panel) != _NOT_CONNECTED

    method(panel, handler)()
    _settle(panel)

    assert _status(panel) == _NOT_CONNECTED
    assert priv(panel, "_run_script_btn", QPushButton).isEnabled()
    assert priv(panel, "_run_script_params_btn", QPushButton).isEnabled()
    assert not priv(panel, "_script_output", QPlainTextEdit).toPlainText()


@pytest.mark.parametrize(("type_text", "literal"), [("", "None"), ("Function", '"Function"')], ids=["any_type", "function"])
def test_search_symbols_sends_the_typed_name_and_chosen_type_and_fills_the_table(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    type_text: str,
    literal: str,
) -> None:
    """Searching sends the stripped name and the chosen type filter, and the reply replaces the stale rows of the symbols table.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        type_text: Entry of the type combo box that is selected.
        literal: Jython literal the bridge must write for the type filter.
    """
    bridge.exec_replies.append(("raw_pattern", _SYMBOL_REPLY))
    table = _table(bridged_panel, "_symbols_table")
    table.setRowCount(3)
    _set_text(bridged_panel, "_sym_name_input", "  main  ")
    combo = priv(bridged_panel, "_sym_type_combo", QComboBox)
    combo.setCurrentIndex(combo.findText(type_text))
    assert combo.currentText() == type_text

    method(bridged_panel, "_on_search_symbols")()
    _settle(bridged_panel)

    assert len(bridge.scripts) == 1
    assert 'raw_pattern = "main"' in bridge.scripts[0]
    assert f"type_filter = {literal}" in bridge.scripts[0]
    assert _rows(table) == [
        ["main", "0x140001000", "Function", "Global"],
        ["g_flag", "0x140020010", "Label", "Settings"],
    ]


def test_search_symbols_failure_is_reported_and_keeps_the_table(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A bridge failure during a symbol search is shown in the status label and leaves the rows already listed.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append(("raw_pattern", ToolError("boom")))
    table = _table(bridged_panel, "_symbols_table")
    method(bridged_panel, "_apply_symbols")(_SYMBOL_REPLY)
    assert table.rowCount() == 2

    method(bridged_panel, "_on_search_symbols")()
    _settle(bridged_panel)

    assert _status(bridged_panel) == "Symbol search failed: boom"
    assert table.rowCount() == 2


@pytest.mark.parametrize("result", [None, [], {"name": "main"}], ids=["none", "empty_list", "dict"])
def test_symbols_table_without_a_list_is_cleared(panel: GhidraPanel, result: object) -> None:
    """A result that is not a non-empty list leaves the symbols table empty instead of keeping the previous rows.

    Args:
        panel: Panel without a bridge.
        result: Result handed to the handler.
    """
    table = _table(panel, "_symbols_table")
    table.setRowCount(2)

    method(panel, "_apply_symbols")(result)

    assert table.rowCount() == 0


def test_symbols_table_fills_missing_fields_with_defaults(panel: GhidraPanel) -> None:
    """A symbol record without any field shows empty cells and the address zero.

    Args:
        panel: Panel without a bridge.
    """
    method(panel, "_apply_symbols")([{}])

    assert _rows(_table(panel, "_symbols_table")) == [["", "0x0", "", ""]]


@pytest.mark.parametrize(
    ("parent_text", "literal"),
    [("  Outer  ", '"Outer"'), ("", "None"), ("   ", "None")],
    ids=["parent", "blank_parent", "spaces_parent"],
)
def test_create_namespace_sends_the_name_and_parent_then_refreshes_the_table(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    parent_text: str,
    literal: str,
) -> None:
    """Creating a namespace sends the stripped name and parent, and a refresh of the namespaces table follows.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        parent_text: Text typed into the parent field.
        literal: Jython literal the bridge must write for the parent.
    """
    bridge.exec_replies.extend(
        [
            ("createNameSpace", {"name": "Parser", "path": "Outer::Parser", "success": True}),
            ("SymbolType.NAMESPACE", _NAMESPACE_REPLY),
        ],
    )
    _set_text(bridged_panel, "_ns_name_input", "  Parser  ")
    _set_text(bridged_panel, "_ns_parent_input", parent_text)

    method(bridged_panel, "_on_create_namespace")()
    _settle(bridged_panel)

    assert len(bridge.scripts) == 2
    assert f"parent_path = {literal}" in bridge.scripts[0]
    assert 'createNameSpace(parent_ns, "Parser", SourceType.USER_DEFINED)' in bridge.scripts[0]
    assert _rows(_table(bridged_panel, "_namespaces_table")) == [["Parser", "Outer::Parser"], ["Global", "Global"]]


@pytest.mark.parametrize("name", ["", "   "])
def test_create_namespace_requires_a_name(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge, name: str) -> None:
    """A blank namespace name is reported and nothing is sent to the bridge.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        name: Text typed into the name field.
    """
    _set_text(bridged_panel, "_ns_name_input", name)
    _set_text(bridged_panel, "_ns_parent_input", "Outer")

    method(bridged_panel, "_on_create_namespace")()
    _settle(bridged_panel)

    assert _status(bridged_panel) == "Namespace name required"
    assert bridge.scripts == []


def test_create_namespace_failure_is_reported_and_no_refresh_follows(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A bridge failure while creating a namespace is shown in the status label and the table is not refreshed.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append(("createNameSpace", ToolError("boom")))
    _set_text(bridged_panel, "_ns_name_input", "Parser")

    method(bridged_panel, "_on_create_namespace")()
    _settle(bridged_panel)

    status = _status(bridged_panel)
    assert status.startswith("Create namespace failed:")
    assert status.endswith("boom")
    assert len(bridge.scripts) == 1
    assert _table(bridged_panel, "_namespaces_table").rowCount() == 0


def test_refresh_namespaces_replaces_the_table_with_the_bridge_reply(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Refreshing lists each namespace by name and path in place of the stale rows.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append(("SymbolType.NAMESPACE", _NAMESPACE_REPLY))
    table = _table(bridged_panel, "_namespaces_table")
    table.setRowCount(3)

    method(bridged_panel, "_on_refresh_namespaces")()
    _settle(bridged_panel)

    assert _rows(table) == [["Parser", "Outer::Parser"], ["Global", "Global"]]


def test_refresh_namespaces_failure_is_reported(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A bridge failure while listing namespaces is shown in the status label.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append(("SymbolType.NAMESPACE", ToolError("boom")))

    method(bridged_panel, "_on_refresh_namespaces")()
    _settle(bridged_panel)

    assert _status(bridged_panel) == "Refresh namespaces failed: boom"


@pytest.mark.parametrize("result", [None, [], {"name": "Parser"}], ids=["none", "empty_list", "dict"])
def test_namespaces_table_without_a_list_is_cleared(panel: GhidraPanel, result: object) -> None:
    """A result that is not a non-empty list leaves the namespaces table empty instead of keeping the previous rows.

    Args:
        panel: Panel without a bridge.
        result: Result handed to the handler.
    """
    table = _table(panel, "_namespaces_table")
    table.setRowCount(2)

    method(panel, "_apply_namespaces")(result)

    assert table.rowCount() == 0


def test_namespaces_table_fills_missing_fields_with_empty_cells(panel: GhidraPanel) -> None:
    """A namespace record without any field shows empty cells.

    Args:
        panel: Panel without a bridge.
    """
    method(panel, "_apply_namespaces")([{}])

    assert _rows(_table(panel, "_namespaces_table")) == [["", ""]]


def test_create_equate_sends_the_parsed_fields_then_refreshes_the_table(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Creating an equate sends the parsed address and value with the stripped name, verifies it, and refreshes the equates table.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.extend([("createEquate", None), ("eqTable.getEquates()", _EQUATE_REPLY)])
    bridge.eval_replies.append(("addresses", {"value": 42, "addresses": [0x401000]}))
    _set_text(bridged_panel, "_eq_addr_input", " 0x401000 ")
    _set_text(bridged_panel, "_eq_value_input", "0x2A")
    _set_text(bridged_panel, "_eq_name_input", "  MAGIC  ")

    method(bridged_panel, "_on_create_equate")()
    _settle(bridged_panel)

    assert len(bridge.scripts) == 2
    assert f"toAddr({0x401000})" in bridge.scripts[0]
    assert f'createEquate("MAGIC", {0x2A})' in bridge.scripts[0]
    assert len(bridge.evals) == 1
    assert 'getEquate("MAGIC")' in bridge.evals[0]
    assert _rows(_table(bridged_panel, "_equates_table")) == [["MAGIC", "42", "1"], ["COLOR_WHITE", "16777215", "3"]]


@pytest.mark.parametrize(
    ("addr", "value", "name", "expected"),
    [
        ("zz", "5", "FIVE", "Invalid address for equate"),
        ("", "5", "FIVE", "Invalid address for equate"),
        ("0x1000", "zz", "FIVE", "Invalid equate value"),
        ("0x1000", "", "FIVE", "Invalid equate value"),
        ("0x1000", "5", "", "Equate name required"),
        ("0x1000", "5", "   ", "Equate name required"),
    ],
    ids=["bad_address", "blank_address", "bad_value", "blank_value", "blank_name", "spaces_name"],
)
def test_create_equate_rejects_an_unusable_field_without_dispatching(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    addr: str,
    value: str,
    name: str,
    expected: str,
) -> None:
    """An address or value that does not parse, or a blank name, is reported and nothing is sent to the bridge.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        addr: Text typed into the address field.
        value: Text typed into the value field.
        name: Text typed into the name field.
        expected: Status text the rejection must show.
    """
    _set_text(bridged_panel, "_eq_addr_input", addr)
    _set_text(bridged_panel, "_eq_value_input", value)
    _set_text(bridged_panel, "_eq_name_input", name)

    method(bridged_panel, "_on_create_equate")()
    _settle(bridged_panel)

    assert _status(bridged_panel) == expected
    assert bridge.scripts == []
    assert bridge.evals == []


def test_create_equate_failure_is_reported_and_no_refresh_follows(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A bridge failure while creating an equate is shown in the status label and the table is not refreshed.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append(("createEquate", ToolError("boom")))
    for name, text in (("_eq_addr_input", "0x1000"), ("_eq_value_input", "5"), ("_eq_name_input", "FIVE")):
        _set_text(bridged_panel, name, text)

    method(bridged_panel, "_on_create_equate")()
    _settle(bridged_panel)

    assert _status(bridged_panel) == "Create equate failed: boom"
    assert len(bridge.scripts) == 1
    assert _table(bridged_panel, "_equates_table").rowCount() == 0


def test_create_equate_that_cannot_be_read_back_is_reported(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """When the bridge's verification finds no equate after the create, the panel reports the verification failure.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append(("createEquate", None))
    bridge.eval_replies.append(("addresses", None))
    for name, text in (("_eq_addr_input", "0x1000"), ("_eq_value_input", "5"), ("_eq_name_input", "FIVE")):
        _set_text(bridged_panel, name, text)

    method(bridged_panel, "_on_create_equate")()
    _settle(bridged_panel)

    assert _status(bridged_panel).startswith("Create equate failed: Equate verification failed")
    assert len(bridge.scripts) == 1
    assert _table(bridged_panel, "_equates_table").rowCount() == 0


def test_refresh_equates_replaces_the_table_with_the_bridge_reply(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Refreshing lists each equate with its decimal value and reference count in place of the stale rows.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append(("eqTable.getEquates()", _EQUATE_REPLY))
    table = _table(bridged_panel, "_equates_table")
    table.setRowCount(3)

    method(bridged_panel, "_on_refresh_equates")()
    _settle(bridged_panel)

    assert _rows(table) == [["MAGIC", "42", "1"], ["COLOR_WHITE", "16777215", "3"]]


def test_refresh_equates_failure_is_reported(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A bridge failure while listing equates is shown in the status label.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append(("eqTable.getEquates()", ToolError("boom")))

    method(bridged_panel, "_on_refresh_equates")()
    _settle(bridged_panel)

    assert _status(bridged_panel) == "Refresh equates failed: boom"


@pytest.mark.parametrize("result", [None, [], {"name": "MAGIC"}], ids=["none", "empty_list", "dict"])
def test_equates_table_without_a_list_is_cleared(panel: GhidraPanel, result: object) -> None:
    """A result that is not a non-empty list leaves the equates table empty instead of keeping the previous rows.

    Args:
        panel: Panel without a bridge.
        result: Result handed to the handler.
    """
    table = _table(panel, "_equates_table")
    table.setRowCount(2)

    method(panel, "_apply_equates")(result)

    assert table.rowCount() == 0


def test_equates_table_fills_missing_fields_with_defaults(panel: GhidraPanel) -> None:
    """An equate record without any field shows an empty name, the value zero and no references.

    Args:
        panel: Panel without a bridge.
    """
    method(panel, "_apply_equates")([{}])

    assert _rows(_table(panel, "_equates_table")) == [["", "0", "0"]]


def test_refresh_relocations_replaces_the_table_with_the_bridge_reply(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Refreshing lists each relocation with its hex address, numeric type and symbol in place of the stale rows.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append(("getRelocationTable", _RELOCATION_REPLY))
    table = _table(bridged_panel, "_relocations_table")
    table.setRowCount(3)

    method(bridged_panel, "_on_refresh_relocations")()
    _settle(bridged_panel)

    assert _rows(table) == [["0x140030000", "3", ""], ["0x140030008", "10", "ImportedFn"]]


def test_refresh_relocations_failure_is_reported(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A bridge failure while listing relocations is shown in the status label.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append(("getRelocationTable", ToolError("boom")))

    method(bridged_panel, "_on_refresh_relocations")()
    _settle(bridged_panel)

    assert _status(bridged_panel) == "Refresh relocations failed: boom"


@pytest.mark.parametrize("result", [None, [], {"address": 1}], ids=["none", "empty_list", "dict"])
def test_relocations_table_without_a_list_is_cleared(panel: GhidraPanel, result: object) -> None:
    """A result that is not a non-empty list leaves the relocations table empty instead of keeping the previous rows.

    Args:
        panel: Panel without a bridge.
        result: Result handed to the handler.
    """
    table = _table(panel, "_relocations_table")
    table.setRowCount(2)

    method(panel, "_apply_relocations")(result)

    assert table.rowCount() == 0


def test_relocations_table_fills_missing_fields_with_defaults(panel: GhidraPanel) -> None:
    """A relocation record without any field shows the address zero and empty cells.

    Args:
        panel: Panel without a bridge.
    """
    method(panel, "_apply_relocations")([{}])

    assert _rows(_table(panel, "_relocations_table")) == [["0x0", "", ""]]


@pytest.mark.parametrize(
    ("addr_text", "literal"),
    [("", "None"), ("   ", "None"), (" 0x1000 ", str(0x1000))],
    ids=["no_address", "spaces_address", "hex_address"],
)
def test_add_external_function_sends_library_name_and_optional_address(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    addr_text: str,
    literal: str,
) -> None:
    """Adding an external function sends the stripped library and name with the parsed address, and reports success.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        addr_text: Text typed into the address field.
        literal: Jython literal the bridge must write for the address.
    """
    bridge.exec_replies.append(("addExtFunction", {"library": "kernel32.dll", "name": "CreateFileW", "address": None, "success": True}))
    _set_text(bridged_panel, "_ext_lib_input", "  kernel32.dll  ")
    _set_text(bridged_panel, "_ext_func_input", "  CreateFileW  ")
    _set_text(bridged_panel, "_ext_addr_input", addr_text)

    method(bridged_panel, "_on_add_external_function")()
    _settle(bridged_panel)

    assert len(bridge.scripts) == 1
    assert f"addr_val = {literal}" in bridge.scripts[0]
    assert 'addExtFunction("kernel32.dll", "CreateFileW", mem_addr, SourceType.USER_DEFINED)' in bridge.scripts[0]
    assert _status(bridged_panel) == "External function 'kernel32.dll::CreateFileW' added"


@pytest.mark.parametrize(
    ("library", "function"),
    [("", "CreateFileW"), ("kernel32.dll", ""), ("   ", "CreateFileW"), ("kernel32.dll", "   "), ("", "")],
    ids=["no_library", "no_function", "spaces_library", "spaces_function", "neither"],
)
def test_add_external_function_requires_library_and_name(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    library: str,
    function: str,
) -> None:
    """A blank library or function name is reported and nothing is sent to the bridge.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        library: Text typed into the library field.
        function: Text typed into the function field.
    """
    _set_text(bridged_panel, "_ext_lib_input", library)
    _set_text(bridged_panel, "_ext_func_input", function)

    method(bridged_panel, "_on_add_external_function")()
    _settle(bridged_panel)

    assert _status(bridged_panel) == "Library and function name required"
    assert bridge.scripts == []


def test_add_external_function_failure_is_reported(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A bridge failure while adding an external function is shown in the status label.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append(("addExtFunction", ToolError("boom")))
    _set_text(bridged_panel, "_ext_lib_input", "kernel32.dll")
    _set_text(bridged_panel, "_ext_func_input", "CreateFileW")

    method(bridged_panel, "_on_add_external_function")()
    _settle(bridged_panel)

    status = _status(bridged_panel)
    assert status.startswith("Add external function failed:")
    assert status.endswith("boom")


def test_run_script_sends_the_stripped_script_and_shows_its_output(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Running sends the stripped editor text, locks the Run button until the reply arrives, and shows the reply as output.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append((_SCRIPT, 42))
    _set_plain(bridged_panel, "_script_editor", f"  {_SCRIPT}  \n")
    run_button = priv(bridged_panel, "_run_script_btn", QPushButton)
    params_button = priv(bridged_panel, "_run_script_params_btn", QPushButton)

    method(bridged_panel, "_on_run_script")()

    assert not run_button.isEnabled()
    assert params_button.isEnabled()
    _settle(bridged_panel)

    assert bridge.scripts == [_SCRIPT]
    assert run_button.isEnabled()
    assert params_button.isEnabled()
    assert priv(bridged_panel, "_script_output", QPlainTextEdit).toPlainText() == "42"
    assert _status(bridged_panel) == "Script executed"


@pytest.mark.parametrize(
    ("handler", "button"),
    [("_on_run_script", "_run_script_btn"), ("_on_run_script_with_params", "_run_script_params_btn")],
    ids=["run", "run_with_params"],
)
@pytest.mark.parametrize("text", ["", "  \n  "], ids=["empty", "spaces"])
def test_running_a_blank_script_is_reported_without_dispatching(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    handler: str,
    button: str,
    text: str,
) -> None:
    """A blank editor is reported, nothing is sent to the bridge, and the run button stays enabled.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        handler: Name of the panel slot under test.
        button: Attribute name of the button the slot would lock.
        text: Text in the script editor.
    """
    _set_plain(bridged_panel, "_script_editor", text)

    method(bridged_panel, handler)()
    _settle(bridged_panel)

    assert _status(bridged_panel) == "Script is empty"
    assert bridge.scripts == []
    assert priv(bridged_panel, button, QPushButton).isEnabled()


def test_run_script_failure_is_shown_as_output_and_unlocks_the_button(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A bridge failure while running a script is shown in the output and status, and the run buttons are enabled again.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append((_SCRIPT, ToolError("boom")))
    _set_plain(bridged_panel, "_script_editor", _SCRIPT)
    run_button = priv(bridged_panel, "_run_script_btn", QPushButton)
    params_button = priv(bridged_panel, "_run_script_params_btn", QPushButton)
    params_button.setEnabled(False)

    method(bridged_panel, "_on_run_script")()
    assert not run_button.isEnabled()
    _settle(bridged_panel)

    assert run_button.isEnabled()
    assert params_button.isEnabled()
    assert priv(bridged_panel, "_script_output", QPlainTextEdit).toPlainText() == "Error: boom"
    assert _status(bridged_panel) == "Script failed: boom"


def test_script_error_handler_logs_the_failure(panel: GhidraPanel) -> None:
    """The script failure handler records one warning that carries the error text.

    Args:
        panel: Panel without a bridge.
    """
    with capture_logs() as logs:
        method(panel, "_on_script_error")(RuntimeError("engine stopped"))

    failures = _events(logs, "ghidra_script_failed")
    assert len(failures) == 1
    assert failures[0]["error"] == "engine stopped"
    assert priv(panel, "_script_output", QPlainTextEdit).toPlainText() == "Error: engine stopped"


@pytest.mark.parametrize(("result", "expected"), [(None, ""), ("", ""), (42, "42"), ("line one\nline two", "line one\nline two")])
def test_script_result_is_shown_as_text_and_unlocks_both_buttons(panel: GhidraPanel, result: object, expected: str) -> None:
    """A script result is shown as text (nothing for no result) and both run buttons are enabled again.

    Args:
        panel: Panel without a bridge.
        result: Result handed to the handler.
        expected: Output text the result must produce.
    """
    run_button = priv(panel, "_run_script_btn", QPushButton)
    params_button = priv(panel, "_run_script_params_btn", QPushButton)
    run_button.setEnabled(False)
    params_button.setEnabled(False)
    _set_plain(panel, "_script_output", "stale output")

    method(panel, "_apply_script_result")(result)

    assert run_button.isEnabled()
    assert params_button.isEnabled()
    assert priv(panel, "_script_output", QPlainTextEdit).toPlainText() == expected
    assert _status(panel) == "Script executed"


@pytest.mark.parametrize("params_text", ['{"depth": 3, "name": "main"}', ' {"depth": 3, "name": "main"} '], ids=["tight", "padded"])
def test_run_script_with_params_injects_the_json_params_and_shows_the_output(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    params_text: str,
) -> None:
    """Running with parameters sends the script after the injected params, locks only its own button, and shows the reply as output.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        params_text: Text typed into the params field.
    """
    bridge.exec_replies.append((_SCRIPT, "result text"))
    _set_plain(bridged_panel, "_script_editor", _SCRIPT)
    _set_text(bridged_panel, "_script_params_input", params_text)
    run_button = priv(bridged_panel, "_run_script_btn", QPushButton)
    params_button = priv(bridged_panel, "_run_script_params_btn", QPushButton)

    method(bridged_panel, "_on_run_script_with_params")()

    assert not params_button.isEnabled()
    assert run_button.isEnabled()
    _settle(bridged_panel)

    expected_literal = json.dumps(json.dumps({"depth": 3, "name": "main"}))
    assert len(bridge.scripts) == 1
    assert bridge.scripts[0].startswith(f"import json as _json\nparams = _json.loads({expected_literal})\n")
    assert bridge.scripts[0].endswith(_SCRIPT)
    assert params_button.isEnabled()
    assert priv(bridged_panel, "_script_output", QPlainTextEdit).toPlainText() == "result text"
    assert _status(bridged_panel) == "Script executed"


@pytest.mark.parametrize("params_text", ["", "   "], ids=["empty", "spaces"])
def test_run_script_with_blank_params_injects_an_empty_object(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    params_text: str,
) -> None:
    """Blank params are sent as an empty JSON object.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        params_text: Text typed into the params field.
    """
    bridge.exec_replies.append((_SCRIPT, 42))
    _set_plain(bridged_panel, "_script_editor", _SCRIPT)
    _set_text(bridged_panel, "_script_params_input", params_text)

    method(bridged_panel, "_on_run_script_with_params")()
    _settle(bridged_panel)

    assert len(bridge.scripts) == 1
    assert bridge.scripts[0].startswith(f"import json as _json\nparams = _json.loads({json.dumps('{}')})\n")
    assert priv(bridged_panel, "_script_output", QPlainTextEdit).toPlainText() == "42"


@pytest.mark.parametrize("params_text", ["not json", '{"depth": ', '  {"depth": 1,  '], ids=["word", "truncated", "padded"])
def test_run_script_with_malformed_params_is_reported_without_dispatching(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    params_text: str,
) -> None:
    """Malformed JSON params are reported with the parser's message, logged, and nothing is sent; the button stays enabled.

    The field's text is stripped before parsing, so the expected error comes from the standard library parsing the stripped text.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        params_text: Text typed into the params field.
    """
    stripped = params_text.strip()
    error = _json_error(stripped)
    _set_plain(bridged_panel, "_script_editor", _SCRIPT)
    _set_text(bridged_panel, "_script_params_input", params_text)

    with capture_logs() as logs:
        method(bridged_panel, "_on_run_script_with_params")()
    _settle(bridged_panel)

    parser_text = f"{error.msg}: line {error.lineno} column {error.colno} (char {error.pos})"
    assert _status(bridged_panel) == f"Invalid JSON params: {parser_text}"
    assert bridge.scripts == []
    assert priv(bridged_panel, "_run_script_params_btn", QPushButton).isEnabled()
    warnings = _events(logs, "ghidra_run_script_invalid_json_params")
    assert len(warnings) == 1
    assert warnings[0]["input_text"] == stripped
    assert warnings[0]["error"] == parser_text


def test_run_script_with_params_failure_is_shown_as_output(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A bridge failure while running with params is shown in the output and status, and the button is enabled again.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append((_SCRIPT, ToolError("boom")))
    _set_plain(bridged_panel, "_script_editor", _SCRIPT)
    _set_text(bridged_panel, "_script_params_input", '{"a": 1}')

    method(bridged_panel, "_on_run_script_with_params")()
    _settle(bridged_panel)

    assert priv(bridged_panel, "_run_script_params_btn", QPushButton).isEnabled()
    assert priv(bridged_panel, "_script_output", QPlainTextEdit).toPlainText() == "Error: boom"
    assert _status(bridged_panel) == "Script failed: boom"


@pytest.mark.parametrize("params_text", ["null", "7"], ids=["null", "number"])
def test_run_script_with_params_that_are_not_an_object_does_not_break_the_slot_or_lock_the_button(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    params_text: str,
) -> None:
    """Valid JSON that is not an object is handled without an exception and leaves the params button usable.

    The params are documented as a JSON object (the field's placeholder is an object and the bridge takes a dictionary). The analyzer
    options field of the same tab rejects non-objects with a message; this field must not let a stray ``null`` or number raise out of
    the slot after it has already locked its button.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        params_text: Text typed into the params field.
    """
    bridge.exec_replies.append((_SCRIPT, 42))
    _set_plain(bridged_panel, "_script_editor", _SCRIPT)
    _set_text(bridged_panel, "_script_params_input", params_text)

    method(bridged_panel, "_on_run_script_with_params")()
    _settle(bridged_panel)

    assert priv(bridged_panel, "_run_script_params_btn", QPushButton).isEnabled()


@pytest.mark.parametrize(
    ("simplification", "literal"),
    [("  normalize  ", '"normalize"'), ("", "None"), ("   ", "None")],
    ids=["style", "blank", "spaces"],
)
def test_apply_decompiler_options_sends_the_style_and_instruction_limit(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    simplification: str,
    literal: str,
) -> None:
    """Applying sends the stripped simplification style (or none) and the spin box value, which the bridge stores.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        simplification: Text typed into the style field.
        literal: Jython literal the bridge must write for the style.
    """
    bridge.exec_replies.append(("DecompInterface", {"success": True, "extra": {}}))
    _set_text(bridged_panel, "_decomp_simplification_input", simplification)
    priv(bridged_panel, "_decomp_max_inst_spin", QSpinBox).setValue(1234)

    method(bridged_panel, "_on_apply_decompiler_options")()
    _settle(bridged_panel)

    assert len(bridge.scripts) == 1
    assert f"simp = {literal}" in bridge.scripts[0]
    assert "max_instr = 1234" in bridge.scripts[0]
    stored = "normalize" if literal != "None" else None
    assert bridge.decompiler_options == {"simplification": stored, "max_instructions": 1234, "extra": {}}
    assert _status(bridged_panel) == "Decompiler options applied"


def test_apply_decompiler_options_failure_is_reported(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A bridge failure while applying decompiler options is shown in the status label.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append(("DecompInterface", ToolError("boom")))

    method(bridged_panel, "_on_apply_decompiler_options")()
    _settle(bridged_panel)

    assert _status(bridged_panel) == "Decompiler options failed: boom"


@pytest.mark.parametrize("name", ["", "   "])
def test_configure_analysis_requires_an_analyzer_name(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge, name: str) -> None:
    """A blank analyzer name is reported and nothing is sent to the bridge.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        name: Text typed into the analyzer name field.
    """
    _set_text(bridged_panel, "_analyzer_name_input", name)
    _set_plain(bridged_panel, "_analyzer_options_input", '{"a": 1}')

    method(bridged_panel, "_on_configure_analysis")()
    _settle(bridged_panel)

    assert _status(bridged_panel) == "Analyzer name required"
    assert bridge.scripts == []


@pytest.mark.parametrize(
    ("enabled", "options_text", "options", "keys_text"),
    [
        (True, "", {}, "[]"),
        (False, "  \n ", {}, "[]"),
        (True, '{"aggressive": true, "timeout_s": 120}', {"aggressive": True, "timeout_s": 120}, "['aggressive', 'timeout_s']"),
    ],
    ids=["enabled_no_options", "disabled_blank_options", "enabled_with_options"],
)
def test_configure_analysis_sends_the_name_flag_and_options(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    *,
    enabled: bool,
    options_text: str,
    options: dict[str, object],
    keys_text: str,
) -> None:
    """Configuring sends the stripped analyzer name, the checkbox state and the parsed options, and reports what was configured.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        enabled: State of the Enabled checkbox.
        options_text: Text typed into the options editor.
        options: The options the text parses to.
        keys_text: How the status text must list the option names.
    """
    bridge.exec_replies.append(("AutoAnalysisManager", {"analyzer": "Decompiler Parameter ID", "enabled": enabled, "success": True}))
    _set_text(bridged_panel, "_analyzer_name_input", "  Decompiler Parameter ID  ")
    priv(bridged_panel, "_analyzer_enabled_check", QCheckBox).setChecked(enabled)
    _set_plain(bridged_panel, "_analyzer_options_input", options_text)

    method(bridged_panel, "_on_configure_analysis")()
    _settle(bridged_panel)

    assert len(bridge.scripts) == 1
    assert 'analyzer_name = "Decompiler Parameter ID"' in bridge.scripts[0]
    assert f"analyzer.setEnabled({enabled})" in bridge.scripts[0]
    assert f"_json.loads({json.dumps(json.dumps(options))})" in bridge.scripts[0]
    assert _status(bridged_panel) == f"Analyzer 'Decompiler Parameter ID' configured (enabled={enabled}, options_keys={keys_text})"


@pytest.mark.parametrize(
    "options_text",
    ["not json", '{"aggressive": ', '\n  {"aggressive": true,\n  '],
    ids=["word", "truncated", "padded"],
)
def test_configure_analysis_with_malformed_options_is_reported_without_dispatching(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    options_text: str,
) -> None:
    """Malformed JSON options are reported with the parser's message and position, logged, and nothing is sent.

    The editor's text is stripped before parsing, so the expected error comes from the standard library parsing the stripped text.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        options_text: Text typed into the options editor.
    """
    stripped = options_text.strip()
    error = _json_error(stripped)
    _set_text(bridged_panel, "_analyzer_name_input", "Decompiler Parameter ID")
    _set_plain(bridged_panel, "_analyzer_options_input", options_text)

    with capture_logs() as logs:
        method(bridged_panel, "_on_configure_analysis")()
    _settle(bridged_panel)

    assert _status(bridged_panel) == f"Analyzer options JSON error: {error.msg} (line {error.lineno}, col {error.colno})"
    assert bridge.scripts == []
    warnings = _events(logs, "ghidra_configure_analysis_invalid_json")
    assert len(warnings) == 1
    assert warnings[0]["input_text"] == stripped
    assert warnings[0]["error"] == f"{error.msg}: line {error.lineno} column {error.colno} (char {error.pos})"
    assert warnings[0]["line"] == error.lineno
    assert warnings[0]["column"] == error.colno


@pytest.mark.parametrize("options_text", ["[1, 2]", '"text"', "7", "null", "true"], ids=["list", "string", "number", "null", "bool"])
def test_configure_analysis_rejects_options_that_are_not_an_object(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    options_text: str,
) -> None:
    """Valid JSON that is not an object is reported and nothing is sent to the bridge.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        options_text: Text typed into the options editor.
    """
    _set_text(bridged_panel, "_analyzer_name_input", "Decompiler Parameter ID")
    _set_plain(bridged_panel, "_analyzer_options_input", options_text)

    method(bridged_panel, "_on_configure_analysis")()
    _settle(bridged_panel)

    assert _status(bridged_panel) == "Analyzer options must be a JSON object"
    assert bridge.scripts == []


def test_configure_analysis_failure_is_reported(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A bridge failure while configuring an analyzer is shown in the status label.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append(("AutoAnalysisManager", ToolError("boom")))
    _set_text(bridged_panel, "_analyzer_name_input", "Decompiler Parameter ID")

    method(bridged_panel, "_on_configure_analysis")()
    _settle(bridged_panel)

    status = _status(bridged_panel)
    assert status.startswith("Configure analysis failed:")
    assert status.endswith("boom")


def test_comments_table_shows_each_comment_and_replaces_stale_rows(panel: GhidraPanel) -> None:
    """Comments fill the table with hex address, type and text, replace stale rows, and leave repainting enabled.

    Args:
        panel: Panel without a bridge.
    """
    table = _table(panel, "_comments_table")
    table.setRowCount(4)

    method(panel, "_apply_comments")(_COMMENT_REPLY)

    assert _rows(table) == [
        ["0x140001000", "EOL", "entry point"],
        ["0x140001010", "PLATE", "first line\nsecond line"],
    ]
    assert table.updatesEnabled()


@pytest.mark.parametrize("result", [None, [], {"address": 1}], ids=["none", "empty_list", "dict"])
def test_comments_table_without_a_list_is_cleared(panel: GhidraPanel, result: object) -> None:
    """A result that is not a non-empty list leaves the comments table empty instead of keeping the previous rows.

    Args:
        panel: Panel without a bridge.
        result: Result handed to the handler.
    """
    table = _table(panel, "_comments_table")
    table.setRowCount(2)

    method(panel, "_apply_comments")(result)

    assert table.rowCount() == 0
    assert table.updatesEnabled()


def test_comments_table_fills_missing_fields_with_defaults(panel: GhidraPanel) -> None:
    """A comment record without any field shows the address zero and empty cells.

    Args:
        panel: Panel without a bridge.
    """
    method(panel, "_apply_comments")([{}])

    assert _rows(_table(panel, "_comments_table")) == [["0x0", "", ""]]


def test_load_all_comments_fills_the_table_from_the_bridge_reply(bridged_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Loading every comment shows the bridge's comment records in the table and reports their count.

    Args:
        bridged_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.exec_replies.append(("getCodeUnits(True)", _COMMENT_REPLY))
    button = priv(bridged_panel, "_load_all_cmt_btn", QPushButton)

    method(bridged_panel, "_on_load_all_comments")()
    _settle(bridged_panel)

    assert _rows(_table(bridged_panel, "_comments_table")) == [
        ["0x140001000", "EOL", "entry point"],
        ["0x140001010", "PLATE", "first line\nsecond line"],
    ]
    assert _status(bridged_panel) == "Loaded 2 comments"
    assert button.isEnabled()
