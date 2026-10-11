# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the bridge guards, connection lifecycle, data-type, headless and result handlers of the Ghidra panel.

Every test drives a real ``GhidraPanel`` by calling the slots its buttons trigger. Where a handler needs a connected bridge, the panel holds
``ScriptedGhidraBridge``, a subclass of the real ``GhidraBridge`` that replaces only the remote-execution transport: the Jython source the
production code builds is recorded and answered from a script, while every method above the transport (argument validation, payload parsing,
error wrapping, state handling) is the production code. The bridge is attached to a genuine, never-connected ``ghidra_bridge`` RPC client
through the bridge's own ``attach_remote_bridge`` seam. Failures the real bridge raises by itself (a missing file, a missing Ghidra
installation, a malformed hex token) travel through the real worker thread back to the panel. Result handlers are fed the real result types
(``DataTypeInfo``, ``DisassemblyLine``, ``FunctionInfo``) and the payload dictionaries the bridge returns, and the expected widget text is
written out by hand. Qt's static file dialogs are replaced with plain functions that return a chosen path, so no modal dialog ever opens.
"""

from __future__ import annotations

import asyncio
import importlib
import socket
from typing import TYPE_CHECKING, Final, cast, override

import pytest
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
)

from intellicrack.bridges.base import DisassemblyLine
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import DataTypeInfo, FunctionInfo, ToolError
from intellicrack.ui.panels.async_bridge import drain_bridge_workers_for
from intellicrack.ui.panels.ghidra_panel import GhidraPanel
from intellicrack.ui.panels.graph_view import CFGGraphView


if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")

_WAIT_MS: Final[int] = 20_000
_ADDR: Final[int] = 0x401000
_ADDR_TEXT: Final[str] = "0x401000"
_NO_BRIDGE: Final[str] = "No bridge configured"
_NOT_CONNECTED: Final[str] = "Ghidra not connected"
_HEADLESS_MISSING: Final[str] = "Ghidra headless script not found for this platform: "
_SCRIPTING_TAB: Final[int] = 11

_ARMED_INPUTS: Final[tuple[tuple[str, str], ...]] = (
    ("_dt_get_addr_input", _ADDR_TEXT),
    ("_dt_set_addr_input", _ADDR_TEXT),
    ("_dt_type_input", "dword"),
    ("_byte_search_input", "48 8B"),
    ("_overlay_name_input", "ovl"),
    ("_goto_func_addr", _ADDR_TEXT),
)

_GUARDED_HANDLERS: Final[tuple[tuple[str, tuple[object, ...]], ...]] = (
    ("_on_get_data_type", ()),
    ("_on_set_data_type", ()),
    ("_on_analyze", ()),
    ("_on_undo", ()),
    ("_on_redo", ()),
    ("_on_search_bytes", ()),
    ("_on_import_debug_info", ()),
    ("_on_diff_programs", ()),
    ("_on_create_overlay_space", ()),
    ("_on_load_binary", ()),
    ("_on_refresh_functions", ()),
    ("_on_goto_function", ()),
    ("_on_cfg_block_clicked", (_ADDR,)),
    ("_load_function_at_address", (_ADDR,)),
)
_GUARDED_IDS: Final[tuple[str, ...]] = tuple(name for name, _ in _GUARDED_HANDLERS)

_SAMPLE_FUNCTION: Final[dict[str, object]] = {
    "name": "main",
    "address": _ADDR,
    "size": 32,
    "calling_convention": "__cdecl",
    "return_type": "int",
}
_SAMPLE_BLOCKS: Final[list[dict[str, object]]] = [
    {
        "start": 0x401000,
        "end": 0x40100F,
        "sources": [0x400FF0],
        "destinations": [0x401010, 0x401020],
        "destination_edges": [
            {"address": 0x401010, "is_conditional": True, "is_fallthrough": False, "is_call": False},
            {"address": 0x401020, "is_conditional": False, "is_fallthrough": True, "is_call": False},
        ],
    },
    {"start": 0x401010, "end": 0x40101F, "sources": [], "destinations": [], "destination_edges": []},
]


class ScriptedGhidraBridge(GhidraBridge):
    """Real ``GhidraBridge`` whose remote-execution transport answers from a script.

    Only the two methods that cross the process boundary to Ghidra are replaced. Each records the Jython source or expression the
    production code built and returns (or raises) the scripted reply whose marker occurs in it. A source with no matching rule raises a
    ``ToolError``, exactly as an unreachable peer would. Every caller above these two methods is the production code under test.
    """

    def __init__(self) -> None:
        """Create the bridge with no scripted replies and no recorded traffic."""
        super().__init__()
        self.rules: list[tuple[str, object]] = []
        self.eval_replies: dict[str, list[object]] = {}
        self.scripts: list[str] = []
        self.expressions: list[str] = []

    @override
    async def _execute_remote(self, code: str) -> object:
        """Record the remote source and return the scripted reply for it.

        Args:
            code: Jython source built by the production code.

        Returns:
            object: The reply of the first rule whose marker occurs in ``code``.

        Raises:
            ToolError: When the matching reply is an error, or when no rule matches.
        """
        await asyncio.sleep(0)
        self.scripts.append(code)
        for marker, reply in self.rules:
            if marker in code:
                if isinstance(reply, ToolError):
                    raise ToolError(reply.message)
                return reply
        msg = "no scripted reply for this remote script"
        raise ToolError(msg)

    @override
    async def _execute_remote_eval(self, expression: str) -> object:
        """Record the remote expression and return the next scripted value for it.

        Args:
            expression: Jython expression built by the production code.

        Returns:
            object: The next queued value for ``expression``; the last value repeats once the queue is down to one entry.

        Raises:
            ToolError: When the value is an error, or when nothing is scripted for ``expression``.
        """
        await asyncio.sleep(0)
        self.expressions.append(expression)
        queue = self.eval_replies.get(expression)
        if not queue:
            msg = "no scripted value for this remote expression"
            raise ToolError(msg)
        value = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(value, ToolError):
            raise ToolError(value.message)
        return value


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


def set_priv(obj: object, name: str, value: object) -> None:
    """Assign a private data attribute on a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.
        value: Value to store.
    """
    setattr(obj, name, value)


def method(obj: object, name: str) -> Callable[..., object]:
    """Look up a (possibly private) method by name.

    Args:
        obj: Object that owns the method.
        name: Method name.

    Returns:
        Callable[..., object]: The bound method.
    """
    return cast("Callable[..., object]", getattr(obj, name))


def status(panel: GhidraPanel) -> str:
    """Read the text of the panel's status label.

    Args:
        panel: Panel whose status label is read.

    Returns:
        str: The current status text.
    """
    label = panel.status_label
    assert label is not None
    return label.text()


def set_text(panel: GhidraPanel, name: str, text: str) -> None:
    """Type text into a line edit of the panel.

    Args:
        panel: Panel that owns the line edit.
        name: Attribute name of the line edit.
        text: Text to enter.
    """
    priv(panel, name, QLineEdit).setText(text)


def plain(panel: GhidraPanel, name: str) -> str:
    """Read the text of a plain-text view of the panel.

    Args:
        panel: Panel that owns the view.
        name: Attribute name of the view.

    Returns:
        str: The view's current text.
    """
    return priv(panel, name, QPlainTextEdit).toPlainText()


def button(panel: GhidraPanel, name: str) -> QPushButton:
    """Look up a push button of the panel.

    Args:
        panel: Panel that owns the button.
        name: Attribute name of the button.

    Returns:
        QPushButton: The button.
    """
    return priv(panel, name, QPushButton)


def action(panel: GhidraPanel, name: str) -> QAction:
    """Look up a menu action of the panel.

    Args:
        panel: Panel that owns the action.
        name: Attribute name of the action.

    Returns:
        QAction: The action.
    """
    return priv(panel, name, QAction)


def cells(table: QTableWidget) -> list[list[str]]:
    """Read every row of a table.

    Args:
        table: Table to read.

    Returns:
        list[list[str]]: The cell texts of every row, top to bottom.
    """
    rows: list[list[str]] = []
    for row in range(table.rowCount()):
        texts: list[str] = []
        for column in range(table.columnCount()):
            item = table.item(row, column)
            assert item is not None
            texts.append(item.text())
        rows.append(texts)
    return rows


def tree_rows(tree: QTreeWidget) -> list[list[str]]:
    """Read every top-level row of a tree.

    Args:
        tree: Tree to read.

    Returns:
        list[list[str]]: The column texts of every top-level item, top to bottom.
    """
    rows: list[list[str]] = []
    for index in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(index)
        assert item is not None
        rows.append([item.text(column) for column in range(tree.columnCount())])
    return rows


def settle(panel: GhidraPanel) -> None:
    """Join the panel's bridge workers and deliver their results, following chained requests.

    Args:
        panel: Panel whose workers are joined.
    """
    for _ in range(4):
        drain_bridge_workers_for(panel, timeout_ms=_WAIT_MS)
        QApplication.processEvents()


def arm_inputs(panel: GhidraPanel) -> None:
    """Fill every input a guarded handler would read, so a skipped guard would go on to use the bridge.

    Args:
        panel: Panel whose inputs are filled.
    """
    for name, text in _ARMED_INPUTS:
        set_text(panel, name, text)


def graph_blocks(panel: GhidraPanel) -> set[int]:
    """Read the start addresses of the blocks drawn in the panel's CFG graph.

    Args:
        panel: Panel whose CFG view is read.

    Returns:
        set[int]: The block start addresses held by the graph scene.
    """
    view = priv(panel, "_cfg_view", QWidget)
    assert isinstance(view, CFGGraphView)
    return set(view.graph_scene().block_items)


def single_file(path: Path) -> Callable[..., tuple[str, str]]:
    """Build a replacement for ``QFileDialog.getOpenFileName`` that picks one file.

    Args:
        path: File the replacement reports as chosen.

    Returns:
        Callable[..., tuple[str, str]]: A plain function with the static dialog's result shape.
    """

    def choose(*_args: object, **_kwargs: object) -> tuple[str, str]:
        """Report the chosen file without opening a dialog.

        Args:
            *_args: Positional arguments passed by the caller (ignored).
            **_kwargs: Keyword arguments passed by the caller (ignored).

        Returns:
            tuple[str, str]: The chosen path and an empty selected filter.
        """
        return (str(path), "")

    return choose


def many_files(paths: list[Path]) -> Callable[..., tuple[list[str], str]]:
    """Build a replacement for ``QFileDialog.getOpenFileNames`` that picks several files.

    Args:
        paths: Files the replacement reports as chosen.

    Returns:
        Callable[..., tuple[list[str], str]]: A plain function with the static dialog's result shape.
    """

    def choose(*_args: object, **_kwargs: object) -> tuple[list[str], str]:
        """Report the chosen files without opening a dialog.

        Args:
            *_args: Positional arguments passed by the caller (ignored).
            **_kwargs: Keyword arguments passed by the caller (ignored).

        Returns:
            tuple[list[str], str]: The chosen paths and an empty selected filter.
        """
        return ([str(path) for path in paths], "")

    return choose


def directory(path: Path) -> Callable[..., str]:
    """Build a replacement for ``QFileDialog.getExistingDirectory`` that picks one directory.

    Args:
        path: Directory the replacement reports as chosen.

    Returns:
        Callable[..., str]: A plain function with the static dialog's result shape.
    """

    def choose(*_args: object, **_kwargs: object) -> str:
        """Report the chosen directory without opening a dialog.

        Args:
            *_args: Positional arguments passed by the caller (ignored).
            **_kwargs: Keyword arguments passed by the caller (ignored).

        Returns:
            str: The chosen directory.
        """
        return str(path)

    return choose


def reserve_port() -> int:
    """Reserve an ephemeral loopback TCP port and release it immediately.

    Returns:
        int: A port that nothing listens on at the moment of the call.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


@pytest.fixture
def panel(qtbot: QtBot) -> Generator[GhidraPanel]:
    """Provide a Ghidra panel without a bridge.

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
def rpc_client() -> Generator[object]:
    """Provide a genuine ``ghidra_bridge`` RPC client that never connects.

    The upstream client is lazy: building it with no namespace never touches the network, and the scripted bridge never sends through it.

    Yields:
        object: The RPC client instance.
    """
    module = importlib.import_module("ghidra_bridge")
    factory = cast("Callable[..., object]", getattr(module, "GhidraBridge"))
    client = factory(namespace=None, connect_to_host="127.0.0.1", connect_to_port=reserve_port(), response_timeout=5)
    try:
        yield client
    finally:
        method(GhidraBridge, "_close_bridge_client")(client)


@pytest.fixture
def bridge(rpc_client: object) -> Generator[ScriptedGhidraBridge]:
    """Provide a scripted bridge that is attached to the RPC client and therefore ready.

    Args:
        rpc_client: Genuine RPC client that never connects.

    Yields:
        ScriptedGhidraBridge: A ready bridge with no scripted replies.
    """
    instance = ScriptedGhidraBridge()
    instance.attach_remote_bridge(rpc_client)
    try:
        yield instance
    finally:
        asyncio.run(instance.shutdown())


@pytest.fixture
def idle_bridge() -> ScriptedGhidraBridge:
    """Provide a scripted bridge that was never connected.

    Returns:
        ScriptedGhidraBridge: A bridge whose state is not ready.
    """
    return ScriptedGhidraBridge()


@pytest.fixture
def ready_panel(panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> Generator[GhidraPanel]:
    """Give the panel a ready bridge.

    Args:
        panel: Panel without a bridge.
        bridge: Ready scripted bridge.

    Yields:
        GhidraPanel: The same panel, now holding the ready bridge.
    """
    panel.set_bridge(bridge)
    try:
        yield panel
    finally:
        drain_bridge_workers_for(panel)


@pytest.fixture
def idle_panel(panel: GhidraPanel, idle_bridge: ScriptedGhidraBridge) -> GhidraPanel:
    """Give the panel a bridge that is not connected.

    Args:
        panel: Panel without a bridge.
        idle_bridge: Scripted bridge that was never connected.

    Returns:
        GhidraPanel: The same panel, now holding the idle bridge.
    """
    panel.set_bridge(idle_bridge)
    return panel


def test_bridge_getter_returns_the_attached_bridge(panel: GhidraPanel, idle_bridge: ScriptedGhidraBridge) -> None:
    """The getter reports no bridge before one is set and the very same bridge afterwards.

    Args:
        panel: Panel without a bridge.
        idle_bridge: Bridge to attach.
    """
    assert panel.get_bridge() is None

    panel.set_bridge(idle_bridge)

    assert panel.get_bridge() is idle_bridge


def test_set_ghidra_path_stores_the_path_on_the_bridge(idle_panel: GhidraPanel, idle_bridge: ScriptedGhidraBridge, tmp_path: Path) -> None:
    """Setting the installation path through the panel changes the path the bridge will launch Ghidra from.

    Args:
        idle_panel: Panel holding an idle bridge.
        idle_bridge: The bridge held by the panel.
        tmp_path: Directory used as the installation path.
    """
    assert idle_bridge.ghidra_path is None

    idle_panel.set_ghidra_path(tmp_path)

    assert idle_bridge.ghidra_path == tmp_path


def test_set_ghidra_path_without_a_bridge_changes_nothing(panel: GhidraPanel, tmp_path: Path) -> None:
    """Setting the installation path on a panel with no bridge is ignored instead of failing.

    Args:
        panel: Panel without a bridge.
        tmp_path: Directory offered as the installation path.
    """
    panel.set_ghidra_path(tmp_path)

    assert panel.get_bridge() is None


@pytest.mark.parametrize(
    ("builder", "attribute"),
    [
        ("_create_data_types_tab", "_data_type_manager"),
        ("_create_program_tree_tab", "_program_tree"),
        ("_create_analysis_extras_tab", "_analysis_extras"),
    ],
    ids=["data_types", "program_tree", "analysis_extras"],
)
def test_tab_built_after_the_bridge_is_set_hands_it_to_its_widget(
    idle_panel: GhidraPanel,
    idle_bridge: ScriptedGhidraBridge,
    builder: str,
    attribute: str,
) -> None:
    """A tab built while the panel already has a bridge gives that bridge to the widget it hosts.

    The widget of a freshly built tab starts with no bridge, so only the tab builder's own hand-over can make it hold the panel's bridge.

    Args:
        idle_panel: Panel holding an idle bridge.
        idle_bridge: The bridge held by the panel.
        builder: Name of the tab builder under test.
        attribute: Attribute name under which the panel keeps the tab's widget.
    """
    container = method(idle_panel, builder)()

    assert isinstance(container, QWidget)
    widget = priv(idle_panel, attribute, QWidget)
    assert container.isAncestorOf(widget)
    assert priv(widget, "_bridge", object) is idle_bridge


@pytest.mark.parametrize(("handler", "args"), _GUARDED_HANDLERS, ids=_GUARDED_IDS)
def test_handler_without_a_bridge_reports_that_none_is_configured(panel: GhidraPanel, handler: str, args: tuple[object, ...]) -> None:
    """With no bridge set, a bridge-backed slot stops at the connection guard and says so on the status label.

    Every input is filled in, so a slot that skipped its guard would go on to use ``None`` as a bridge.

    Args:
        panel: Panel without a bridge.
        handler: Name of the panel slot under test.
        args: Positional arguments the slot takes.
    """
    arm_inputs(panel)

    method(panel, handler)(*args)
    settle(panel)

    assert status(panel) == _NO_BRIDGE
    assert panel.get_bridge() is None


@pytest.mark.parametrize(("handler", "args"), _GUARDED_HANDLERS, ids=_GUARDED_IDS)
def test_handler_with_an_unconnected_bridge_reports_that_ghidra_is_not_connected(
    idle_panel: GhidraPanel,
    idle_bridge: ScriptedGhidraBridge,
    handler: str,
    args: tuple[object, ...],
) -> None:
    """With a bridge that is not connected, a bridge-backed slot stops at the connection guard without sending anything.

    Args:
        idle_panel: Panel holding an idle bridge.
        idle_bridge: The bridge held by the panel.
        handler: Name of the panel slot under test.
        args: Positional arguments the slot takes.
    """
    arm_inputs(idle_panel)

    method(idle_panel, handler)(*args)
    settle(idle_panel)

    assert status(idle_panel) == _NOT_CONNECTED
    assert idle_bridge.scripts == []


@pytest.mark.parametrize("handler", ["_on_connect", "_on_start_headless", "_on_run_headless_batch"])
def test_lifecycle_handler_without_a_bridge_reports_that_none_is_configured(panel: GhidraPanel, handler: str) -> None:
    """Connecting, starting headless Ghidra and running a batch all refuse to start when the panel has no bridge.

    Args:
        panel: Panel without a bridge.
        handler: Name of the panel slot under test.
    """
    method(panel, handler)()
    settle(panel)

    assert status(panel) == _NO_BRIDGE
    assert button(panel, "_connect_btn").isEnabled()
    assert button(panel, "_headless_btn").isEnabled()
    assert action(panel, "_headless_batch_btn").isEnabled()


def test_disconnect_without_a_bridge_does_nothing(panel: GhidraPanel) -> None:
    """Disconnecting a panel that has no bridge leaves the status label alone.

    Args:
        panel: Panel without a bridge.
    """
    before = status(panel)

    method(panel, "_on_disconnect")()
    settle(panel)

    assert status(panel) == before


def test_get_data_type_with_a_blank_address_sends_nothing(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A blank address returns before any request is built and leaves the result view empty.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    set_text(ready_panel, "_dt_get_addr_input", "   ")

    method(ready_panel, "_on_get_data_type")()
    settle(ready_panel)

    assert bridge.scripts == []
    assert not plain(ready_panel, "_dt_result_view")
    assert button(ready_panel, "_dt_get_btn").isEnabled()


@pytest.mark.parametrize("text", ["zz", "0xzz", "1.5"])
def test_get_data_type_rejects_an_unparsable_address(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge, text: str) -> None:
    """An address that is neither a decimal number nor a hexadecimal number is reported in the result view and nothing is sent.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
        text: Address text typed into the input.
    """
    set_text(ready_panel, "_dt_get_addr_input", text)

    method(ready_panel, "_on_get_data_type")()
    settle(ready_panel)

    assert plain(ready_panel, "_dt_result_view") == "Invalid address"
    assert bridge.scripts == []
    assert button(ready_panel, "_dt_get_btn").isEnabled()


@pytest.mark.parametrize("text", ["0x401000", "0X401000", "4198400"])
def test_get_data_type_looks_up_the_parsed_address_and_shows_the_type(
    ready_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    text: str,
) -> None:
    """Hex with either prefix case and plain decimal text reach the bridge as the same number, and the answer fills the result view.

    The button stays disabled while the request is in flight and is enabled again once the result is delivered.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
        text: Address text typed into the input.
    """
    bridge.rules = [
        (
            "_dt_payload",
            {
                "address": _ADDR,
                "name": "dword",
                "category": "/",
                "size": 4,
                "is_pointer": False,
                "is_array": False,
                "array_length": None,
                "base_type": None,
            },
        ),
    ]
    set_text(ready_panel, "_dt_get_addr_input", text)

    method(ready_panel, "_on_get_data_type")()

    assert not button(ready_panel, "_dt_get_btn").isEnabled()
    settle(ready_panel)
    assert len(bridge.scripts) == 1
    assert f"toAddr({_ADDR})" in bridge.scripts[0]
    assert plain(ready_panel, "_dt_result_view") == "Name: dword\nCategory: /\nSize: 4"
    assert button(ready_panel, "_dt_get_btn").isEnabled()


def test_get_data_type_reports_an_address_without_a_defined_type(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """An address where Ghidra has no data defined produces the explicit "no data type" note.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    bridge.rules = [("_dt_payload", None)]
    set_text(ready_panel, "_dt_get_addr_input", _ADDR_TEXT)

    method(ready_panel, "_on_get_data_type")()
    settle(ready_panel)

    assert plain(ready_panel, "_dt_result_view") == "No data type defined at this address"
    assert button(ready_panel, "_dt_get_btn").isEnabled()


def test_get_data_type_shows_the_bridge_error_in_the_result_view(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A failed lookup is shown in the result view and the button is enabled again.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    bridge.rules = [("_dt_payload", ToolError("no program open"))]
    set_text(ready_panel, "_dt_get_addr_input", _ADDR_TEXT)

    method(ready_panel, "_on_get_data_type")()
    settle(ready_panel)

    assert plain(ready_panel, "_dt_result_view") == "Error: no program open"
    assert button(ready_panel, "_dt_get_btn").isEnabled()


@pytest.mark.parametrize(
    ("info", "expected"),
    [
        (
            DataTypeInfo(
                address=_ADDR,
                name="dword",
                category="/",
                size=4,
                is_pointer=False,
                is_array=False,
                array_length=None,
                base_type=None,
            ),
            "Name: dword\nCategory: /\nSize: 4",
        ),
        (
            DataTypeInfo(
                address=_ADDR,
                name="",
                category="",
                size=0,
                is_pointer=False,
                is_array=False,
                array_length=None,
                base_type=None,
            ),
            "Size: 0",
        ),
    ],
    ids=["named", "unnamed_zero_size"],
)
def test_data_type_result_lists_only_the_fields_that_are_set(panel: GhidraPanel, info: DataTypeInfo, expected: str) -> None:
    """The result view lists name and category only when they are not empty, and always lists the size.

    Args:
        panel: Panel without a bridge.
        info: Data type the bridge reported.
        expected: Text the result view must show.
    """
    button(panel, "_dt_get_btn").setEnabled(False)

    method(panel, "_apply_get_data_type")(info)

    assert plain(panel, "_dt_result_view") == expected
    assert button(panel, "_dt_get_btn").isEnabled()


@pytest.mark.parametrize(
    ("address", "type_name"),
    [("", "dword"), (_ADDR_TEXT, ""), ("   ", "   ")],
    ids=["no_address", "no_type", "both_blank"],
)
def test_set_data_type_needs_both_an_address_and_a_type(
    ready_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    address: str,
    type_name: str,
) -> None:
    """Applying a type with either input blank returns without sending anything or changing the status.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
        address: Address text typed into the input.
        type_name: Type text typed into the input.
    """
    before = status(ready_panel)
    set_text(ready_panel, "_dt_set_addr_input", address)
    set_text(ready_panel, "_dt_type_input", type_name)

    method(ready_panel, "_on_set_data_type")()
    settle(ready_panel)

    assert bridge.scripts == []
    assert status(ready_panel) == before
    assert button(ready_panel, "_dt_set_btn").isEnabled()


def test_set_data_type_rejects_an_unparsable_address(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """An address that cannot be parsed is reported on the status label and nothing is sent.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    set_text(ready_panel, "_dt_set_addr_input", "zz")
    set_text(ready_panel, "_dt_type_input", "dword")

    method(ready_panel, "_on_set_data_type")()
    settle(ready_panel)

    assert status(ready_panel) == "Invalid address"
    assert bridge.scripts == []
    assert button(ready_panel, "_dt_set_btn").isEnabled()


@pytest.mark.parametrize(
    ("reply", "expected"),
    [(True, "Data type applied successfully"), (False, "Failed to apply data type")],
    ids=["applied", "refused"],
)
def test_set_data_type_reports_whether_ghidra_applied_the_type(
    ready_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    *,
    reply: bool,
    expected: str,
) -> None:
    """The type name and parsed address reach the bridge and its yes or no answer becomes the status text.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
        reply: Value Ghidra's remote script evaluates to.
        expected: Status text the answer must produce.
    """
    bridge.rules = [("listing.createData(addr, parsed)", reply)]
    set_text(ready_panel, "_dt_set_addr_input", _ADDR_TEXT)
    set_text(ready_panel, "_dt_type_input", "dword")

    method(ready_panel, "_on_set_data_type")()

    assert not button(ready_panel, "_dt_set_btn").isEnabled()
    settle(ready_panel)
    assert len(bridge.scripts) == 1
    assert f"toAddr({_ADDR})" in bridge.scripts[0]
    assert '_ic_resolve_data_type(dtm, "dword")' in bridge.scripts[0]
    assert status(ready_panel) == expected
    assert button(ready_panel, "_dt_set_btn").isEnabled()


def test_set_data_type_reports_the_bridge_error_on_the_status_label(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A failed assignment shows the bridge's wrapped error on the status label and enables the button again.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    bridge.rules = [("listing.createData(addr, parsed)", ToolError("transaction refused"))]
    set_text(ready_panel, "_dt_set_addr_input", _ADDR_TEXT)
    set_text(ready_panel, "_dt_type_input", "dword")

    method(ready_panel, "_on_set_data_type")()
    settle(ready_panel)

    assert status(ready_panel) == "Set data type error: Failed to set data type: transaction refused"
    assert button(ready_panel, "_dt_set_btn").isEnabled()


def test_connect_completion_with_a_ready_bridge_reports_connected(ready_panel: GhidraPanel) -> None:
    """A finished connection attempt on a ready bridge shows "Connected" and brings the toolbar in line with the bridge.

    Args:
        ready_panel: Panel holding a ready bridge.
    """
    button(ready_panel, "_disconnect_btn").setEnabled(False)
    button(ready_panel, "_connect_btn").setEnabled(True)

    method(ready_panel, "_on_connect_success")()

    assert status(ready_panel) == "Connected"
    assert button(ready_panel, "_disconnect_btn").isEnabled()
    assert not button(ready_panel, "_connect_btn").isEnabled()
    assert button(ready_panel, "_load_btn").isEnabled()
    assert button(ready_panel, "_analyze_btn").isEnabled()


@pytest.mark.parametrize(
    ("last_error", "expected"),
    [("port closed", "Connection failed: port closed"), (None, "Connection failed")],
    ids=["with_error", "without_error"],
)
def test_connect_completion_with_an_unready_bridge_reports_the_failure(
    idle_panel: GhidraPanel,
    idle_bridge: ScriptedGhidraBridge,
    last_error: str | None,
    expected: str,
) -> None:
    """A finished connection attempt on a bridge that is not ready reports the failure with the bridge's last error when it has one.

    Args:
        idle_panel: Panel holding an idle bridge.
        idle_bridge: The bridge held by the panel.
        last_error: Error text recorded on the bridge state.
        expected: Status text the failure must produce.
    """
    idle_bridge.state.last_error = last_error
    button(idle_panel, "_connect_btn").setEnabled(False)

    method(idle_panel, "_on_connect_success")()

    assert status(idle_panel) == expected
    assert button(idle_panel, "_connect_btn").isEnabled()
    assert not button(idle_panel, "_disconnect_btn").isEnabled()
    assert not button(idle_panel, "_load_btn").isEnabled()


def test_connect_completion_without_a_bridge_reports_the_failure(panel: GhidraPanel) -> None:
    """A finished connection attempt on a panel that has lost its bridge reports a plain failure.

    Args:
        panel: Panel without a bridge.
    """
    method(panel, "_on_connect_success")()

    assert status(panel) == "Connection failed"


def test_disconnect_shuts_the_bridge_down_and_resets_the_toolbar(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Disconnecting runs the bridge's real shutdown, then shows "Disconnected" and lets the toolbar offer Connect again.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    assert not button(ready_panel, "_connect_btn").isEnabled()

    method(ready_panel, "_on_disconnect")()

    assert not button(ready_panel, "_disconnect_btn").isEnabled()
    settle(ready_panel)
    assert status(ready_panel) == "Disconnected"
    assert not bridge.state.is_ready()
    assert button(ready_panel, "_connect_btn").isEnabled()
    assert not button(ready_panel, "_load_btn").isEnabled()
    assert not button(ready_panel, "_analyze_btn").isEnabled()


def test_disconnect_failure_is_reported_and_the_toolbar_follows_the_bridge(ready_panel: GhidraPanel) -> None:
    """A failed shutdown is shown on the status label and the toolbar is brought back in line with the bridge, which is still ready.

    Args:
        ready_panel: Panel holding a ready bridge.
    """
    button(ready_panel, "_disconnect_btn").setEnabled(False)

    method(ready_panel, "_on_disconnect_error")(RuntimeError("shutdown timed out"))

    assert status(ready_panel) == "Disconnect failed: shutdown timed out"
    assert button(ready_panel, "_disconnect_btn").isEnabled()


def test_load_binary_dialog_cancel_sends_nothing(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Cancelling the file dialog loads nothing and leaves the status label alone.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    before = status(ready_panel)

    method(ready_panel, "_on_load_binary")()
    settle(ready_panel)

    assert bridge.scripts == []
    assert status(ready_panel) == before
    assert button(ready_panel, "_load_btn").isEnabled()


def test_load_binary_imports_the_chosen_file_through_the_bridge(
    ready_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The file picked in the dialog is imported by the bridge and the panel reports it as loaded.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
        monkeypatch: Fixture used to replace the static file dialog.
        tmp_path: Directory that holds the chosen file.
    """
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"critcov sample bytes")
    bridge.rules = [
        ("importFile(_JFile(", {"imported": True, "name": sample.name}),
        ("getLanguage()", {"processor": "x86", "pointer_size": 8}),
        ("'extraction_errors'", {"entry_point": _ADDR, "sections": [], "imports": [], "exports": []}),
    ]
    monkeypatch.setattr(QFileDialog, "getOpenFileName", single_file(sample))

    method(ready_panel, "_on_load_binary")()

    assert not button(ready_panel, "_load_btn").isEnabled()
    settle(ready_panel)
    assert status(ready_panel) == "Loaded: sample.bin"
    assert button(ready_panel, "_load_btn").isEnabled()
    assert bridge.state.binary_loaded
    assert bridge.state.target_path == sample.resolve()


def test_load_binary_failure_reports_the_bridge_refusal(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge, tmp_path: Path) -> None:
    """Loading a file that does not exist is refused by the real bridge and the refusal reaches the status label.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
        tmp_path: Directory in which the missing file would live.
    """
    missing = tmp_path / "absent.bin"

    assert ready_panel.load_binary(missing) is True

    assert not button(ready_panel, "_load_btn").isEnabled()
    settle(ready_panel)
    assert status(ready_panel) == f"Load failed: File not found: {missing}"
    assert button(ready_panel, "_load_btn").isEnabled()
    assert not bridge.state.binary_loaded
    assert bridge.scripts == []


@pytest.mark.parametrize("timeout", ["abc", "ten seconds"])
def test_analyze_rejects_a_timeout_that_is_not_a_number(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge, timeout: str) -> None:
    """An analysis timeout that is not a number is reported with its text, the button is enabled again and nothing is sent.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
        timeout: Timeout text typed into the input.
    """
    set_text(ready_panel, "_analyze_timeout_input", timeout)

    method(ready_panel, "_on_analyze")()
    settle(ready_panel)

    assert status(ready_panel) == f"Invalid analysis timeout: {timeout!r}"
    assert button(ready_panel, "_analyze_btn").isEnabled()
    assert bridge.scripts == []
    assert bridge.expressions == []


def test_analysis_runs_on_the_bridge_and_refreshes_every_view(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A finished analysis reports completion and reloads the function list, the imports table and the exports table.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    bridge.rules = [
        ("_ic_run_analysis", None),
        ("getFunctionManager", [_SAMPLE_FUNCTION]),
        ("getExternalSymbols", [{"dll": "KERNEL32.dll", "function": "CreateFileW", "address": 0x2000}]),
        ("isExternalEntryPoint", [{"name": "Start", "address": _ADDR}]),
    ]
    bridge.eval_replies = {"_ic_analysis_done": [True], "_ic_analysis_error": [None]}
    set_text(ready_panel, "_analyze_timeout_input", "30")

    method(ready_panel, "_on_analyze")()

    assert status(ready_panel) == "Analyzing..."
    assert not button(ready_panel, "_analyze_btn").isEnabled()
    settle(ready_panel)
    assert status(ready_panel) == "Analysis complete"
    assert button(ready_panel, "_analyze_btn").isEnabled()
    assert tree_rows(priv(ready_panel, "_func_tree", QTreeWidget)) == [["main", "0x401000", "32"]]
    assert cells(priv(ready_panel, "_imports_table", QTableWidget)) == [["KERNEL32.dll", "CreateFileW", "0x2000"]]
    assert cells(priv(ready_panel, "_exports_table", QTableWidget)) == [["Start", "0", "0x401000"]]


def test_analysis_honors_the_typed_timeout(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """The timeout typed into the panel bounds how long the bridge waits for Ghidra's analysis to finish.

    Ghidra reports "not done" twice and then "done". With a quarter-second budget the real bridge gives up at the second poll and says so;
    a panel that ignored the typed value would let the bridge wait for the default budget and see the analysis complete.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    bridge.rules = [("_ic_run_analysis", None)]
    bridge.eval_replies = {"_ic_analysis_done": [False, False, True], "_ic_analysis_error": [None]}
    set_text(ready_panel, "_analyze_timeout_input", "0.25")

    method(ready_panel, "_on_analyze")()
    settle(ready_panel)

    assert status(ready_panel) == "Analysis failed: Ghidra analysis did not complete within 0s"
    assert button(ready_panel, "_analyze_btn").isEnabled()


def test_analysis_failure_is_reported_and_the_toolbar_is_resynchronized(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A refused analysis shows the bridge error and the analyze button is enabled again because the bridge is still ready.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    bridge.rules = [("_ic_run_analysis", ToolError("kickoff refused"))]

    method(ready_panel, "_on_analyze")()
    settle(ready_panel)

    assert status(ready_panel) == "Analysis failed: kickoff refused"
    assert button(ready_panel, "_analyze_btn").isEnabled()


def test_start_headless_without_an_installation_directory_does_nothing(idle_panel: GhidraPanel, idle_bridge: ScriptedGhidraBridge) -> None:
    """Cancelling the install-directory prompt leaves the bridge without a path and the start button usable.

    Args:
        idle_panel: Panel holding an idle bridge.
        idle_bridge: The bridge held by the panel.
    """
    before = status(idle_panel)

    method(idle_panel, "_on_start_headless")()
    settle(idle_panel)

    assert idle_bridge.ghidra_path is None
    assert status(idle_panel) == before
    assert button(idle_panel, "_headless_btn").isEnabled()


def test_start_headless_uses_the_directory_chosen_in_the_prompt(
    idle_panel: GhidraPanel,
    idle_bridge: ScriptedGhidraBridge,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The directory picked in the prompt becomes the bridge's installation path and the bridge's own refusal of it is reported.

    The picked directory holds no Ghidra installation, so the real bridge refuses before it creates a project or starts a process.

    Args:
        idle_panel: Panel holding an idle bridge.
        idle_bridge: The bridge held by the panel.
        monkeypatch: Fixture used to replace the static directory dialog.
        tmp_path: Directory picked as the installation path.
    """
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", directory(tmp_path))

    method(idle_panel, "_on_start_headless")()

    assert status(idle_panel) == "Starting headless Ghidra..."
    assert not button(idle_panel, "_headless_btn").isEnabled()
    settle(idle_panel)
    assert idle_bridge.ghidra_path == tmp_path
    assert status(idle_panel).startswith(f"Headless start failed: {_HEADLESS_MISSING}")
    assert str(tmp_path) in status(idle_panel)
    assert button(idle_panel, "_headless_btn").isEnabled()
    assert list(tmp_path.iterdir()) == []


def test_start_headless_does_not_ask_when_the_path_is_already_known(
    idle_panel: GhidraPanel,
    idle_bridge: ScriptedGhidraBridge,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """With an installation path already set, the prompt is not consulted and the known path is the one the bridge refuses.

    Args:
        idle_panel: Panel holding an idle bridge.
        idle_bridge: The bridge held by the panel.
        monkeypatch: Fixture used to replace the static directory dialog.
        tmp_path: Directory used as the installation path.
    """
    known = tmp_path / "known"
    known.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    idle_bridge.ghidra_path = known
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", directory(other))

    method(idle_panel, "_on_start_headless")()
    settle(idle_panel)

    assert idle_bridge.ghidra_path == known
    assert status(idle_panel).startswith(f"Headless start failed: {_HEADLESS_MISSING}")
    assert str(known) in status(idle_panel)
    assert str(other) not in status(idle_panel)


@pytest.mark.parametrize("with_project", [True, False], ids=["with_project", "without_project"])
def test_headless_start_completion_reports_the_project_and_resynchronizes_the_toolbar(
    idle_panel: GhidraPanel,
    idle_bridge: ScriptedGhidraBridge,
    tmp_path: Path,
    *,
    with_project: bool,
) -> None:
    """A finished headless start names the project when the bridge has one and enables the start button again.

    Args:
        idle_panel: Panel holding an idle bridge.
        idle_bridge: The bridge held by the panel.
        tmp_path: Directory used as the project path.
        with_project: Whether the bridge has an open project.
    """
    project = tmp_path / "intellicrack"
    if with_project:
        set_priv(idle_bridge, "_project_path", project)
    button(idle_panel, "_headless_btn").setEnabled(False)
    button(idle_panel, "_connect_btn").setEnabled(False)

    method(idle_panel, "_on_headless_started")()

    expected = f"Headless Ghidra started | Project: {project}" if with_project else "Headless Ghidra started"
    assert status(idle_panel) == expected
    assert button(idle_panel, "_headless_btn").isEnabled()
    assert button(idle_panel, "_connect_btn").isEnabled()


def test_headless_batch_without_an_installation_directory_does_nothing(idle_panel: GhidraPanel, idle_bridge: ScriptedGhidraBridge) -> None:
    """Cancelling the install-directory prompt abandons the batch before it asks for files.

    Args:
        idle_panel: Panel holding an idle bridge.
        idle_bridge: The bridge held by the panel.
    """
    before = status(idle_panel)

    method(idle_panel, "_on_run_headless_batch")()
    settle(idle_panel)

    assert idle_bridge.ghidra_path is None
    assert status(idle_panel) == before
    assert action(idle_panel, "_headless_batch_btn").isEnabled()


def test_headless_batch_without_files_does_nothing(idle_panel: GhidraPanel, idle_bridge: ScriptedGhidraBridge, tmp_path: Path) -> None:
    """Cancelling the file prompt abandons the batch and leaves its action enabled.

    Args:
        idle_panel: Panel holding an idle bridge.
        idle_bridge: The bridge held by the panel.
        tmp_path: Directory used as the installation path.
    """
    idle_bridge.ghidra_path = tmp_path
    before = status(idle_panel)

    method(idle_panel, "_on_run_headless_batch")()
    settle(idle_panel)

    assert status(idle_panel) == before
    assert action(idle_panel, "_headless_batch_btn").isEnabled()


def test_headless_batch_reports_the_bridge_refusal(
    idle_panel: GhidraPanel,
    idle_bridge: ScriptedGhidraBridge,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The directory and files picked in the prompts reach the real bridge, whose refusal of the empty installation is reported.

    Args:
        idle_panel: Panel holding an idle bridge.
        idle_bridge: The bridge held by the panel.
        monkeypatch: Fixture used to replace the static dialogs.
        tmp_path: Directory picked as the installation path.
    """
    target = tmp_path / "target.exe"
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", directory(tmp_path))
    monkeypatch.setattr(QFileDialog, "getOpenFileNames", many_files([target]))

    method(idle_panel, "_on_run_headless_batch")()

    assert status(idle_panel) == "Running headless batch..."
    assert not action(idle_panel, "_headless_batch_btn").isEnabled()
    settle(idle_panel)
    assert idle_bridge.ghidra_path == tmp_path
    assert status(idle_panel).startswith(f"Headless batch failed: {_HEADLESS_MISSING}")
    assert str(tmp_path) in status(idle_panel)
    assert action(idle_panel, "_headless_batch_btn").isEnabled()


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ({"project_dir": "p", "return_code": 0, "success": True}, "Headless batch complete (exit code 0)"),
        ("done", "Headless batch complete (exit code None)"),
    ],
    ids=["dict_result", "other_result"],
)
def test_headless_batch_completion_reports_the_exit_code(panel: GhidraPanel, result: object, expected: str) -> None:
    """A finished batch shows the exit code from the bridge's result dictionary and enables its action again.

    Args:
        panel: Panel without a bridge.
        result: Result handed to the handler.
        expected: Status text the result must produce.
    """
    action(panel, "_headless_batch_btn").setEnabled(False)

    method(panel, "_on_headless_batch_complete")(result)

    assert status(panel) == expected
    assert action(panel, "_headless_batch_btn").isEnabled()


@pytest.mark.parametrize(
    ("handler", "marker", "done", "failed"),
    [
        ("_on_undo", "currentProgram.undo()", "Undo complete", "Undo failed: Undo failed: boom"),
        ("_on_redo", "currentProgram.redo()", "Redo complete", "Redo failed: Redo failed: boom"),
    ],
    ids=["undo", "redo"],
)
def test_undo_and_redo_send_their_own_command_and_report_the_outcome(
    ready_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    handler: str,
    marker: str,
    done: str,
    failed: str,
) -> None:
    """Undo and redo each send their own one-line command to Ghidra and show a completion or failure status.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
        handler: Name of the panel slot under test.
        marker: Remote statement the command must contain.
        done: Status text a successful command must produce.
        failed: Status text a failing command must produce.
    """
    bridge.rules = [(marker, True)]
    method(ready_panel, handler)()
    settle(ready_panel)
    assert bridge.scripts == [f"{marker}\nTrue"]
    assert status(ready_panel) == done

    bridge.rules = [(marker, ToolError("boom"))]
    method(ready_panel, handler)()
    settle(ready_panel)
    assert status(ready_panel) == failed


@pytest.mark.parametrize("pattern", ["", "   "])
def test_byte_search_with_a_blank_pattern_sends_nothing(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge, pattern: str) -> None:
    """A blank pattern returns before any request is built and leaves the search button enabled.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
        pattern: Pattern text typed into the toolbar input.
    """
    set_text(ready_panel, "_byte_search_input", pattern)
    before = status(ready_panel)

    method(ready_panel, "_on_search_bytes")()
    settle(ready_panel)

    assert bridge.scripts == []
    assert status(ready_panel) == before
    assert button(ready_panel, "_byte_search_btn").isEnabled()


def test_byte_search_lists_the_matches_in_the_scripting_output(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Matches are listed as uppercase hex addresses in the scripting tab's output, which is brought to the front.

    The wildcard pattern is converted to the signed byte and mask arrays Ghidra's Java ``byte[]`` needs: 0x8B becomes -117 and a mask byte
    of 0xFF becomes -1.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    bridge.rules = [("memory.findBytes", [0x401000, 0x2AB0])]
    set_text(ready_panel, "_byte_search_input", "48 8B ?? ??")
    tabs = priv(ready_panel, "_data_tabs", QTabWidget)
    tabs.setCurrentIndex(0)

    method(ready_panel, "_on_search_bytes")()

    assert not button(ready_panel, "_byte_search_btn").isEnabled()
    settle(ready_panel)
    assert len(bridge.scripts) == 1
    assert "[72, -117, 0, 0]" in bridge.scripts[0]
    assert "[-1, -1, 0, 0]" in bridge.scripts[0]
    assert plain(ready_panel, "_script_output") == "0x401000\n0x2AB0"
    assert status(ready_panel) == "Byte search: 2 match(es)"
    assert tabs.currentIndex() == _SCRIPTING_TAB
    current = tabs.currentWidget()
    assert current is not None
    assert current.isAncestorOf(priv(ready_panel, "_script_output", QPlainTextEdit))
    assert button(ready_panel, "_byte_search_btn").isEnabled()


def test_byte_search_without_matches_says_so(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A search with no hits shows a "no matches" note and a zero count.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    bridge.rules = [("memory.findBytes", [])]
    set_text(ready_panel, "_byte_search_input", "DE AD")

    method(ready_panel, "_on_search_bytes")()
    settle(ready_panel)

    assert plain(ready_panel, "_script_output") == "No matches found."
    assert status(ready_panel) == "Byte search: 0 match(es)"


def test_byte_search_reports_a_malformed_pattern_from_the_real_bridge(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A pattern with a token that is not a hex byte is refused by the bridge before anything is sent, and the refusal is reported.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    set_text(ready_panel, "_byte_search_input", "ZZ")

    method(ready_panel, "_on_search_bytes")()
    settle(ready_panel)

    assert status(ready_panel) == "Byte search failed: Malformed hex token in pattern: 'ZZ'"
    assert bridge.scripts == []
    assert button(ready_panel, "_byte_search_btn").isEnabled()


def test_byte_search_reports_a_transport_failure(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A search that fails on the wire is reported on the status label and the button is enabled again.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    bridge.rules = [("memory.findBytes", ToolError("peer vanished"))]
    set_text(ready_panel, "_byte_search_input", "48 8B")

    method(ready_panel, "_on_search_bytes")()
    settle(ready_panel)

    assert status(ready_panel) == "Byte search failed: peer vanished"
    assert button(ready_panel, "_byte_search_btn").isEnabled()


def test_import_debug_info_dialog_cancel_sends_nothing(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Cancelling the debug-file dialog imports nothing and leaves the status label alone.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    before = status(ready_panel)

    method(ready_panel, "_on_import_debug_info")()
    settle(ready_panel)

    assert bridge.scripts == []
    assert status(ready_panel) == before


def test_import_debug_info_reports_a_missing_file_from_the_real_bridge(
    ready_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A chosen debug file that does not exist is refused by the real bridge before anything is sent.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
        monkeypatch: Fixture used to replace the static file dialog.
        tmp_path: Directory in which the missing file would live.
    """
    missing = tmp_path / "absent.pdb"
    monkeypatch.setattr(QFileDialog, "getOpenFileName", single_file(missing))

    method(ready_panel, "_on_import_debug_info")()
    settle(ready_panel)

    assert status(ready_panel) == f"Debug import failed: Debug info file not found: {missing}"
    assert bridge.scripts == []


def test_import_debug_info_reports_the_imported_file(
    ready_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A chosen debug file that Ghidra imports is reported by its file name.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
        monkeypatch: Fixture used to replace the static file dialog.
        tmp_path: Directory that holds the debug file.
    """
    symbols = tmp_path / "symbols.pdb"
    symbols.write_bytes(b"pdb")
    bridge.rules = [
        (
            "intellicrack.import_debug_info",
            {"path": str(symbols), "success": True, "type": "pdb", "analyzer": "PdbUniversalAnalyzer", "error": None},
        ),
    ]
    monkeypatch.setattr(QFileDialog, "getOpenFileName", single_file(symbols))

    method(ready_panel, "_on_import_debug_info")()
    settle(ready_panel)

    assert len(bridge.scripts) == 1
    assert status(ready_panel) == "Debug info imported: symbols.pdb"


def test_diff_dialog_cancel_sends_nothing(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Cancelling the program dialog compares nothing and leaves the status label alone.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    before = status(ready_panel)

    method(ready_panel, "_on_diff_programs")()
    settle(ready_panel)

    assert bridge.scripts == []
    assert status(ready_panel) == before


def test_diff_lists_the_differing_addresses_in_the_scripting_output(
    ready_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A comparison shows the difference count and each differing address in the scripting tab's output, which is brought to the front.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
        monkeypatch: Fixture used to replace the static file dialog.
        tmp_path: Directory that holds the other program.
    """
    other = tmp_path / "other.exe"
    bridge.rules = [
        ("ProgramDiff(currentProgram, other_prog)", {"differences": 2, "details": [{"address": 0x401000}, {"address": 0x402ABC}]}),
    ]
    monkeypatch.setattr(QFileDialog, "getOpenFileName", single_file(other))
    tabs = priv(ready_panel, "_data_tabs", QTabWidget)
    tabs.setCurrentIndex(0)

    method(ready_panel, "_on_diff_programs")()

    assert status(ready_panel) == "Comparing programs..."
    settle(ready_panel)
    assert plain(ready_panel, "_script_output") == "Differences found: 2\n  0x401000\n  0x402ABC"
    assert status(ready_panel) == "Diff complete"
    assert tabs.currentIndex() == _SCRIPTING_TAB
    current = tabs.currentWidget()
    assert current is not None
    assert current.isAncestorOf(priv(ready_panel, "_script_output", QPlainTextEdit))


def test_diff_failure_is_reported_on_the_status_label(
    ready_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A comparison that fails on the wire is reported on the status label.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
        monkeypatch: Fixture used to replace the static file dialog.
        tmp_path: Directory that holds the other program.
    """
    bridge.rules = [("ProgramDiff(currentProgram, other_prog)", ToolError("import refused"))]
    monkeypatch.setattr(QFileDialog, "getOpenFileName", single_file(tmp_path / "other.exe"))

    method(ready_panel, "_on_diff_programs")()
    settle(ready_panel)

    assert status(ready_panel) == "Diff failed: import refused"


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ("raw comparison text", "raw comparison text"),
        ({"differences": 3, "details": None}, "Differences found: 3"),
        ({}, "Differences found: 0"),
    ],
    ids=["not_a_dict", "details_not_a_list", "empty_dict"],
)
def test_diff_result_shapes_other_than_the_bridge_payload_are_still_shown(panel: GhidraPanel, result: object, expected: str) -> None:
    """A result that is not a dictionary is shown as text, and a dictionary without a usable detail list shows only its count.

    Args:
        panel: Panel without a bridge.
        result: Result handed to the handler.
        expected: Text the scripting output must show.
    """
    method(panel, "_apply_diff_results")(result)

    assert plain(panel, "_script_output") == expected
    assert status(panel) == "Diff complete"


def test_overlay_space_needs_a_name(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Creating an overlay with a blank name is refused on the status label and nothing is sent.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    set_text(ready_panel, "_overlay_name_input", "   ")

    method(ready_panel, "_on_create_overlay_space")()
    settle(ready_panel)

    assert status(ready_panel) == "Overlay name required"
    assert bridge.scripts == []


def test_overlay_space_is_created_under_the_typed_name(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """The typed overlay name reaches the bridge and its creation is reported with that name.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    bridge.rules = [("createOverlaySpace", {"name": "ovl", "success": True})]
    set_text(ready_panel, "_overlay_name_input", " ovl ")

    method(ready_panel, "_on_create_overlay_space")()
    settle(ready_panel)

    assert len(bridge.scripts) == 1
    assert 'currentProgram.createOverlaySpace("ovl", default_space)' in bridge.scripts[0]
    assert status(ready_panel) == "Overlay space 'ovl' created"


def test_overlay_space_failure_is_reported_on_the_status_label(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A creation that fails on the wire is reported on the status label.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    bridge.rules = [("createOverlaySpace", ToolError("duplicate space"))]
    set_text(ready_panel, "_overlay_name_input", "ovl")

    method(ready_panel, "_on_create_overlay_space")()
    settle(ready_panel)

    assert status(ready_panel) == "Create overlay failed: duplicate space"


def test_function_refresh_failure_is_reported_and_the_button_enabled(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A function listing that fails is reported on the status label and the refresh button is enabled again.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    bridge.rules = [("getFunctionManager", ToolError("no program"))]

    method(ready_panel, "_on_refresh_functions")()

    assert not button(ready_panel, "_refresh_funcs_btn").isEnabled()
    settle(ready_panel)
    assert status(ready_panel) == "Function refresh failed: no program"
    assert button(ready_panel, "_refresh_funcs_btn").isEnabled()


def test_goto_function_failure_is_reported_and_the_button_enabled(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A go-to lookup that fails is reported on the status label and the Go button is enabled again.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    bridge.rules = [("_func_info", ToolError("no program"))]
    set_text(ready_panel, "_goto_func_addr", _ADDR_TEXT)

    method(ready_panel, "_on_goto_function")()

    assert not button(ready_panel, "_goto_func_btn").isEnabled()
    settle(ready_panel)
    assert f"toAddr({_ADDR})" in bridge.scripts[0]
    assert status(ready_panel) == "Go to function failed: no program"
    assert button(ready_panel, "_goto_func_btn").isEnabled()


def test_clicking_a_function_without_an_address_does_nothing(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A tree row that carries no integer address loads nothing.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    before = status(ready_panel)

    method(ready_panel, "_on_function_clicked")(QTreeWidgetItem(["main", "0x401000", "32"]), 0)
    settle(ready_panel)

    assert bridge.scripts == []
    assert status(ready_panel) == before


def test_clicking_a_function_loads_every_code_view_for_its_address(ready_panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Clicking a row of the function list loads decompilation, disassembly, p-code and the CFG for the address stored in the row.

    The row is produced by the panel's own list handler from a ``FunctionInfo``, so the address the click handler reads back is the one the
    list handler stored.

    Args:
        ready_panel: Panel holding a ready bridge.
        bridge: The bridge held by the panel.
    """
    bridge.rules = [
        ("_decompile_outcome", {"status": "ok", "code": "int main(void) { return 0; }", "error": None}),
        ("instructions.append", [{"address": _ADDR, "bytes": "31 C0", "mnemonic": "XOR", "operands": "EAX, EAX"}]),
        ("_pcode_payload", {"function": "main", "pcode_ops": [{"address": _ADDR, "opcode": 5, "mnemonic": "COPY"}]}),
        ("_bb_payload", {"function": "main", "blocks": _SAMPLE_BLOCKS}),
        ("getReferencesTo", []),
        ("getReferencesFrom", []),
    ]
    function = FunctionInfo(
        name="main",
        address=_ADDR,
        size=32,
        calling_convention="__cdecl",
        return_type="int",
        parameters=[],
        local_variables=[],
    )
    method(ready_panel, "_apply_functions")([function])
    item = priv(ready_panel, "_func_tree", QTreeWidget).topLevelItem(0)
    assert item is not None

    method(ready_panel, "_on_function_clicked")(item, 0)
    settle(ready_panel)

    assert len(bridge.scripts) == 6
    assert all(f"toAddr({_ADDR})" in script for script in bridge.scripts)
    assert plain(ready_panel, "_decompiled_view") == "int main(void) { return 0; }"
    assert plain(ready_panel, "_disasm_view") == "0x401000  " + "31 C0".ljust(24) + "  XOR EAX, EAX"
    assert plain(ready_panel, "_pcode_view") == "; Function: main\n  0x401000  COPY"
    assert graph_blocks(ready_panel) == {0x401000, 0x401010}


@pytest.mark.parametrize("result", [None, "", "   \n"], ids=["none", "empty", "blank"])
def test_decompilation_without_code_shows_an_inline_note(panel: GhidraPanel, result: object) -> None:
    """A missing or blank decompilation is replaced by a comment line in the view and the same note on the status label.

    Args:
        panel: Panel without a bridge.
        result: Result handed to the handler.
    """
    method(panel, "_apply_decompiled")(result)

    assert plain(panel, "_decompiled_view") == "// No decompilation available at this address"
    assert status(panel) == "No decompilation available at this address"


def test_decompilation_with_code_replaces_the_view_text(panel: GhidraPanel) -> None:
    """Decompiled code is shown as it is and the status label is left alone.

    Args:
        panel: Panel without a bridge.
    """
    before = status(panel)

    method(panel, "_apply_decompiled")("int main(void) {\n  return 0;\n}")

    assert plain(panel, "_decompiled_view") == "int main(void) {\n  return 0;\n}"
    assert status(panel) == before


def test_disassembly_lines_are_shown_with_address_padded_bytes_and_text(panel: GhidraPanel) -> None:
    """Each line shows the uppercase hex address, the byte string padded to 24 columns, then mnemonic and operands.

    Args:
        panel: Panel without a bridge.
    """
    lines = [
        DisassemblyLine(address=0x401000, bytes_str="48 8B 05 10 00 00 00", mnemonic="MOV", operands="RAX, [0x401018]"),
        DisassemblyLine(address=0x401007, bytes_str="C3", mnemonic="RET", operands=""),
    ]

    method(panel, "_apply_disassembly")(lines)

    assert plain(panel, "_disasm_view") == "\n".join([
        "0x401000  " + "48 8B 05 10 00 00 00".ljust(24) + "  MOV RAX, [0x401018]",
        "0x401007  " + "C3".ljust(24) + "  RET ",
    ])


def test_empty_disassembly_keeps_the_previous_view(panel: GhidraPanel) -> None:
    """An empty disassembly result leaves the text already in the view alone.

    Args:
        panel: Panel without a bridge.
    """
    priv(panel, "_disasm_view", QPlainTextEdit).setPlainText("previous")

    method(panel, "_apply_disassembly")([])

    assert plain(panel, "_disasm_view") == "previous"


def test_missing_pcode_result_keeps_the_previous_view(panel: GhidraPanel) -> None:
    """A missing p-code result leaves the text already in the view alone.

    Args:
        panel: Panel without a bridge.
    """
    priv(panel, "_pcode_view", QPlainTextEdit).setPlainText("previous")

    method(panel, "_apply_pcode")(None)

    assert plain(panel, "_pcode_view") == "previous"


def test_pcode_payload_is_shown_as_a_function_header_and_one_line_per_operation(panel: GhidraPanel) -> None:
    """The p-code view starts with the function name and lists each operation's uppercase hex address and mnemonic.

    Args:
        panel: Panel without a bridge.
    """
    payload: dict[str, object] = {
        "function": "main",
        "pcode_ops": [
            {"address": 0x401000, "opcode": 5, "mnemonic": "COPY", "output": None, "inputs": []},
            {"address": 0x401ABC, "opcode": 10, "mnemonic": "RETURN", "output": None, "inputs": []},
        ],
    }

    method(panel, "_apply_pcode")(payload)

    assert plain(panel, "_pcode_view") == "; Function: main\n  0x401000  COPY\n  0x401ABC  RETURN"


def test_pcode_for_an_address_outside_any_function_does_not_show_the_text_none(panel: GhidraPanel) -> None:
    """When Ghidra finds no function at the address its payload carries a null function name, which must not be printed as "None".

    The bridge answers ``{'function': None, 'pcode_ops': []}`` for an address that lies in no function, so the view should stay empty.

    Args:
        panel: Panel without a bridge.
    """
    method(panel, "_apply_pcode")({"function": None, "pcode_ops": []})

    assert not plain(panel, "_pcode_view")


def test_pcode_operations_without_a_function_name_have_no_header(panel: GhidraPanel) -> None:
    """A payload that names no function lists its operations without a header line.

    Args:
        panel: Panel without a bridge.
    """
    payload: dict[str, object] = {"pcode_ops": [{"address": 0x401000, "opcode": 5, "mnemonic": "COPY"}]}

    method(panel, "_apply_pcode")(payload)

    assert plain(panel, "_pcode_view") == "  0x401000  COPY"


@pytest.mark.parametrize(
    ("handler", "result", "expected", "done"),
    [
        ("_apply_byte_search_results", [0x401000], "0x401000", "Byte search: 1 match(es)"),
        ("_apply_diff_results", {"differences": 1, "details": [{"address": 0x2AB0}]}, "Differences found: 1\n  0x2AB0", "Diff complete"),
    ],
    ids=["byte_search", "diff"],
)
def test_scripting_output_is_filled_even_without_the_data_tab_widget(
    panel: GhidraPanel,
    handler: str,
    result: object,
    expected: str,
    done: str,
) -> None:
    """Results are written to the scripting output and reported on the status label when the panel has no tab widget to switch.

    Args:
        panel: Panel without a bridge.
        handler: Name of the result handler under test.
        result: Result handed to the handler.
        expected: Text the scripting output must show.
        done: Status text the result must produce.
    """
    set_priv(panel, "_data_tabs", None)

    method(panel, handler)(result)

    assert plain(panel, "_script_output") == expected
    assert status(panel) == done


def test_missing_cfg_result_keeps_the_previous_graph(panel: GhidraPanel) -> None:
    """A missing CFG result leaves the graph that is already drawn alone.

    Args:
        panel: Panel without a bridge.
    """
    method(panel, "_apply_cfg")({"function": "main", "blocks": _SAMPLE_BLOCKS})
    assert graph_blocks(panel) == {0x401000, 0x401010}

    method(panel, "_apply_cfg")(None)

    assert graph_blocks(panel) == {0x401000, 0x401010}


def test_cfg_payload_is_drawn_as_one_graph_node_per_block(panel: GhidraPanel) -> None:
    """The graph view holds one node for each block of the bridge's payload, keyed by the block's start address.

    Args:
        panel: Panel without a bridge.
    """
    method(panel, "_apply_cfg")({"function": "main", "blocks": _SAMPLE_BLOCKS})

    assert graph_blocks(panel) == {0x401000, 0x401010}


def test_cfg_text_view_lists_each_block_with_its_sources_and_destinations(qtbot: QtBot, panel: GhidraPanel) -> None:
    """With a plain-text CFG view, each block is a header line followed by its sources and destinations when it has any.

    The panel only builds a text view when the graph module cannot be imported, so the view is put into the panel's private slot directly.

    Args:
        qtbot: pytest-qt fixture that owns the replacement view.
        panel: Panel without a bridge.
    """
    fallback = QPlainTextEdit()
    qtbot.addWidget(fallback)
    set_priv(panel, "_cfg_view", fallback)

    method(panel, "_apply_cfg")({"function": "main", "blocks": _SAMPLE_BLOCKS})

    expected = "Block: 0x401000 - 0x40100F\n  Sources: 0x400FF0\n  Destinations: 0x401010, 0x401020\nBlock: 0x401010 - 0x40101F"
    assert fallback.toPlainText() == expected
