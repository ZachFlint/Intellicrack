# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the disassembly-range, function context menu, imports, exports, strings, xref, label and bookmark handlers of the Ghidra panel.

Every test drives a real ``GhidraPanel`` under the offscreen ``QApplication`` by calling the slots its buttons and menus trigger. Ghidra
itself is never started: the bridge is always a real ``GhidraBridge``, either untouched (not connected) or ``ScriptedGhidraBridge``, a
subclass that replaces only the Jython wire exchange (``_execute_remote`` and ``_execute_remote_eval``). Everything above the wire, the
bridge's own argument handling, readback verification and result parsing, runs unmodified, and the panel receives the real dataclasses
and dictionaries that the bridge produces. Qt's blocking entry points are driven from inside their own event loops: the context menus
are answered by a timer that presses Return on the wanted entry, the function-flags dialog by a timer that sets its check boxes and
clicks its button, and the static input and message dialogs are replaced with plain functions that return a chosen answer.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Final, cast, override

import pytest
from PyQt6.QtCore import QCoreApplication, QPoint, Qt, QTimer
from PyQt6.QtGui import QAction
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
)

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import CrossReference, ExportInfo, FunctionInfo, ImportInfo, StringInfo, ToolError
from intellicrack.ui.panels.async_bridge import bridge_workers_for, drain_bridge_workers_for
from intellicrack.ui.panels.ghidra_panel import GhidraPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping

    from pytestqt.qtbot import QtBot


type Prompt = tuple[str, str, object]

pytestmark = pytest.mark.usefixtures("qapp")

_WAIT_MS: Final[int] = 20_000
_SETTLE_ROUNDS: Final[int] = 6
_ADDR: Final[int] = 0x401000
_PANEL_WIDTH: Final[int] = 1400
_PANEL_HEIGHT: Final[int] = 900
_LABELS_TAB: Final[int] = 4
_CALL_GRAPH_TAB: Final[int] = 8
_FLAGS_TITLE: Final[str] = "Set Function Flags"

_ACTION_KEYS: Final[tuple[str, ...]] = (
    "rename",
    "edit_sig",
    "flags",
    "add_cmt",
    "set_var",
    "rename_var",
    "call_graph",
    "stack",
    "body",
    "conventions",
    "set_color",
    "delete",
)

_FUNC_MENU_CAPTIONS: Final[list[str]] = [
    "Rename Function",
    "Edit Signature",
    "Set Function Flags",
    "Add Comment",
    "Set Variable Type",
    "Rename Variable",
    "Show Call Graph",
    "Get Stack Frame",
    "Get Function Body",
    "Show Calling Conventions",
    "Set Color",
    "-",
    "Delete Function",
]

_ARMED_INPUTS: Final[tuple[tuple[str, str], ...]] = (
    ("_disasm_range_start_input", "0x401000"),
    ("_disasm_range_end_input", "0x401010"),
    ("_create_func_addr", "0x401000"),
    ("_ref_from_input", "0x401000"),
    ("_ref_to_input", "0x402000"),
    ("_label_addr_input", "0x401000"),
    ("_label_name_input", "armed_label"),
    ("_bm_addr_input", "0x401000"),
    ("_bm_category_input", "Armed"),
)

_GUARDED_HANDLERS: Final[tuple[tuple[str, tuple[object, ...]], ...]] = (
    ("_on_disassemble_range", ()),
    ("_on_clear_code_bytes", ()),
    ("_on_create_function", ()),
    ("_refresh_imports", ()),
    ("_refresh_exports", ()),
    ("search_strings", ("needle",)),
    ("show_xrefs", (_ADDR,)),
    ("_on_add_reference", ()),
    ("_on_delete_reference", ()),
    ("_on_set_label", ()),
    ("_on_refresh_labels", ()),
    ("_on_remove_label", ()),
    ("_on_promote_symbol_to_primary", ()),
    ("_on_create_bookmark", ()),
    ("_on_refresh_bookmarks", ()),
    ("_on_remove_bookmark", ()),
)
_GUARDED_IDS: Final[list[str]] = [name for name, _ in _GUARDED_HANDLERS]

_INVALID_INPUT_CASES: Final[tuple[tuple[str, tuple[tuple[str, str], ...], str], ...]] = (
    (
        "_on_disassemble_range",
        (("_disasm_range_start_input", "zz"), ("_disasm_range_end_input", "0x401010")),
        "Invalid start address for disassemble range",
    ),
    (
        "_on_disassemble_range",
        (("_disasm_range_start_input", "0x401000"), ("_disasm_range_end_input", "zz")),
        "Invalid end address for disassemble range",
    ),
    (
        "_on_clear_code_bytes",
        (("_disasm_range_start_input", "zz"), ("_disasm_range_end_input", "0x401010")),
        "Invalid start address for clear code bytes",
    ),
    (
        "_on_clear_code_bytes",
        (("_disasm_range_start_input", "0x401000"), ("_disasm_range_end_input", "zz")),
        "Invalid end address for clear code bytes",
    ),
    ("_on_create_function", (("_create_func_addr", "zz"),), "Invalid address for create function"),
    ("_on_create_function", (("_create_func_addr", ""),), "Invalid address for create function"),
    (
        "_on_add_reference",
        (("_ref_from_input", "0x401000"), ("_ref_to_input", "zz")),
        "Invalid to-address for add reference",
    ),
    (
        "_on_delete_reference",
        (("_ref_from_input", "zz"), ("_ref_to_input", "0x402000")),
        "Invalid from-address for delete reference",
    ),
    (
        "_on_delete_reference",
        (("_ref_from_input", "0x401000"), ("_ref_to_input", "zz")),
        "Invalid to-address for delete reference",
    ),
    ("_on_set_label", (("_label_addr_input", "zz"), ("_label_name_input", "main")), "Invalid address for set label"),
    ("_on_set_label", (("_label_addr_input", "0x401000"), ("_label_name_input", "   ")), "Label name required"),
    ("_on_create_bookmark", (("_bm_addr_input", "zz"), ("_bm_category_input", "Crack")), "Invalid address for bookmark"),
    ("_on_create_bookmark", (("_bm_addr_input", "0x401000"), ("_bm_category_input", "  ")), "Bookmark category required"),
)
_INVALID_INPUT_IDS: Final[list[str]] = [
    "disassemble_bad_start",
    "disassemble_bad_end",
    "clear_bad_start",
    "clear_bad_end",
    "create_function_bad_address",
    "create_function_empty_address",
    "add_reference_bad_target",
    "delete_reference_bad_source",
    "delete_reference_bad_target",
    "set_label_bad_address",
    "set_label_blank_name",
    "bookmark_bad_address",
    "bookmark_blank_category",
]

_LABELS: Final[list[dict[str, object]]] = [
    {"name": "main", "address": _ADDR, "type": "Function"},
    {"name": "loc_401004", "address": _ADDR + 4, "type": "Label"},
]
_BOOKMARKS: Final[list[dict[str, object]]] = [
    {"address": _ADDR, "category": "Crack", "comment": "patch here", "type": "Warning"},
    {"address": _ADDR + 8, "category": "Analysis", "comment": "checked", "type": "Note"},
]
_BODY_PAYLOAD: Final[dict[str, object]] = {
    "name": "main",
    "address": 0x140001000,
    "is_thunk": False,
    "thunked_function": None,
    "ranges": [{"start": 0x140001000, "end": 0x14000100F}, {"start": 0x140001020, "end": 0x14000102F}],
    "total_size": 32,
}
_BODY_MESSAGE: Final[str] = (
    "Function: main\nAddress: 0x140001000\nSize: 32 bytes\n  Range: 0x140001000 - 0x14000100F\n  Range: 0x140001020 - 0x14000102F"
)


class ScriptedGhidraBridge(GhidraBridge):
    """Real ``GhidraBridge`` whose Jython wire answers from a script.

    Only the two methods that cross the process boundary to Ghidra are replaced. Each returns (or raises) the reply registered for the
    first needle that occurs in the script text the production code sent, and raises a ``ToolError`` when nothing matches. The bridge is
    attached to a placeholder client so its state is ready, exactly as after a real connection. Every caller above the two methods is
    the production code under test.
    """

    def __init__(self) -> None:
        """Create a ready bridge with no scripted replies."""
        super().__init__()
        self.exec_rules: list[tuple[str, object]] = []
        self.eval_rules: list[tuple[str, object]] = []
        self.sent: list[str] = []
        self.sent_eval: list[str] = []
        self.attach_remote_bridge(object())

    def reply_exec(self, needle: str, reply: object) -> None:
        """Register the reply for a script that contains a needle.

        Args:
            needle: Text that identifies the script.
            reply: Value to return, or a ``ToolError`` to raise a fresh copy of.
        """
        self.exec_rules.append((needle, reply))

    def reply_eval(self, needle: str, reply: object) -> None:
        """Register the reply for an expression that contains a needle.

        Args:
            needle: Text that identifies the expression.
            reply: Value to return, or a ``ToolError`` to raise a fresh copy of.
        """
        self.eval_rules.append((needle, reply))

    @override
    async def _execute_remote(self, code: str) -> object:
        """Record the script and return its scripted reply.

        Args:
            code: Jython script built by the production code.

        Returns:
            object: The scripted reply.
        """
        await asyncio.sleep(0)
        self.sent.append(code)
        return _scripted_reply(self.exec_rules, code)

    @override
    async def _execute_remote_eval(self, expression: str) -> object:
        """Record the expression and return its scripted reply.

        Args:
            expression: Jython expression built by the production code.

        Returns:
            object: The scripted reply.
        """
        await asyncio.sleep(0)
        self.sent_eval.append(expression)
        return _scripted_reply(self.eval_rules, expression)


def _scripted_reply(rules: list[tuple[str, object]], text: str) -> object:
    """Return the reply registered for the first rule whose needle occurs in the text.

    Args:
        rules: Needle and reply pairs in registration order.
        text: Script or expression the production code sent.

    Returns:
        object: The scripted reply.

    Raises:
        ToolError: When the matching reply is an error, or when no rule matches.
    """
    for needle, reply in rules:
        if needle in text:
            if isinstance(reply, ToolError):
                raise ToolError(reply.message)
            return reply
    msg = "no scripted reply for: " + text.strip().splitlines()[0]
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


def call(obj: object, name: str, *args: object) -> object:
    """Call a (possibly private) method by name.

    Args:
        obj: Object that owns the method.
        name: Method name.
        *args: Positional arguments for the call.

    Returns:
        object: The method's return value.
    """
    method = cast("Callable[..., object]", getattr(obj, name))
    return method(*args)


def status(panel: GhidraPanel) -> str:
    """Read the status text the panel shows in its toolbar.

    Args:
        panel: Panel whose status label is read.

    Returns:
        str: The status text.
    """
    label = panel.status_label
    assert label is not None
    return label.text()


def fill(panel: GhidraPanel, name: str, text: str) -> None:
    """Type text into a line edit of the panel.

    Args:
        panel: Panel that owns the line edit.
        name: Attribute name of the line edit.
        text: Text to enter.
    """
    priv(panel, name, QLineEdit).setText(text)


def settle(panel: GhidraPanel) -> None:
    """Join the panel's bridge workers and deliver their results, following chained requests.

    Args:
        panel: Panel whose workers are joined.
    """
    for _ in range(_SETTLE_ROUNDS):
        drain_bridge_workers_for(panel, timeout_ms=_WAIT_MS)
        QCoreApplication.processEvents()


def rows(table: QTableWidget) -> list[list[str]]:
    """Read every cell of a table.

    Args:
        table: Table to read.

    Returns:
        list[list[str]]: The cell texts of every row, top to bottom.
    """
    result: list[list[str]] = []
    for row in range(table.rowCount()):
        cells: list[str] = []
        for column in range(table.columnCount()):
            item = table.item(row, column)
            assert item is not None
            cells.append(item.text())
        result.append(cells)
    return result


def tree_rows(tree: QTreeWidget) -> list[list[str]]:
    """Read every top-level row of a tree.

    Args:
        tree: Tree to read.

    Returns:
        list[list[str]]: The column texts of every top-level item, top to bottom.
    """
    result: list[list[str]] = []
    for index in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(index)
        assert item is not None
        result.append([item.text(column) for column in range(tree.columnCount())])
    return result


def function_info(name: str, address: int, size: int) -> FunctionInfo:
    """Build the record the bridge returns for an analyzed function.

    Args:
        name: Function name.
        address: Entry point.
        size: Size in bytes.

    Returns:
        FunctionInfo: A function with no parameters or locals.
    """
    return FunctionInfo(
        name=name,
        address=address,
        size=size,
        calling_convention="__stdcall",
        return_type="int",
        parameters=[],
        local_variables=[],
    )


def function_payload(name: str, address: int, size: int) -> dict[str, object]:
    """Build the dictionary the Ghidra script returns for one function.

    Args:
        name: Function name.
        address: Entry point.
        size: Size in bytes.

    Returns:
        dict[str, object]: The payload of one ``get_functions`` entry.
    """
    return {"name": name, "address": address, "size": size, "calling_convention": "__cdecl", "return_type": "int"}


def key_click(widget: QWidget, key: Qt.Key) -> None:
    """Send a key press and release to a widget.

    Args:
        widget: Widget that receives the key.
        key: Key to press.
    """
    cast("Callable[..., object]", getattr(QTest, "keyClick"))(widget, key)


def expose(qtbot: QtBot, panel: GhidraPanel) -> None:
    """Show the panel at a size that gives every table and tree real row geometry.

    Args:
        qtbot: pytest-qt fixture used to wait for the window.
        panel: Panel to show.
    """
    panel.resize(_PANEL_WIDTH, _PANEL_HEIGHT)
    panel.show()
    qtbot.waitExposed(panel)
    QCoreApplication.processEvents()


def script_text_dialog(monkeypatch: pytest.MonkeyPatch, answers: Mapping[str, tuple[str, bool]]) -> list[Prompt]:
    """Replace ``QInputDialog.getText`` with a function that answers by prompt label.

    Args:
        monkeypatch: Fixture that restores the dialog afterwards.
        answers: Text and acceptance returned for each prompt label.

    Returns:
        list[Prompt]: Title, label and default text of every prompt shown, in order.
    """
    prompts: list[Prompt] = []

    def _answer(_parent: object, title: str, label: str, **kwargs: object) -> tuple[str, bool]:
        """Record the prompt and return its scripted answer.

        Args:
            _parent: Parent widget, ignored.
            title: Dialog title.
            label: Prompt label that selects the answer.
            **kwargs: Keyword arguments of the real call; only ``text`` is recorded.

        Returns:
            tuple[str, bool]: The scripted text and whether the dialog was accepted.
        """
        prompts.append((title, label, kwargs.get("text")))
        return answers[label]

    monkeypatch.setattr(QInputDialog, "getText", _answer)
    return prompts


def record_information(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Replace ``QMessageBox.information`` with a function that records what it was asked to show.

    Args:
        monkeypatch: Fixture that restores the dialog afterwards.

    Returns:
        list[tuple[str, str]]: Title and text of every message, in order.
    """
    shown: list[tuple[str, str]] = []

    def _information(_parent: object, title: str, text: str, *_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        """Record the message and close it as if the user pressed OK.

        Args:
            _parent: Parent widget, ignored.
            title: Dialog title.
            text: Message text.
            *_args: Remaining positional arguments, ignored.
            **_kwargs: Keyword arguments, ignored.

        Returns:
            QMessageBox.StandardButton: The OK button.
        """
        shown.append((title, text))
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "information", _information)
    return shown


def answer_question(monkeypatch: pytest.MonkeyPatch, answer: QMessageBox.StandardButton) -> list[tuple[str, str]]:
    """Replace ``QMessageBox.question`` with a function that returns a chosen button.

    Args:
        monkeypatch: Fixture that restores the dialog afterwards.
        answer: Button the "user" presses.

    Returns:
        list[tuple[str, str]]: Title and text of every question asked, in order.
    """
    asked: list[tuple[str, str]] = []

    def _question(_parent: object, title: str, text: str, *_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        """Record the question and return the chosen button.

        Args:
            _parent: Parent widget, ignored.
            title: Dialog title.
            text: Question text.
            *_args: Remaining positional arguments, ignored.
            **_kwargs: Keyword arguments, ignored.

        Returns:
            QMessageBox.StandardButton: The chosen button.
        """
        asked.append((title, text))
        return answer

    monkeypatch.setattr(QMessageBox, "question", _question)
    return asked


def drive_menu(panel: GhidraPanel, caption: str | None) -> list[str]:
    """Arrange for the next context menu to be answered from inside its own event loop.

    ``QMenu.exec`` returns only once the menu closes, so a zero-delay timer records the entries the menu offers, confirms the wanted entry
    by moving the active entry onto it and pressing Return, and always closes the menu afterwards, which also ends the call when no entry
    is chosen. When no menu opens, the timer fires on the caller's next event processing and records nothing.

    Args:
        panel: Panel whose menu will open.
        caption: Caption of the entry to confirm, or None to dismiss the menu without choosing.

    Returns:
        list[str]: Captions the menu offered, with ``-`` for a separator; empty until the menu opens.
    """
    offered: list[str] = []

    def _run() -> None:
        """Confirm the wanted entry of the open menu and close it."""
        popup = QApplication.activePopupWidget()
        visible = [menu for menu in panel.findChildren(QMenu, options=Qt.FindChildOption.FindDirectChildrenOnly) if menu.isVisible()]
        found = popup if isinstance(popup, QMenu) else (visible[-1] if visible else None)
        if found is None:
            return
        try:
            offered.extend("-" if action.isSeparator() else action.text() for action in found.actions())
            for action in found.actions():
                if caption is not None and action.text() == caption:
                    found.setActiveAction(action)
                    key_click(found, Qt.Key.Key_Return)
        finally:
            found.close()

    QTimer.singleShot(0, _run)
    return offered


def answer_flags_dialog(panel: GhidraPanel, states: Mapping[str, Qt.CheckState], *, accept: bool) -> list[str]:
    """Arrange for the function-flags dialog to be answered from inside its own event loop.

    The dialog's modal loop returns only once it closes, so a zero-delay timer sets the named check boxes, clicks OK or Cancel, and
    always rejects any dialog that is still open afterwards, so a failure cannot leave the test blocked.

    Args:
        panel: Panel that will open the dialog.
        states: Check state to set on each box, keyed by the box caption.
        accept: Whether to click OK (True) or Cancel (False).

    Returns:
        list[str]: Notes of what the timer found: the dialog title once it ran, or a description of what was missing.
    """
    seen: list[str] = []

    def _run() -> None:
        """Operate the open dialog and close it."""
        dialogs = [dialog for dialog in panel.findChildren(QDialog) if dialog.windowTitle() == _FLAGS_TITLE]
        try:
            if not dialogs:
                seen.append("no dialog")
                return
            dialog = dialogs[-1]
            seen.append(dialog.windowTitle())
            for box in dialog.findChildren(QCheckBox):
                if box.text() in states:
                    box.setCheckState(states[box.text()])
            button_boxes = dialog.findChildren(QDialogButtonBox)
            which = QDialogButtonBox.StandardButton.Ok if accept else QDialogButtonBox.StandardButton.Cancel
            button = button_boxes[0].button(which) if button_boxes else None
            if button is None:
                seen.append("no button")
                return
            button.click()
        finally:
            modal = QApplication.activeModalWidget()
            if isinstance(modal, QDialog):
                modal.reject()

    QTimer.singleShot(0, _run)
    return seen


def dispatch(panel: GhidraPanel, bridge: GhidraBridge, actions: dict[str, QAction], key: str, name: str = "main") -> None:
    """Hand one chosen context-menu action to the panel's dispatcher.

    Args:
        panel: Panel under test.
        bridge: Bridge the dispatcher is given.
        actions: The menu entries by key.
        key: Key of the chosen entry.
        name: Display name of the targeted function.
    """
    call(panel, "_dispatch_func_menu_action", actions[key], actions, _ADDR, name, bridge)


def select_function(qtbot: QtBot, panel: GhidraPanel) -> QPoint:
    """Show the panel with one listed function and return the point over its row.

    Args:
        qtbot: pytest-qt fixture used to show the panel.
        panel: Panel to fill.

    Returns:
        QPoint: A viewport point inside the function's row.
    """
    expose(qtbot, panel)
    call(panel, "_apply_functions", [function_info("main", _ADDR, 16)])
    tree = priv(panel, "_func_tree", QTreeWidget)
    item = tree.topLevelItem(0)
    assert item is not None
    return tree.visualItemRect(item).center()


def select_table_row(qtbot: QtBot, panel: GhidraPanel, table_name: str, row: int) -> QPoint:
    """Show the Labels/Bookmarks tab and return the point over one row of one of its tables.

    Args:
        qtbot: pytest-qt fixture used to show the panel.
        panel: Panel whose table is read.
        table_name: Attribute name of the table.
        row: Row the point must lie in.

    Returns:
        QPoint: A viewport point inside the first cell of the row.
    """
    priv(panel, "_data_tabs", QTabWidget).setCurrentIndex(_LABELS_TAB)
    expose(qtbot, panel)
    item = priv(panel, table_name, QTableWidget).item(row, 0)
    assert item is not None
    return priv(panel, table_name, QTableWidget).visualItemRect(item).center()


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
def unconnected_panel(panel: GhidraPanel) -> GhidraPanel:
    """Give the panel a real bridge that is not connected to Ghidra.

    Args:
        panel: Panel without a bridge.

    Returns:
        GhidraPanel: The same panel, now holding an untouched ``GhidraBridge``.
    """
    panel.set_bridge(GhidraBridge())
    return panel


@pytest.fixture
def bridge() -> ScriptedGhidraBridge:
    """Provide a ready bridge with no scripted replies.

    Returns:
        ScriptedGhidraBridge: The bridge.
    """
    return ScriptedGhidraBridge()


@pytest.fixture
def wired(panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> GhidraPanel:
    """Give the panel the ready scripted bridge.

    Args:
        panel: Panel without a bridge.
        bridge: Ready scripted bridge.

    Returns:
        GhidraPanel: The same panel, now holding the bridge.
    """
    panel.set_bridge(bridge)
    return panel


@pytest.fixture
def actions(panel: GhidraPanel) -> dict[str, QAction]:
    """Build one real menu action for every entry of the function context menu.

    Args:
        panel: Panel that owns the actions.

    Returns:
        dict[str, QAction]: The actions by dispatcher key.
    """
    return {key: QAction(key, panel) for key in _ACTION_KEYS}


def _assert_nothing_sent(panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Assert that no request reached the bridge, after joining every worker the panel started.

    Args:
        panel: Panel whose workers are joined.
        bridge: Bridge that must have seen no script.
    """
    settle(panel)
    assert bridge.sent == []
    assert bridge.sent_eval == []


def _arm_inputs(panel: GhidraPanel) -> None:
    """Fill every input the guarded handlers read with a valid value.

    Args:
        panel: Panel whose inputs are filled.
    """
    for name, text in _ARMED_INPUTS:
        fill(panel, name, text)


@pytest.mark.parametrize(("handler", "args"), _GUARDED_HANDLERS, ids=_GUARDED_IDS)
def test_handler_without_a_bridge_reports_it_and_dispatches_nothing(panel: GhidraPanel, handler: str, args: tuple[object, ...]) -> None:
    """With no bridge configured a handler says so and starts no request, even though every input holds a valid value.

    Args:
        panel: Panel without a bridge.
        handler: Name of the panel method under test.
        args: Positional arguments the method takes.
    """
    _arm_inputs(panel)

    call(panel, handler, *args)
    settle(panel)

    assert status(panel) == "No bridge configured"
    assert bridge_workers_for(panel) == []


@pytest.mark.parametrize(("handler", "args"), _GUARDED_HANDLERS, ids=_GUARDED_IDS)
def test_handler_with_an_unconnected_bridge_reports_it_and_dispatches_nothing(
    unconnected_panel: GhidraPanel,
    handler: str,
    args: tuple[object, ...],
) -> None:
    """With a bridge that is not connected a handler says so and starts no request, even though every input holds a valid value.

    A handler that dispatched anyway would reach the real bridge, which refuses with its own message and replaces the status.

    Args:
        unconnected_panel: Panel holding an untouched ``GhidraBridge``.
        handler: Name of the panel method under test.
        args: Positional arguments the method takes.
    """
    _arm_inputs(unconnected_panel)

    call(unconnected_panel, handler, *args)
    settle(unconnected_panel)

    assert status(unconnected_panel) == "Ghidra not connected"
    assert bridge_workers_for(unconnected_panel) == []


@pytest.mark.parametrize(("handler", "fields", "expected"), _INVALID_INPUT_CASES, ids=_INVALID_INPUT_IDS)
def test_handler_rejects_bad_input_without_dispatching(
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    handler: str,
    fields: tuple[tuple[str, str], ...],
    expected: str,
) -> None:
    """An address that is not a number, or a missing name or category, is reported in the status bar and nothing is sent to Ghidra.

    Args:
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        handler: Name of the panel slot under test.
        fields: Input attribute names and the text typed into each.
        expected: Status text the rejection must show.
    """
    for name, text in fields:
        fill(wired, name, text)

    call(wired, handler)

    assert status(wired) == expected
    _assert_nothing_sent(wired, bridge)


def test_disassemble_range_runs_the_command_and_then_shows_the_start_block(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Disassembling a range sends both addresses, then loads the block at the start address into the disassembly tab.

    Args:
        qtbot: pytest-qt fixture used to wait for the results.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    operands = "qword ptr [RSP + 0x8], RBX"
    bridge.reply_exec("DisassembleCommand", {"applied": True, "instructions_created": 4})
    bridge.reply_exec("getInstructionAt", [{"address": _ADDR, "bytes": "48 89 5C 24 08", "mnemonic": "MOV", "operands": operands}])
    fill(wired, "_disasm_range_start_input", "0x401000")
    fill(wired, "_disasm_range_end_input", "0x401010")
    view = priv(wired, "_disasm_view", QPlainTextEdit)
    expected = "0x401000  " + "48 89 5C 24 08".ljust(24) + "  MOV " + operands

    call(wired, "_on_disassemble_range")

    qtbot.waitUntil(lambda: view.toPlainText() == expected, timeout=_WAIT_MS)
    settle(wired)
    assert len(bridge.sent) == 2
    assert f"start = toAddr({_ADDR})" in bridge.sent[0]
    assert f"end = toAddr({_ADDR + 0x10})" in bridge.sent[0]
    assert f"addr = toAddr({_ADDR})" in bridge.sent[1]
    assert status(wired) == "Block 0x401000"
    assert priv(wired, "_code_tabs", QTabWidget).currentWidget() is priv(wired, "_disasm_tab", QWidget)


def test_disassemble_range_rejected_by_ghidra_is_reported_and_loads_nothing(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """When Ghidra refuses the command the failure is shown and no block is loaded.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("DisassembleCommand", {"applied": False, "instructions_created": 0})
    fill(wired, "_disasm_range_start_input", "0x401000")
    fill(wired, "_disasm_range_end_input", "0x401010")

    call(wired, "_on_disassemble_range")

    qtbot.waitUntil(lambda: status(wired).startswith("Disassemble range failed: "), timeout=_WAIT_MS)
    settle(wired)
    assert "0x401000-0x401010" in status(wired)
    assert len(bridge.sent) == 1
    assert not priv(wired, "_disasm_view", QPlainTextEdit).toPlainText()


def test_clear_code_bytes_sends_the_range_and_reports_it_cleared(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Clearing code bytes sends both addresses and then shows the cleared range in hexadecimal.

    Args:
        qtbot: pytest-qt fixture used to wait for the result.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("clearCodeUnits", {"had_code": True, "cleared": True})
    fill(wired, "_disasm_range_start_input", "0x401000")
    fill(wired, "_disasm_range_end_input", "4198416")

    call(wired, "_on_clear_code_bytes")

    qtbot.waitUntil(lambda: status(wired) == "Cleared code bytes 0x401000-0x401010", timeout=_WAIT_MS)
    settle(wired)
    assert len(bridge.sent) == 1
    assert f"start = toAddr({_ADDR})" in bridge.sent[0]
    assert f"end = toAddr({_ADDR + 0x10})" in bridge.sent[0]


def test_clear_code_bytes_without_a_payload_is_reported_as_a_failure(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """When Ghidra returns nothing for the clear request the failure is shown instead of the cleared message.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("clearCodeUnits", None)
    fill(wired, "_disasm_range_start_input", "0x401000")
    fill(wired, "_disasm_range_end_input", "0x401010")

    call(wired, "_on_clear_code_bytes")

    qtbot.waitUntil(lambda: status(wired).startswith("Clear code bytes failed: "), timeout=_WAIT_MS)
    settle(wired)
    assert "returned no payload" in status(wired)


@pytest.mark.parametrize(
    ("typed_name", "name_literal"),
    [("  my_func  ", '"my_func"'), ("", "None"), ("   ", "None")],
    ids=["named", "empty_name", "blank_name"],
)
def test_create_function_sends_the_address_and_optional_name_and_refreshes_the_list(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    typed_name: str,
    name_literal: str,
) -> None:
    """Creating a function sends the address with the trimmed name, or no name when blank, then reloads the function list.

    Args:
        qtbot: pytest-qt fixture used to wait for the refreshed list.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        typed_name: Text typed into the name field.
        name_literal: Name argument the Ghidra script must carry.
    """
    bridge.reply_exec("createFunction(", {"name": "my_func", "address": _ADDR, "size": 16})
    bridge.reply_exec("fm.getFunctions(True)", [function_payload("my_func", _ADDR, 16)])
    fill(wired, "_create_func_addr", "0x401000")
    fill(wired, "_create_func_name", typed_name)
    tree = priv(wired, "_func_tree", QTreeWidget)

    call(wired, "_on_create_function")

    qtbot.waitUntil(lambda: tree.topLevelItemCount() == 1, timeout=_WAIT_MS)
    settle(wired)
    assert f"createFunction(addr, {name_literal})" in bridge.sent[0]
    assert f"addr = toAddr({_ADDR})" in bridge.sent[0]
    assert tree_rows(tree) == [["my_func", "0x401000", "16"]]
    assert priv(wired, "_func_count_label", QLabel).text() == "Functions (1)"


def test_create_function_refused_by_ghidra_is_reported_and_the_list_is_left_alone(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """When Ghidra creates no function the failure is shown and the function list is not reloaded.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("createFunction(", None)
    fill(wired, "_create_func_addr", "0x401000")

    call(wired, "_on_create_function")

    qtbot.waitUntil(lambda: status(wired).startswith("Create function failed: "), timeout=_WAIT_MS)
    settle(wired)
    assert "0x401000" in status(wired)
    assert len(bridge.sent) == 1


def test_function_body_dialog_lists_name_address_size_and_ranges(panel: GhidraPanel, monkeypatch: pytest.MonkeyPatch) -> None:
    """The body dialog shows the function's name, entry address, size and each address range in hexadecimal.

    Args:
        panel: Panel without a bridge.
        monkeypatch: Fixture that records the dialog.
    """
    shown = record_information(monkeypatch)

    call(panel, "_show_function_body_info", dict(_BODY_PAYLOAD))

    assert shown == [("Function Body", _BODY_MESSAGE)]


def test_function_body_dialog_names_the_function_a_thunk_forwards_to(panel: GhidraPanel, monkeypatch: pytest.MonkeyPatch) -> None:
    """A thunk gets an extra line naming the function it forwards to, between the size and the ranges.

    Args:
        panel: Panel without a bridge.
        monkeypatch: Fixture that records the dialog.
    """
    shown = record_information(monkeypatch)
    payload: dict[str, object] = {
        "name": "ExitProcess",
        "address": 0x140002000,
        "is_thunk": True,
        "thunked_function": "KERNELBASE.dll!ExitProcess",
        "ranges": [{"start": 0x140002000, "end": 0x140002005}],
        "total_size": 6,
    }

    call(panel, "_show_function_body_info", payload)

    assert shown == [
        (
            "Function Body",
            "Function: ExitProcess\nAddress: 0x140002000\nSize: 6 bytes\nThunk -> KERNELBASE.dll!ExitProcess\n  Range: 0x140002000 - 0x140002005",
        ),
    ]


@pytest.mark.parametrize("ranges", [[], None], ids=["empty_list", "not_a_list"])
def test_function_body_dialog_without_ranges_shows_only_the_header_lines(
    panel: GhidraPanel,
    monkeypatch: pytest.MonkeyPatch,
    ranges: list[object] | None,
) -> None:
    """A body with an empty or unusable range list shows the three header lines and no range line.

    Args:
        panel: Panel without a bridge.
        monkeypatch: Fixture that records the dialog.
        ranges: Value of the ``ranges`` entry.
    """
    shown = record_information(monkeypatch)
    payload: dict[str, object] = {"name": "stub", "address": 0x1000, "is_thunk": False, "ranges": ranges, "total_size": 0}

    call(panel, "_show_function_body_info", payload)

    assert shown == [("Function Body", "Function: stub\nAddress: 0x1000\nSize: 0 bytes")]


@pytest.mark.parametrize(("result", "text"), [(None, "None"), ("no function here", "no function here")], ids=["none", "text"])
def test_function_body_dialog_shows_a_non_dictionary_result_as_text(
    panel: GhidraPanel,
    monkeypatch: pytest.MonkeyPatch,
    result: object,
    text: str,
) -> None:
    """A result that is not a dictionary is shown as its text and nothing else.

    Args:
        panel: Panel without a bridge.
        monkeypatch: Fixture that records the dialog.
        result: Result handed to the handler.
        text: Message the dialog must show.
    """
    shown = record_information(monkeypatch)

    call(panel, "_show_function_body_info", result)

    assert shown == [("Function Body", text)]


def test_rename_action_renames_the_function_and_reloads_the_list(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Renaming prompts with the current name, sends the trimmed new name for the clicked address, and reloads the function list.

    Args:
        qtbot: pytest-qt fixture used to wait for the reloaded list.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt.
    """
    prompts = script_text_dialog(monkeypatch, {"New name:": ("  renamed_fn  ", True)})
    bridge.reply_exec("func.setName(", None)
    bridge.reply_eval("lambda f: f.getName()", "renamed_fn")
    bridge.reply_exec("fm.getFunctions(True)", [function_payload("renamed_fn", _ADDR, 16)])
    tree = priv(wired, "_func_tree", QTreeWidget)

    dispatch(wired, bridge, actions, "rename")

    qtbot.waitUntil(lambda: tree.topLevelItemCount() == 1, timeout=_WAIT_MS)
    settle(wired)
    assert prompts == [("Rename Function", "New name:", "main")]
    assert 'func.setName("renamed_fn"' in bridge.sent[0]
    assert f"addr = toAddr({_ADDR})" in bridge.sent[0]
    assert tree_rows(tree) == [["renamed_fn", "0x401000", "16"]]


@pytest.mark.parametrize(("typed", "accepted"), [("", True), ("   ", True), ("renamed_fn", False)], ids=["empty", "blank", "cancelled"])
def test_rename_action_without_a_usable_answer_sends_nothing(
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
    typed: str,
    *,
    accepted: bool,
) -> None:
    """An empty name, a blank name or a cancelled prompt leaves the function alone.

    Args:
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt.
        typed: Text the prompt returns.
        accepted: Whether the prompt was accepted.
    """
    prompts = script_text_dialog(monkeypatch, {"New name:": (typed, accepted)})

    dispatch(wired, bridge, actions, "rename")

    assert len(prompts) == 1
    _assert_nothing_sent(wired, bridge)


def test_rename_action_reports_a_name_ghidra_did_not_keep(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the readback shows another name the failure is shown and the function list is not reloaded.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt.
    """
    _ = script_text_dialog(monkeypatch, {"New name:": ("renamed_fn", True)})
    bridge.reply_exec("func.setName(", None)
    bridge.reply_eval("lambda f: f.getName()", "old_name")

    dispatch(wired, bridge, actions, "rename")

    qtbot.waitUntil(lambda: status(wired).startswith("Rename failed: "), timeout=_WAIT_MS)
    settle(wired)
    assert "expected 'renamed_fn', observed 'old_name'" in status(wired)
    assert len(bridge.sent) == 1


def test_edit_signature_action_asks_three_questions_and_sends_the_answers(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Editing a signature asks for return type, calling convention and name, then sends all three for the clicked address.

    Args:
        qtbot: pytest-qt fixture used to wait for the result.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompts.
    """
    prompts = script_text_dialog(
        monkeypatch,
        {"Return type:": ("int", True), "Calling convention:": ("__stdcall", True), "Function name:": ("new_main", True)},
    )
    bridge.reply_exec("func.setReturnType", {"name": "new_main", "address": _ADDR, "return_type": "int", "calling_convention": "__stdcall"})

    dispatch(wired, bridge, actions, "edit_sig")

    qtbot.waitUntil(lambda: status(wired) == "Signature updated", timeout=_WAIT_MS)
    settle(wired)
    assert [(label, default) for _, label, default in prompts] == [
        ("Return type:", None),
        ("Calling convention:", None),
        ("Function name:", "main"),
    ]
    assert 'rt = "int"' in bridge.sent[0]
    assert 'cc = "__stdcall"' in bridge.sent[0]
    assert 'nm = "new_main"' in bridge.sent[0]
    assert f"addr = toAddr({_ADDR})" in bridge.sent[0]


@pytest.mark.parametrize(
    ("answers", "asked"),
    [
        ({"Return type:": ("int", False)}, ["Return type:"]),
        ({"Return type:": ("int", True), "Calling convention:": ("", False)}, ["Return type:", "Calling convention:"]),
        (
            {"Return type:": ("int", True), "Calling convention:": ("", True), "Function name:": ("x", False)},
            ["Return type:", "Calling convention:", "Function name:"],
        ),
    ],
    ids=["cancel_return_type", "cancel_convention", "cancel_name"],
)
def test_edit_signature_action_stops_at_the_first_cancelled_question(
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
    answers: dict[str, tuple[str, bool]],
    asked: list[str],
) -> None:
    """Cancelling any of the three questions ends the edit without asking the rest and without sending anything.

    Args:
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompts.
        answers: Scripted answers by prompt label.
        asked: Labels that must have been asked, in order.
    """
    prompts = script_text_dialog(monkeypatch, answers)

    dispatch(wired, bridge, actions, "edit_sig")

    assert [label for _, label, _ in prompts] == asked
    _assert_nothing_sent(wired, bridge)


def test_edit_signature_action_reports_a_missing_function(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When Ghidra finds no function at the address the failure is shown instead of the success message.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompts.
    """
    _ = script_text_dialog(
        monkeypatch,
        {"Return type:": ("", True), "Calling convention:": ("", True), "Function name:": ("main", True)},
    )
    bridge.reply_exec("func.setReturnType", None)

    dispatch(wired, bridge, actions, "edit_sig")

    qtbot.waitUntil(lambda: status(wired).startswith("Signature update failed: "), timeout=_WAIT_MS)
    settle(wired)
    assert "No function at 0x401000" in status(wired)


@pytest.mark.parametrize(
    ("states", "present", "absent"),
    [
        ({}, [], ["func.setNoReturn", "func.setVarArgs", "func.setInline"]),
        (
            {"No Return": Qt.CheckState.Checked, "Var Args": Qt.CheckState.Unchecked},
            ["func.setNoReturn(True)", "func.setVarArgs(False)"],
            ["func.setInline"],
        ),
        (
            {"Inline": Qt.CheckState.Checked, "No Return": Qt.CheckState.Unchecked, "Var Args": Qt.CheckState.Checked},
            ["func.setNoReturn(False)", "func.setVarArgs(True)", "func.setInline(True)"],
            [],
        ),
    ],
    ids=["all_unchanged", "two_flags", "all_flags"],
)
def test_flags_action_sends_only_the_flags_the_user_decided(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    states: dict[str, Qt.CheckState],
    present: list[str],
    absent: list[str],
) -> None:
    """A box left half-checked means leave unchanged, so only checked or cleared boxes reach Ghidra, and the result is shown.

    Args:
        qtbot: pytest-qt fixture used to wait for the result.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        states: Check state set on each box before OK is clicked.
        present: Calls the script must contain.
        absent: Calls the script must not contain.
    """
    reply: dict[str, object] = {"name": "main", "address": _ADDR, "no_return": True, "var_args": False, "is_inline": False}
    bridge.reply_exec("func.hasNoReturn()", reply)

    seen = answer_flags_dialog(wired, states, accept=True)
    dispatch(wired, bridge, actions, "flags")
    QCoreApplication.processEvents()

    qtbot.waitUntil(lambda: status(wired) == f"Flags updated: {reply}", timeout=_WAIT_MS)
    settle(wired)
    assert seen == [_FLAGS_TITLE]
    assert len(bridge.sent) == 1
    for text in present:
        assert text in bridge.sent[0]
    for text in absent:
        assert text not in bridge.sent[0]
    assert f"addr = toAddr({_ADDR})" in bridge.sent[0]


def test_flags_action_cancelled_sends_nothing(wired: GhidraPanel, bridge: ScriptedGhidraBridge, actions: dict[str, QAction]) -> None:
    """Cancelling the flags dialog, even after ticking a box, sends nothing to Ghidra.

    Args:
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
    """
    seen = answer_flags_dialog(wired, {"No Return": Qt.CheckState.Checked}, accept=False)

    dispatch(wired, bridge, actions, "flags")
    QCoreApplication.processEvents()

    assert seen == [_FLAGS_TITLE]
    _assert_nothing_sent(wired, bridge)


def test_flags_action_reports_a_missing_function(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
) -> None:
    """When Ghidra finds no function at the address the failure is shown instead of the flags.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
    """
    bridge.reply_exec("func.hasNoReturn()", None)

    seen = answer_flags_dialog(wired, {"Inline": Qt.CheckState.Checked}, accept=True)
    dispatch(wired, bridge, actions, "flags")
    QCoreApplication.processEvents()

    qtbot.waitUntil(lambda: status(wired).startswith("Set function flags failed: "), timeout=_WAIT_MS)
    settle(wired)
    assert seen == [_FLAGS_TITLE]
    assert "No function at 0x401000" in status(wired)


def test_add_comment_action_sends_the_trimmed_comment_as_an_end_of_line_comment(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Adding a comment sends the trimmed text as an end-of-line comment at the clicked address and confirms it.

    Args:
        qtbot: pytest-qt fixture used to wait for the result.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt.
    """
    prompts = script_text_dialog(monkeypatch, {"Comment:": ("  entry point check  ", True)})
    bridge.reply_exec("cu.setComment(", None)
    bridge.reply_eval("cu.getComment(", "entry point check")

    dispatch(wired, bridge, actions, "add_cmt")

    qtbot.waitUntil(lambda: status(wired) == "Comment added", timeout=_WAIT_MS)
    settle(wired)
    assert [label for _, label, _ in prompts] == ["Comment:"]
    assert 'cu.setComment(CodeUnit.EOL_COMMENT, "entry point check")' in bridge.sent[0]
    assert f"addr = toAddr({_ADDR})" in bridge.sent[0]


@pytest.mark.parametrize(("typed", "accepted"), [("", True), ("   ", True), ("note", False)], ids=["empty", "blank", "cancelled"])
def test_add_comment_action_without_a_usable_answer_sends_nothing(
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
    typed: str,
    *,
    accepted: bool,
) -> None:
    """An empty comment, a blank comment or a cancelled prompt adds nothing.

    Args:
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt.
        typed: Text the prompt returns.
        accepted: Whether the prompt was accepted.
    """
    prompts = script_text_dialog(monkeypatch, {"Comment:": (typed, accepted)})

    dispatch(wired, bridge, actions, "add_cmt")

    assert len(prompts) == 1
    _assert_nothing_sent(wired, bridge)


def test_add_comment_action_reports_a_comment_that_did_not_round_trip(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the readback differs from the comment the failure is shown instead of the confirmation.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt.
    """
    _ = script_text_dialog(monkeypatch, {"Comment:": ("entry point check", True)})
    bridge.reply_exec("cu.setComment(", None)
    bridge.reply_eval("cu.getComment(", "something else")

    dispatch(wired, bridge, actions, "add_cmt")

    qtbot.waitUntil(lambda: status(wired).startswith("Add comment failed: "), timeout=_WAIT_MS)
    settle(wired)
    assert "did not round-trip" in status(wired)


def test_set_variable_type_action_splits_the_answer_at_the_first_colon(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ``name:type`` answer is split at the first colon, each half trimmed, and sent for the clicked function.

    Args:
        qtbot: pytest-qt fixture used to wait for the result.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt.
    """
    label = "Variable name:type (e.g. myVar:int):"
    _ = script_text_dialog(monkeypatch, {label: ("  myVar : unsigned int ", True)})
    bridge.reply_exec("var.setDataType(", reply=True)

    dispatch(wired, bridge, actions, "set_var")

    qtbot.waitUntil(lambda: status(wired) == "Variable type set", timeout=_WAIT_MS)
    settle(wired)
    assert 'var.getName() == "myVar"' in bridge.sent[0]
    assert '_ic_resolve_data_type(dtm, "unsigned int")' in bridge.sent[0]
    assert f"addr = toAddr({_ADDR})" in bridge.sent[0]


@pytest.mark.parametrize(("typed", "accepted"), [("no colon here", True), ("myVar:int", False)], ids=["no_colon", "cancelled"])
def test_set_variable_type_action_without_a_usable_answer_sends_nothing(
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
    typed: str,
    *,
    accepted: bool,
) -> None:
    """An answer without a colon, or a cancelled prompt, sets no type.

    Args:
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt.
        typed: Text the prompt returns.
        accepted: Whether the prompt was accepted.
    """
    prompts = script_text_dialog(monkeypatch, {"Variable name:type (e.g. myVar:int):": (typed, accepted)})

    dispatch(wired, bridge, actions, "set_var")

    assert len(prompts) == 1
    _assert_nothing_sent(wired, bridge)


def test_set_variable_type_action_reports_a_variable_ghidra_does_not_have(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When Ghidra finds no such variable the failure names it instead of confirming the change.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt.
    """
    _ = script_text_dialog(monkeypatch, {"Variable name:type (e.g. myVar:int):": ("ghost:int", True)})
    bridge.reply_exec("var.setDataType(", reply=False)

    dispatch(wired, bridge, actions, "set_var")

    qtbot.waitUntil(lambda: status(wired).startswith("Set variable type failed: "), timeout=_WAIT_MS)
    settle(wired)
    assert "Variable 'ghost' not found in function at 0x401000" in status(wired)


def test_rename_variable_action_splits_the_answer_at_the_first_colon(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ``name:new_name`` answer is split at the first colon, each half trimmed, and sent for the clicked function.

    Args:
        qtbot: pytest-qt fixture used to wait for the result.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt.
    """
    label = "Variable name:new_name (e.g. myVar:newName):"
    _ = script_text_dialog(monkeypatch, {label: (" local_8 : buffer_len ", True)})
    bridge.reply_exec("var.setName(", reply=True)

    dispatch(wired, bridge, actions, "rename_var")

    qtbot.waitUntil(lambda: status(wired) == "Variable renamed", timeout=_WAIT_MS)
    settle(wired)
    assert 'var.getName() == "local_8"' in bridge.sent[0]
    assert 'var.setName("buffer_len"' in bridge.sent[0]
    assert f"addr = toAddr({_ADDR})" in bridge.sent[0]


@pytest.mark.parametrize(("typed", "accepted"), [("no colon here", True), ("a:b", False)], ids=["no_colon", "cancelled"])
def test_rename_variable_action_without_a_usable_answer_sends_nothing(
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
    typed: str,
    *,
    accepted: bool,
) -> None:
    """An answer without a colon, or a cancelled prompt, renames nothing.

    Args:
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt.
        typed: Text the prompt returns.
        accepted: Whether the prompt was accepted.
    """
    prompts = script_text_dialog(monkeypatch, {"Variable name:new_name (e.g. myVar:newName):": (typed, accepted)})

    dispatch(wired, bridge, actions, "rename_var")

    assert len(prompts) == 1
    _assert_nothing_sent(wired, bridge)


def test_call_graph_action_switches_to_the_call_graph_tab_and_builds_the_tree(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
) -> None:
    """Showing the call graph selects its tab, fills the address field and builds the tree from the bridge's call tree.

    Args:
        qtbot: pytest-qt fixture used to wait for the tree.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
    """
    tree_payload: dict[str, object] = {
        "function": "main",
        "address": _ADDR,
        "children": [{"function": "helper", "address": 0x401100, "children": []}],
    }
    bridge.reply_exec("get_callee_tree(", tree_payload)
    tree = priv(wired, "_call_graph_tree", QTreeWidget)

    dispatch(wired, bridge, actions, "call_graph")

    qtbot.waitUntil(lambda: tree.topLevelItemCount() == 1, timeout=_WAIT_MS)
    settle(wired)
    assert priv(wired, "_data_tabs", QTabWidget).currentIndex() == _CALL_GRAPH_TAB
    assert priv(wired, "_cg_addr_input", QLineEdit).text() == "0x401000"
    assert tree_rows(tree) == [["main", "0x401000"]]
    top = tree.topLevelItem(0)
    assert top is not None
    assert top.childCount() == 1
    child = top.child(0)
    assert child is not None
    assert (child.text(0), child.text(1)) == ("helper", "0x401100")
    assert f"addr = toAddr({_ADDR})" in bridge.sent[0]
    assert 'direction = "callees"' in bridge.sent[0]


def test_call_graph_action_without_a_tab_widget_still_builds_the_tree(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
) -> None:
    """With no data-tab widget attached the call graph is still requested for the clicked address and no tab changes.

    The panel keeps its tab widget in a private attribute that is empty only before the tabs are built; it is cleared here to reach the
    guard that skips the tab switch.

    Args:
        qtbot: pytest-qt fixture used to wait for the tree.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
    """
    bridge.reply_exec("get_callee_tree(", {"function": "main", "address": _ADDR, "children": []})
    tabs = priv(wired, "_data_tabs", QTabWidget)
    before = tabs.currentIndex()
    setattr(wired, "_data_tabs", None)
    tree = priv(wired, "_call_graph_tree", QTreeWidget)

    dispatch(wired, bridge, actions, "call_graph")

    qtbot.waitUntil(lambda: tree.topLevelItemCount() == 1, timeout=_WAIT_MS)
    settle(wired)
    assert tabs.currentIndex() == before
    assert priv(wired, "_cg_addr_input", QLineEdit).text() == "0x401000"
    assert tree_rows(tree) == [["main", "0x401000"]]


def test_stack_action_shows_the_frame_the_bridge_returned(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asking for the stack frame sends the clicked address and shows the returned frame in a dialog titled Stack Frame.

    Args:
        qtbot: pytest-qt fixture used to wait for the dialog.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that records the dialog.
    """
    shown = record_information(monkeypatch)
    frame: dict[str, object] = {
        "function": "main",
        "frame_size": 32,
        "variables": [{"name": "local_8", "offset": -8, "size": 8, "type": "long"}],
    }
    bridge.reply_exec("func.getStackFrame()", frame)

    dispatch(wired, bridge, actions, "stack")

    qtbot.waitUntil(lambda: bool(shown), timeout=_WAIT_MS)
    settle(wired)
    assert shown == [("Stack Frame", str(frame))]
    assert f"addr = toAddr({_ADDR})" in bridge.sent[0]


def test_stack_action_reports_a_failure_in_the_status_bar(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused stack-frame request is shown in the status bar and opens no dialog.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that records the dialog.
    """
    shown = record_information(monkeypatch)
    bridge.reply_exec("func.getStackFrame()", ToolError("peer refused the frame"))

    dispatch(wired, bridge, actions, "stack")

    qtbot.waitUntil(lambda: status(wired) == "Stack frame failed: peer refused the frame", timeout=_WAIT_MS)
    settle(wired)
    assert shown == []


def test_body_action_shows_the_function_body(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asking for the function body sends the clicked address and shows name, address, size and ranges in a Function Body dialog.

    Args:
        qtbot: pytest-qt fixture used to wait for the dialog.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that records the dialog.
    """
    shown = record_information(monkeypatch)
    bridge.reply_exec("func.getBody()", dict(_BODY_PAYLOAD))

    dispatch(wired, bridge, actions, "body")

    qtbot.waitUntil(lambda: bool(shown), timeout=_WAIT_MS)
    settle(wired)
    assert shown == [("Function Body", _BODY_MESSAGE)]
    assert f"addr = toAddr({_ADDR})" in bridge.sent[0]


def test_body_action_without_a_payload_is_reported_in_the_status_bar(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When Ghidra returns no body the failure is shown in the status bar and no dialog opens.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that records the dialog.
    """
    shown = record_information(monkeypatch)
    bridge.reply_exec("func.getBody()", None)

    dispatch(wired, bridge, actions, "body")

    qtbot.waitUntil(lambda: status(wired).startswith("Function body failed: "), timeout=_WAIT_MS)
    settle(wired)
    assert "no payload" in status(wired)
    assert shown == []


def test_conventions_action_lists_the_calling_conventions_one_per_line(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The calling conventions Ghidra knows are shown one per line in a dialog titled Calling Conventions.

    Args:
        qtbot: pytest-qt fixture used to wait for the dialog.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that records the dialog.
    """
    shown = record_information(monkeypatch)
    bridge.reply_exec("getCallingConventions()", ["__cdecl", "__stdcall", "__fastcall"])

    dispatch(wired, bridge, actions, "conventions")

    qtbot.waitUntil(lambda: bool(shown), timeout=_WAIT_MS)
    settle(wired)
    assert shown == [("Calling Conventions", "__cdecl\n__stdcall\n__fastcall")]


def test_conventions_action_reports_a_failure_in_the_status_bar(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused request for the calling conventions is shown in the status bar and opens no dialog.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that records the dialog.
    """
    shown = record_information(monkeypatch)
    bridge.reply_exec("getCallingConventions()", ToolError("peer refused conventions"))

    dispatch(wired, bridge, actions, "conventions")

    qtbot.waitUntil(lambda: status(wired) == "Calling conventions failed: peer refused conventions", timeout=_WAIT_MS)
    settle(wired)
    assert shown == []


@pytest.mark.parametrize(
    ("typed", "color_int"),
    [("FF0000", 0xFF0000), ("  00ff7f  ", 0x00FF7F), ("0x123456", 0x123456)],
    ids=["red", "padded_lowercase", "prefixed"],
)
def test_set_color_action_reads_the_answer_as_a_hexadecimal_rgb_value(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
    typed: str,
    color_int: int,
) -> None:
    """The answer is a hexadecimal RGB value, sent as the integer it denotes for the clicked address, and the status confirms it.

    Args:
        qtbot: pytest-qt fixture used to wait for the result.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt.
        typed: Text the prompt returns.
        color_int: Colour the text denotes.
    """
    _ = script_text_dialog(monkeypatch, {"RGB color (e.g. FF0000 for red):": (typed, True)})
    bridge.reply_exec("isInHeadlessMode()", {"applied": True, "backend": "colorizing_service", "error": None, "headless": False})

    dispatch(wired, bridge, actions, "set_color")

    qtbot.waitUntil(lambda: status(wired) == "Color set at 0x401000", timeout=_WAIT_MS)
    settle(wired)
    assert f"color_int = {color_int}" in bridge.sent[0]
    assert f"addr = toAddr({_ADDR})" in bridge.sent[0]


def test_set_color_action_rejects_text_that_is_not_hexadecimal(
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Text that is not hexadecimal is reported in the status bar and nothing is sent.

    Args:
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt.
    """
    _ = script_text_dialog(monkeypatch, {"RGB color (e.g. FF0000 for red):": ("red", True)})

    dispatch(wired, bridge, actions, "set_color")

    assert status(wired) == "Invalid color hex value"
    _assert_nothing_sent(wired, bridge)


@pytest.mark.parametrize(("typed", "accepted"), [("", True), ("   ", True), ("FF0000", False)], ids=["empty", "blank", "cancelled"])
def test_set_color_action_without_a_usable_answer_does_nothing(
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
    typed: str,
    *,
    accepted: bool,
) -> None:
    """An empty answer, a blank answer or a cancelled prompt sends nothing and leaves the status alone.

    Args:
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt.
        typed: Text the prompt returns.
        accepted: Whether the prompt was accepted.
    """
    before = status(wired)
    prompts = script_text_dialog(monkeypatch, {"RGB color (e.g. FF0000 for red):": (typed, accepted)})

    dispatch(wired, bridge, actions, "set_color")

    assert len(prompts) == 1
    assert status(wired) == before
    _assert_nothing_sent(wired, bridge)


def test_set_color_action_reports_a_colour_ghidra_could_not_apply(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When Ghidra applies no colour the reason it gave is shown instead of the confirmation.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt.
    """
    _ = script_text_dialog(monkeypatch, {"RGB color (e.g. FF0000 for red):": ("FF0000", True)})
    bridge.reply_exec("isInHeadlessMode()", {"applied": False, "backend": "none", "error": "needs a colorizing service", "headless": True})

    dispatch(wired, bridge, actions, "set_color")

    qtbot.waitUntil(lambda: status(wired).startswith("Set color failed: "), timeout=_WAIT_MS)
    settle(wired)
    assert "needs a colorizing service" in status(wired)


def test_delete_action_asks_first_and_after_a_yes_deletes_and_reloads_the_list(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deleting asks for confirmation naming the function and its address, and after a Yes removes it and reloads the list.

    Args:
        qtbot: pytest-qt fixture used to wait for the reloaded list.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the question.
    """
    asked = answer_question(monkeypatch, QMessageBox.StandardButton.Yes)
    bridge.reply_exec("fm.removeFunction", {"exists": True, "name": "main", "removed": True})
    bridge.reply_exec("fm.getFunctions(True)", [function_payload("other", 0x402000, 8)])
    tree = priv(wired, "_func_tree", QTreeWidget)

    dispatch(wired, bridge, actions, "delete")

    qtbot.waitUntil(lambda: tree.topLevelItemCount() == 1, timeout=_WAIT_MS)
    settle(wired)
    assert asked == [("Delete Function", "Delete function 'main' at 0x401000?")]
    assert f"addr = toAddr({_ADDR})" in bridge.sent[0]
    assert tree_rows(tree) == [["other", "0x402000", "8"]]


def test_delete_action_after_a_no_deletes_nothing(
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Answering No to the confirmation sends nothing to Ghidra.

    Args:
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the question.
    """
    asked = answer_question(monkeypatch, QMessageBox.StandardButton.No)

    dispatch(wired, bridge, actions, "delete")

    assert len(asked) == 1
    _assert_nothing_sent(wired, bridge)


def test_delete_action_reports_a_function_ghidra_does_not_have(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When Ghidra has no function at the address the failure is shown and the list is not reloaded.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the question.
    """
    _ = answer_question(monkeypatch, QMessageBox.StandardButton.Yes)
    bridge.reply_exec("fm.removeFunction", {"exists": False, "name": None, "removed": False})

    dispatch(wired, bridge, actions, "delete")

    qtbot.waitUntil(lambda: status(wired).startswith("Delete failed: "), timeout=_WAIT_MS)
    settle(wired)
    assert "0x401000" in status(wired)
    assert len(bridge.sent) == 1


def test_an_action_the_function_menu_does_not_own_does_nothing(
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    actions: dict[str, QAction],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A chosen action that is none of the menu's entries opens no prompt and sends nothing.

    Args:
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        actions: Context-menu actions.
        monkeypatch: Fixture that replaces the prompt and the question.
    """
    prompts = script_text_dialog(monkeypatch, {})
    asked = answer_question(monkeypatch, QMessageBox.StandardButton.Yes)
    before = status(wired)

    call(wired, "_dispatch_func_menu_action", QAction("stranger", wired), actions, _ADDR, "main", bridge)

    assert prompts == []
    assert asked == []
    assert status(wired) == before
    _assert_nothing_sent(wired, bridge)


def test_func_menu_ignores_a_position_without_an_item(qtbot: QtBot, wired: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A right click on empty space in the function tree opens no menu and sends nothing.

    Args:
        qtbot: pytest-qt fixture used to show the panel.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    expose(qtbot, wired)
    offered = drive_menu(wired, None)

    call(wired, "_on_func_context_menu", QPoint(5, 5))
    QCoreApplication.processEvents()

    assert offered == []
    assert QApplication.activePopupWidget() is None
    _assert_nothing_sent(wired, bridge)


def test_func_menu_ignores_an_item_without_an_address(qtbot: QtBot, wired: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A row that carries no function address opens no menu and sends nothing.

    Args:
        qtbot: pytest-qt fixture used to show the panel.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    expose(qtbot, wired)
    tree = priv(wired, "_func_tree", QTreeWidget)
    item = QTreeWidgetItem(["plain", "", ""])
    tree.addTopLevelItem(item)
    offered = drive_menu(wired, None)

    call(wired, "_on_func_context_menu", tree.visualItemRect(item).center())
    QCoreApplication.processEvents()

    assert offered == []
    assert QApplication.activePopupWidget() is None
    _assert_nothing_sent(wired, bridge)


def test_func_menu_offers_every_function_action_and_dismissing_it_sends_nothing(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """The function menu offers the twelve actions in order with a separator before Delete, and closing it without a choice does nothing.

    Args:
        qtbot: pytest-qt fixture used to show the panel.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    point = select_function(qtbot, wired)
    offered = drive_menu(wired, None)

    call(wired, "_on_func_context_menu", point)
    QCoreApplication.processEvents()

    assert offered == _FUNC_MENU_CAPTIONS
    _assert_nothing_sent(wired, bridge)


def test_func_menu_choice_runs_the_action_for_the_clicked_function(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Choosing Get Function Body from the open menu asks Ghidra about the clicked function and shows the answer.

    Args:
        qtbot: pytest-qt fixture used to show the panel and wait for the dialog.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        monkeypatch: Fixture that records the dialog.
    """
    shown = record_information(monkeypatch)
    bridge.reply_exec("func.getBody()", dict(_BODY_PAYLOAD))
    point = select_function(qtbot, wired)
    offered = drive_menu(wired, "Get Function Body")

    call(wired, "_on_func_context_menu", point)

    qtbot.waitUntil(lambda: bool(shown), timeout=_WAIT_MS)
    settle(wired)
    assert offered == _FUNC_MENU_CAPTIONS
    assert shown == [("Function Body", _BODY_MESSAGE)]
    assert f"addr = toAddr({_ADDR})" in bridge.sent[0]


def test_func_menu_choice_with_a_bridge_that_is_not_connected_reports_it_and_asks_nothing(
    qtbot: QtBot,
    unconnected_panel: GhidraPanel,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A choice made after the connection is gone reports the missing connection and does not even open the action's prompt.

    Args:
        qtbot: pytest-qt fixture used to show the panel.
        unconnected_panel: Panel holding an untouched ``GhidraBridge``.
        monkeypatch: Fixture that replaces the prompt.
    """
    prompts = script_text_dialog(monkeypatch, {"New name:": ("renamed", True)})
    point = select_function(qtbot, unconnected_panel)
    offered = drive_menu(unconnected_panel, "Rename Function")

    call(unconnected_panel, "_on_func_context_menu", point)
    settle(unconnected_panel)

    assert offered == _FUNC_MENU_CAPTIONS
    assert status(unconnected_panel) == "Ghidra not connected"
    assert prompts == []
    assert bridge_workers_for(unconnected_panel) == []


def test_apply_imports_shows_dll_function_and_hex_address_and_replaces_stale_rows(panel: GhidraPanel) -> None:
    """Imports fill the table with DLL, function and uppercase hexadecimal address, replacing whatever was listed before.

    Args:
        panel: Panel without a bridge.
    """
    table = priv(panel, "_imports_table", QTableWidget)
    stale = ImportInfo(dll="old.dll", function="Old", ordinal=None, address=1)
    call(panel, "_apply_imports", [stale, stale, stale])
    assert table.rowCount() == 3

    call(
        panel,
        "_apply_imports",
        [
            ImportInfo(dll="KERNEL32.dll", function="CreateFileW", ordinal=None, address=0x7FF812340000),
            ImportInfo(dll="ntdll.dll", function="NtClose", ordinal=12, address=0x10),
        ],
    )

    assert rows(table) == [["KERNEL32.dll", "CreateFileW", "0x7FF812340000"], ["ntdll.dll", "NtClose", "0x10"]]


def test_apply_imports_without_a_list_empties_the_table(panel: GhidraPanel) -> None:
    """A result that is not a list leaves the imports table empty instead of keeping the previous rows.

    Args:
        panel: Panel without a bridge.
    """
    table = priv(panel, "_imports_table", QTableWidget)
    table.setRowCount(2)

    call(panel, "_apply_imports", None)

    assert table.rowCount() == 0


def test_apply_exports_shows_name_ordinal_and_hex_address_and_replaces_stale_rows(panel: GhidraPanel) -> None:
    """Exports fill the table with name, decimal ordinal and uppercase hexadecimal address, replacing whatever was listed before.

    Args:
        panel: Panel without a bridge.
    """
    table = priv(panel, "_exports_table", QTableWidget)
    stale = ExportInfo(name="old", ordinal=1, address=1)
    call(panel, "_apply_exports", [stale, stale])
    assert table.rowCount() == 2

    call(
        panel,
        "_apply_exports",
        [ExportInfo(name="DllMain", ordinal=7, address=0x180001000), ExportInfo(name="Other", ordinal=300, address=0x18000ABCD)],
    )

    assert rows(table) == [["DllMain", "7", "0x180001000"], ["Other", "300", "0x18000ABCD"]]


def test_apply_exports_without_a_list_empties_the_table(panel: GhidraPanel) -> None:
    """A result that is not a list leaves the exports table empty instead of keeping the previous rows.

    Args:
        panel: Panel without a bridge.
    """
    table = priv(panel, "_exports_table", QTableWidget)
    table.setRowCount(2)

    call(panel, "_apply_exports", "unexpected")

    assert table.rowCount() == 0


def test_refresh_imports_lists_what_the_bridge_returns(qtbot: QtBot, wired: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Refreshing imports asks Ghidra for its external symbols and fills the table with the parsed result.

    Args:
        qtbot: pytest-qt fixture used to wait for the table.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec(
        "getExternalSymbols()",
        [
            {"dll": "KERNEL32.dll", "function": "CreateFileW", "address": 0x1000},
            {"dll": "USER32.dll", "function": "MessageBoxW", "address": 0x1008},
        ],
    )
    table = priv(wired, "_imports_table", QTableWidget)

    call(wired, "_refresh_imports")

    qtbot.waitUntil(lambda: table.rowCount() == 2, timeout=_WAIT_MS)
    settle(wired)
    assert rows(table) == [["KERNEL32.dll", "CreateFileW", "0x1000"], ["USER32.dll", "MessageBoxW", "0x1008"]]


def test_refresh_imports_failure_is_reported_in_the_status_bar(qtbot: QtBot, wired: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A refused imports request is shown in the status bar and leaves the table as it was.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("getExternalSymbols()", ToolError("peer refused imports"))
    table = priv(wired, "_imports_table", QTableWidget)
    table.setRowCount(1)

    call(wired, "_refresh_imports")

    qtbot.waitUntil(lambda: status(wired) == "Imports refresh failed: peer refused imports", timeout=_WAIT_MS)
    settle(wired)
    assert table.rowCount() == 1


def test_refresh_exports_lists_what_the_bridge_returns(qtbot: QtBot, wired: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Refreshing exports asks Ghidra for its entry-point symbols and fills the table with their names and addresses.

    Args:
        qtbot: pytest-qt fixture used to wait for the table.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec(
        "isExternalEntryPoint()",
        [{"name": "DllMain", "address": 0x180001000}, {"name": "Other", "address": 0x180002000}],
    )
    table = priv(wired, "_exports_table", QTableWidget)

    call(wired, "_refresh_exports")

    qtbot.waitUntil(lambda: table.rowCount() == 2, timeout=_WAIT_MS)
    settle(wired)
    assert [(row[0], row[2]) for row in rows(table)] == [("DllMain", "0x180001000"), ("Other", "0x180002000")]


def test_refresh_exports_failure_is_reported_in_the_status_bar(qtbot: QtBot, wired: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A refused exports request is shown in the status bar and leaves the table as it was.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("isExternalEntryPoint()", ToolError("peer refused exports"))
    table = priv(wired, "_exports_table", QTableWidget)
    table.setRowCount(1)

    call(wired, "_refresh_exports")

    qtbot.waitUntil(lambda: status(wired) == "Exports refresh failed: peer refused exports", timeout=_WAIT_MS)
    settle(wired)
    assert table.rowCount() == 1


def test_apply_strings_shows_address_value_section_and_encoding_and_enables_the_button(panel: GhidraPanel) -> None:
    """Found strings fill the table with hex address, value, section and encoding, replacing stale rows, and re-enable Search.

    Args:
        panel: Panel without a bridge.
    """
    table = priv(panel, "_strings_table", QTableWidget)
    button = priv(panel, "_string_search_btn", QPushButton)
    stale = StringInfo(address=1, value="old", encoding="ascii", section=".old")
    call(panel, "_apply_strings", [stale, stale, stale])
    assert table.rowCount() == 3
    button.setEnabled(False)

    call(
        panel,
        "_apply_strings",
        [
            StringInfo(address=0x403000, value="hello world", encoding="ascii", section=".rdata"),
            StringInfo(address=0x404010, value="wide", encoding="utf-16le", section=".data"),
        ],
    )

    assert rows(table) == [["0x403000", "hello world", ".rdata", "ascii"], ["0x404010", "wide", ".data", "utf-16le"]]
    assert button.isEnabled()


def test_apply_strings_without_a_list_empties_the_table_and_enables_the_button(panel: GhidraPanel) -> None:
    """A result that is not a list empties the strings table and still re-enables Search.

    Args:
        panel: Panel without a bridge.
    """
    table = priv(panel, "_strings_table", QTableWidget)
    button = priv(panel, "_string_search_btn", QPushButton)
    table.setRowCount(2)
    button.setEnabled(False)

    call(panel, "_apply_strings", None)

    assert table.rowCount() == 0
    assert button.isEnabled()


def test_search_strings_disables_the_button_and_fills_the_table_from_the_bridge(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Searching disables Search while the request runs, sends the pattern, and fills the table with the matches when it returns.

    Args:
        qtbot: pytest-qt fixture used to wait for the table.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("hasStringValue()", [{"address": 0x403000, "value": "hello world", "type_name": "string"}])
    table = priv(wired, "_strings_table", QTableWidget)
    button = priv(wired, "_string_search_btn", QPushButton)
    assert button.isEnabled()

    call(wired, "search_strings", "hello")

    assert not button.isEnabled()
    qtbot.waitUntil(lambda: table.rowCount() == 1, timeout=_WAIT_MS)
    settle(wired)
    row = rows(table)[0]
    assert (row[0], row[1], row[3]) == ("0x403000", "hello world", "ascii")
    assert button.isEnabled()
    assert 're.compile("hello"' in bridge.sent[0]


def test_search_strings_failure_enables_the_button_and_keeps_the_rows(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """A refused search re-enables Search and leaves the previous results in place.

    Args:
        qtbot: pytest-qt fixture used to wait for the button.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("hasStringValue()", ToolError("peer refused the search"))
    table = priv(wired, "_strings_table", QTableWidget)
    button = priv(wired, "_string_search_btn", QPushButton)
    call(wired, "_apply_strings", [StringInfo(address=0x403000, value="kept", encoding="ascii", section=".rdata")])
    button.setEnabled(True)

    call(wired, "search_strings", "needle")

    assert not button.isEnabled()
    qtbot.waitUntil(button.isEnabled, timeout=_WAIT_MS)
    settle(wired)
    assert rows(table) == [["0x403000", "kept", ".rdata", "ascii"]]
    assert len(bridge.sent) == 1


@pytest.mark.parametrize("typed", ["hello", "  hello  "], ids=["plain", "padded"])
def test_search_input_sends_the_trimmed_pattern(qtbot: QtBot, wired: GhidraPanel, bridge: ScriptedGhidraBridge, typed: str) -> None:
    """The search box sends its trimmed text as the pattern when Search or Return is used.

    Args:
        qtbot: pytest-qt fixture used to wait for the result.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        typed: Text typed into the search box.
    """
    bridge.reply_exec("hasStringValue()", [])
    button = priv(wired, "_string_search_btn", QPushButton)
    fill(wired, "_string_search_input", typed)

    call(wired, "_on_search_strings")

    qtbot.waitUntil(lambda: len(bridge.sent) == 1 and button.isEnabled(), timeout=_WAIT_MS)
    settle(wired)
    assert 're.compile("hello", re.IGNORECASE)' in bridge.sent[0]


@pytest.mark.parametrize("typed", ["", "   "], ids=["empty", "blank"])
def test_search_input_without_text_searches_nothing(wired: GhidraPanel, bridge: ScriptedGhidraBridge, typed: str) -> None:
    """An empty or blank search box starts no search and leaves Search enabled.

    Args:
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        typed: Text typed into the search box.
    """
    button = priv(wired, "_string_search_btn", QPushButton)
    fill(wired, "_string_search_input", typed)

    call(wired, "_on_search_strings")

    assert button.isEnabled()
    _assert_nothing_sent(wired, bridge)


def test_apply_xrefs_to_lists_each_caller_with_its_address_type_and_function(panel: GhidraPanel) -> None:
    """Each reference to the address becomes a To row with the caller's address, the reference type and the caller's function.

    Args:
        panel: Panel without a bridge.
    """
    tree = priv(panel, "_xrefs_tree", QTreeWidget)

    call(
        panel,
        "_apply_xrefs_to",
        [
            CrossReference(from_address=0x402000, to_address=_ADDR, ref_type="call", from_function="caller_fn", to_function="target"),
            CrossReference(from_address=0x7FF812340000, to_address=_ADDR, ref_type="data", from_function=None, to_function=None),
        ],
    )

    assert tree_rows(tree) == [["To", "0x402000", "call", "caller_fn"], ["To", "0x7FF812340000", "data", ""]]


def test_apply_xrefs_from_lists_each_callee_with_its_address_type_and_function(panel: GhidraPanel) -> None:
    """Each reference from the address becomes a From row with the target's address, the reference type and the target's function.

    Args:
        panel: Panel without a bridge.
    """
    tree = priv(panel, "_xrefs_tree", QTreeWidget)

    call(
        panel,
        "_apply_xrefs_from",
        [
            CrossReference(from_address=_ADDR, to_address=0x403000, ref_type="jump", from_function="target", to_function="callee_fn"),
            CrossReference(from_address=_ADDR, to_address=0x403100, ref_type="read", from_function="target", to_function=None),
        ],
    )

    assert tree_rows(tree) == [["From", "0x403000", "jump", "callee_fn"], ["From", "0x403100", "read", ""]]


def test_show_xrefs_lists_callers_and_callees_from_the_bridge(qtbot: QtBot, wired: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Showing references asks Ghidra both directions for the address and lists the callers and callees it returns.

    Args:
        qtbot: pytest-qt fixture used to wait for the tree.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec(
        "getReferencesTo(",
        [{"from": 0x402000, "to": _ADDR, "type": "UNCONDITIONAL_CALL", "from_function": "caller_fn", "to_function": "target"}],
    )
    bridge.reply_exec(
        "getReferencesFrom(",
        [{"from": _ADDR, "to": 0x403000, "type": "UNCONDITIONAL_JUMP", "from_function": "target", "to_function": "callee_fn"}],
    )
    tree = priv(wired, "_xrefs_tree", QTreeWidget)

    call(wired, "show_xrefs", _ADDR)

    qtbot.waitUntil(lambda: tree.topLevelItemCount() == 2, timeout=_WAIT_MS)
    settle(wired)
    assert sorted(tree_rows(tree)) == [["From", "0x403000", "jump", "callee_fn"], ["To", "0x402000", "call", "caller_fn"]]
    assert all(f"addr = toAddr({_ADDR})" in script for script in bridge.sent)
    assert len(bridge.sent) == 2


def test_show_xrefs_failure_names_the_failed_lookup_in_the_status_bar(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """A refused references-to lookup is shown in the status bar by name while the other direction still lists its result.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("getReferencesTo(", ToolError("xrefs to refused"))
    bridge.reply_exec("getReferencesFrom(", [])
    tree = priv(wired, "_xrefs_tree", QTreeWidget)

    call(wired, "show_xrefs", _ADDR)

    qtbot.waitUntil(lambda: status(wired) == "Xrefs-to lookup failed: xrefs to refused", timeout=_WAIT_MS)
    settle(wired)
    assert tree_rows(tree) == [["From", "—", "—", "(no callees)"]]


def test_apply_labels_shows_name_hex_address_and_type_and_replaces_stale_rows(panel: GhidraPanel) -> None:
    """Labels fill the table with name, uppercase hexadecimal address and symbol type, replacing whatever was listed before.

    Args:
        panel: Panel without a bridge.
    """
    table = priv(panel, "_labels_table", QTableWidget)
    call(panel, "_apply_labels", [{"name": "old", "address": 1, "type": "Label"}] * 3)
    assert table.rowCount() == 3

    call(panel, "_apply_labels", _LABELS)

    assert rows(table) == [["main", "0x401000", "Function"], ["loc_401004", "0x401004", "Label"]]


def test_apply_bookmarks_shows_address_category_comment_and_type_and_replaces_stale_rows(panel: GhidraPanel) -> None:
    """Bookmarks fill the table with hex address, category, comment and type, replacing whatever was listed before.

    Args:
        panel: Panel without a bridge.
    """
    table = priv(panel, "_bookmarks_table", QTableWidget)
    call(panel, "_apply_bookmarks", [{"address": 1, "category": "old", "comment": "old", "type": "Note"}] * 2)
    assert table.rowCount() == 2

    call(panel, "_apply_bookmarks", _BOOKMARKS)

    assert rows(table) == [["0x401000", "Crack", "patch here", "Warning"], ["0x401008", "Analysis", "checked", "Note"]]


def _set_row(table: QTableWidget, cells: tuple[str | None, ...]) -> None:
    """Replace the table's content with one row and make it the current row.

    Args:
        table: Table to fill.
        cells: Text of each cell, or None to leave the cell without an item.
    """
    table.setRowCount(0)
    table.insertRow(0)
    for column, text in enumerate(cells):
        if text is not None:
            table.setItem(0, column, QTableWidgetItem(text))
    table.setCurrentCell(0, 0)
    assert table.currentRow() == 0


@pytest.mark.parametrize(
    "cells",
    [("main", "zz", "Function"), ("main", None, "Function")],
    ids=["unparsable_address", "missing_address_cell"],
)
def test_remove_label_with_an_unusable_address_cell_reports_it_and_sends_nothing(
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    cells: tuple[str | None, ...],
) -> None:
    """A selected label row whose address cell is empty or not a number is reported and nothing is removed.

    Args:
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        cells: Cell texts of the selected row.
    """
    _set_row(priv(wired, "_labels_table", QTableWidget), cells)

    call(wired, "_on_remove_label")

    assert status(wired) == "Selected label row has an invalid address"
    _assert_nothing_sent(wired, bridge)


@pytest.mark.parametrize(
    ("cells", "expected"),
    [
        (None, "Select a label row first"),
        (("main", "zz", "Function"), "Selected label row has an invalid address"),
        (("main", None, "Function"), "Selected label row has an invalid address"),
    ],
    ids=["no_row", "unparsable_address", "missing_address_cell"],
)
def test_promote_without_a_usable_selection_reports_it_and_sends_nothing(
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    cells: tuple[str | None, ...] | None,
    expected: str,
) -> None:
    """Promoting with no selected row, or a row whose address cell is unusable, is reported and nothing is promoted.

    Args:
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        cells: Cell texts of the selected row, or None for no row.
        expected: Status text the selection problem must show.
    """
    table = priv(wired, "_labels_table", QTableWidget)
    if cells is None:
        table.setRowCount(0)
        assert table.currentRow() == -1
    else:
        _set_row(table, cells)

    call(wired, "_on_promote_symbol_to_primary")

    assert status(wired) == expected
    _assert_nothing_sent(wired, bridge)


def test_promote_sends_the_selected_label_and_reloads_the_labels(qtbot: QtBot, wired: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """Promoting the selected label sends its address and name, then reloads the labels around the typed address.

    Args:
        qtbot: pytest-qt fixture used to wait for the reloaded table.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("already_primary", {"promoted": True, "already_primary": False})
    bridge.reply_exec("getSymbolIterator", [{"name": "loc_401004", "address": _ADDR + 4, "type": "Label"}])
    fill(wired, "_label_addr_input", "0x401000")
    table = priv(wired, "_labels_table", QTableWidget)
    call(wired, "_apply_labels", _LABELS)
    table.setCurrentCell(1, 0)

    call(wired, "_on_promote_symbol_to_primary")

    qtbot.waitUntil(lambda: rows(table) == [["loc_401004", "0x401004", "Label"]], timeout=_WAIT_MS)
    settle(wired)
    assert f"addr = toAddr({_ADDR + 4})" in bridge.sent[0]
    assert 'target_name = "loc_401004"' in bridge.sent[0]
    assert len(bridge.sent) == 2


def test_promote_failure_is_reported_in_the_status_bar(qtbot: QtBot, wired: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """When Ghidra promotes nothing the failure is shown in the status bar and the labels are not reloaded.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("already_primary", {"promoted": False, "already_primary": False})
    table = priv(wired, "_labels_table", QTableWidget)
    call(wired, "_apply_labels", _LABELS)
    table.setCurrentCell(0, 0)

    call(wired, "_on_promote_symbol_to_primary")

    qtbot.waitUntil(lambda: status(wired).startswith("Promote symbol failed: "), timeout=_WAIT_MS)
    settle(wired)
    assert "No symbol named 'main' found at 0x401000" in status(wired)
    assert len(bridge.sent) == 1


def test_label_menu_ignores_a_position_without_an_item(qtbot: QtBot, wired: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A right click on empty space in the labels table opens no menu and sends nothing.

    Args:
        qtbot: pytest-qt fixture used to show the panel.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    priv(wired, "_data_tabs", QTabWidget).setCurrentIndex(_LABELS_TAB)
    expose(qtbot, wired)
    offered = drive_menu(wired, None)

    call(wired, "_on_label_context_menu", QPoint(5, 5))
    QCoreApplication.processEvents()

    assert offered == []
    assert QApplication.activePopupWidget() is None
    _assert_nothing_sent(wired, bridge)


def test_label_menu_selects_the_clicked_row_and_dismissing_it_sends_nothing(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """The label menu offers Remove and Promote, makes the clicked row current, and closing it without a choice does nothing.

    Args:
        qtbot: pytest-qt fixture used to show the panel.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    call(wired, "_apply_labels", _LABELS)
    point = select_table_row(qtbot, wired, "_labels_table", 1)
    offered = drive_menu(wired, None)

    call(wired, "_on_label_context_menu", point)
    QCoreApplication.processEvents()

    assert offered == ["Remove Label", "Promote to Primary"]
    assert priv(wired, "_labels_table", QTableWidget).currentRow() == 1
    _assert_nothing_sent(wired, bridge)


def test_label_menu_remove_removes_the_clicked_label_and_reloads_the_labels(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Choosing Remove Label sends the address and name of the clicked row, then reloads the labels around the typed address.

    Args:
        qtbot: pytest-qt fixture used to show the panel and wait for the reloaded table.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("sym.delete()", {"removed": True})
    bridge.reply_exec("getSymbolIterator", [{"name": "main", "address": _ADDR, "type": "Function"}])
    fill(wired, "_label_addr_input", "0x401000")
    table = priv(wired, "_labels_table", QTableWidget)
    call(wired, "_apply_labels", _LABELS)
    point = select_table_row(qtbot, wired, "_labels_table", 1)
    drive_menu(wired, "Remove Label")

    call(wired, "_on_label_context_menu", point)

    qtbot.waitUntil(lambda: rows(table) == [["main", "0x401000", "Function"]], timeout=_WAIT_MS)
    settle(wired)
    assert f"addr = toAddr({_ADDR + 4})" in bridge.sent[0]
    assert 'target_name = "loc_401004"' in bridge.sent[0]
    assert len(bridge.sent) == 2


def test_label_menu_promote_promotes_the_clicked_label_and_reloads_the_labels(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Choosing Promote to Primary sends the address and name of the clicked row, then reloads the labels around the typed address.

    Args:
        qtbot: pytest-qt fixture used to show the panel and wait for the reloaded table.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("already_primary", {"promoted": True, "already_primary": False})
    bridge.reply_exec("getSymbolIterator", [{"name": "loc_401004", "address": _ADDR + 4, "type": "Label"}])
    fill(wired, "_label_addr_input", "0x401000")
    table = priv(wired, "_labels_table", QTableWidget)
    call(wired, "_apply_labels", _LABELS)
    point = select_table_row(qtbot, wired, "_labels_table", 1)
    drive_menu(wired, "Promote to Primary")

    call(wired, "_on_label_context_menu", point)

    qtbot.waitUntil(lambda: rows(table) == [["loc_401004", "0x401004", "Label"]], timeout=_WAIT_MS)
    settle(wired)
    assert f"addr = toAddr({_ADDR + 4})" in bridge.sent[0]
    assert 'target_name = "loc_401004"' in bridge.sent[0]
    assert len(bridge.sent) == 2


def test_create_bookmark_sends_the_trimmed_fields_and_the_chosen_type_then_reloads_the_bookmarks(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Creating a bookmark sends address, trimmed category and comment and the chosen type, then reloads the bookmark list.

    Args:
        qtbot: pytest-qt fixture used to wait for the reloaded table.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("bm.setBookmark(", None)
    bridge.reply_eval("getBookmarks(", [["Crack", "patch here"]])
    bridge.reply_exec("getBookmarksIterator", [_BOOKMARKS[0]])
    fill(wired, "_bm_addr_input", "0x401000")
    fill(wired, "_bm_category_input", "  Crack ")
    fill(wired, "_bm_comment_input", " patch here  ")
    priv(wired, "_bm_type_combo", QComboBox).setCurrentText("Warning")
    table = priv(wired, "_bookmarks_table", QTableWidget)

    call(wired, "_on_create_bookmark")

    qtbot.waitUntil(lambda: table.rowCount() == 1, timeout=_WAIT_MS)
    settle(wired)
    assert f'bm.setBookmark(toAddr({_ADDR}), "Warning", "Crack", "patch here")' in bridge.sent[0]
    assert rows(table) == [["0x401000", "Crack", "patch here", "Warning"]]


def test_create_bookmark_not_confirmed_by_ghidra_is_reported_and_the_list_is_left_alone(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """When the readback does not show the bookmark the failure is shown and the bookmark list is not reloaded.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("bm.setBookmark(", None)
    bridge.reply_eval("getBookmarks(", [])
    fill(wired, "_bm_addr_input", "0x401000")
    fill(wired, "_bm_category_input", "Crack")

    call(wired, "_on_create_bookmark")

    qtbot.waitUntil(lambda: status(wired).startswith("Create bookmark failed: "), timeout=_WAIT_MS)
    settle(wired)
    assert "Bookmark verification failed" in status(wired)
    assert len(bridge.sent) == 1


@pytest.mark.parametrize(
    ("cells", "expected"),
    [
        (None, "Select a bookmark row first"),
        (("0x401000", "Crack", "patch here", "Warning"), None),
        (("zz", "Crack", "patch here", "Warning"), "Selected bookmark row has an invalid address"),
        ((None, "Crack", "patch here", "Warning"), "Selected bookmark row has an invalid address"),
    ],
    ids=["no_row", "usable_row", "unparsable_address", "missing_address_cell"],
)
def test_remove_bookmark_selection_problems_are_reported_and_a_usable_row_is_sent(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    cells: tuple[str | None, ...] | None,
    expected: str | None,
) -> None:
    """Removing with no selected row, or an unusable address cell, is reported and nothing is removed; a usable row is sent.

    Args:
        qtbot: pytest-qt fixture used to wait for a usable row's result.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
        cells: Cell texts of the selected row, or None for no row.
        expected: Status text the selection problem must show, or None when the row is usable.
    """
    bridge.reply_exec("bm.removeBookmark(bk)", {"removed": 1})
    bridge.reply_exec("getBookmarksIterator", [])
    table = priv(wired, "_bookmarks_table", QTableWidget)
    if cells is None:
        table.setRowCount(0)
        assert table.currentRow() == -1
    else:
        _set_row(table, cells)

    call(wired, "_on_remove_bookmark")

    if expected is None:
        qtbot.waitUntil(lambda: len(bridge.sent) == 2, timeout=_WAIT_MS)
        settle(wired)
        assert f"addr = toAddr({_ADDR})" in bridge.sent[0]
    else:
        assert status(wired) == expected
        _assert_nothing_sent(wired, bridge)


def test_remove_bookmark_without_category_or_type_removes_every_bookmark_at_the_address(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Empty category and type cells are sent as no filter, so every bookmark at the row's address is removed.

    Args:
        qtbot: pytest-qt fixture used to wait for the reload.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("bm.removeBookmark(bk)", {"removed": 2})
    bridge.reply_exec("getBookmarksIterator", [])
    table = priv(wired, "_bookmarks_table", QTableWidget)
    call(wired, "_apply_bookmarks", [{"address": _ADDR, "category": "", "comment": "x", "type": ""}])
    table.setCurrentCell(0, 0)

    call(wired, "_on_remove_bookmark")

    qtbot.waitUntil(lambda: len(bridge.sent) == 2, timeout=_WAIT_MS)
    settle(wired)
    assert "cat_filter = None" in bridge.sent[0]
    assert "type_filter = None" in bridge.sent[0]
    assert table.rowCount() == 0


def test_bookmark_menu_ignores_a_position_without_an_item(qtbot: QtBot, wired: GhidraPanel, bridge: ScriptedGhidraBridge) -> None:
    """A right click on empty space in the bookmarks table opens no menu and sends nothing.

    Args:
        qtbot: pytest-qt fixture used to show the panel.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    priv(wired, "_data_tabs", QTabWidget).setCurrentIndex(_LABELS_TAB)
    expose(qtbot, wired)
    offered = drive_menu(wired, None)

    call(wired, "_on_bookmark_context_menu", QPoint(5, 5))
    QCoreApplication.processEvents()

    assert offered == []
    assert QApplication.activePopupWidget() is None
    _assert_nothing_sent(wired, bridge)


def test_bookmark_menu_selects_the_clicked_row_and_dismissing_it_sends_nothing(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """The bookmark menu offers Remove, makes the clicked row current, and closing it without a choice does nothing.

    Args:
        qtbot: pytest-qt fixture used to show the panel.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    call(wired, "_apply_bookmarks", _BOOKMARKS)
    point = select_table_row(qtbot, wired, "_bookmarks_table", 1)
    offered = drive_menu(wired, None)

    call(wired, "_on_bookmark_context_menu", point)
    QCoreApplication.processEvents()

    assert offered == ["Remove Bookmark"]
    assert priv(wired, "_bookmarks_table", QTableWidget).currentRow() == 1
    _assert_nothing_sent(wired, bridge)


def test_bookmark_menu_remove_removes_the_clicked_bookmark_and_reloads_the_bookmarks(
    qtbot: QtBot,
    wired: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Choosing Remove Bookmark sends the address, category and type of the clicked row, then reloads the bookmark list.

    Args:
        qtbot: pytest-qt fixture used to show the panel and wait for the reloaded table.
        wired: Panel holding the ready scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.reply_exec("bm.removeBookmark(bk)", {"removed": 1})
    bridge.reply_exec("getBookmarksIterator", [_BOOKMARKS[0]])
    table = priv(wired, "_bookmarks_table", QTableWidget)
    call(wired, "_apply_bookmarks", _BOOKMARKS)
    point = select_table_row(qtbot, wired, "_bookmarks_table", 1)
    drive_menu(wired, "Remove Bookmark")

    call(wired, "_on_bookmark_context_menu", point)

    qtbot.waitUntil(lambda: rows(table) == [["0x401000", "Crack", "patch here", "Warning"]], timeout=_WAIT_MS)
    settle(wired)
    assert f"addr = toAddr({_ADDR + 8})" in bridge.sent[0]
    assert 'cat_filter = "Analysis"' in bridge.sent[0]
    assert 'type_filter = "Note"' in bridge.sent[0]
    assert len(bridge.sent) == 2


@pytest.mark.parametrize(
    ("answers", "asked"),
    [
        ({"Field name:": ("", True)}, ["Field name:"]),
        ({"Field name:": ("   ", True)}, ["Field name:"]),
        ({"Field name:": ("size", False)}, ["Field name:"]),
        ({"Field name:": ("size", True), "Field type:": ("", True)}, ["Field name:", "Field type:"]),
        ({"Field name:": ("size", True), "Field type:": ("   ", True)}, ["Field name:", "Field type:"]),
        ({"Field name:": ("size", True), "Field type:": ("int", False)}, ["Field name:", "Field type:"]),
    ],
    ids=["empty_name", "blank_name", "cancelled_name", "empty_type", "blank_type", "cancelled_type"],
)
def test_add_struct_field_without_a_usable_name_and_type_adds_nothing(
    panel: GhidraPanel,
    monkeypatch: pytest.MonkeyPatch,
    answers: dict[str, tuple[str, bool]],
    asked: list[str],
) -> None:
    """An empty, blank or cancelled field name or type ends the question sequence and leaves the pending fields and their label untouched.

    Args:
        panel: Panel without a bridge.
        monkeypatch: Fixture that replaces the prompts.
        answers: Scripted answers by prompt label.
        asked: Labels that must have been asked, in order.
    """
    prompts = script_text_dialog(monkeypatch, answers)

    call(panel, "_on_add_struct_field")

    assert [label for _, label, _ in prompts] == asked
    assert priv(panel, "_struct_fields_list", list[tuple[str, str]]) == []
    assert not priv(panel, "_struct_fields_label", QLabel).text()
