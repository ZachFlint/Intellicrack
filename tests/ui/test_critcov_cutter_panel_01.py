# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage tests for the Cutter panel's guards, dialogs, navigation, console and data-view handlers.

Every test drives a real ``CutterPanel`` under the offscreen ``QApplication``. Bridge-facing behavior runs against real ``CutterBridge``
objects: a bridge that never loaded a binary (it raises the documented ``no binary loaded`` error for every request), a
``RecordingBridge`` subclass that answers the panel's requests from scripted data and records the arguments it received, and, in the
tests marked ``spawns_process``, a bridge backed by the radare2 process loaded with a real System32 DLL. Expected values come from the
documented contract of each handler (status texts, the column layout of each table, the signed-delta convention of the seek buttons,
the argument order of the bridge calls) and from the bytes of the DLL on disk, never from reading the value back out of the code under
test. Qt's static dialog functions are replaced with plain functions that return a chosen answer, so no modal dialog ever opens.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, Literal, cast, override

import pytest
from PyQt6.QtCore import QCoreApplication, QPoint, QSettings, Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QInputDialog,
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
from intellicrack.bridges.cutter import CutterBridge
from intellicrack.core.types import CrossReference, ExportInfo, FunctionInfo, StringInfo, ToolError
from intellicrack.ui.panels.async_bridge import bridge_workers_for, drain_bridge_workers_for, run_bridge_coroutine
from intellicrack.ui.panels.cutter_panel import CutterPanel
from intellicrack.ui.panels.graph_view import CFGGraphView


if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")

_WAIT_MS: Final[int] = 30_000
_LIVE_WAIT_MS: Final[int] = 240_000
_LIVE_TIMEOUT_S: Final[float] = 240.0
_NO_BINARY: Final[str] = "no binary loaded"
_EM_DASH: Final[str] = "—"
_DEFAULT_SPLIT_SIZES: Final[list[int]] = [400, 250, 150]
_SETTINGS_ORG: Final[str] = "Intellicrack"
_SETTINGS_APP: Final[str] = "CutterPanel"
_SETTINGS_KEY: Final[str] = "outer_splitter_sizes"
_DECOMPILE_PLACEHOLDER: Final[str] = "// No decompilation available at this address"

_parse_address = cast("Callable[[str], int | None]", getattr(CutterPanel, "_parse_address"))
_load_outer_splitter_sizes = cast("Callable[[], list[int]]", getattr(CutterPanel, "_load_outer_splitter_sizes"))


class RecordingBridge(CutterBridge):
    """Real ``CutterBridge`` subclass that records panel requests and answers them from scripted data.

    Only the request methods the panel calls are overridden. Each override records its name and arguments in :attr:`recorded`, raises a
    ``ToolError`` when :attr:`script_failures` holds a message for that method, and otherwise returns the scripted value. No radare2
    process is involved, so the panel's reaction to every kind of answer can be driven deterministically.
    """

    def __init__(self) -> None:
        """Create a bridge that reports a loaded binary and answers every request with empty data."""
        super().__init__()
        self.state.binary_loaded = True
        self.recorded: list[tuple[str, tuple[object, ...]]] = []
        self.script_failures: dict[str, str] = {}
        self.script_functions: list[FunctionInfo] = []
        self.script_decompiled: str = ""
        self.script_disassembly: list[DisassemblyLine] = []
        self.script_graph: list[dict[str, Any]] = []
        self.script_xrefs_to: list[CrossReference] = []
        self.script_xrefs_from: list[CrossReference] = []
        self.script_strings: list[StringInfo] = []
        self.script_exports: list[ExportInfo] = []
        self.script_commands: dict[str, str] = {}
        self.script_history_output: str = ""
        self.script_function_address: int | None = None
        self.script_bytes: bytes = b""

    def _script_enter(self, name: str, *args: object) -> None:
        """Record one request and raise the scripted failure for it, if any.

        Args:
            name: Name of the bridge method that was called.
            *args: Arguments the panel passed.

        Raises:
            ToolError: When a failure message is scripted for ``name``.
        """
        self.recorded.append((name, args))
        message = self.script_failures.get(name)
        if message is not None:
            raise ToolError(message)

    @override
    async def get_functions(self, filter_pattern: str | None = None) -> list[FunctionInfo]:
        """Return the scripted functions.

        Args:
            filter_pattern: Name filter the panel sent.

        Returns:
            list[FunctionInfo]: Copy of the scripted function list.
        """
        self._script_enter("get_functions", filter_pattern)
        return list(self.script_functions)

    @override
    async def decompile(self, address: int, backend: Literal["pdg", "pdd"] = "pdg") -> str:
        """Return the scripted decompiler text.

        Args:
            address: Function address.
            backend: Decompiler backend the panel selected.

        Returns:
            str: The scripted decompiled text.
        """
        self._script_enter("decompile", address, backend)
        return self.script_decompiled

    @override
    async def disassemble(self, address: int, count: int = 20) -> list[DisassemblyLine]:
        """Return the scripted disassembly.

        Args:
            address: Start address.
            count: Instruction count (not part of what the panel chooses).

        Returns:
            list[DisassemblyLine]: Copy of the scripted instruction list.
        """
        _ = count
        self._script_enter("disassemble", address)
        return list(self.script_disassembly)

    @override
    async def get_function_graph(self, address: int) -> list[dict[str, Any]]:
        """Return the scripted basic blocks.

        Args:
            address: Function address.

        Returns:
            list[dict[str, Any]]: Copy of the scripted block list.
        """
        self._script_enter("get_function_graph", address)
        return [dict(block) for block in self.script_graph]

    @override
    async def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Return the scripted inbound references.

        Args:
            address: Target address.

        Returns:
            list[CrossReference]: Copy of the scripted list.
        """
        self._script_enter("get_xrefs_to", address)
        return list(self.script_xrefs_to)

    @override
    async def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Return the scripted outbound references.

        Args:
            address: Source address.

        Returns:
            list[CrossReference]: Copy of the scripted list.
        """
        self._script_enter("get_xrefs_from", address)
        return list(self.script_xrefs_from)

    @override
    async def add_xref(
        self,
        from_address: int,
        to_address: int,
        xref_type: Literal["code", "call", "data"] = "code",
    ) -> bool:
        """Record a request to add a cross-reference.

        Args:
            from_address: Source address.
            to_address: Target address.
            xref_type: Cross-reference kind.

        Returns:
            bool: Always ``True``.
        """
        self._script_enter("add_xref", from_address, to_address, xref_type)
        return True

    @override
    async def remove_xref(self, to_address: int, from_address: int | None = None) -> bool:
        """Record a request to remove a cross-reference.

        Args:
            to_address: Target address.
            from_address: Source address.

        Returns:
            bool: Always ``True``.
        """
        self._script_enter("remove_xref", to_address, from_address)
        return True

    @override
    async def search_strings(self, pattern: str) -> list[StringInfo]:
        """Return the scripted string matches.

        Args:
            pattern: Search pattern the panel sent.

        Returns:
            list[StringInfo]: Copy of the scripted list.
        """
        self._script_enter("search_strings", pattern)
        return list(self.script_strings)

    @override
    async def get_exports(self) -> list[ExportInfo]:
        """Return the scripted exports.

        Returns:
            list[ExportInfo]: Copy of the scripted list.
        """
        self._script_enter("get_exports")
        return list(self.script_exports)

    @override
    async def rename_function(self, address: int, new_name: str) -> bool:
        """Record a rename request.

        Args:
            address: Function address.
            new_name: New name.

        Returns:
            bool: Always ``True``.
        """
        self._script_enter("rename_function", address, new_name)
        return True

    @override
    async def add_comment(self, address: int, comment: str, comment_type: str = "EOL") -> bool:
        """Record a comment request.

        Args:
            address: Comment address.
            comment: Comment text.
            comment_type: Comment kind (not part of what the panel chooses).

        Returns:
            bool: Always ``True``.
        """
        _ = comment_type
        self._script_enter("add_comment", address, comment)
        return True

    @override
    async def write_bytes(self, address: int, hex_data: str) -> bool:
        """Record a patch request.

        Args:
            address: Patch address.
            hex_data: Hex text to write.

        Returns:
            bool: Always ``True``.
        """
        self._script_enter("write_bytes", address, hex_data)
        return True

    @override
    async def read_bytes(self, address: int, count: int) -> bytes:
        """Return the scripted bytes.

        Args:
            address: Read address.
            count: Number of bytes requested.

        Returns:
            bytes: The scripted bytes.
        """
        self._script_enter("read_bytes", address, count)
        return self.script_bytes

    @override
    async def save_binary(self, path: str | None = None) -> bool:
        """Record a save request.

        Args:
            path: Destination path the panel sent.

        Returns:
            bool: Always ``True``.
        """
        self._script_enter("save_binary", path)
        return True

    @override
    async def execute_command(self, command: str) -> str:
        """Return the scripted output of a raw command.

        Args:
            command: Raw command text.

        Returns:
            str: Scripted output, or an empty string for an unscripted command.
        """
        self._script_enter("execute_command", command)
        return self.script_commands.get(command, "")

    @override
    async def seek(self, address: int) -> str:
        """Record an absolute seek.

        Args:
            address: Target address.

        Returns:
            str: Empty output.
        """
        self._script_enter("seek", address)
        return ""

    @override
    async def seek_relative(self, delta: int) -> str:
        """Record a relative seek.

        Args:
            delta: Signed byte delta.

        Returns:
            str: Empty output.
        """
        self._script_enter("seek_relative", delta)
        return ""

    @override
    async def seek_undo(self) -> str:
        """Return the scripted seek-history output for an undo.

        Returns:
            str: The scripted history output.
        """
        self._script_enter("seek_undo")
        return self.script_history_output

    @override
    async def seek_redo(self) -> str:
        """Return the scripted seek-history output for a redo.

        Returns:
            str: The scripted history output.
        """
        self._script_enter("seek_redo")
        return self.script_history_output

    @override
    async def get_function_address(self, name: str) -> int | None:
        """Return the scripted function address.

        Args:
            name: Function name the panel sent.

        Returns:
            int | None: The scripted address.
        """
        self._script_enter("get_function_address", name)
        return self.script_function_address


def _status(panel: CutterPanel) -> str:
    """Read the panel's status label.

    Args:
        panel: Panel under test.

    Returns:
        str: Current status text.
    """
    label = panel.status_label
    assert label is not None
    return label.text()


def _member[T](owner: object, name: str, kind: type[T]) -> T:
    """Read a private member of a product object with a checked type.

    Args:
        owner: Object that holds the member.
        name: Attribute name.
        kind: Expected type of the member.

    Returns:
        T: The member, narrowed to ``kind``.
    """
    value: object = getattr(owner, name)
    assert isinstance(value, kind)
    return value


def _invoke(owner: object, name: str, *args: object) -> object:
    """Call a private method of a product object.

    Args:
        owner: Object that holds the method.
        name: Method name.
        *args: Positional arguments for the call.

    Returns:
        object: The method's return value.
    """
    method = cast("Callable[..., object]", getattr(owner, name))
    return method(*args)


def _settle(panel: CutterPanel) -> None:
    """Join the panel's bridge workers and deliver their results, following chained requests.

    Args:
        panel: Panel whose workers are joined.
    """
    for _ in range(6):
        drain_bridge_workers_for(panel, timeout_ms=_WAIT_MS)
        QCoreApplication.processEvents()


def _table_rows(table: QTableWidget) -> list[list[str]]:
    """Read every cell of a table as text.

    Args:
        table: Table to read.

    Returns:
        list[list[str]]: One list of cell texts per row.
    """
    rows: list[list[str]] = []
    for row in range(table.rowCount()):
        cells: list[str] = []
        for column in range(table.columnCount()):
            item = table.item(row, column)
            cells.append("" if item is None else item.text())
        rows.append(cells)
    return rows


def _tree_rows(tree: QTreeWidget) -> list[list[str]]:
    """Read every top-level row of a tree as text.

    Args:
        tree: Tree to read.

    Returns:
        list[list[str]]: One list of column texts per top-level item.
    """
    rows: list[list[str]] = []
    for index in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(index)
        assert item is not None
        rows.append([item.text(column) for column in range(tree.columnCount())])
    return rows


def _console_lines(panel: CutterPanel) -> list[str]:
    """Read the non-empty lines of the panel's console.

    Args:
        panel: Panel under test.

    Returns:
        list[str]: Console lines in order.
    """
    text = panel.console_output.toPlainText()
    return [line for line in text.splitlines() if line]


def _disasm_text(panel: CutterPanel) -> str:
    """Read the disassembly view text.

    Args:
        panel: Panel under test.

    Returns:
        str: Plain text of the disassembly view.
    """
    return _member(panel, "_disasm_view", QPlainTextEdit).toPlainText()


def _function(name: str, address: int, size: int) -> FunctionInfo:
    """Build a function record of the bridge's real result type.

    Args:
        name: Function name.
        address: Function address.
        size: Function size in bytes.

    Returns:
        FunctionInfo: The record.
    """
    return FunctionInfo(
        name=name,
        address=address,
        size=size,
        calling_convention="cdecl",
        return_type="int",
        parameters=[],
        local_variables=[],
    )


def _instructions() -> list[DisassemblyLine]:
    """Build two instructions of the bridge's real result type.

    Returns:
        list[DisassemblyLine]: A ``push`` and a ``mov`` at consecutive addresses.
    """
    return [
        DisassemblyLine(address=0x401000, bytes_str="55", mnemonic="push", operands="ebp"),
        DisassemblyLine(address=0x401001, bytes_str="89e5", mnemonic="mov", operands="ebp, esp"),
    ]


def _asm_line(address: int, raw: str, mnemonic: str, operands: str) -> str:
    """Build the documented disassembly view line for one instruction.

    The view shows the address in hex, the raw bytes left-justified in a 24-character column, then mnemonic and operands.

    Args:
        address: Instruction address.
        raw: Raw bytes as hex text.
        mnemonic: Instruction mnemonic.
        operands: Instruction operands.

    Returns:
        str: The expected view line.
    """
    return f"0x{address:X}  {raw.ljust(24)}  {mnemonic} {operands}"


def _graph_blocks() -> list[dict[str, Any]]:
    """Build two basic blocks in the shape the bridge returns for a function graph.

    Returns:
        list[dict[str, Any]]: An entry block that jumps to a returning block.
    """
    return [
        {"offset": 0x401000, "jump": 0x401010, "fail": None, "ops": [{"disasm": "push ebp"}]},
        {"offset": 0x401010, "jump": None, "fail": None, "ops": [{"disasm": "ret"}]},
    ]


def _function_item(panel: CutterPanel, address: int) -> QTreeWidgetItem:
    """Find the function-tree row that carries ``address``.

    Args:
        panel: Panel under test.
        address: Function address stored on the row.

    Returns:
        QTreeWidgetItem: The matching row.
    """
    tree = _member(panel, "_func_tree", QTreeWidget)
    for index in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(index)
        assert item is not None
        payload: object = item.data(0, Qt.ItemDataRole.UserRole)
        if payload == address:
            return item
    return pytest.fail(f"no function row carries address 0x{address:X}")


def _has_function_named(panel: CutterPanel, name: str) -> bool:
    """Report whether any function-tree row shows ``name``.

    Args:
        panel: Panel under test.
        name: Function name to look for.

    Returns:
        bool: ``True`` when a row's name column equals ``name``.
    """
    tree = _member(panel, "_func_tree", QTreeWidget)
    for index in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(index)
        if item is not None and item.text(0) == name:
            return True
    return False


def _tab_widget_of(widget: QWidget) -> QTabWidget:
    """Find the tab widget that hosts ``widget`` as a page.

    Args:
        widget: Page widget.

    Returns:
        QTabWidget: The nearest ancestor tab widget.
    """
    node = widget.parentWidget()
    while node is not None and not isinstance(node, QTabWidget):
        node = node.parentWidget()
    assert node is not None
    return node


def _row_position(tree: QTreeWidget, row: int) -> QPoint:
    """Return the viewport position of the middle of a top-level row.

    Args:
        tree: Tree holding the row.
        row: Top-level row index.

    Returns:
        QPoint: A point inside the row, in viewport coordinates.
    """
    item = tree.topLevelItem(row)
    assert item is not None
    center = tree.visualItemRect(item).center()
    found = tree.itemAt(center)
    assert found is not None
    assert found.text(0) == item.text(0)
    assert found.text(1) == item.text(1)
    return center


def _row_of(tree: QTreeWidget, direction: str) -> int:
    """Find the top-level row whose first column equals ``direction``.

    Args:
        tree: Cross-reference tree.
        direction: ``"To"`` or ``"From"``.

    Returns:
        int: Row index.
    """
    for index in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(index)
        if item is not None and item.text(0) == direction:
            return index
    return pytest.fail(f"no {direction} row in the cross-reference tree")


def _isolate_path(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    """Replace ``PATH`` with one empty directory so no analysis backend can be found.

    Args:
        monkeypatch: Fixture that restores ``PATH`` at teardown.
        root: Parent directory for the empty directory.
    """
    empty = root / "emptybin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))


def _text_dialog(*answers: tuple[str, bool]) -> Callable[..., tuple[str, bool]]:
    """Build a replacement for ``QInputDialog.getText`` that answers from a fixed sequence.

    Args:
        *answers: ``(text, accepted)`` pairs returned by successive prompts.

    Returns:
        Callable[..., tuple[str, bool]]: Function with the static dialog's result shape.
    """
    remaining = list(answers)

    def _answer(*_args: object, **_kwargs: object) -> tuple[str, bool]:
        """Return the next scripted answer.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            tuple[str, bool]: Text and accepted flag.
        """
        return remaining.pop(0)

    return _answer


def _int_dialog(value: int, *, accepted: bool) -> Callable[..., tuple[int, bool]]:
    """Build a replacement for ``QInputDialog.getInt`` that answers with a fixed value.

    Args:
        value: Number the dialog reports.
        accepted: Whether the dialog reports acceptance.

    Returns:
        Callable[..., tuple[int, bool]]: Function with the static dialog's result shape.
    """

    def _answer(*_args: object, **_kwargs: object) -> tuple[int, bool]:
        """Return the scripted answer.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            tuple[int, bool]: Number and accepted flag.
        """
        return (value, accepted)

    return _answer


def _file_dialog(path: str) -> Callable[..., tuple[str, str]]:
    """Build a replacement for a ``QFileDialog`` file picker that picks a fixed path.

    Args:
        path: Path the picker reports; empty text means the user cancelled.

    Returns:
        Callable[..., tuple[str, str]]: Function with the static dialog's result shape.
    """

    def _pick(*_args: object, **_kwargs: object) -> tuple[str, str]:
        """Return the scripted path.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            tuple[str, str]: Path and an empty filter.
        """
        return (path, "")

    return _pick


@pytest.fixture
def panel() -> Generator[CutterPanel]:
    """Build a Cutter panel without a bridge and tear it down with its workers joined.

    Yields:
        CutterPanel: A freshly constructed panel.
    """
    widget = CutterPanel()
    try:
        yield widget
    finally:
        _settle(widget)
        _ = widget.stop_tool()
        widget.close()
        widget.deleteLater()


@pytest.fixture
def bridge() -> RecordingBridge:
    """Build a recording bridge that reports a loaded binary.

    Returns:
        RecordingBridge: A bridge with empty scripts.
    """
    return RecordingBridge()


@pytest.fixture
def wired_panel(panel: CutterPanel, bridge: RecordingBridge) -> CutterPanel:
    """Attach the recording bridge to the panel.

    Args:
        panel: Panel without a bridge.
        bridge: Recording bridge to attach.

    Returns:
        CutterPanel: The same panel, now holding the bridge.
    """
    panel.set_bridge(bridge)
    return panel


@pytest.fixture
def live_panel(panel: CutterPanel, real_pe_dll: Path) -> Generator[CutterPanel]:
    """Attach a bridge backed by radare2, loaded with a real DLL and quick-analyzed, to the panel.

    Args:
        panel: Panel without a bridge.
        real_pe_dll: Real System32 DLL to load.

    Yields:
        CutterPanel: The panel holding the live bridge.
    """
    live = CutterBridge()
    panel.set_bridge(live)
    try:
        _ = run_bridge_coroutine(live.load_binary(real_pe_dll), timeout_s=_LIVE_TIMEOUT_S)
        _ = run_bridge_coroutine(live.analyze("quick"), timeout_s=_LIVE_TIMEOUT_S)
        yield panel
    finally:
        _settle(panel)
        _ = run_bridge_coroutine(live.shutdown(), timeout_s=_LIVE_TIMEOUT_S)


@pytest.mark.parametrize("stored", [[500, 0, 120], [500, 300], [500, 300, 120, 80]], ids=["zero-size", "two-panes", "four-panes"])
def test_malformed_persisted_splitter_sizes_fall_back_to_defaults(stored: list[int]) -> None:
    """Persisted sizes that are not three positive numbers are ignored in favor of the seeded defaults.

    Args:
        stored: Malformed value written to the settings store.
    """
    QSettings(_SETTINGS_ORG, _SETTINGS_APP).setValue(_SETTINGS_KEY, stored)
    assert _load_outer_splitter_sizes() == _DEFAULT_SPLIT_SIZES


def test_valid_persisted_splitter_sizes_are_returned() -> None:
    """Three positive persisted sizes are returned unchanged."""
    QSettings(_SETTINGS_ORG, _SETTINGS_APP).setValue(_SETTINGS_KEY, [500, 300, 120])
    assert _load_outer_splitter_sizes() == [500, 300, 120]


def test_splitter_moved_without_a_splitter_persists_nothing(panel: CutterPanel) -> None:
    """A splitter-moved notification with no outer splitter writes nothing to the settings store.

    Args:
        panel: Panel under test.
    """
    QSettings(_SETTINGS_ORG, _SETTINGS_APP).remove(_SETTINGS_KEY)
    setattr(panel, "_outer_splitter", None)
    _ = _invoke(panel, "_on_outer_splitter_moved", 0, 0)
    assert QSettings(_SETTINGS_ORG, _SETTINGS_APP).value(_SETTINGS_KEY) is None


def test_get_bridge_returns_the_attached_bridge(panel: CutterPanel, bridge: RecordingBridge) -> None:
    """The accessor reports no bridge until one is attached, then the very same object.

    Args:
        panel: Panel under test.
        bridge: Bridge to attach.
    """
    assert panel.get_bridge() is None
    panel.set_bridge(bridge)
    assert panel.get_bridge() is bridge


def test_analyze_binary_without_bridge_reports_and_declines(panel: CutterPanel, tmp_path: Path) -> None:
    """Without a bridge the panel declines to load, says so, and keeps no binary.

    Args:
        panel: Panel under test.
        tmp_path: Per-test temporary directory.
    """
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ")
    assert panel.analyze_binary(target) is False
    assert _status(panel) == "No bridge configured"
    assert getattr(panel, "_current_binary") is None
    assert bridge_workers_for(panel) == []


def test_analyze_binary_missing_file_declines_before_loading(wired_panel: CutterPanel, bridge: RecordingBridge, tmp_path: Path) -> None:
    """A path that does not exist is refused before any load starts and before the panel remembers it.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        tmp_path: Per-test temporary directory.
    """
    assert wired_panel.analyze_binary(tmp_path / "missing.bin") is False
    _settle(wired_panel)
    assert getattr(wired_panel, "_current_binary") is None
    assert _status(wired_panel) == "Ready"
    assert _member(wired_panel, "_load_btn", QPushButton).isEnabled()
    assert bridge.recorded == []


def test_inherit_app_binary_keeps_the_existing_selection(wired_panel: CutterPanel, bridge: RecordingBridge, tmp_path: Path) -> None:
    """A panel that already tracks a binary refuses to adopt the application's binary.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        tmp_path: Per-test temporary directory.
    """
    chosen = tmp_path / "chosen.bin"
    chosen.write_bytes(b"MZ")
    offered = tmp_path / "offered.bin"
    offered.write_bytes(b"MZ")
    setattr(wired_panel, "_current_binary", chosen)
    assert wired_panel.inherit_app_binary(offered) is False
    _settle(wired_panel)
    assert getattr(wired_panel, "_current_binary") == chosen
    assert _status(wired_panel) == "Ready"
    assert bridge.recorded == []


def test_inherit_app_binary_ignores_a_missing_file(wired_panel: CutterPanel, tmp_path: Path) -> None:
    """An offered path that does not exist is not adopted.

    Args:
        wired_panel: Panel holding the recording bridge.
        tmp_path: Per-test temporary directory.
    """
    assert wired_panel.inherit_app_binary(tmp_path / "missing.bin") is False
    assert getattr(wired_panel, "_current_binary") is None
    assert _status(wired_panel) == "Ready"


def test_inherit_app_binary_without_bridge_reports_missing_bridge(panel: CutterPanel, tmp_path: Path) -> None:
    """Adoption routes through the normal load, which reports that no bridge is configured.

    Args:
        panel: Panel under test.
        tmp_path: Per-test temporary directory.
    """
    offered = tmp_path / "offered.bin"
    offered.write_bytes(b"MZ")
    assert panel.inherit_app_binary(offered) is False
    assert _status(panel) == "No bridge configured"
    assert getattr(panel, "_current_binary") is None


def test_inherit_app_binary_adopts_file_and_starts_load(
    panel: CutterPanel,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """An existing file is adopted, remembered and handed to the bridge's loader, whose failure is reported.

    Args:
        panel: Panel under test.
        monkeypatch: Fixture used to remove every analysis backend from ``PATH``.
        tmp_path: Per-test temporary directory.
    """
    _isolate_path(monkeypatch, tmp_path)
    panel.set_bridge(CutterBridge())
    offered = tmp_path / "offered.bin"
    offered.write_bytes(b"MZ")
    assert panel.inherit_app_binary(offered) is True
    assert getattr(panel, "_current_binary") == offered
    assert _status(panel) == "Loading: offered.bin"
    _settle(panel)
    assert _status(panel) == "Load failed: cutter not available"
    assert _member(panel, "_load_btn", QPushButton).isEnabled()


def test_start_tool_without_bridge_still_reports_started(panel: CutterPanel, qtbot: QtBot) -> None:
    """Starting without a bridge says so but still announces that the tool started.

    Args:
        panel: Panel under test.
        qtbot: pytest-qt fixture used to wait for the signal.
    """
    with qtbot.waitSignal(panel.tool_started, timeout=_WAIT_MS):
        assert panel.start_tool() is True
    assert _status(panel) == "No bridge configured"


def test_start_tool_reports_unavailable_backend_and_closes(
    panel: CutterPanel,
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A bridge whose backend cannot be found fails to initialize, reports why, and announces the tool closed.

    Args:
        panel: Panel under test.
        qtbot: pytest-qt fixture used to wait for the signal.
        monkeypatch: Fixture used to remove every analysis backend from ``PATH``.
        tmp_path: Per-test temporary directory.
    """
    _isolate_path(monkeypatch, tmp_path)
    panel.set_bridge(CutterBridge())
    with qtbot.waitSignal(panel.tool_closed, timeout=_WAIT_MS):
        assert panel.start_tool() is True
    assert _status(panel) == "Init failed: cutter not available"


@pytest.mark.spawns_process
def test_start_tool_connects_to_the_real_backend(panel: CutterPanel, qtbot: QtBot) -> None:
    """With radare2 on ``PATH`` the bridge initializes, the status reads connected, and the tool-started signal fires.

    Args:
        panel: Panel under test.
        qtbot: pytest-qt fixture used to wait for the signal.
    """
    live = CutterBridge()
    panel.set_bridge(live)
    with qtbot.waitSignal(panel.tool_started, timeout=_LIVE_WAIT_MS):
        assert panel.start_tool() is True
    assert _status(panel) == "Connected"
    assert live.state.is_ready()


def test_load_binary_dialog_cancelled_leaves_panel_untouched(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancelling the file dialog starts no load and remembers no binary.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the file dialog.
    """
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_dialog(""))
    _ = _invoke(wired_panel, "_on_load_binary")
    _settle(wired_panel)
    assert _status(wired_panel) == "Ready"
    assert getattr(wired_panel, "_current_binary") is None
    assert bridge.recorded == []


def test_load_binary_dialog_pick_starts_load_and_reports_failure(
    panel: CutterPanel,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A picked file is loaded through the bridge; when the backend is missing the failure is shown and the button re-enabled.

    Args:
        panel: Panel under test.
        monkeypatch: Fixture used to replace the file dialog and empty ``PATH``.
        tmp_path: Per-test temporary directory.
    """
    _isolate_path(monkeypatch, tmp_path)
    picked = tmp_path / "picked.bin"
    picked.write_bytes(b"MZ")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_dialog(str(picked)))
    panel.set_bridge(CutterBridge())
    load_button = _member(panel, "_load_btn", QPushButton)
    _ = _invoke(panel, "_on_load_binary")
    assert getattr(panel, "_current_binary") == picked
    assert _status(panel) == "Loading: picked.bin"
    assert not load_button.isEnabled()
    _settle(panel)
    assert _status(panel) == "Load failed: cutter not available"
    assert load_button.isEnabled()


def test_analyze_without_loaded_binary_asks_for_one(panel: CutterPanel) -> None:
    """Analyzing with a bridge that holds no binary prompts the user to load one and starts nothing.

    Args:
        panel: Panel under test.
    """
    panel.set_bridge(CutterBridge())
    _ = _invoke(panel, "_on_analyze")
    assert _status(panel) == "No binary loaded - load a binary first"
    assert _member(panel, "_analyze_btn", QPushButton).isEnabled()
    assert bridge_workers_for(panel) == []


def test_analyze_failure_is_reported_and_button_reenabled(panel: CutterPanel) -> None:
    """A failing analysis shows the error and gives the Analyze button back.

    Args:
        panel: Panel under test.
    """
    failing = CutterBridge()
    failing.state.binary_loaded = True
    panel.set_bridge(failing)
    analyze_button = _member(panel, "_analyze_btn", QPushButton)
    _ = _invoke(panel, "_on_analyze")
    assert _status(panel) == "Analyzing (normal)..."
    assert not analyze_button.isEnabled()
    _settle(panel)
    assert _status(panel) == f"Analysis failed: {_NO_BINARY}"
    assert analyze_button.isEnabled()


_PASS_ACTIONS: Final[list[str]] = [
    "_analyze_basic_blocks_btn",
    "_analyze_function_calls_btn",
    "_analyze_references_btn",
    "_autoname_functions_btn",
]


@pytest.mark.parametrize("action_name", _PASS_ACTIONS)
def test_analysis_pass_without_bridge_reports_missing_bridge(panel: CutterPanel, action_name: str) -> None:
    """Every standalone analysis pass says that no bridge is configured when none is attached.

    Args:
        panel: Panel under test.
        action_name: Attribute name of the pass's menu action.
    """
    _member(panel, action_name, QAction).trigger()
    assert _status(panel) == "No bridge configured"
    assert bridge_workers_for(panel) == []


@pytest.mark.parametrize("action_name", _PASS_ACTIONS)
def test_analysis_pass_without_loaded_binary_asks_for_one(panel: CutterPanel, action_name: str) -> None:
    """Every standalone analysis pass asks for a loaded binary and starts no work when the bridge holds none.

    Args:
        panel: Panel under test.
        action_name: Attribute name of the pass's menu action.
    """
    panel.set_bridge(CutterBridge())
    _member(panel, action_name, QAction).trigger()
    assert _status(panel) == "No binary loaded - load a binary first"
    assert bridge_workers_for(panel) == []


def test_refresh_functions_without_bridge_does_nothing(panel: CutterPanel) -> None:
    """Refreshing the function list without a bridge leaves the Refresh button usable and the tree empty.

    Args:
        panel: Panel under test.
    """
    refresh_button = _member(panel, "_refresh_funcs_btn", QPushButton)
    _ = _invoke(panel, "_on_refresh_functions")
    assert refresh_button.isEnabled()
    assert _member(panel, "_func_tree", QTreeWidget).topLevelItemCount() == 0
    assert bridge_workers_for(panel) == []


def test_function_click_without_bridge_does_nothing(panel: CutterPanel) -> None:
    """Clicking a function row when no bridge is attached changes no view and records no address.

    Args:
        panel: Panel under test.
    """
    _ = _invoke(panel, "_apply_functions", [_function("sub.main", 0x401000, 32)])
    _member(panel, "_func_tree", QTreeWidget).itemClicked.emit(_function_item(panel, 0x401000), 0)
    _settle(panel)
    assert getattr(panel, "_xrefs_current_address") is None
    assert _status(panel) == "Ready"
    assert not _disasm_text(panel)


def test_function_click_ignores_row_without_an_address(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A row that carries no integer address is ignored instead of being sent to the bridge.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    stray = QTreeWidgetItem(["no-address", "", ""])
    _ = _invoke(wired_panel, "_on_function_clicked", stray, 0)
    _settle(wired_panel)
    assert getattr(wired_panel, "_xrefs_current_address") is None
    assert bridge.recorded == []


def test_function_click_populates_decompiler_disassembly_graph_and_xrefs(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """Clicking a function row asks the bridge for its decompilation, disassembly, graph and xrefs and fills every view.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_decompiled = "int main(void) {\n    return 0;\n}"
    bridge.script_disassembly = _instructions()
    bridge.script_graph = _graph_blocks()
    bridge.script_xrefs_to = [CrossReference(0x402000, 0x401000, "call", "main_caller", None)]
    bridge.script_xrefs_from = [CrossReference(0x401000, 0x403000, "jump", None, None)]
    _ = _invoke(wired_panel, "_apply_functions", [_function("sub.main", 0x401000, 32)])
    _member(wired_panel, "_func_tree", QTreeWidget).itemClicked.emit(_function_item(wired_panel, 0x401000), 0)
    _settle(wired_panel)

    assert ("decompile", (0x401000, "pdg")) in bridge.recorded
    assert ("disassemble", (0x401000,)) in bridge.recorded
    assert ("get_function_graph", (0x401000,)) in bridge.recorded
    assert _member(wired_panel, "_decompiled_view", QPlainTextEdit).toPlainText() == "int main(void) {\n    return 0;\n}"
    assert _disasm_text(wired_panel) == "\n".join([
        _asm_line(0x401000, "55", "push", "ebp"),
        _asm_line(0x401001, "89e5", "mov", "ebp, esp"),
    ])
    assert sorted(_member(wired_panel, "_cfg_view", CFGGraphView).graph_scene().block_items) == [0x401000, 0x401010]
    assert getattr(wired_panel, "_xrefs_current_address") == 0x401000
    assert sorted(_tree_rows(_member(wired_panel, "_xrefs_tree", QTreeWidget))) == [
        ["From", "0x403000", "jump", ""],
        ["To", "0x402000", "call", "main_caller"],
    ]
    extras = _member(wired_panel, "_static_extras_tab", QWidget)
    blocks_tab = _member(extras, "_basic_blocks_tab", QWidget)
    assert _member(blocks_tab, "_addr_input", QLineEdit).text() == "0x401000"


def test_function_click_reports_decompile_failure_in_the_view(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A decompiler failure is written into the Decompiler tab and the status bar.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_failures["decompile"] = "no decompiler"
    bridge.script_graph = _graph_blocks()
    _ = _invoke(wired_panel, "_apply_functions", [_function("sub.main", 0x401000, 32)])
    _member(wired_panel, "_func_tree", QTreeWidget).itemClicked.emit(_function_item(wired_panel, 0x401000), 0)
    _settle(wired_panel)
    assert _member(wired_panel, "_decompiled_view", QPlainTextEdit).toPlainText() == "// Decompilation failed: no decompiler"
    assert _status(wired_panel) == "Decompile failed: no decompiler"


def test_decompile_selected_without_bridge_reports_missing_bridge(panel: CutterPanel) -> None:
    """Decompiling with no bridge says so.

    Args:
        panel: Panel under test.
    """
    _ = _invoke(panel, "_on_decompile_selected")
    assert _status(panel) == "No bridge configured"


def test_decompile_selected_without_selection_asks_for_one(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """Decompiling with no function selected asks the user to select one and sends no request.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    _ = _invoke(wired_panel, "_on_decompile_selected")
    _settle(wired_panel)
    assert _status(wired_panel) == "No function selected"
    assert bridge.recorded == []


def test_graph_selected_without_bridge_reports_missing_bridge(panel: CutterPanel) -> None:
    """Showing the graph with no bridge says so.

    Args:
        panel: Panel under test.
    """
    _ = _invoke(panel, "_on_graph_selected")
    assert _status(panel) == "No bridge configured"


def test_graph_selected_without_selection_asks_for_one(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """Showing the graph with no function selected asks the user to select one and sends no request.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    _ = _invoke(wired_panel, "_on_graph_selected")
    _settle(wired_panel)
    assert _status(wired_panel) == "No function selected"
    assert bridge.recorded == []


def test_graph_selected_loads_graph_of_selected_function_and_shows_cfg_tab(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """The selected function's graph is requested, drawn, and the CFG tab is brought to the front.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_graph = _graph_blocks()
    _ = _invoke(wired_panel, "_apply_functions", [_function("sub.main", 0x401000, 32), _function("sub.other", 0x402000, 16)])
    _function_item(wired_panel, 0x402000).setSelected(True)
    _ = _invoke(wired_panel, "_on_graph_selected")
    _settle(wired_panel)
    assert ("get_function_graph", (0x402000,)) in bridge.recorded
    assert sorted(_member(wired_panel, "_cfg_view", CFGGraphView).graph_scene().block_items) == [0x401000, 0x401010]
    assert _member(wired_panel, "_code_tabs", QTabWidget).currentIndex() == 2


def test_graph_selected_failure_clears_stale_graph_and_reports(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A failed graph request empties the CFG view and shows the error.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_failures["get_function_graph"] = "afbj failed"
    scene = _member(wired_panel, "_cfg_view", CFGGraphView).graph_scene()
    _ = _invoke(wired_panel, "_apply_graph", _graph_blocks())
    assert scene.block_items
    _ = _invoke(wired_panel, "_apply_functions", [_function("sub.main", 0x401000, 32)])
    _function_item(wired_panel, 0x401000).setSelected(True)
    _ = _invoke(wired_panel, "_on_graph_selected")
    _settle(wired_panel)
    assert scene.block_items == {}
    assert _status(wired_panel) == "CFG failed: afbj failed"


def test_selected_function_address_follows_the_selection(panel: CutterPanel) -> None:
    """The selected-address helper reports nothing for an empty selection and the row's address once one is selected.

    Args:
        panel: Panel under test.
    """
    assert _invoke(panel, "_get_selected_function_address") is None
    _ = _invoke(panel, "_apply_functions", [_function("sub.main", 0x401000, 32), _function("sub.other", 0x402000, 16)])
    _function_item(panel, 0x401000).setSelected(True)
    assert _invoke(panel, "_get_selected_function_address") == 0x401000


@pytest.mark.parametrize(
    ("text", "expected"),
    [("0x10", 16), ("0X1f", 31), ("  0x401000  ", 0x401000), ("42", 42), (" 7 ", 7)],
)
def test_parse_address_accepts_hex_and_decimal(text: str, expected: int) -> None:
    """Hex text with a ``0x`` prefix and plain decimal text parse to their integer values, ignoring surrounding spaces.

    Args:
        text: Address text typed by the user.
        expected: Integer value of the text.
    """
    assert _parse_address(text) == expected


@pytest.mark.parametrize("text", ["", "   ", "0xZZ", "abc", "0x", "12 34", "1.5"])
def test_parse_address_rejects_unparseable_text(text: str) -> None:
    """Empty or non-numeric address text yields no address.

    Args:
        text: Address text typed by the user.
    """
    assert _parse_address(text) is None


def test_parse_address_rejects_negative_numbers() -> None:
    """The documented contract is that only non-negative integers parse; a negative decimal yields no address."""
    assert _parse_address("-5") is None


@pytest.mark.parametrize("value", [None, "", "  \n\t"])
def test_apply_decompiled_shows_placeholder_for_blank_result(panel: CutterPanel, value: object) -> None:
    """A missing or blank decompilation replaces stale text with the placeholder line.

    Args:
        panel: Panel under test.
        value: Blank decompiler result.
    """
    view = _member(panel, "_decompiled_view", QPlainTextEdit)
    view.setPlainText("stale")
    _ = _invoke(panel, "_apply_decompiled", value)
    assert view.toPlainText() == _DECOMPILE_PLACEHOLDER


def test_apply_decompiled_shows_text_as_given(panel: CutterPanel) -> None:
    """Non-blank decompiler output is shown verbatim.

    Args:
        panel: Panel under test.
    """
    _ = _invoke(panel, "_apply_decompiled", "int x;")
    assert _member(panel, "_decompiled_view", QPlainTextEdit).toPlainText() == "int x;"


def test_decompile_error_is_written_into_view_and_status(panel: CutterPanel) -> None:
    """A decompile error is shown in the Decompiler tab and the status bar.

    Args:
        panel: Panel under test.
    """
    _ = _invoke(panel, "_on_decompile_error", RuntimeError("boom"))
    assert _member(panel, "_decompiled_view", QPlainTextEdit).toPlainText() == "// Decompilation failed: boom"
    assert _status(panel) == "Decompile failed: boom"


def test_apply_disassembly_formats_each_instruction_line(panel: CutterPanel) -> None:
    """Each instruction becomes one line: hex address, padded raw bytes, mnemonic and operands.

    Args:
        panel: Panel under test.
    """
    _ = _invoke(panel, "_apply_disassembly", _instructions())
    assert _disasm_text(panel) == "\n".join([
        _asm_line(0x401000, "55", "push", "ebp"),
        _asm_line(0x401001, "89e5", "mov", "ebp, esp"),
    ])


@pytest.mark.parametrize("value", [None, []])
def test_apply_disassembly_ignores_empty_result(panel: CutterPanel, value: object) -> None:
    """An empty disassembly result leaves the view's current text alone.

    Args:
        panel: Panel under test.
        value: Empty bridge result.
    """
    view = _member(panel, "_disasm_view", QPlainTextEdit)
    view.setPlainText("kept")
    _ = _invoke(panel, "_apply_disassembly", value)
    assert view.toPlainText() == "kept"


def test_apply_graph_loads_blocks_then_reports_an_empty_result(panel: CutterPanel) -> None:
    """Blocks are laid out in the CFG scene; an empty result clears the scene and says no blocks were found.

    Args:
        panel: Panel under test.
    """
    scene = _member(panel, "_cfg_view", CFGGraphView).graph_scene()
    _ = _invoke(panel, "_apply_graph", _graph_blocks())
    assert sorted(scene.block_items) == [0x401000, 0x401010]
    assert _status(panel) == "Ready"
    _ = _invoke(panel, "_apply_graph", [])
    assert scene.block_items == {}
    assert _status(panel) == "No basic blocks found for this function"


def test_graph_error_clears_graph_and_reports(panel: CutterPanel) -> None:
    """A graph error empties the CFG scene and shows the error in the status bar.

    Args:
        panel: Panel under test.
    """
    scene = _member(panel, "_cfg_view", CFGGraphView).graph_scene()
    _ = _invoke(panel, "_apply_graph", _graph_blocks())
    _ = _invoke(panel, "_on_graph_error", RuntimeError("boom"))
    assert scene.block_items == {}
    assert _status(panel) == "CFG failed: boom"


def test_cfg_block_click_without_bridge_reports_missing_bridge(panel: CutterPanel) -> None:
    """Clicking a CFG block with no bridge says so and does not switch tabs.

    Args:
        panel: Panel under test.
    """
    tabs = _member(panel, "_code_tabs", QTabWidget)
    tabs.setCurrentIndex(2)
    _ = _invoke(panel, "_on_cfg_block_clicked", 0x401010)
    assert _status(panel) == "No bridge configured"
    assert tabs.currentIndex() == 2


def test_cfg_block_click_seeks_to_block_and_shows_disassembly(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """Clicking a CFG block seeks to its address, shows the Disassembly tab and fills it from that address.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_disassembly = _instructions()
    tabs = _member(wired_panel, "_code_tabs", QTabWidget)
    tabs.setCurrentIndex(2)
    _ = _invoke(wired_panel, "_on_cfg_block_clicked", 0x401010)
    assert tabs.currentWidget() is _member(wired_panel, "_disasm_view", QPlainTextEdit)
    _settle(wired_panel)
    assert ("seek", (0x401010,)) in bridge.recorded
    assert ("disassemble", (0x401010,)) in bridge.recorded
    assert _status(wired_panel) == "@ 0x401010"
    assert _disasm_text(wired_panel) == "\n".join([
        _asm_line(0x401000, "55", "push", "ebp"),
        _asm_line(0x401001, "89e5", "mov", "ebp, esp"),
    ])


def test_cfg_block_click_seek_failure_is_reported(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A failed seek from a CFG block click is shown in the status bar.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_failures["seek"] = "denied"
    _ = _invoke(wired_panel, "_on_cfg_block_clicked", 0x401010)
    _settle(wired_panel)
    assert _status(wired_panel) == "Seek failed: denied"


@pytest.mark.parametrize(
    ("method", "prefix", "table_name"),
    [
        ("_refresh_imports", "Imports refresh failed", "_imports_table"),
        ("_refresh_exports", "Exports refresh failed", "_exports_table"),
        ("_refresh_sections", "Sections refresh failed", "_sections_table"),
    ],
)
def test_refresh_failure_is_reported_in_status(panel: CutterPanel, method: str, prefix: str, table_name: str) -> None:
    """A table refresh against a bridge with no loaded binary shows the error and leaves the table empty.

    Args:
        panel: Panel under test.
        method: Name of the panel's refresh method.
        prefix: Documented prefix of the failure status.
        table_name: Attribute name of the table.
    """
    panel.set_bridge(CutterBridge())
    _ = _invoke(panel, method)
    _settle(panel)
    assert _status(panel) == f"{prefix}: {_NO_BINARY}"
    assert _member(panel, table_name, QTableWidget).rowCount() == 0


@pytest.mark.parametrize(
    ("method", "table_name"),
    [
        ("_refresh_imports", "_imports_table"),
        ("_refresh_exports", "_exports_table"),
        ("_refresh_sections", "_sections_table"),
    ],
)
def test_refresh_without_bridge_leaves_table_alone(panel: CutterPanel, method: str, table_name: str) -> None:
    """Refreshing a table with no bridge sends nothing and keeps the rows already shown.

    Args:
        panel: Panel under test.
        method: Name of the panel's refresh method.
        table_name: Attribute name of the table.
    """
    table = _member(panel, table_name, QTableWidget)
    table.setRowCount(1)
    _ = _invoke(panel, method)
    _settle(panel)
    assert table.rowCount() == 1
    assert bridge_workers_for(panel) == []


def test_refresh_exports_fills_table_with_name_ordinal_and_hex_address(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """Each export becomes a row of name, decimal ordinal and hex address.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_exports = [
        ExportInfo(name="CreateThing", ordinal=7, address=0x180001000),
        ExportInfo(name="DestroyThing", ordinal=12, address=0x180002A40),
    ]
    _ = _invoke(wired_panel, "_refresh_exports")
    _settle(wired_panel)
    assert _table_rows(_member(wired_panel, "_exports_table", QTableWidget)) == [
        ["CreateThing", "7", "0x180001000"],
        ["DestroyThing", "12", "0x180002A40"],
    ]


def test_search_strings_without_bridge_leaves_button_enabled(panel: CutterPanel) -> None:
    """A string search with no bridge sends nothing and never disables the Search button.

    Args:
        panel: Panel under test.
    """
    panel.search_strings("abc")
    assert _member(panel, "_string_search_btn", QPushButton).isEnabled()
    assert bridge_workers_for(panel) == []


def test_search_button_forwards_trimmed_pattern_and_fills_table(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """The Search button sends the trimmed pattern, locks itself while waiting, and lists each match by address, value, section and encoding.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_strings = [
        StringInfo(address=0x402010, value="hello world", encoding="ascii", section=".rdata"),
        StringInfo(address=0x402040, value="wide", encoding="utf-16le", section=".data"),
    ]
    _member(wired_panel, "_string_search_input", QLineEdit).setText("  hello  ")
    search_button = _member(wired_panel, "_string_search_btn", QPushButton)
    search_button.click()
    assert not search_button.isEnabled()
    _settle(wired_panel)
    assert ("search_strings", ("hello",)) in bridge.recorded
    assert search_button.isEnabled()
    assert _table_rows(_member(wired_panel, "_strings_table", QTableWidget)) == [
        ["0x402010", "hello world", ".rdata", "ascii"],
        ["0x402040", "wide", ".data", "utf-16le"],
    ]


def test_search_with_blank_pattern_sends_nothing(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """Pressing Return in an empty or blank search box starts no search.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    search_input = _member(wired_panel, "_string_search_input", QLineEdit)
    search_input.setText("   ")
    search_input.returnPressed.emit()
    _settle(wired_panel)
    assert _member(wired_panel, "_string_search_btn", QPushButton).isEnabled()
    assert bridge.recorded == []


def test_search_failure_reenables_button_and_keeps_table_empty(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A failed string search gives the Search button back and adds no rows.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_failures["search_strings"] = "bad regex"
    wired_panel.search_strings("(")
    _settle(wired_panel)
    assert _member(wired_panel, "_string_search_btn", QPushButton).isEnabled()
    assert _member(wired_panel, "_strings_table", QTableWidget).rowCount() == 0


def test_show_xrefs_without_bridge_keeps_tree_and_address(panel: CutterPanel) -> None:
    """Showing xrefs with no bridge neither clears the tree nor remembers an address.

    Args:
        panel: Panel under test.
    """
    tree = _member(panel, "_xrefs_tree", QTreeWidget)
    tree.addTopLevelItem(QTreeWidgetItem(["To", "0x1", "call", "kept"]))
    _ = _invoke(panel, "_show_xrefs", 0x401000)
    assert getattr(panel, "_xrefs_current_address") is None
    assert _tree_rows(tree) == [["To", "0x1", "call", "kept"]]


def test_apply_xrefs_to_lists_callers_and_placeholder(panel: CutterPanel) -> None:
    """Inbound references show their source address, type and function; no references show a placeholder row.

    Args:
        panel: Panel under test.
    """
    tree = _member(panel, "_xrefs_tree", QTreeWidget)
    _ = _invoke(
        panel,
        "_apply_xrefs_to",
        [
            CrossReference(0x402000, 0x401000, "call", "caller_fn", None),
            CrossReference(0x402100, 0x401000, "data", None, None),
        ],
    )
    assert _tree_rows(tree) == [
        ["To", "0x402000", "call", "caller_fn"],
        ["To", "0x402100", "data", ""],
    ]
    tree.clear()
    _ = _invoke(panel, "_apply_xrefs_to", [])
    assert _tree_rows(tree) == [["To", _EM_DASH, _EM_DASH, "(no callers)"]]


def test_apply_xrefs_from_lists_callees_and_placeholder(panel: CutterPanel) -> None:
    """Outbound references show their target address, type and function; no references show a placeholder row.

    Args:
        panel: Panel under test.
    """
    tree = _member(panel, "_xrefs_tree", QTreeWidget)
    _ = _invoke(
        panel,
        "_apply_xrefs_from",
        [
            CrossReference(0x401000, 0x403000, "call", None, "callee_fn"),
            CrossReference(0x401000, 0x403100, "jump", None, None),
        ],
    )
    assert _tree_rows(tree) == [
        ["From", "0x403000", "call", "callee_fn"],
        ["From", "0x403100", "jump", ""],
    ]
    tree.clear()
    _ = _invoke(panel, "_apply_xrefs_from", [])
    assert _tree_rows(tree) == [["From", _EM_DASH, _EM_DASH, "(no callees)"]]


def test_xrefs_context_menu_without_current_address_opens_nothing(panel: CutterPanel) -> None:
    """With no function shown the xref context menu does not open.

    Args:
        panel: Panel under test.
    """
    _ = _invoke(panel, "_on_xrefs_context_menu", QPoint(2, 2))
    assert QApplication.activePopupWidget() is None


@pytest.mark.parametrize("xref_type", ["code", "call", "data"])
def test_add_xref_sends_current_address_target_and_kind(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
    xref_type: str,
) -> None:
    """Adding an xref sends the shown function's address as the source, the typed target, and the chosen kind, then refreshes the tree.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
        xref_type: Cross-reference kind chosen in the menu.
    """
    _ = _invoke(wired_panel, "_show_xrefs", 0x401000)
    _settle(wired_panel)
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(("0x402000", True)))
    _ = _invoke(wired_panel, "_ctx_add_xref", xref_type)
    _settle(wired_panel)
    assert ("add_xref", (0x401000, 0x402000, xref_type)) in bridge.recorded
    assert bridge.recorded[-1][0] in {"get_xrefs_to", "get_xrefs_from"}


def test_add_xref_without_current_address_does_nothing(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no function shown there is no source address, so nothing is sent.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
    """
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(("0x402000", True)))
    _ = _invoke(wired_panel, "_ctx_add_xref", "code")
    _settle(wired_panel)
    assert bridge.recorded == []


def test_add_xref_without_bridge_does_nothing(panel: CutterPanel, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no bridge adding an xref does nothing and does not even prompt for a target.

    Args:
        panel: Panel under test.
        monkeypatch: Fixture used to replace the input dialog.
    """
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(("0x402000", True)))
    _ = _invoke(panel, "_ctx_add_xref", "code")
    assert _status(panel) == "Ready"
    assert bridge_workers_for(panel) == []


@pytest.mark.parametrize("answer", [("", False), ("0x402000", False), ("", True)], ids=["cancelled", "rejected", "empty"])
def test_add_xref_cancelled_prompt_sends_nothing(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
    answer: tuple[str, bool],
) -> None:
    """A cancelled or empty target prompt adds no xref.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
        answer: Answer the prompt gives.
    """
    _ = _invoke(wired_panel, "_show_xrefs", 0x401000)
    _settle(wired_panel)
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(answer))
    _ = _invoke(wired_panel, "_ctx_add_xref", "code")
    _settle(wired_panel)
    assert [name for name, _ in bridge.recorded if name == "add_xref"] == []


def test_add_xref_invalid_target_is_reported(wired_panel: CutterPanel, bridge: RecordingBridge, monkeypatch: pytest.MonkeyPatch) -> None:
    """A target that is not an address is rejected with a status message and nothing is sent.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
    """
    _ = _invoke(wired_panel, "_show_xrefs", 0x401000)
    _settle(wired_panel)
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(("not-an-address", True)))
    _ = _invoke(wired_panel, "_ctx_add_xref", "code")
    _settle(wired_panel)
    assert _status(wired_panel) == "Invalid target address"
    assert [name for name, _ in bridge.recorded if name == "add_xref"] == []


def test_add_xref_failure_is_reported(wired_panel: CutterPanel, bridge: RecordingBridge, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed add-xref request is shown in the status bar.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
    """
    _ = _invoke(wired_panel, "_show_xrefs", 0x401000)
    _settle(wired_panel)
    bridge.script_failures["add_xref"] = "locked"
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(("0x402000", True)))
    _ = _invoke(wired_panel, "_ctx_add_xref", "call")
    _settle(wired_panel)
    assert _status(wired_panel) == "Add xref failed: locked"


def _open_xrefs(panel: CutterPanel, bridge: RecordingBridge) -> None:
    """Show the cross-references of the function at ``0x401000`` with one caller and one callee.

    Args:
        panel: Panel holding ``bridge``.
        bridge: Bridge whose xref scripts are filled in.
    """
    bridge.script_xrefs_to = [CrossReference(0x402000, 0x401000, "call", "caller_fn", None)]
    bridge.script_xrefs_from = [CrossReference(0x401000, 0x403000, "jump", None, "callee_fn")]
    _ = _invoke(panel, "_show_xrefs", 0x401000)
    _settle(panel)


def _show_xrefs_tab(panel: CutterPanel, qtbot: QtBot) -> QTreeWidget:
    """Show the panel and bring the XRefs tab to the front so row positions are laid out.

    Args:
        panel: Panel under test.
        qtbot: pytest-qt fixture used to wait for the window.

    Returns:
        QTreeWidget: The cross-reference tree.
    """
    tree = _member(panel, "_xrefs_tree", QTreeWidget)
    with qtbot.waitExposed(panel):
        panel.show()
    _tab_widget_of(tree).setCurrentWidget(tree)
    QCoreApplication.processEvents()
    return tree


def test_remove_xref_on_caller_row_removes_edge_into_current_function(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    qtbot: QtBot,
) -> None:
    """Removing a "To" row removes the edge from that row's address into the shown function.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        qtbot: pytest-qt fixture used to show the panel.
    """
    _open_xrefs(wired_panel, bridge)
    tree = _show_xrefs_tab(wired_panel, qtbot)
    position = _row_position(tree, _row_of(tree, "To"))
    _ = _invoke(wired_panel, "_ctx_remove_xref", position)
    _settle(wired_panel)
    assert ("remove_xref", (0x401000, 0x402000)) in bridge.recorded


def test_remove_xref_on_callee_row_removes_edge_out_of_current_function(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    qtbot: QtBot,
) -> None:
    """Removing a "From" row removes the edge from the shown function to that row's address.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        qtbot: pytest-qt fixture used to show the panel.
    """
    _open_xrefs(wired_panel, bridge)
    tree = _show_xrefs_tab(wired_panel, qtbot)
    position = _row_position(tree, _row_of(tree, "From"))
    _ = _invoke(wired_panel, "_ctx_remove_xref", position)
    _settle(wired_panel)
    assert ("remove_xref", (0x403000, 0x401000)) in bridge.recorded


def test_remove_xref_placeholder_row_cannot_be_resolved(wired_panel: CutterPanel, bridge: RecordingBridge, qtbot: QtBot) -> None:
    """A placeholder row has no address to remove, so the user is told and nothing is sent.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        qtbot: pytest-qt fixture used to show the panel.
    """
    _ = _invoke(wired_panel, "_show_xrefs", 0x401000)
    _settle(wired_panel)
    tree = _show_xrefs_tab(wired_panel, qtbot)
    position = _row_position(tree, _row_of(tree, "To"))
    _ = _invoke(wired_panel, "_ctx_remove_xref", position)
    _settle(wired_panel)
    assert _status(wired_panel) == "Cannot resolve xref address for removal"
    assert [name for name, _ in bridge.recorded if name == "remove_xref"] == []


def test_remove_xref_failure_is_reported(wired_panel: CutterPanel, bridge: RecordingBridge, qtbot: QtBot) -> None:
    """A failed removal is shown in the status bar.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        qtbot: pytest-qt fixture used to show the panel.
    """
    _open_xrefs(wired_panel, bridge)
    tree = _show_xrefs_tab(wired_panel, qtbot)
    bridge.script_failures["remove_xref"] = "locked"
    _ = _invoke(wired_panel, "_ctx_remove_xref", _row_position(tree, _row_of(tree, "To")))
    _settle(wired_panel)
    assert _status(wired_panel) == "Remove xref failed: locked"


def test_remove_xref_outside_any_row_does_nothing(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """Right-clicking empty space in the XRefs tree removes nothing.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    _ = _invoke(wired_panel, "_show_xrefs", 0x401000)
    _settle(wired_panel)
    _member(wired_panel, "_xrefs_tree", QTreeWidget).clear()
    _ = _invoke(wired_panel, "_ctx_remove_xref", QPoint(2, 2))
    _settle(wired_panel)
    assert [name for name, _ in bridge.recorded if name == "remove_xref"] == []


def test_remove_xref_without_current_address_or_bridge_does_nothing(panel: CutterPanel, bridge: RecordingBridge) -> None:
    """Removal is ignored with no bridge, and with a bridge but no function shown.

    Args:
        panel: Panel under test.
        bridge: Bridge attached for the second half.
    """
    _ = _invoke(panel, "_ctx_remove_xref", QPoint(2, 2))
    panel.set_bridge(bridge)
    _ = _invoke(panel, "_ctx_remove_xref", QPoint(2, 2))
    _settle(panel)
    assert _status(panel) == "Ready"
    assert bridge.recorded == []


def test_console_ignores_blank_command(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A blank console command prints nothing and sends nothing.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    _member(wired_panel, "_console_input", QLineEdit).setText("   ")
    _member(wired_panel, "_console_run_btn", QPushButton).click()
    _settle(wired_panel)
    assert _console_lines(wired_panel) == []
    assert bridge.recorded == []


def test_console_command_without_bridge_echoes_and_reports_error(panel: CutterPanel) -> None:
    """With no bridge the command is echoed, an error line follows, and the input is cleared.

    Args:
        panel: Panel under test.
    """
    command_input = _member(panel, "_console_input", QLineEdit)
    command_input.setText("  pdf  ")
    _member(panel, "_console_run_btn", QPushButton).click()
    assert _console_lines(panel) == ["> pdf", "[error] No bridge configured"]
    assert not command_input.text()
    assert _member(panel, "_console_run_btn", QPushButton).isEnabled()


def test_console_command_runs_and_prints_trimmed_output(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A command is echoed, sent trimmed, locks the Run button while pending, and its output is printed without trailing blank lines.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_commands["iI"] = "arch x86\nbits 64\n\n"
    command_input = _member(wired_panel, "_console_input", QLineEdit)
    command_input.setText("iI")
    run_button = _member(wired_panel, "_console_run_btn", QPushButton)
    run_button.click()
    assert not run_button.isEnabled()
    assert not command_input.text()
    _settle(wired_panel)
    assert ("execute_command", ("iI",)) in bridge.recorded
    assert _console_lines(wired_panel) == ["> iI", "arch x86", "bits 64"]
    assert run_button.isEnabled()


def test_console_command_with_blank_output_prints_only_the_echo(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A command that prints only whitespace adds nothing below its echo and still re-enables the Run button.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_commands["e asm.bits"] = "  \n"
    _member(wired_panel, "_console_input", QLineEdit).setText("e asm.bits")
    run_button = _member(wired_panel, "_console_run_btn", QPushButton)
    run_button.click()
    _settle(wired_panel)
    assert _console_lines(wired_panel) == ["> e asm.bits"]
    assert run_button.isEnabled()


def test_console_command_failure_is_printed_and_run_button_reenabled(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A failing command prints an error line and gives the Run button back.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_failures["execute_command"] = "pipe closed"
    _member(wired_panel, "_console_input", QLineEdit).setText("pdf")
    run_button = _member(wired_panel, "_console_run_btn", QPushButton)
    run_button.click()
    _settle(wired_panel)
    assert _console_lines(wired_panel) == ["> pdf", "[error] pipe closed"]
    assert run_button.isEnabled()


def test_refresh_new_tabs_without_bridge_sends_nothing(panel: CutterPanel) -> None:
    """Refreshing the secondary tabs with no bridge dispatches no work.

    Args:
        panel: Panel under test.
    """
    _ = _invoke(panel, "_refresh_new_tabs")
    assert bridge_workers_for(panel) == []


def test_save_binary_without_bridge_reports_missing_bridge(panel: CutterPanel, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Saving with no bridge says so even when a destination would be chosen.

    Args:
        panel: Panel under test.
        monkeypatch: Fixture used to replace the save dialog.
        tmp_path: Per-test temporary directory.
    """
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _file_dialog(str(tmp_path / "out.bin")))
    _member(panel, "_save_btn", QAction).trigger()
    assert _status(panel) == "No bridge configured"


def test_save_binary_cancelled_dialog_saves_nothing(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancelling the save dialog sends no request and leaves the status alone.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the save dialog.
    """
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _file_dialog(""))
    _member(wired_panel, "_save_btn", QAction).trigger()
    _settle(wired_panel)
    assert _status(wired_panel) == "Ready"
    assert bridge.recorded == []


def test_save_binary_sends_chosen_path_and_reports_success(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The chosen destination is sent to the bridge and the status confirms the save.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the save dialog.
        tmp_path: Per-test temporary directory.
    """
    destination = str(tmp_path / "patched.bin")
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _file_dialog(destination))
    _member(wired_panel, "_save_btn", QAction).trigger()
    assert _status(wired_panel) == "Saving..."
    _settle(wired_panel)
    assert ("save_binary", (destination,)) in bridge.recorded
    assert _status(wired_panel) == f"Saved: {destination}"


def test_save_binary_failure_is_reported(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A failed save is shown in the status bar.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the save dialog.
        tmp_path: Per-test temporary directory.
    """
    bridge.script_failures["save_binary"] = "disk full"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _file_dialog(str(tmp_path / "patched.bin")))
    _member(wired_panel, "_save_btn", QAction).trigger()
    _settle(wired_panel)
    assert _status(wired_panel) == "Save failed: disk full"


def test_patch_dialog_without_bridge_reports_missing_bridge(panel: CutterPanel) -> None:
    """Patching with no bridge says so before prompting.

    Args:
        panel: Panel under test.
    """
    _member(panel, "_patch_btn", QAction).trigger()
    assert _status(panel) == "No bridge configured"


@pytest.mark.parametrize(
    "answers",
    [
        [("", False)],
        [("0x401000", False)],
        [("0x401000", True), ("", False)],
        [("0x401000", True), ("90 90", False)],
    ],
    ids=["no-address", "address-rejected", "no-data", "data-rejected"],
)
def test_patch_dialog_cancelled_prompt_writes_nothing(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
    answers: list[tuple[str, bool]],
) -> None:
    """Cancelling either the address prompt or the data prompt writes nothing.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
        answers: Successive prompt answers.
    """
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(*answers))
    _member(wired_panel, "_patch_btn", QAction).trigger()
    _settle(wired_panel)
    assert _status(wired_panel) == "Ready"
    assert bridge.recorded == []


def test_patch_dialog_invalid_address_is_reported(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An address that does not parse is rejected before the data prompt.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
    """
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(("zz", True)))
    _member(wired_panel, "_patch_btn", QAction).trigger()
    _settle(wired_panel)
    assert _status(wired_panel) == "Invalid address"
    assert bridge.recorded == []


def test_patch_dialog_writes_hex_bytes_at_parsed_address(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The parsed address and the typed hex text are written, and the status confirms the patch.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
    """
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(("0x401000", True), ("90 90 90", True)))
    _member(wired_panel, "_patch_btn", QAction).trigger()
    _settle(wired_panel)
    assert ("write_bytes", (0x401000, "90 90 90")) in bridge.recorded
    assert _status(wired_panel) == "Patched @ 0x401000"


def test_patch_dialog_failure_is_reported(wired_panel: CutterPanel, bridge: RecordingBridge, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed write is shown in the status bar.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
    """
    bridge.script_failures["write_bytes"] = "read-only"
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(("0x401000", True), ("90", True)))
    _member(wired_panel, "_patch_btn", QAction).trigger()
    _settle(wired_panel)
    assert _status(wired_panel) == "Patch failed: read-only"


def test_goto_without_bridge_reports_missing_bridge(panel: CutterPanel) -> None:
    """The Go button says that no bridge is configured when none is attached.

    Args:
        panel: Panel under test.
    """
    _member(panel, "_goto_input", QLineEdit).setText("0x401000")
    _member(panel, "_goto_btn", QPushButton).click()
    assert _status(panel) == "No bridge configured"


@pytest.mark.parametrize(("text", "status"), [("", "Ready"), ("   ", "Ready"), ("xyz", "Invalid address")])
def test_goto_unusable_address_sends_nothing(wired_panel: CutterPanel, bridge: RecordingBridge, text: str, status: str) -> None:
    """A blank address is ignored silently and a non-numeric one is reported; neither seeks.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        text: Text typed into the address box.
        status: Expected status text afterwards.
    """
    _member(wired_panel, "_goto_input", QLineEdit).setText(text)
    _member(wired_panel, "_goto_btn", QPushButton).click()
    _settle(wired_panel)
    assert _status(wired_panel) == status
    assert bridge.recorded == []


def test_goto_seeks_then_shows_disassembly_at_the_address(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """Go seeks to the typed address, reports it, then shows the disassembly requested at that address.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_disassembly = _instructions()
    _member(wired_panel, "_goto_input", QLineEdit).setText(" 0x401000 ")
    _member(wired_panel, "_goto_btn", QPushButton).click()
    _settle(wired_panel)
    assert ("seek", (0x401000,)) in bridge.recorded
    assert ("disassemble", (0x401000,)) in bridge.recorded
    assert _status(wired_panel) == "@ 0x401000"
    assert _disasm_text(wired_panel).splitlines()[0] == _asm_line(0x401000, "55", "push", "ebp")


def test_goto_seek_failure_is_reported(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A failed seek is shown in the status bar and no disassembly is requested.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_failures["seek"] = "bad address"
    _member(wired_panel, "_goto_input", QLineEdit).setText("0x401000")
    _member(wired_panel, "_goto_btn", QPushButton).click()
    _settle(wired_panel)
    assert _status(wired_panel) == "Seek failed: bad address"
    assert [name for name, _ in bridge.recorded if name == "disassemble"] == []


def test_seek_follow_ups_are_inert_without_bridge(panel: CutterPanel) -> None:
    """The seek completion handlers do nothing when the panel holds no bridge.

    Args:
        panel: Panel under test.
    """
    _ = _invoke(panel, "_on_goto_complete", 0x401000)
    _ = _invoke(panel, "_on_seek_relative_complete")
    _ = _invoke(panel, "_on_seek_relative_address_resolved", "0x401010")
    _ = _invoke(panel, "_on_seek_history_navigated", "history line")
    _settle(panel)
    assert _status(panel) == "Ready"
    assert _console_lines(panel) == []
    assert bridge_workers_for(panel) == []


@pytest.mark.parametrize(
    "button_name",
    ["_seek_back_btn", "_seek_fwd_btn", "_seek_back_history_btn", "_seek_fwd_history_btn"],
)
def test_seek_buttons_without_bridge_report_missing_bridge(panel: CutterPanel, button_name: str) -> None:
    """Every seek button says that no bridge is configured when none is attached.

    Args:
        panel: Panel under test.
        button_name: Attribute name of the seek button.
    """
    _member(panel, "_seek_delta_input", QLineEdit).setText("16")
    _member(panel, button_name, QPushButton).click()
    assert _status(panel) == "No bridge configured"


def test_seek_relative_steps_by_signed_delta_then_refreshes_view(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """Seek + sends the typed delta, Seek - sends it negated (hex accepted), and the new position is queried and disassembled.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_commands["s"] = "0x401010\n"
    bridge.script_disassembly = _instructions()
    delta_input = _member(wired_panel, "_seek_delta_input", QLineEdit)
    delta_input.setText("16")
    _member(wired_panel, "_seek_fwd_btn", QPushButton).click()
    _settle(wired_panel)
    assert ("seek_relative", (16,)) in bridge.recorded
    assert ("execute_command", ("s",)) in bridge.recorded
    assert ("disassemble", (0x401010,)) in bridge.recorded
    assert _status(wired_panel) == "Seeked"

    delta_input.setText("0x20")
    _member(wired_panel, "_seek_back_btn", QPushButton).click()
    _settle(wired_panel)
    assert ("seek_relative", (-32,)) in bridge.recorded


@pytest.mark.parametrize(("text", "status"), [("abc", "Invalid delta"), ("0", "Ready"), ("", "Ready")])
def test_seek_relative_unusable_delta_sends_nothing(wired_panel: CutterPanel, bridge: RecordingBridge, text: str, status: str) -> None:
    """A non-numeric delta is reported; a zero or empty delta is ignored; neither seeks.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        text: Text typed into the delta box.
        status: Expected status text afterwards.
    """
    _member(wired_panel, "_seek_delta_input", QLineEdit).setText(text)
    _member(wired_panel, "_seek_fwd_btn", QPushButton).click()
    _settle(wired_panel)
    assert _status(wired_panel) == status
    assert bridge.recorded == []


def test_seek_relative_failure_is_reported(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A failed relative seek is shown in the status bar.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_failures["seek_relative"] = "out of range"
    _member(wired_panel, "_seek_delta_input", QLineEdit).setText("8")
    _member(wired_panel, "_seek_fwd_btn", QPushButton).click()
    _settle(wired_panel)
    assert _status(wired_panel) == "Seek failed: out of range"


@pytest.mark.parametrize("output", ["garbage", "", "  "])
def test_seek_position_query_ignores_unparseable_output(wired_panel: CutterPanel, bridge: RecordingBridge, output: str) -> None:
    """When the position query prints no address, no disassembly is requested.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        output: What the position query printed.
    """
    _ = _invoke(wired_panel, "_on_seek_relative_address_resolved", output)
    _settle(wired_panel)
    assert bridge.recorded == []


def test_seek_position_query_with_no_output_requests_nothing(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A missing position-query result requests no disassembly.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    _ = _invoke(wired_panel, "_on_seek_relative_address_resolved", None)
    _settle(wired_panel)
    assert bridge.recorded == []


@pytest.mark.parametrize(
    ("button_name", "method"),
    [("_seek_back_history_btn", "seek_undo"), ("_seek_fwd_history_btn", "seek_redo")],
)
def test_seek_history_buttons_print_output_and_refresh_view(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    button_name: str,
    method: str,
) -> None:
    """Back and Forward print what the history command printed, then query the new position and disassemble there.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        button_name: Attribute name of the history button.
        method: Bridge method the button must call.
    """
    bridge.script_history_output = "seek history entry\n"
    bridge.script_commands["s"] = "0x401020"
    _member(wired_panel, button_name, QPushButton).click()
    _settle(wired_panel)
    assert (method, ()) in bridge.recorded
    assert ("execute_command", ("s",)) in bridge.recorded
    assert ("disassemble", (0x401020,)) in bridge.recorded
    assert _console_lines(wired_panel) == ["seek history entry"]
    assert _status(wired_panel) == "Seeked"


def test_seek_history_with_blank_output_prints_nothing(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A history command that printed only whitespace adds no console line.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_history_output = " \n"
    _member(wired_panel, "_seek_back_history_btn", QPushButton).click()
    _settle(wired_panel)
    assert _console_lines(wired_panel) == []
    assert _status(wired_panel) == "Seeked"


def test_find_function_without_bridge_reports_missing_bridge(panel: CutterPanel) -> None:
    """The Find button says that no bridge is configured when none is attached.

    Args:
        panel: Panel under test.
    """
    _member(panel, "_find_func_input", QLineEdit).setText("main")
    _member(panel, "_find_func_btn", QPushButton).click()
    assert _status(panel) == "No bridge configured"


def test_find_function_with_blank_name_sends_nothing(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A blank function name starts no lookup.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    _member(wired_panel, "_find_func_input", QLineEdit).setText("  ")
    _member(wired_panel, "_find_func_btn", QPushButton).click()
    _settle(wired_panel)
    assert _status(wired_panel) == "Ready"
    assert bridge.recorded == []


def test_find_function_navigates_to_resolved_address(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A resolved function name fills the address box and shows the disassembly at that address.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_function_address = 0x401500
    bridge.script_disassembly = _instructions()
    _member(wired_panel, "_find_func_input", QLineEdit).setText(" main ")
    _member(wired_panel, "_find_func_btn", QPushButton).click()
    _settle(wired_panel)
    assert ("get_function_address", ("main",)) in bridge.recorded
    assert _member(wired_panel, "_goto_input", QLineEdit).text() == "0x401500"
    assert ("disassemble", (0x401500,)) in bridge.recorded
    assert _status(wired_panel) == "@ 0x401500"


def test_find_function_unknown_name_is_reported(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """An unresolved function name is reported and the address box is left alone.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_function_address = None
    _member(wired_panel, "_find_func_input", QLineEdit).setText("nosuch")
    _member(wired_panel, "_find_func_btn", QPushButton).click()
    _settle(wired_panel)
    assert _status(wired_panel) == "Function not found: nosuch"
    assert not _member(wired_panel, "_goto_input", QLineEdit).text()


def test_find_function_lookup_failure_is_reported(wired_panel: CutterPanel, bridge: RecordingBridge) -> None:
    """A failed lookup is shown in the status bar.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
    """
    bridge.script_failures["get_function_address"] = "not analyzed"
    _member(wired_panel, "_find_func_input", QLineEdit).setText("main")
    _member(wired_panel, "_find_func_btn", QPushButton).click()
    _settle(wired_panel)
    assert _status(wired_panel) == "Find failed: not analyzed"


@pytest.mark.parametrize("resolved", [None, "0x401000", 3.5])
def test_find_func_result_requires_an_integer_address(panel: CutterPanel, resolved: object) -> None:
    """Anything other than an integer address counts as not found.

    Args:
        panel: Panel under test.
        resolved: Lookup result handed to the handler.
    """
    _ = _invoke(panel, "_on_find_func_result", "target", resolved)
    assert _status(panel) == "Function not found: target"


def test_function_context_menu_ignores_blank_space(panel: CutterPanel) -> None:
    """A context-menu request over empty space in the function tree opens no menu.

    Args:
        panel: Panel under test.
    """
    _ = _invoke(panel, "_on_func_context_menu", QPoint(3, 3))
    assert QApplication.activePopupWidget() is None


def test_function_context_menu_ignores_row_without_address(panel: CutterPanel, qtbot: QtBot) -> None:
    """A context-menu request over a row that carries no integer address opens no menu.

    Args:
        panel: Panel under test.
        qtbot: pytest-qt fixture used to show the panel.
    """
    tree = _member(panel, "_func_tree", QTreeWidget)
    tree.addTopLevelItem(QTreeWidgetItem(["no-address", "", ""]))
    with qtbot.waitExposed(panel):
        panel.show()
    position = _row_position(tree, 0)
    _ = _invoke(panel, "_on_func_context_menu", position)
    assert QApplication.activePopupWidget() is None


def test_rename_function_sends_name_and_refreshes_listing(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A confirmed new name is sent with the function's address, announced, and the function list is reloaded.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
    """
    bridge.script_functions = [_function("renamed_main", 0x401000, 32)]
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(("renamed_main", True)))
    _ = _invoke(wired_panel, "_ctx_rename_function", 0x401000)
    _settle(wired_panel)
    assert ("rename_function", (0x401000, "renamed_main")) in bridge.recorded
    assert ("get_functions", (None,)) in bridge.recorded
    assert _status(wired_panel) == "Renamed 0x401000 -> renamed_main"
    assert _function_item(wired_panel, 0x401000).text(0) == "renamed_main"


def test_rename_function_failure_is_reported(wired_panel: CutterPanel, bridge: RecordingBridge, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed rename is shown in the status bar.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
    """
    bridge.script_failures["rename_function"] = "name taken"
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(("dup", True)))
    _ = _invoke(wired_panel, "_ctx_rename_function", 0x401000)
    _settle(wired_panel)
    assert _status(wired_panel) == "Rename failed: name taken"


@pytest.mark.parametrize("answer", [("", False), ("name", False), ("", True)], ids=["cancelled", "rejected", "empty"])
def test_rename_function_cancelled_prompt_sends_nothing(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
    answer: tuple[str, bool],
) -> None:
    """A cancelled or empty name prompt renames nothing.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
        answer: Answer the prompt gives.
    """
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(answer))
    _ = _invoke(wired_panel, "_ctx_rename_function", 0x401000)
    _settle(wired_panel)
    assert bridge.recorded == []


def test_add_comment_sends_address_and_text(wired_panel: CutterPanel, bridge: RecordingBridge, monkeypatch: pytest.MonkeyPatch) -> None:
    """A confirmed comment is sent with the function's address and the status confirms it.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
    """
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(("checks the license", True)))
    _ = _invoke(wired_panel, "_ctx_add_comment", 0x401000)
    _settle(wired_panel)
    assert ("add_comment", (0x401000, "checks the license")) in bridge.recorded
    assert _status(wired_panel) == "Comment added @ 0x401000"


def test_add_comment_failure_is_reported(wired_panel: CutterPanel, bridge: RecordingBridge, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed comment request is shown in the status bar.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
    """
    bridge.script_failures["add_comment"] = "read-only project"
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(("note", True)))
    _ = _invoke(wired_panel, "_ctx_add_comment", 0x401000)
    _settle(wired_panel)
    assert _status(wired_panel) == "Comment failed: read-only project"


@pytest.mark.parametrize("answer", [("", False), ("note", False), ("", True)], ids=["cancelled", "rejected", "empty"])
def test_add_comment_cancelled_prompt_sends_nothing(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
    answer: tuple[str, bool],
) -> None:
    """A cancelled or empty comment prompt adds no comment.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
        answer: Answer the prompt gives.
    """
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(answer))
    _ = _invoke(wired_panel, "_ctx_add_comment", 0x401000)
    _settle(wired_panel)
    assert bridge.recorded == []


def test_copy_address_puts_hex_text_on_clipboard(panel: CutterPanel) -> None:
    """Copy Address places the address as upper-case hex on the clipboard and says so.

    Args:
        panel: Panel under test.
    """
    _ = _invoke(panel, "_ctx_copy_address", 0x401A2C)
    clipboard = QApplication.clipboard()
    assert clipboard is not None
    assert clipboard.text() == "0x401A2C"
    assert _status(panel) == "Copied 0x401A2C"


def test_read_bytes_prints_hex_dump_with_address(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The chosen byte count is requested and the bytes are printed as spaced hex after the address.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
    """
    bridge.script_bytes = b"\xde\xad\xbe\xef"
    monkeypatch.setattr(QInputDialog, "getInt", _int_dialog(4, accepted=True))
    _ = _invoke(wired_panel, "_ctx_read_bytes", 0x401000)
    _settle(wired_panel)
    assert ("read_bytes", (0x401000, 4)) in bridge.recorded
    assert _console_lines(wired_panel) == ["[0x401000] de ad be ef"]


def test_read_bytes_cancelled_prompt_reads_nothing(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancelling the count prompt reads nothing.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
    """
    monkeypatch.setattr(QInputDialog, "getInt", _int_dialog(4, accepted=False))
    _ = _invoke(wired_panel, "_ctx_read_bytes", 0x401000)
    _settle(wired_panel)
    assert bridge.recorded == []
    assert _console_lines(wired_panel) == []


def test_read_bytes_failure_is_printed_in_console(
    wired_panel: CutterPanel,
    bridge: RecordingBridge,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed read prints an error line in the console.

    Args:
        wired_panel: Panel holding the recording bridge.
        bridge: The attached bridge.
        monkeypatch: Fixture used to replace the input dialog.
    """
    bridge.script_failures["read_bytes"] = "bad range"
    monkeypatch.setattr(QInputDialog, "getInt", _int_dialog(4, accepted=True))
    _ = _invoke(wired_panel, "_ctx_read_bytes", 0x401000)
    _settle(wired_panel)
    assert _console_lines(wired_panel) == ["[error] Read failed: bad range"]


def test_show_read_bytes_prints_non_bytes_text_and_skips_none(panel: CutterPanel) -> None:
    """Text results are printed after the address and a missing result prints nothing.

    Args:
        panel: Panel under test.
    """
    _ = _invoke(panel, "_show_read_bytes", 0x10, "unreadable")
    _ = _invoke(panel, "_show_read_bytes", 0x20, None)
    assert _console_lines(panel) == ["[0x10] unreadable"]


@pytest.mark.parametrize("method", ["_ctx_rename_function", "_ctx_add_comment", "_ctx_read_bytes"])
def test_context_actions_without_bridge_do_nothing(panel: CutterPanel, monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    """The per-function context actions are inert with no bridge, even if the dialogs would accept.

    Args:
        panel: Panel under test.
        monkeypatch: Fixture used to replace the input dialogs.
        method: Name of the context action.
    """
    monkeypatch.setattr(QInputDialog, "getText", _text_dialog(("value", True)))
    monkeypatch.setattr(QInputDialog, "getInt", _int_dialog(4, accepted=True))
    _ = _invoke(panel, method, 0x401000)
    assert _status(panel) == "Ready"
    assert _console_lines(panel) == []
    assert bridge_workers_for(panel) == []


@pytest.mark.spawns_process
def test_goto_shows_real_disassembly_and_read_bytes_matches_file(
    live_panel: CutterPanel,
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
    real_pe_dll: Path,
) -> None:
    """Go lands on the DLL's code section with real instructions, and Read Bytes prints the bytes the file holds there.

    Args:
        live_panel: Panel holding a bridge loaded with the DLL.
        qtbot: pytest-qt fixture used to wait for the views.
        monkeypatch: Fixture used to replace the input dialog.
        real_pe_dll: The loaded DLL.
    """
    live = live_panel.get_bridge()
    assert live is not None
    sections = run_bridge_coroutine(live.get_sections(), timeout_s=_LIVE_TIMEOUT_S)
    assert sections is not None
    text = next(section for section in sections if section.name == ".text")
    address = text.virtual_address
    expected = real_pe_dll.read_bytes()[text.raw_offset : text.raw_offset + 8]

    _member(live_panel, "_goto_input", QLineEdit).setText(f"0x{address:X}")
    _ = _invoke(live_panel, "_on_goto_address")
    qtbot.waitUntil(lambda: _disasm_text(live_panel).startswith(f"0x{address:X}  "), timeout=_LIVE_WAIT_MS)
    assert _status(live_panel) == f"@ 0x{address:X}"

    monkeypatch.setattr(QInputDialog, "getInt", _int_dialog(8, accepted=True))
    _ = _invoke(live_panel, "_ctx_read_bytes", address)
    dump = f"[0x{address:X}] {expected.hex(' ')}"
    qtbot.waitUntil(lambda: dump in _console_lines(live_panel), timeout=_LIVE_WAIT_MS)


@pytest.mark.spawns_process
def test_rename_function_shows_new_name_in_real_function_tree(
    live_panel: CutterPanel,
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Renaming a function of the loaded DLL reloads the function tree with the new name on the same address.

    Args:
        live_panel: Panel holding a bridge loaded with the DLL.
        qtbot: pytest-qt fixture used to wait for the tree.
        monkeypatch: Fixture used to replace the input dialog.
    """
    live = live_panel.get_bridge()
    assert live is not None
    functions = run_bridge_coroutine(live.get_functions(), timeout_s=_LIVE_TIMEOUT_S)
    assert functions is not None
    target = next(function for function in functions if function.size > 8)
    new_name = "critcov_renamed_fn"

    monkeypatch.setattr(QInputDialog, "getText", _text_dialog((new_name, True)))
    _ = _invoke(live_panel, "_ctx_rename_function", target.address)
    qtbot.waitUntil(lambda: _has_function_named(live_panel, new_name), timeout=_LIVE_WAIT_MS)
    assert _status(live_panel) == f"Renamed 0x{target.address:X} -> {new_name}"
    assert _function_item(live_panel, target.address).text(0) == new_name
