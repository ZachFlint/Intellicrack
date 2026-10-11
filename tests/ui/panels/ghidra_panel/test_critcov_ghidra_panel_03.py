# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the structure, memory, segment, program-info, call-graph and comment handlers of the Ghidra panel.

Every test drives a real ``GhidraPanel`` under the offscreen ``QApplication`` by calling the slots its buttons trigger. Ghidra itself is
never started: the bridge is always a real ``GhidraBridge``, either untouched (to prove the connection guards) or ``ScriptedGhidraBridge``,
a subclass that replaces only the two methods that carry Jython source to the Ghidra process and bring a value back. Everything above that
seam is production code: the bridge builds its real scripts, checks the real read-back, and wraps real failures in ``ToolError``, and the
panel's request travels through the real worker thread to its own result handler. Scripted replies use the payload shapes written in
``src/intellicrack/bridges/ghidra.py`` (``name``/``start``/``end``/``size``/``read``/``write``/``execute``/``initialized`` for memory
blocks, ``function``/``address``/``children`` for call trees, ``caller_address``/``caller_function`` for callers and so on). Expected
table cells, tree rows and hex-dump lines are written out by hand from those field names and the documented column layout.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import json
import re
from itertools import starmap
from typing import TYPE_CHECKING, Final, cast, override

import pytest
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTreeWidget,
    QTreeWidgetItem,
)

from intellicrack.bridges.base import BridgeState
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError
from intellicrack.ui.panels.async_bridge import drain_bridge_workers_for
from intellicrack.ui.panels.ghidra_panel import GhidraPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping

    from pytestqt.qtbot import QtBot


type TreeRows = list[tuple[str, str, TreeRows]]

pytestmark = pytest.mark.usefixtures("qapp")

_WAIT_MS: Final[int] = 20_000
_WIRE_DOWN: Final[str] = "wire down"
_STATUS_NO_BRIDGE: Final[str] = "No bridge configured"
_STATUS_NOT_CONNECTED: Final[str] = "Ghidra not connected"
_UNUSED_PORT: Final[int] = 1
_HEX_COLUMN_WIDTH: Final[int] = 47

_ARMED_TEXT: Final[tuple[tuple[str, str], ...]] = (
    ("_struct_name_input", "Header"),
    ("_apply_struct_addr_input", "0x401000"),
    ("_apply_struct_name_input", "Header"),
    ("_read_addr_input", "0x401000"),
    ("_write_addr_input", "0x401000"),
    ("_write_hex_input", "90 90"),
    ("_block_name_input", "new_blk"),
    ("_block_start_input", "0x1000"),
    ("_block_mapped_addr_input", "0x2000"),
    ("_block_remove_name_input", "rm_blk"),
    ("_block_split_name_input", "split_blk"),
    ("_block_split_addr_input", "0x1800"),
    ("_block_move_name_input", "move_blk"),
    ("_block_move_start_input", "0x3000"),
    ("_block_meta_name_input", "meta_blk"),
    ("_block_new_name_input", "renamed_blk"),
    ("_block_comment_input", "block note"),
    ("_block_join_name1_input", "join_a"),
    ("_block_join_name2_input", "join_b"),
    ("_meta_name_input", "prog.exe"),
    ("_meta_base_input", "0x400000"),
    ("_cg_addr_input", "0x401000"),
    ("_cmt_addr_input", "0x401000"),
    ("_cmt_text_input", "analyst note"),
)

_ALL_HANDLERS: Final[tuple[str, ...]] = (
    "_on_define_structure",
    "_on_refresh_structures",
    "_on_apply_structure",
    "_on_refresh_memory_map",
    "_on_read_bytes",
    "_on_write_bytes",
    "_on_create_memory_block",
    "_on_remove_memory_block",
    "_on_split_memory_block",
    "_on_move_memory_block",
    "_on_rename_memory_block",
    "_on_set_memory_block_comment",
    "_on_join_memory_blocks",
    "_on_refresh_segments",
    "_on_refresh_program_info",
    "_on_update_metadata",
    "_on_build_call_graph",
    "_on_show_callers",
    "_on_show_slice",
    "_on_add_comment",
    "_on_remove_comment",
    "_on_refresh_comments",
    "_on_load_all_comments",
)

_VALIDATION_CASES: Final[tuple[tuple[str, str, dict[str, str], str], ...]] = (
    ("define_blank_name", "_on_define_structure", {"_struct_name_input": "   "}, "Structure name required"),
    ("apply_bad_address", "_on_apply_structure", {"_apply_struct_addr_input": "zz"}, "Invalid address for apply structure"),
    ("apply_empty_address", "_on_apply_structure", {"_apply_struct_addr_input": ""}, "Invalid address for apply structure"),
    ("apply_blank_name", "_on_apply_structure", {"_apply_struct_name_input": "  "}, "Structure name required"),
    ("read_bad_address", "_on_read_bytes", {"_read_addr_input": "zz"}, "Invalid address for read bytes"),
    ("write_bad_address", "_on_write_bytes", {"_write_addr_input": "zz"}, "Invalid address for write bytes"),
    ("write_blank_hex", "_on_write_bytes", {"_write_hex_input": "  "}, "Hex data required"),
    ("write_non_hex", "_on_write_bytes", {"_write_hex_input": "zz"}, "Invalid hex data"),
    ("write_odd_digit_count", "_on_write_bytes", {"_write_hex_input": "9 0 9"}, "Invalid hex data"),
    ("block_blank_name", "_on_create_memory_block", {"_block_name_input": ""}, "Block name required"),
    ("block_bad_start", "_on_create_memory_block", {"_block_start_input": "zz"}, "Invalid start address for memory block"),
    ("split_blank_name", "_on_split_memory_block", {"_block_split_name_input": ""}, "Block name required for split"),
    ("split_bad_address", "_on_split_memory_block", {"_block_split_addr_input": "zz"}, "Invalid split address for memory block"),
    ("move_blank_name", "_on_move_memory_block", {"_block_move_name_input": ""}, "Block name required for move"),
    ("move_bad_start", "_on_move_memory_block", {"_block_move_start_input": "zz"}, "Invalid new start address for memory block"),
    ("rename_blank_name", "_on_rename_memory_block", {"_block_meta_name_input": ""}, "Block name required for rename"),
    ("rename_blank_new_name", "_on_rename_memory_block", {"_block_new_name_input": ""}, "New name required for rename"),
    ("comment_blank_block_name", "_on_set_memory_block_comment", {"_block_meta_name_input": ""}, "Block name required for comment"),
    ("join_blank_first", "_on_join_memory_blocks", {"_block_join_name1_input": ""}, "Both block names required for join"),
    ("join_blank_second", "_on_join_memory_blocks", {"_block_join_name2_input": ""}, "Both block names required for join"),
    ("metadata_nothing", "_on_update_metadata", {"_meta_name_input": "", "_meta_base_input": ""}, "No metadata to update"),
    ("graph_bad_address", "_on_build_call_graph", {"_cg_addr_input": "zz"}, "Invalid address for call graph"),
    ("callers_bad_address", "_on_show_callers", {"_cg_addr_input": "zz"}, "Invalid address for callers"),
    ("slice_bad_address", "_on_show_slice", {"_cg_addr_input": "zz"}, "Invalid address for slice"),
    ("comment_bad_address", "_on_add_comment", {"_cmt_addr_input": "zz"}, "Invalid address for comment"),
    ("comment_blank_text", "_on_add_comment", {"_cmt_text_input": "   "}, "Comment text required"),
    ("remove_comment_bad_address", "_on_remove_comment", {"_cmt_addr_input": "zz"}, "Invalid address for remove comment"),
    ("refresh_comments_bad_address", "_on_refresh_comments", {"_cmt_addr_input": "zz"}, "Invalid address for refresh comments"),
)

_DISPATCH_ERRORS: Final[tuple[tuple[str, str, str, str], ...]] = (
    ("define_structure", "_on_define_structure", "initialized", "Define structure failed: "),
    ("refresh_structures", "_on_refresh_structures", "initialized", "Refresh structures failed: "),
    ("apply_structure", "_on_apply_structure", "initialized", "Apply structure failed: "),
    ("refresh_memory_map", "_on_refresh_memory_map", "initialized", "Refresh memory map failed: "),
    ("read_bytes", "_on_read_bytes", "initialized", "Read bytes failed: "),
    ("write_bytes", "_on_write_bytes", "initialized", "Write bytes failed: "),
    ("create_initialized", "_on_create_memory_block", "initialized", "Create memory block failed: "),
    ("create_uninitialized", "_on_create_memory_block", "uninitialized", "Create uninitialized block failed: "),
    ("create_byte_mapped", "_on_create_memory_block", "byte_mapped", "Create byte-mapped block failed: "),
    ("create_bit_mapped", "_on_create_memory_block", "bit_mapped", "Create bit-mapped block failed: "),
    ("remove_block", "_on_remove_memory_block", "initialized", "Remove memory block failed: "),
    ("split_block", "_on_split_memory_block", "initialized", "Split memory block failed: "),
    ("move_block", "_on_move_memory_block", "initialized", "Move memory block failed: "),
    ("rename_block", "_on_rename_memory_block", "initialized", "Rename memory block failed: "),
    ("block_comment", "_on_set_memory_block_comment", "initialized", "Set memory block comment failed: "),
    ("join_blocks", "_on_join_memory_blocks", "initialized", "Join memory blocks failed: "),
    ("refresh_segments", "_on_refresh_segments", "initialized", "Refresh segments failed: "),
    ("refresh_program_info", "_on_refresh_program_info", "initialized", "Refresh program info failed: "),
    ("update_metadata", "_on_update_metadata", "initialized", "Update metadata failed: "),
    ("call_graph", "_on_build_call_graph", "initialized", "Build call graph failed: "),
    ("callers", "_on_show_callers", "initialized", "Get callers failed: "),
    ("slice", "_on_show_slice", "initialized", "Get slice failed: "),
    ("add_comment", "_on_add_comment", "initialized", "Add comment failed: "),
    ("remove_comment", "_on_remove_comment", "initialized", "Remove comment failed: "),
    ("refresh_comments", "_on_refresh_comments", "initialized", "Refresh comments failed: "),
)

_MEMORY_BLOCK_REPLY: Final[list[dict[str, object]]] = [
    {
        "name": "new_blk",
        "start": 0x1000,
        "end": 0x103F,
        "size": 64,
        "read": True,
        "write": True,
        "execute": False,
        "initialized": True,
        "volatile": False,
    },
]
_MEMORY_BLOCK_ROW: Final[list[list[str]]] = [["new_blk", "0x1000", "0x103F", "64", "R", "W", "", "I"]]

_CREATE_CASES: Final[tuple[tuple[str, str, dict[str, object], tuple[str, ...]], ...]] = (
    (
        "initialized",
        "zz",
        {"name": "new_blk", "start": 0x1000, "size": 64, "permissions": "rw", "success": True},
        ('memory.createInitializedBlock("new_blk", addr, 64, 0, monitor, False)', 'perms = "rw"', "addr = toAddr(4096)"),
    ),
    (
        "uninitialized",
        "zz",
        {"name": "new_blk", "success": True},
        ('memory.createUninitializedBlock("new_blk", addr, 64, False)', "addr = toAddr(4096)"),
    ),
    (
        "byte_mapped",
        "0x2000",
        {"name": "new_blk", "success": True},
        ('memory.createByteMappedBlock("new_blk", addr, mapped_addr, 64, False)', "addr = toAddr(4096)", "mapped_addr = toAddr(8192)"),
    ),
    (
        "bit_mapped",
        "0x2000",
        {"name": "new_blk", "success": True},
        ('memory.createBitMappedBlock("new_blk", addr, mapped_addr, 64, False)', "addr = toAddr(4096)", "mapped_addr = toAddr(8192)"),
    ),
)

_BLOCK_OP_CASES: Final[tuple[tuple[str, str, dict[str, object], tuple[str, ...]], ...]] = (
    ("remove", "_on_remove_memory_block", {"found": True, "ok": True}, ('memory.getBlock("rm_blk")',)),
    (
        "split",
        "_on_split_memory_block",
        {"found": True, "in_range": True, "ok": True},
        ('memory.getBlock("split_blk")', "block.contains(toAddr(6144))", "memory.split(block, toAddr(6144))"),
    ),
    (
        "move",
        "_on_move_memory_block",
        {"found": True, "ok": True},
        ('memory.getBlock("move_blk")', "memory.moveBlock(block, toAddr(12288), monitor)"),
    ),
    (
        "rename",
        "_on_rename_memory_block",
        {"found": True, "ok": True},
        ('memory.getBlock("meta_blk")', 'block.setName("renamed_blk")'),
    ),
    (
        "set_comment",
        "_on_set_memory_block_comment",
        {"found": True, "ok": True},
        ('memory.getBlock("meta_blk")', 'block.setComment("block note")'),
    ),
    (
        "join",
        "_on_join_memory_blocks",
        {"found1": True, "found2": True, "joined_name": "join_a", "ok": True},
        ('block1 = memory.getBlock("join_a")', 'block2 = memory.getBlock("join_b")'),
    ),
)

_SEGMENT_REPLY: Final[list[dict[str, object]]] = [
    {
        "name": ".text",
        "start": 0x140001000,
        "end": 0x1400010FF,
        "size": 256,
        "read": True,
        "write": False,
        "execute": True,
        "initialized": True,
        "volatile": False,
        "type": "Default",
        "source_name": "Headers",
        "comment": "",
    },
    {"name": "stack", "start": 0x10, "end": 0x1F, "size": 16, "read": False, "write": True, "execute": False},
]
_SEGMENT_ROWS: Final[list[list[str]]] = [
    [".text", "0x140001000", "0x1400010FF", "256", "R", "", "X", "Default", "Headers"],
    ["stack", "0x10", "0x1F", "16", "", "W", "", "", ""],
]

_READ_DUMP_CASES: Final[tuple[tuple[str, object, tuple[tuple[str, str, str], ...]], ...]] = (
    (
        "bytes_list_with_unprintable_edges",
        {"bytes": [0x00, 0x1F, 0x20, 0x7E, 0x7F, 0x80, 0xFF, 0x41]},
        (("00000000", "00 1F 20 7E 7F 80 FF 41", ".. ~...A"),),
    ),
    ("hex_text_when_bytes_is_not_a_list", {"bytes": None, "hex": "41 42 43"}, (("00000000", "41 42 43", "ABC"),)),
    ("empty_hex_text", {"bytes": None, "hex": ""}, ()),
    ("bytes_object", b"AB", (("00000000", "41 42", "AB"),)),
    ("bytearray_object", bytearray(b"z"), (("00000000", "7A", "z"),)),
    ("hex_string", "41 42 43 44", (("00000000", "41 42 43 44", "ABCD"),)),
    ("empty_bytes", b"", ()),
    (
        "exactly_one_full_line",
        bytes(range(0x30, 0x40)),
        (("00000000", "30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F", "0123456789:;<=>?"),),
    ),
    (
        "one_byte_over_a_line",
        bytes(range(0x30, 0x41)),
        (
            ("00000000", "30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F", "0123456789:;<=>?"),
            ("00000010", "40", "@"),
        ),
    ),
)

_PROGRAM_INFO_REPLY: Final[dict[str, object]] = {
    "name": "prog.exe",
    "language": "x86:LE:64:default",
    "image_base": 0x140000000,
    "pointer_size": 8,
    "num_functions": 12,
}
_PROGRAM_INFO_ROWS: Final[list[list[str]]] = [
    ["name", "prog.exe"],
    ["language", "x86:LE:64:default"],
    ["image_base", "5368709120"],
    ["pointer_size", "8"],
    ["num_functions", "12"],
]

_UNEXPECTED_PROGRAM_INFO: Final[tuple[tuple[str, object, str], ...]] = (
    ("text", "oops", "str"),
    ("list", [1, 2], "list"),
    ("none", None, "NoneType"),
    ("dataclass_type", BridgeState, "type"),
)

_METADATA_CASES: Final[tuple[tuple[str, str, str, dict[str, object], tuple[str, ...]], ...]] = (
    (
        "name_and_base",
        "renamed.exe",
        "0x400000",
        {"name": "renamed.exe", "image_base": 0x400000},
        ('new_name = "renamed.exe"', "new_base = 4194304"),
    ),
    ("name_only", "only.exe", "", {"name": "only.exe", "image_base": 0}, ('new_name = "only.exe"', "new_base = None")),
    ("base_only", "", "0x1000", {"name": "whatever.exe", "image_base": 0x1000}, ("new_name = None", "new_base = 4096")),
)

_COMMENT_ROWS_REPLY: Final[list[dict[str, object]]] = [
    {"address": 0x401000, "type": "EOL", "comment": "first"},
    {"address": 0x401010, "type": "PRE", "comment": "second"},
]
_COMMENT_ROWS: Final[list[list[str]]] = [["0x401000", "EOL", "first"], ["0x401010", "PRE", "second"]]

_CALL_TREE: Final[dict[str, object]] = {
    "function": "main",
    "address": 0x401000,
    "children": [
        {
            "function": "helper",
            "address": 0x402000,
            "children": [{"function": "leaf", "address": 0x403000, "children": []}],
        },
        {"function": "other", "address": 0x404000, "children": []},
    ],
}
_CALL_TREE_ROWS: Final[TreeRows] = [
    (
        "main",
        "0x401000",
        [
            ("helper", "0x402000", [("leaf", "0x403000", [])]),
            ("other", "0x404000", []),
        ],
    ),
]


class ScriptedGhidraBridge(GhidraBridge):
    """Real ``GhidraBridge`` whose remote-script channel answers from a script.

    Only the two methods that cross the process boundary to Ghidra are replaced: ``_execute_remote`` (run Jython source, return its trailing
    value) and ``_execute_remote_eval`` (evaluate one expression). Each records the source it was given and returns, or raises, the next
    scripted reply; with nothing scripted it raises a ``ToolError``. The replies are plain lists that tests fill before they call a panel
    slot, ``remote_replies`` for source execution and ``eval_replies`` for expression evaluation, and ``scripts`` and ``evals`` collect what
    the production code sent. Every caller above those two methods is the production bridge code.
    """

    def __init__(self) -> None:
        """Create the bridge with no scripted replies and nothing sent yet."""
        super().__init__()
        self.remote_replies: list[object] = []
        self.eval_replies: list[object] = []
        self.scripts: list[str] = []
        self.evals: list[str] = []

    @staticmethod
    def _take(replies: list[object]) -> object:
        """Remove and return the next scripted reply, raising it when it is an error.

        Args:
            replies: Queue of scripted replies.

        Returns:
            object: The next scripted value.

        Raises:
            ToolError: When the queue is empty or the next reply is itself a ``ToolError``.
        """
        if not replies:
            msg = "no scripted reply"
            raise ToolError(msg)
        reply = replies.pop(0)
        if isinstance(reply, ToolError):
            raise ToolError(reply.message, tool_name=reply.tool_name, details=dict(reply.details))
        return reply

    @override
    async def _execute_remote(self, code: str) -> object:
        """Record the Jython source and return the next scripted reply.

        Args:
            code: Jython source the production code asked Ghidra to run.

        Returns:
            object: The next scripted source-execution reply.
        """
        await asyncio.sleep(0)
        self.scripts.append(code)
        return self._take(self.remote_replies)

    @override
    async def _execute_remote_eval(self, expression: str) -> object:
        """Record the expression and return the next scripted evaluation reply.

        Args:
            expression: Jython expression the production code asked Ghidra to evaluate.

        Returns:
            object: The next scripted evaluation reply.
        """
        await asyncio.sleep(0)
        self.evals.append(expression)
        return self._take(self.eval_replies)


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


def _lazy_rpc_client() -> object:
    """Build a real, never-connected ``ghidra_bridge`` RPC client.

    The upstream client is lazy: building it opens no socket, and the scripted bridge never sends anything through it.

    Returns:
        object: The ``ghidra_bridge.GhidraBridge`` client instance.
    """
    module = importlib.import_module("ghidra_bridge")
    factory = cast("Callable[..., object]", module.GhidraBridge)
    return factory(namespace=None, connect_to_host="127.0.0.1", connect_to_port=_UNUSED_PORT, response_timeout=5)


def _status(panel: GhidraPanel) -> str:
    """Read the panel status label.

    Args:
        panel: Panel whose status label is read.

    Returns:
        str: The label text.
    """
    label = panel.status_label
    assert label is not None
    return label.text()


def _table(panel: GhidraPanel, name: str) -> QTableWidget:
    """Look up a table of the panel.

    Args:
        panel: Panel that owns the table.
        name: Attribute name of the table.

    Returns:
        QTableWidget: The table.
    """
    return priv(panel, name, QTableWidget)


def _tree(panel: GhidraPanel) -> QTreeWidget:
    """Look up the call graph tree of the panel.

    Args:
        panel: Panel that owns the tree.

    Returns:
        QTreeWidget: The call graph tree.
    """
    return priv(panel, "_call_graph_tree", QTreeWidget)


def _fields(panel: GhidraPanel) -> list[tuple[str, str]]:
    """Look up the pending structure field list of the panel.

    Args:
        panel: Panel that owns the list.

    Returns:
        list[tuple[str, str]]: The live list of (name, type) pairs.
    """
    return cast("list[tuple[str, str]]", getattr(panel, "_struct_fields_list"))


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


def _item_rows(item: QTreeWidgetItem | None) -> tuple[str, str, TreeRows]:
    """Read one tree item and everything below it.

    Args:
        item: Item to read.

    Returns:
        tuple[str, str, TreeRows]: Name column, address column and the rows of the item's children.
    """
    assert item is not None
    children = [_item_rows(item.child(index)) for index in range(item.childCount())]
    return (item.text(0), item.text(1), children)


def _tree_rows(tree: QTreeWidget) -> TreeRows:
    """Read every top-level item of a tree with its descendants.

    Args:
        tree: Tree to read.

    Returns:
        TreeRows: The nested rows, top to bottom.
    """
    return [_item_rows(tree.topLevelItem(index)) for index in range(tree.topLevelItemCount())]


def _all_names(rows: TreeRows) -> list[str]:
    """Collect the name column of every row of a nested tree, depth first.

    Args:
        rows: Nested rows to walk.

    Returns:
        list[str]: Every name in the rows and below them.
    """
    names: list[str] = []
    for name, _address, children in rows:
        names.append(name)
        names.extend(_all_names(children))
    return names


def _dump_line(offset: str, hex_text: str, ascii_text: str) -> str:
    """Write one hex-dump line: offset, hex column padded to its fixed width, then the printable text.

    Args:
        offset: Eight-digit hexadecimal offset.
        hex_text: Space-separated byte values.
        ascii_text: Printable rendering of the bytes.

    Returns:
        str: The dump line.
    """
    return f"{offset}  {hex_text.ljust(_HEX_COLUMN_WIDTH)}  {ascii_text}"


def _type_into(panel: GhidraPanel, name: str, text: str) -> None:
    """Type text into a line edit or plain-text edit of the panel.

    Args:
        panel: Panel that owns the widget.
        name: Attribute name of the widget.
        text: Text to enter.
    """
    widget: object = getattr(panel, name)
    if isinstance(widget, QPlainTextEdit):
        widget.setPlainText(text)
    else:
        priv(panel, name, QLineEdit).setText(text)


def _arm(panel: GhidraPanel, overrides: Mapping[str, str] | None = None) -> None:
    """Fill every input the slice's handlers read with a valid value, then apply overrides.

    Args:
        panel: Panel whose inputs are filled.
        overrides: Replacement text by attribute name, applied after the valid values.
    """
    values: dict[str, str] = dict(_ARMED_TEXT)
    if overrides is not None:
        values.update(overrides)
    for name, text in values.items():
        _type_into(panel, name, text)


def _pick(panel: GhidraPanel, name: str, text: str) -> None:
    """Select an entry of a combo box of the panel by its text.

    Args:
        panel: Panel that owns the combo box.
        name: Attribute name of the combo box.
        text: Entry to select.
    """
    combo = priv(panel, name, QComboBox)
    index = combo.findText(text)
    assert index >= 0
    combo.setCurrentIndex(index)


def _settle(panel: GhidraPanel) -> None:
    """Join the panel's bridge workers and deliver the results they queued.

    Args:
        panel: Panel whose workers are joined.
    """
    drain_bridge_workers_for(panel)
    QApplication.processEvents()


def _wait_status(qtbot: QtBot, panel: GhidraPanel, expected: str) -> None:
    """Wait until the panel status label shows a given text.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        panel: Panel whose status label is watched.
        expected: Status text to wait for.
    """
    qtbot.waitUntil(lambda: _status(panel) == expected, timeout=_WAIT_MS)


def _wait_rows(qtbot: QtBot, table: QTableWidget, count: int) -> None:
    """Wait until a table holds a given number of rows.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        table: Table that is watched.
        count: Row count to wait for.
    """
    qtbot.waitUntil(lambda: table.rowCount() == count, timeout=_WAIT_MS)


def _sent_fields(script: str) -> list[tuple[str, str]]:
    """Decode the structure fields the bridge embedded in a ``define_structure`` script.

    The bridge writes the fields as a JSON document inside a JSON string literal, so the literal is decoded twice with the standard library.

    Args:
        script: Jython source the bridge sent.

    Returns:
        list[tuple[str, str]]: The (name, type) pairs in the order they were sent.
    """
    literals = re.findall(r"fields_data = _json\.loads\((.+)\)", script)
    assert len(literals) == 1
    decoded = cast("list[dict[str, object]]", json.loads(cast("str", json.loads(literals[0]))))
    return [(str(entry["name"]), str(entry["type"])) for entry in decoded]


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
def bridge() -> ScriptedGhidraBridge:
    """Provide a scripted bridge that reports itself connected and has nothing scripted yet.

    Returns:
        ScriptedGhidraBridge: A bridge attached to a real, never-connected RPC client.
    """
    scripted = ScriptedGhidraBridge()
    scripted.attach_remote_bridge(_lazy_rpc_client())
    return scripted


@pytest.fixture
def idle_bridge() -> ScriptedGhidraBridge:
    """Provide a scripted bridge that was never connected.

    Returns:
        ScriptedGhidraBridge: A bridge whose state is not ready.
    """
    return ScriptedGhidraBridge()


@pytest.fixture
def bridged_panel(panel: GhidraPanel, bridge: ScriptedGhidraBridge) -> GhidraPanel:
    """Give the panel the connected scripted bridge.

    Args:
        panel: Panel without a bridge.
        bridge: Connected scripted bridge.

    Returns:
        GhidraPanel: The same panel, now holding the bridge.
    """
    panel.set_bridge(bridge)
    return panel


@pytest.mark.parametrize("handler", _ALL_HANDLERS)
def test_handler_without_a_bridge_reports_it_and_changes_nothing(panel: GhidraPanel, handler: str) -> None:
    """With no bridge set, a handler says so in the status line and leaves the form and pending fields alone.

    Every input is valid, so a handler that skipped its bridge guard would go on to call a method of ``None``.

    Args:
        panel: Panel without a bridge.
        handler: Name of the panel slot under test.
    """
    _arm(panel)
    _fields(panel).append(("keep", "dword"))

    method(panel, handler)()
    _settle(panel)

    assert panel.get_bridge() is None
    assert _status(panel) == _STATUS_NO_BRIDGE
    assert _fields(panel) == [("keep", "dword")]
    assert priv(panel, "_load_all_cmt_btn", QPushButton).isEnabled()


@pytest.mark.parametrize("handler", _ALL_HANDLERS)
def test_handler_with_an_unconnected_bridge_reports_it_and_sends_nothing(
    panel: GhidraPanel,
    idle_bridge: ScriptedGhidraBridge,
    handler: str,
) -> None:
    """A bridge that is set but not connected is refused by the guard before anything is sent to it.

    Args:
        panel: Panel without a bridge.
        idle_bridge: Scripted bridge whose state is not ready.
        handler: Name of the panel slot under test.
    """
    panel.set_bridge(idle_bridge)
    _arm(panel)
    _fields(panel).append(("keep", "dword"))

    method(panel, handler)()
    _settle(panel)

    assert _status(panel) == _STATUS_NOT_CONNECTED
    assert idle_bridge.scripts == []
    assert idle_bridge.evals == []
    assert _fields(panel) == [("keep", "dword")]
    assert priv(panel, "_load_all_cmt_btn", QPushButton).isEnabled()


@pytest.mark.parametrize("case", _VALIDATION_CASES, ids=[case[0] for case in _VALIDATION_CASES])
def test_handler_rejects_an_unusable_input_without_sending_anything(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    case: tuple[str, str, dict[str, str], str],
) -> None:
    """An empty name, an unparsable address or unusable hex data is reported once and nothing reaches the bridge.

    Every other input is valid, and settling afterwards would show a second status line from the bridge if the handler had dispatched.

    Args:
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge, to prove nothing was sent.
        case: Case id, handler name, input overrides and the expected status text.
    """
    _case_id, handler, overrides, expected = case
    _arm(bridged_panel, overrides)
    _fields(bridged_panel).append(("keep", "dword"))

    method(bridged_panel, handler)()
    _settle(bridged_panel)

    assert _status(bridged_panel) == expected
    assert bridge.scripts == []
    assert bridge.evals == []
    assert _fields(bridged_panel) == [("keep", "dword")]


@pytest.mark.parametrize("mapped_text", ["zz", ""])
@pytest.mark.parametrize("block_type", ["byte_mapped", "bit_mapped"])
def test_mapped_block_without_a_usable_mapped_address_is_refused(
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    block_type: str,
    mapped_text: str,
) -> None:
    """A byte-mapped or bit-mapped block needs a parsable mapped address, and nothing is sent without one.

    Args:
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge, to prove nothing was sent.
        block_type: Block type selected in the form.
        mapped_text: Text typed into the mapped-address input.
    """
    _arm(bridged_panel, {"_block_mapped_addr_input": mapped_text})
    _pick(bridged_panel, "_block_type_combo", block_type)

    method(bridged_panel, "_on_create_memory_block")()
    _settle(bridged_panel)

    assert _status(bridged_panel) == "Invalid mapped address for memory block"
    assert bridge.scripts == []


@pytest.mark.parametrize("case", _DISPATCH_ERRORS, ids=[case[0] for case in _DISPATCH_ERRORS])
def test_handler_reports_a_failed_bridge_call_in_the_status_line(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    case: tuple[str, str, str, str],
) -> None:
    """A valid request goes through the real worker to the bridge, and the bridge's failure comes back as the status line.

    The scripted wire raises one ``ToolError``. The panel's prefix names the operation, and the bridge's own text ends the line, whether
    the bridge passes the error on or wraps it first.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that fails its first call.
        case: Case id, handler name, create-form block type and the status prefix the failure must show.
    """
    _case_id, handler, block_type, prefix = case
    _arm(bridged_panel)
    _pick(bridged_panel, "_block_type_combo", block_type)
    bridge.remote_replies.append(ToolError(_WIRE_DOWN))

    method(bridged_panel, handler)()

    qtbot.waitUntil(lambda: _status(bridged_panel).startswith(prefix), timeout=_WAIT_MS)
    _settle(bridged_panel)
    assert _status(bridged_panel).startswith(prefix)
    assert _status(bridged_panel).endswith(_WIRE_DOWN)
    assert len(bridge.scripts) == 1
    assert bridge.evals == []


def test_define_structure_sends_the_pending_fields_and_refreshes_the_table(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Defining a structure sends the trimmed name and the fields in entry order, clears the pending list and refreshes the table.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that answers the define and the follow-up listing.
    """
    _type_into(bridged_panel, "_struct_name_input", "  Header  ")
    _fields(bridged_panel).extend([("tag", "dword"), ("length", "word")])
    label = priv(bridged_panel, "_struct_fields_label", QLabel)
    label.setText("Fields: tag:dword, length:word")
    label.setToolTip("Fields: tag:dword, length:word")
    bridge.remote_replies.extend(
        [
            {"name": "Header", "size": 6, "field_count": 2},
            [{"name": "Header", "size": 6, "field_count": 2, "path": "/"}],
        ],
    )

    method(bridged_panel, "_on_define_structure")()

    assert _fields(bridged_panel) == []
    assert not label.text()
    assert not label.toolTip()
    table = _table(bridged_panel, "_structs_table")
    _wait_rows(qtbot, table, 1)
    _settle(bridged_panel)
    assert _rows(table) == [["Header", "6", "2", "/"]]
    assert _sent_fields(bridge.scripts[0]) == [("tag", "dword"), ("length", "word")]
    assert 'StructureDataType(CategoryPath.ROOT, "Header", 0)' in bridge.scripts[0]


def test_refresh_structures_lists_what_the_bridge_returns(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Refreshing structures replaces the stale rows with one row per structure the bridge lists.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that answers the listing.
    """
    table = _table(bridged_panel, "_structs_table")
    table.setRowCount(3)
    bridge.remote_replies.append(
        [
            {"name": "Header", "size": 6, "field_count": 2, "path": "/"},
            {"name": "Entry", "size": 16, "field_count": 4, "path": "/pe"},
        ],
    )

    method(bridged_panel, "_on_refresh_structures")()

    _wait_rows(qtbot, table, 2)
    _settle(bridged_panel)
    assert _rows(table) == [["Header", "6", "2", "/"], ["Entry", "16", "4", "/pe"]]


def test_structures_table_uses_defaults_for_missing_fields(panel: GhidraPanel) -> None:
    """A structure entry without size, field count or path is shown with zeros and an empty path.

    Args:
        panel: Panel without a bridge.
    """
    method(panel, "_apply_structures")([{"name": "Bare"}])

    assert _rows(_table(panel, "_structs_table")) == [["Bare", "0", "0", ""]]


@pytest.mark.parametrize("result", [None, {"name": "not a list"}], ids=["none", "dict"])
def test_structures_table_is_cleared_when_the_result_is_not_a_list(panel: GhidraPanel, result: object) -> None:
    """A result that is not a list empties the structures table instead of keeping the previous rows.

    Args:
        panel: Panel without a bridge.
        result: Result handed to the handler.
    """
    table = _table(panel, "_structs_table")
    table.setRowCount(2)

    method(panel, "_apply_structures")(result)

    assert table.rowCount() == 0


def test_apply_structure_sends_the_address_and_trimmed_name(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Applying a structure sends the parsed address and the trimmed name, and reports success with the hexadecimal address.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that answers the request.
    """
    _arm(bridged_panel, {"_apply_struct_name_input": "  Header  "})
    bridge.remote_replies.append(True)

    method(bridged_panel, "_on_apply_structure")()

    _wait_status(qtbot, bridged_panel, "Structure 'Header' applied at 0x401000")
    _settle(bridged_panel)
    assert "addr = toAddr(4198400)" in bridge.scripts[0]
    assert 's.getName() == "Header"' in bridge.scripts[0]


def test_apply_structure_reports_an_unknown_structure_from_the_bridge(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """When Ghidra finds no structure of that name, the bridge's refusal is shown in the status line.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that reports nothing applied.
    """
    _arm(bridged_panel, {"_apply_struct_name_input": "Nope"})
    bridge.remote_replies.append(None)

    method(bridged_panel, "_on_apply_structure")()

    _wait_status(qtbot, bridged_panel, "Apply structure failed: Structure 'Nope' not found")
    _settle(bridged_panel)


def test_read_bytes_sends_the_address_and_length_and_shows_the_dump(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Reading bytes sends the parsed address and the chosen length and renders the returned bytes as a two-line hex dump.

    The twenty bytes are 0x41 through 0x54, so the dump is one full line of sixteen and a second line of four, and the second line's hex
    column is padded so the printable text stays aligned.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that answers the read.
    """
    _arm(bridged_panel)
    priv(bridged_panel, "_read_len_spin", QSpinBox).setValue(20)
    bridge.remote_replies.append({"address": 0x401000, "bytes": list(range(0x41, 0x55))})
    view = priv(bridged_panel, "_hex_dump_view", QPlainTextEdit)

    method(bridged_panel, "_on_read_bytes")()

    qtbot.waitUntil(lambda: bool(view.toPlainText()), timeout=_WAIT_MS)
    _settle(bridged_panel)
    first = "00000000  41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50  ABCDEFGHIJKLMNOP"
    second = "00000010  51 52 53 54" + " " * 38 + "QRST"
    assert view.toPlainText() == f"{first}\n{second}"
    assert "addr = toAddr(4198400)" in bridge.scripts[0]
    assert "jpype.JArray(jpype.JByte)(20)" in bridge.scripts[0]


@pytest.mark.parametrize("case", _READ_DUMP_CASES, ids=[case[0] for case in _READ_DUMP_CASES])
def test_read_result_renders_as_a_fixed_width_hex_dump(
    panel: GhidraPanel,
    case: tuple[str, object, tuple[tuple[str, str, str], ...]],
) -> None:
    """Every result form is shown as sixteen-byte lines of offset, padded hex column and printable text.

    Bytes from 0x20 through 0x7E print as themselves and every other byte prints as a dot. A result with no bytes leaves the view empty.

    Args:
        panel: Panel without a bridge.
        case: Case id, the result handed to the handler and the expected dump lines as (offset, hex, text).
    """
    _case_id, result, lines = case
    view = priv(panel, "_hex_dump_view", QPlainTextEdit)
    view.setPlainText("stale")

    method(panel, "_apply_read_bytes")(result)

    assert view.toPlainText() == "\n".join(starmap(_dump_line, lines))


def test_read_result_of_none_clears_the_dump(panel: GhidraPanel) -> None:
    """A read that produced nothing empties the dump view.

    Args:
        panel: Panel without a bridge.
    """
    view = priv(panel, "_hex_dump_view", QPlainTextEdit)
    view.setPlainText("stale")

    method(panel, "_apply_read_bytes")(None)

    assert not view.toPlainText()


def test_read_result_without_a_bytes_key_falls_back_to_its_hex_text(panel: GhidraPanel) -> None:
    """A result that carries only the ``hex`` text is still rendered, as the handler's documentation describes.

    ``_apply_read_bytes`` documents a dict with ``hex``, ``bytes`` and ``address`` keys and falls back to ``hex`` when ``bytes`` is not a
    list. Reading ``bytes`` with an empty list as the default means a dict without that key never reaches the fallback and renders as an
    empty dump.

    Args:
        panel: Panel without a bridge.
    """
    view = priv(panel, "_hex_dump_view", QPlainTextEdit)

    method(panel, "_apply_read_bytes")({"hex": "41 42 43"})

    assert view.toPlainText() == _dump_line("00000000", "41 42 43", "ABC")


@pytest.mark.parametrize(("block_type", "mapped_text", "reply", "tokens"), _CREATE_CASES, ids=[case[0] for case in _CREATE_CASES])
def test_create_memory_block_sends_the_form_values_and_refreshes_the_map(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    block_type: str,
    mapped_text: str,
    reply: dict[str, object],
    tokens: tuple[str, ...],
) -> None:
    """Each block type calls its own creation routine with the name, start, size and (where it applies) mapped address.

    The start is 0x1000 (4096) and the mapped address 0x2000 (8192), so a handler that swapped them would send the wrong script. The two
    block types that ignore the mapped address are given an unparsable one and must still be created. The follow-up memory-map listing
    fills the table with the block.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that answers the creation and the follow-up listing.
        block_type: Block type selected in the form.
        mapped_text: Text typed into the mapped-address input.
        reply: Scripted answer to the creation request.
        tokens: Pieces the bridge's script must contain.
    """
    _arm(bridged_panel, {"_block_name_input": "  new_blk  ", "_block_perms_input": " rw ", "_block_mapped_addr_input": mapped_text})
    priv(bridged_panel, "_block_size_spin", QSpinBox).setValue(64)
    _pick(bridged_panel, "_block_type_combo", block_type)
    bridge.remote_replies.extend([reply, _MEMORY_BLOCK_REPLY])
    table = _table(bridged_panel, "_memory_table")

    method(bridged_panel, "_on_create_memory_block")()

    _wait_rows(qtbot, table, 1)
    _settle(bridged_panel)
    assert _rows(table) == _MEMORY_BLOCK_ROW
    for token in tokens:
        assert token in bridge.scripts[0]


@pytest.mark.parametrize(("handler", "reply", "tokens"), [case[1:] for case in _BLOCK_OP_CASES], ids=[case[0] for case in _BLOCK_OP_CASES])
def test_block_operation_sends_its_own_form_values_and_refreshes_the_map(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    handler: str,
    reply: dict[str, object],
    tokens: tuple[str, ...],
) -> None:
    """Remove, split, move, rename, comment and join each read their own row of the form, then refresh the memory map.

    Every row holds a different name, so a handler that read a neighbouring input would send the wrong block name.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that answers the operation and the follow-up listing.
        handler: Name of the panel slot under test.
        reply: Scripted answer to the operation.
        tokens: Pieces the bridge's script must contain.
    """
    _arm(bridged_panel)
    bridge.remote_replies.extend([reply, _MEMORY_BLOCK_REPLY])
    table = _table(bridged_panel, "_memory_table")

    method(bridged_panel, handler)()

    _wait_rows(qtbot, table, 1)
    _settle(bridged_panel)
    assert _rows(table) == _MEMORY_BLOCK_ROW
    for token in tokens:
        assert token in bridge.scripts[0]


def test_segments_table_shows_each_segment_with_its_permissions(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Refreshing segments replaces the stale rows with one row per segment, with hex bounds and one letter per granted permission.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that answers the listing.
    """
    table = _table(bridged_panel, "_segments_table")
    table.setRowCount(3)
    bridge.remote_replies.append(_SEGMENT_REPLY)

    method(bridged_panel, "_on_refresh_segments")()

    _wait_rows(qtbot, table, 2)
    _settle(bridged_panel)
    assert _rows(table) == _SEGMENT_ROWS


@pytest.mark.parametrize("result", [None, {"name": "not a list"}], ids=["none", "dict"])
def test_segments_table_is_cleared_when_the_result_is_not_a_list(panel: GhidraPanel, result: object) -> None:
    """A result that is not a list empties the segments table instead of keeping the previous rows.

    Args:
        panel: Panel without a bridge.
        result: Result handed to the handler.
    """
    table = _table(panel, "_segments_table")
    table.setRowCount(2)

    method(panel, "_apply_segments")(result)

    assert table.rowCount() == 0


def test_program_info_table_lists_each_property_in_order(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Refreshing program information replaces the stale rows with one property and value row per key, in the bridge's order.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that answers the request.
    """
    table = _table(bridged_panel, "_program_info_table")
    table.setRowCount(2)
    bridge.remote_replies.append(_PROGRAM_INFO_REPLY)

    method(bridged_panel, "_on_refresh_program_info")()

    _wait_rows(qtbot, table, len(_PROGRAM_INFO_ROWS))
    _settle(bridged_panel)
    assert _rows(table) == _PROGRAM_INFO_ROWS


def test_program_info_accepts_a_dataclass_instance(panel: GhidraPanel) -> None:
    """A dataclass result is shown field by field, in declaration order, with every value written as text.

    Args:
        panel: Panel without a bridge.
    """
    table = _table(panel, "_program_info_table")
    table.setRowCount(2)

    method(panel, "_apply_program_info")(BridgeState(connected=True, tool_running=True, target_pid=7))

    assert _rows(table) == [
        ["connected", "True"],
        ["tool_running", "True"],
        ["binary_loaded", "False"],
        ["process_attached", "False"],
        ["target_path", "None"],
        ["target_pid", "7"],
        ["last_error", "None"],
    ]


@pytest.mark.parametrize("case", _UNEXPECTED_PROGRAM_INFO, ids=[case[0] for case in _UNEXPECTED_PROGRAM_INFO])
def test_program_info_of_an_unexpected_type_is_reported_as_an_error_row(panel: GhidraPanel, case: tuple[str, object, str]) -> None:
    """A result that is neither a dict nor a dataclass instance becomes one error row and a status line naming its type.

    A dataclass class object is not an instance, so it is reported the same way.

    Args:
        panel: Panel without a bridge.
        case: Case id, the result handed to the handler and the name of its type.
    """
    _case_id, result, type_name = case
    table = _table(panel, "_program_info_table")
    table.setRowCount(3)

    method(panel, "_apply_program_info")(result)

    assert _rows(table) == [["error", f"program_info returned unexpected type: {type_name}"]]
    assert _status(panel) == f"Program info has unexpected shape: {type_name}"


@pytest.mark.parametrize(
    ("case_id", "name_text", "base_text", "readback", "tokens"),
    _METADATA_CASES,
    ids=[case[0] for case in _METADATA_CASES],
)
def test_update_metadata_sends_only_the_values_that_were_entered(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
    case_id: str,
    name_text: str,
    base_text: str,
    readback: dict[str, object],
    tokens: tuple[str, ...],
) -> None:
    """The program name and the image base are each sent when entered and left unchanged when blank.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that applies the change and answers the read-back.
        case_id: Case id, used only for the test id.
        name_text: Text typed into the program-name input.
        base_text: Text typed into the image-base input.
        readback: Name and image base the program reports after the change.
        tokens: Pieces the bridge's script must contain.
    """
    del case_id
    _arm(bridged_panel, {"_meta_name_input": name_text, "_meta_base_input": base_text})
    bridge.remote_replies.append(None)
    bridge.eval_replies.append(readback)

    method(bridged_panel, "_on_update_metadata")()

    _wait_status(qtbot, bridged_panel, "Metadata updated")
    _settle(bridged_panel)
    for token in tokens:
        assert token in bridge.scripts[0]
    assert len(bridge.evals) == 1


def test_update_metadata_shows_the_bridge_verification_failure(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """When Ghidra reports a different program name after the change, the bridge's verification error is shown.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge whose read-back disagrees with the request.
    """
    _arm(bridged_panel, {"_meta_name_input": "wanted.exe", "_meta_base_input": ""})
    bridge.remote_replies.append(None)
    bridge.eval_replies.append({"name": "actual.exe", "image_base": 0})

    method(bridged_panel, "_on_update_metadata")()

    _wait_status(
        qtbot,
        bridged_panel,
        "Update metadata failed: Program name verification failed: expected 'wanted.exe', observed 'actual.exe'",
    )
    _settle(bridged_panel)


def test_building_a_call_graph_clears_the_previous_tree_before_the_answer_arrives(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """The old tree is emptied as soon as a build starts, and a failed build leaves it empty.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that fails the request.
    """
    _arm(bridged_panel)
    tree = _tree(bridged_panel)
    tree.addTopLevelItem(QTreeWidgetItem(["stale", "0x0"]))
    bridge.remote_replies.append(ToolError(_WIRE_DOWN))

    method(bridged_panel, "_on_build_call_graph")()

    assert tree.topLevelItemCount() == 0
    _wait_status(qtbot, bridged_panel, f"Build call graph failed: {_WIRE_DOWN}")
    _settle(bridged_panel)
    assert tree.topLevelItemCount() == 0


def test_building_a_call_graph_sends_the_address_depth_and_direction_and_shows_the_tree(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """The build sends the parsed address, the chosen depth and the chosen direction and shows the returned tree with its nesting.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that answers with a three-level call tree.
    """
    _arm(bridged_panel)
    priv(bridged_panel, "_cg_depth_spin", QSpinBox).setValue(3)
    _pick(bridged_panel, "_cg_direction_combo", "callers")
    bridge.remote_replies.append(_CALL_TREE)
    tree = _tree(bridged_panel)

    method(bridged_panel, "_on_build_call_graph")()

    qtbot.waitUntil(lambda: tree.topLevelItemCount() == 1, timeout=_WAIT_MS)
    _settle(bridged_panel)
    assert _tree_rows(tree) == _CALL_TREE_ROWS
    assert "addr = toAddr(4198400)" in bridge.scripts[0]
    assert 'direction = "callers"' in bridge.scripts[0]
    assert "get_caller_tree(func, 3, 0, set())" in bridge.scripts[0]


def test_call_tree_without_children_uses_the_callees_key(panel: GhidraPanel) -> None:
    """A node that lists its callees under ``callees`` instead of ``children`` still gets them as child rows.

    Args:
        panel: Panel without a bridge.
    """
    payload: dict[str, object] = {"name": "root", "address": 0x10, "callees": [{"name": "c1", "address": 0x20}]}

    method(panel, "_apply_call_graph")(payload)

    assert _tree_rows(_tree(panel)) == [("root", "0x10", [("c1", "0x20", [])])]


def test_call_tree_skips_children_that_are_not_nodes(panel: GhidraPanel) -> None:
    """Entries of a children list that are not dictionaries are ignored and the real nodes are kept.

    Args:
        panel: Panel without a bridge.
    """
    payload: dict[str, object] = {"function": "root", "address": 0x10, "children": ["junk", 5, {"function": "real", "address": 0x30}]}

    method(panel, "_apply_call_graph")(payload)

    assert _tree_rows(_tree(panel)) == [("root", "0x10", [("real", "0x30", [])])]


@pytest.mark.parametrize("children", [None, "text", {"function": "x"}], ids=["none", "text", "dict"])
def test_call_tree_node_whose_children_are_not_a_list_has_no_child_rows(panel: GhidraPanel, children: object) -> None:
    """A node whose ``children`` value is not a list is shown as a single row with nothing below it.

    Args:
        panel: Panel without a bridge.
        children: Value of the node's ``children`` key.
    """
    payload: dict[str, object] = {"function": "root", "address": 0x10, "children": children}

    method(panel, "_apply_call_graph")(payload)

    assert _tree_rows(_tree(panel)) == [("root", "0x10", [])]


def test_call_tree_given_as_a_list_shows_one_top_level_row_per_node(panel: GhidraPanel) -> None:
    """A list result becomes top-level rows, each named by its ``name`` or else its ``function``.

    Args:
        panel: Panel without a bridge.
    """
    tree = _tree(panel)
    tree.addTopLevelItem(QTreeWidgetItem(["stale", "0x0"]))
    payload: list[dict[str, object]] = [
        {"function": "f1", "address": 0x10},
        {"name": "n2", "address": 0x20},
        {"name": "", "function": "f3", "address": 0},
    ]

    method(panel, "_apply_call_graph")(payload)

    assert _tree_rows(tree) == [("f1", "0x10", []), ("n2", "0x20", []), ("f3", "0x0", [])]


@pytest.mark.parametrize("result", [None, "text", 5], ids=["none", "text", "number"])
def test_call_tree_of_another_type_leaves_the_tree_empty(panel: GhidraPanel, result: object) -> None:
    """A result that is neither a dict nor a list empties the tree and adds nothing.

    Args:
        panel: Panel without a bridge.
        result: Result handed to the handler.
    """
    tree = _tree(panel)
    tree.addTopLevelItem(QTreeWidgetItem(["stale", "0x0"]))

    method(panel, "_apply_call_graph")(result)

    assert tree.topLevelItemCount() == 0


def test_both_direction_call_tree_shows_the_callers_the_bridge_returns(panel: GhidraPanel) -> None:
    """A call tree built in both directions shows the callers as well as the callees.

    For direction ``both`` the bridge returns ``callees`` and ``callers`` as separate lists on the root. The panel reads only
    ``children`` or ``callees``, so the callers the user asked for are silently dropped.

    Args:
        panel: Panel without a bridge.
    """
    payload: dict[str, object] = {
        "function": "main",
        "address": 0x401000,
        "direction": "both",
        "callees": [{"function": "callee_a", "address": 0x402000, "children": []}],
        "callers": [{"function": "caller_b", "address": 0x403000, "children": []}],
    }

    method(panel, "_apply_call_graph")(payload)

    names = _all_names(_tree_rows(_tree(panel)))
    assert "callee_a" in names
    assert "caller_b" in names


def test_show_callers_lists_each_calling_function(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Showing callers replaces the tree with one row per calling function, with its hexadecimal entry address.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that answers with two callers.
    """
    _arm(bridged_panel)
    tree = _tree(bridged_panel)
    tree.addTopLevelItem(QTreeWidgetItem(["stale", "0x0"]))
    bridge.remote_replies.append(
        [
            {"caller_address": 0x401100, "caller_function": "caller_one", "call_site": 0x401105, "ref_type": "UNCONDITIONAL_CALL"},
            {"caller_address": 0x402200, "caller_function": "caller_two", "call_site": 0x402210, "ref_type": "UNCONDITIONAL_CALL"},
        ],
    )

    method(bridged_panel, "_on_show_callers")()

    qtbot.waitUntil(lambda: _tree_rows(tree) == [("caller_one", "0x401100", []), ("caller_two", "0x402200", [])], timeout=_WAIT_MS)
    _settle(bridged_panel)
    assert "addr = toAddr(4198400)" in bridge.scripts[0]
    assert "getReferencesTo(addr)" in bridge.scripts[0]


@pytest.mark.parametrize("result", [None, {"caller_function": "x"}], ids=["none", "dict"])
def test_callers_result_that_is_not_a_list_empties_the_tree(panel: GhidraPanel, result: object) -> None:
    """A callers result that is not a list empties the tree and adds nothing.

    Args:
        panel: Panel without a bridge.
        result: Result handed to the handler.
    """
    tree = _tree(panel)
    tree.addTopLevelItem(QTreeWidgetItem(["stale", "0x0"]))

    method(panel, "_apply_callers")(result)

    assert tree.topLevelItemCount() == 0


def test_callers_from_outside_any_function_are_still_listed(panel: GhidraPanel) -> None:
    """A call made from code that no function contains is listed instead of breaking the whole result.

    The bridge reports such a call with ``caller_address`` and ``caller_function`` both ``None`` and only the call site filled in. The
    panel converts the address with ``int()``, which rejects ``None``, so the handler raises and no caller at all is shown.

    Args:
        panel: Panel without a bridge.
    """
    payload: list[dict[str, object]] = [
        {"caller_address": None, "caller_function": None, "call_site": 0x401005, "ref_type": "UNCONDITIONAL_CALL"},
    ]

    method(panel, "_apply_callers")(payload)

    assert _tree(panel).topLevelItemCount() == 1


def test_show_slice_lists_each_slice_address(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Showing a slice replaces the tree with one row per slice address, written in hexadecimal in both columns.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that answers with a slice of two addresses.
    """
    _arm(bridged_panel)
    tree = _tree(bridged_panel)
    tree.addTopLevelItem(QTreeWidgetItem(["stale", "0x0"]))
    bridge.remote_replies.append(
        {"address": 0x401000, "direction": "backward", "slice_addresses": [0x401000, 0x40100A], "slice_pcode_ops": []},
    )

    method(bridged_panel, "_on_show_slice")()

    qtbot.waitUntil(lambda: _tree_rows(tree) == [("0x401000", "0x401000", []), ("0x40100A", "0x40100A", [])], timeout=_WAIT_MS)
    _settle(bridged_panel)
    assert "addr = toAddr(4198400)" in bridge.scripts[0]


@pytest.mark.parametrize(
    "result",
    [None, [1, 2], {"address": 1}, {"slice_addresses": "not a list"}],
    ids=["none", "list", "no_addresses", "addresses_not_a_list"],
)
def test_slice_result_without_addresses_empties_the_tree(panel: GhidraPanel, result: object) -> None:
    """A slice result that is not a dict, or has no list of addresses, empties the tree and adds nothing.

    Args:
        panel: Panel without a bridge.
        result: Result handed to the handler.
    """
    tree = _tree(panel)
    tree.addTopLevelItem(QTreeWidgetItem(["stale", "0x0"]))

    method(panel, "_apply_slice")(result)

    assert tree.topLevelItemCount() == 0


def test_add_comment_sends_the_trimmed_text_and_chosen_type(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Adding a comment sends the parsed address, the chosen comment type and the trimmed text, and reports success after the read-back matches.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that stores the comment and reads it back.
    """
    _arm(bridged_panel, {"_cmt_text_input": "  hello  "})
    _pick(bridged_panel, "_cmt_type_combo", "PRE")
    bridge.remote_replies.append(None)
    bridge.eval_replies.append("hello")

    method(bridged_panel, "_on_add_comment")()

    _wait_status(qtbot, bridged_panel, "Comment added")
    _settle(bridged_panel)
    assert 'cu.setComment(CodeUnit.PRE_COMMENT, "hello")' in bridge.scripts[0]
    assert "addr = toAddr(4198400)" in bridge.scripts[0]


def test_add_comment_shows_the_bridge_verification_failure(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """When the stored comment does not read back as sent, the bridge's verification error is shown.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge whose read-back differs from the comment.
    """
    _arm(bridged_panel)
    bridge.remote_replies.append(None)
    bridge.eval_replies.append("something else")

    method(bridged_panel, "_on_add_comment")()

    _wait_status(
        qtbot,
        bridged_panel,
        "Add comment failed: Comment verification failed at 0x401000: comment did not round-trip",
    )
    _settle(bridged_panel)


def test_remove_comment_clears_the_chosen_type_and_refreshes_the_table(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Removing a comment clears the chosen comment type at the parsed address and then reloads the comment table.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that clears the comment, reads it back empty and lists what remains.
    """
    _arm(bridged_panel)
    _pick(bridged_panel, "_cmt_type_combo", "PLATE")
    table = _table(bridged_panel, "_comments_table")
    table.setRowCount(3)
    bridge.remote_replies.extend([None, [{"address": 0x401000, "type": "EOL", "comment": "kept"}]])
    bridge.eval_replies.append(None)

    method(bridged_panel, "_on_remove_comment")()

    _wait_rows(qtbot, table, 1)
    _settle(bridged_panel)
    assert _rows(table) == [["0x401000", "EOL", "kept"]]
    assert "cu.setComment(CodeUnit.PLATE_COMMENT, None)" in bridge.scripts[0]
    assert "addr = toAddr(4198400)" in bridge.scripts[0]


def test_refresh_comments_lists_the_comments_of_the_address_range(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Refreshing comments asks for the range that starts at the parsed address and fills the table from the answer.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that answers with two comments.
    """
    _arm(bridged_panel)
    table = _table(bridged_panel, "_comments_table")
    table.setRowCount(3)
    bridge.remote_replies.append(_COMMENT_ROWS_REPLY)

    method(bridged_panel, "_on_refresh_comments")()

    _wait_rows(qtbot, table, 2)
    _settle(bridged_panel)
    assert _rows(table) == _COMMENT_ROWS
    assert "start = toAddr(4198400)" in bridge.scripts[0]
    assert "end = toAddr(4198400 + 256)" in bridge.scripts[0]


def test_load_all_comments_disables_the_button_until_the_comments_arrive(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """Loading every comment disables the button and shows a progress line, then fills the table and re-enables the button.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that answers with two comments.
    """
    button = priv(bridged_panel, "_load_all_cmt_btn", QPushButton)
    table = _table(bridged_panel, "_comments_table")
    bridge.remote_replies.append(_COMMENT_ROWS_REPLY)

    method(bridged_panel, "_on_load_all_comments")()

    assert not button.isEnabled()
    assert _status(bridged_panel) == "Loading all comments..."
    _wait_status(qtbot, bridged_panel, "Loaded 2 comments")
    _settle(bridged_panel)
    assert button.isEnabled()
    assert _rows(table) == _COMMENT_ROWS


def test_load_all_comments_failure_reenables_the_button_and_reports_it(
    qtbot: QtBot,
    bridged_panel: GhidraPanel,
    bridge: ScriptedGhidraBridge,
) -> None:
    """A failed bulk load re-enables the button and puts the bridge's error in the status line.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        bridged_panel: Panel holding a connected scripted bridge.
        bridge: The scripted bridge that fails the request.
    """
    button = priv(bridged_panel, "_load_all_cmt_btn", QPushButton)
    bridge.remote_replies.append(ToolError(_WIRE_DOWN))

    method(bridged_panel, "_on_load_all_comments")()

    assert not button.isEnabled()
    _wait_status(qtbot, bridged_panel, f"Load all comments failed: {_WIRE_DOWN}")
    _settle(bridged_panel)
    assert button.isEnabled()


def test_load_all_comments_result_that_cannot_be_applied_still_reenables_the_button(panel: GhidraPanel) -> None:
    """A bulk result the table cannot take never leaves the Load All button disabled.

    Args:
        panel: Panel without a bridge.
    """
    button = priv(panel, "_load_all_cmt_btn", QPushButton)
    button.setEnabled(False)

    with contextlib.suppress(ValueError):
        method(panel, "_apply_all_comments_success")([{"address": "not a number", "type": "EOL", "comment": "x"}])

    assert button.isEnabled()
