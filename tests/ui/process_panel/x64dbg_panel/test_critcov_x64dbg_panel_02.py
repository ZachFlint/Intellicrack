# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Coverage for the x64dbg panel slots that guard, validate, dispatch to the bridge and render its results.

x64dbg is not installed in the test container, so every test drives the real ``X64DbgPanel`` and checks widget state. Bridge-backed slots
run against ``RecordingBridge``, a subclass of the real ``X64DbgBridge`` that replaces only the two methods that cross the process
boundary (``_send_pipe_command`` and ``_send_command``) with a transcript and scripted replies; everything above that boundary is the
production bridge code. Cases that touch the operating system use a real child process that holds a known marker in a mapped view and
the real Win32 memory APIs, and the connected-pipe case uses the real named-pipe server helper. Expected values come from the documented
payload shapes in the bridge, the hex dump layout (sixteen bytes per line) and the arithmetic of the addresses involved.
"""

from __future__ import annotations

import asyncio
import ctypes
import subprocess
import sys
import time
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

import pytest
from PyQt6.QtCore import QSignalBlocker, Qt
from PyQt6.QtWidgets import QFileDialog, QTableWidget, QTableWidgetItem

from intellicrack.bridges.base import StackFrame
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import MemoryRegion, ModuleInfo, ThreadInfo, ToolError
from intellicrack.ui.panels.async_bridge import bridge_workers_for, drain_bridge_workers_for, run_bridge_coroutine
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel
from tests._helpers import realcov_pipe_server as pipe_server


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterator, Mapping

    from PyQt6.QtWidgets import QApplication
    from pytestqt.qtbot import QtBot

    from intellicrack.bridges.x64dbg import PipeCommandResult


type PipeReply = PipeCommandResult | ToolError
type RpcLog = list[tuple[str, dict[str, Any] | None]]

_Dynamic = Any

_WAIT_MS: int = 20_000
_PIPE_READY_TIMEOUT_S: float = 10.0
_SERVER_MODULE = "tests._helpers.realcov_pipe_server"
_MARKER_TEXT = "CRITCOV_X64DBG_PANEL02_MARKER"
_MARKER = _MARKER_TEXT.encode("ascii")
_BYTES_PER_LINE: int = 16
_DEFAULT_READ_SIZE: int = 256
_NO_REPLY = "no scripted reply for "
_NO_CONSOLE = "no scripted console output for "
_NO_BRIDGE_LINE = "[!] No bridge configured"
_DIAGNOSTIC = "x64dbg installation not configured"
_CHILD_SOURCE = (
    "import ctypes, mmap, sys\n"
    f"marker = b'{_MARKER_TEXT}'\n"
    "view = mmap.mmap(-1, 65536)\n"
    "view[:len(marker)] = marker\n"
    "print(ctypes.addressof(ctypes.c_char.from_buffer(view)), flush=True)\n"
    "sys.stdin.read()\n"
)


class RecordingBridge(X64DbgBridge):
    """Real ``X64DbgBridge`` whose transport answers from a script and keeps a transcript.

    Only ``_send_pipe_command`` and ``_send_command`` are replaced. A pipe command with no scripted reply raises a non-recoverable
    ``ToolError`` whose message is ``no scripted reply for <name>``; a console command raises ``no scripted console output for <text>``
    unless ``console_reply`` is set. ``replies`` holds the scripted reply (or ``ToolError`` to raise) keyed by RPC name, ``sent_rpcs``
    every ``(rpc_name, params)`` pair requested in order, and ``sent_commands`` every console command text requested in order.
    """

    def __init__(self) -> None:
        """Create the bridge with an empty script and transcript."""
        super().__init__()
        self.replies: dict[str, PipeReply] = {}
        self.console_reply: str | None = None
        self.sent_rpcs: RpcLog = []
        self.sent_commands: list[str] = []

    async def _send_pipe_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> PipeCommandResult:
        """Return the scripted reply for ``command`` after recording it.

        Args:
            command: RPC name requested by the production code.
            params: RPC parameters requested by the production code.

        Returns:
            PipeCommandResult: The scripted reply.

        Raises:
            ToolError: When the reply is scripted as an error or no reply is scripted.
        """
        await asyncio.sleep(0)
        self.sent_rpcs.append((command, params))
        if command not in self.replies:
            msg = f"{_NO_REPLY}{command}"
            raise ToolError(msg, tool_name="x64dbg", details={"x64dbg_error_code": "remote_error"})
        reply = self.replies[command]
        if isinstance(reply, ToolError):
            raise ToolError(reply.message, tool_name=reply.tool_name, details=dict(reply.details))
        return reply

    async def _send_command(self, command: str) -> str:
        """Record the console command and return the scripted output.

        Args:
            command: Console command text built by the production code.

        Returns:
            str: The scripted console output.

        Raises:
            ToolError: When no console output is scripted.
        """
        await asyncio.sleep(0)
        self.sent_commands.append(command)
        if self.console_reply is None:
            msg = f"{_NO_CONSOLE}{command}"
            raise ToolError(msg, tool_name="x64dbg", details={"x64dbg_error_code": "remote_error"})
        return self.console_reply


class Rig(NamedTuple):
    """A panel wired to a recording bridge.

    Attributes:
        panel: The panel under test.
        bridge: The bridge installed on the panel.
    """

    panel: X64DbgPanel
    bridge: RecordingBridge


class ChildRig(NamedTuple):
    """A panel wired to a real bridge attached to a real child process.

    Attributes:
        panel: The panel under test.
        bridge: Plain ``X64DbgBridge`` attached to the child.
        address: Address of the marker inside the child.
    """

    panel: X64DbgPanel
    bridge: X64DbgBridge
    address: int


class FailCase(NamedTuple):
    """A slot whose bridge call fails, with the transcript the bridge must record.

    Attributes:
        slot: Panel slot name.
        inputs: Widget attribute name to text; ``{path}`` is replaced by a temp path.
        needle: Console text the error handler must print; ``{path}`` is replaced by a temp path.
        rpcs: Expected pipe transcript; ``{path}`` is replaced by a temp path.
        commands: Expected console-command transcript; ``{path}`` is replaced by a temp path.
    """

    slot: str
    inputs: dict[str, str]
    needle: str
    rpcs: RpcLog
    commands: list[str]


class OkCase(NamedTuple):
    """A slot whose bridge call succeeds, with the line the success handler must print.

    Attributes:
        slot: Panel slot name.
        inputs: Widget attribute name to text.
        replies: Scripted pipe replies.
        console_reply: Scripted console output, or ``None``.
        output: Name of the text widget that receives the line.
        line: Expected text of the line.
        rpcs: Expected pipe transcript prefix.
    """

    slot: str
    inputs: dict[str, str]
    replies: dict[str, PipeCommandResult]
    console_reply: str | None
    output: str
    line: str
    rpcs: RpcLog


def _priv(obj: object, name: str) -> _Dynamic:
    """Read a private attribute or method of a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.

    Returns:
        _Dynamic: The attribute value.
    """
    return getattr(obj, name)


def _console(panel: X64DbgPanel) -> str:
    """Return the console text of the panel.

    Args:
        panel: Panel to read.

    Returns:
        str: Plain text of the console.
    """
    return str(_priv(panel, "_console_output").toPlainText())


def _trace(panel: X64DbgPanel) -> str:
    """Return the trace output text of the panel.

    Args:
        panel: Panel to read.

    Returns:
        str: Plain text of the trace output.
    """
    return str(_priv(panel, "_trace_output").toPlainText())


def _status(panel: X64DbgPanel) -> str:
    """Return the status label text of the panel.

    Args:
        panel: Panel to read.

    Returns:
        str: Text of the toolbar status label, or an empty string when there is none.
    """
    label = panel.status_label
    return label.text() if label is not None else ""


def _last_line(text: str) -> str:
    """Return the last line of a text block.

    Args:
        text: Text block.

    Returns:
        str: Final line.
    """
    return text.splitlines()[-1]


def _fill(panel: X64DbgPanel, inputs: Mapping[str, str]) -> None:
    """Set the text of the named line edits.

    Args:
        panel: Panel that owns the widgets.
        inputs: Widget attribute name to text.
    """
    for name, text in inputs.items():
        _priv(panel, name).setText(text)


def _wait_for(qtbot: QtBot, predicate: Callable[[], bool]) -> None:
    """Spin the event loop until ``predicate`` holds.

    Args:
        qtbot: The pytest-qt helper.
        predicate: Condition to wait for.
    """
    qtbot.waitUntil(predicate, timeout=_WAIT_MS)


def _wait_console(qtbot: QtBot, panel: X64DbgPanel, needle: str) -> None:
    """Spin the event loop until the console holds ``needle``.

    Args:
        qtbot: The pytest-qt helper.
        panel: Panel whose console is watched.
        needle: Text to wait for.
    """
    _wait_for(qtbot, lambda: needle in _console(panel))


def _picker(path: str) -> Callable[..., tuple[str, str]]:
    """Build a stand-in for a Qt file dialog static function that returns ``path``.

    Args:
        path: Path the dialog reports as chosen.

    Returns:
        Callable[..., tuple[str, str]]: Function with the dialog's call signature.
    """

    def pick(*_args: object, **_kwargs: object) -> tuple[str, str]:
        """Return the chosen path and an empty filter.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            tuple[str, str]: The path and an empty filter string.
        """
        return (path, "")

    return pick


def _seed_row(table: QTableWidget, name: str, value: str) -> QTableWidgetItem:
    """Put one two-cell row in a register table without emitting its change signal.

    Args:
        table: Register table to seed.
        name: Register name.
        value: Register value text.

    Returns:
        QTableWidgetItem: The value cell.
    """
    with QSignalBlocker(table):
        table.setRowCount(1)
        table.setItem(0, 0, QTableWidgetItem(name))
        item = QTableWidgetItem(value)
        table.setItem(0, 1, item)
    return item


def _seed_two_rows(table: QTableWidget) -> None:
    """Fill a table with two stale rows without emitting its change signal.

    Args:
        table: Table to fill.
    """
    with QSignalBlocker(table):
        table.setRowCount(2)
        for row in range(2):
            table.setItem(row, 0, QTableWidgetItem(f"stale{row}"))
            table.setItem(row, 1, QTableWidgetItem("0x1"))


def _cell(table: QTableWidget, row: int, column: int) -> str:
    """Return the text of one table cell.

    Args:
        table: Table to read.
        row: Row index.
        column: Column index.

    Returns:
        str: Cell text.
    """
    item = table.item(row, column)
    assert item is not None, f"cell ({row}, {column}) is empty"
    return item.text()


def _select_first_row(table: QTableWidget) -> None:
    """Make the first row the current row.

    Args:
        table: Table to select in.
    """
    table.setCurrentCell(0, 0)


def _seed_all(panel: X64DbgPanel) -> None:
    """Fill every input and select a valid row in every table, so only a missing bridge can stop a slot.

    Args:
        panel: Panel to arm.
    """
    _fill(
        panel,
        {
            "_mem_addr_input": "0x401000",
            "_mem_size_input": "16",
            "_console_input": "bp 401000",
            "_run_to_input": "0x401000",
            "_run_to_party_input": "0",
            "_set_ip_input": "0x401000",
            "_wp_addr_input": "0x401000",
            "_search_pattern_input": "AA BB",
            "_trace_cond_input": "rax == 1",
            "_trace_log_input": "step",
            "_trace_logfile_input": "C:\\traces\\run.log",
            "_trace_record_addr_input": "0x401000",
            "_lbl_addr_input": "0x401000",
            "_lbl_text_input": "entry",
            "_cmt_addr_input": "0x401000",
            "_cmt_text_input": "why",
            "_alloc_size_input": "4096",
        },
    )
    module_table = _priv(panel, "_module_table")
    module_table.setRowCount(1)
    module_table.setItem(0, 0, QTableWidgetItem("kernel32.dll"))
    _select_first_row(module_table)
    wp_table = _priv(panel, "_wp_table")
    wp_table.setRowCount(1)
    wp_item = QTableWidgetItem("0x401000")
    wp_item.setData(Qt.ItemDataRole.UserRole, 1)
    wp_table.setItem(0, 0, wp_item)
    _select_first_row(wp_table)
    _priv(panel, "_apply_labels")([{"address": "0x401000", "text": "entry"}])
    _select_first_row(_priv(panel, "_lbl_table"))
    _priv(panel, "_apply_comments")([{"address": "0x401000", "text": "why"}])
    _select_first_row(_priv(panel, "_cmt_table"))
    _priv(panel, "_apply_memmap")([MemoryRegion(0x401000, 0x1000, "r--", "MEM_COMMIT", "MEM_PRIVATE", None)])
    _select_first_row(_priv(panel, "_mmap_table"))


def _wait_for_pipe(pipe_name: str) -> None:
    """Block until the named pipe exists, using the real ``WaitNamedPipeW``.

    Args:
        pipe_name: Endpoint the child server hosts.

    Raises:
        ToolError: If the pipe never appears within the readiness deadline.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    deadline = time.monotonic() + _PIPE_READY_TIMEOUT_S
    while time.monotonic() < deadline:
        if kernel32.WaitNamedPipeW(pipe_name, 200):
            return
        time.sleep(0.05)
    msg = f"Server pipe {pipe_name} never became available"
    raise ToolError(msg)


def _stop_child(child: subprocess.Popen[Any]) -> None:
    """Terminate and reap a child process.

    Args:
        child: Child started by a fixture.
    """
    if child.poll() is None:
        child.terminate()
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=10)


@pytest.fixture
def panel(qapp: QApplication) -> Generator[X64DbgPanel]:
    """Provide a panel with no bridge and join its workers on teardown.

    Args:
        qapp: The shared offscreen QApplication fixture.

    Yields:
        X64DbgPanel: The panel under test.
    """
    widget = X64DbgPanel()
    try:
        yield widget
    finally:
        drain_bridge_workers_for(widget)
        widget.close()
        qapp.processEvents()


@pytest.fixture
def rig(panel: X64DbgPanel) -> Rig:
    """Provide the panel wired to a recording bridge.

    Args:
        panel: The panel under test.

    Returns:
        Rig: Panel and bridge.
    """
    bridge = RecordingBridge()
    panel.set_bridge(bridge)
    return Rig(panel, bridge)


@pytest.fixture
def marker_child() -> Iterator[tuple[int, int]]:
    """Yield a child process that holds a known marker in a mapped view.

    The child prints the address of the view's first byte, which is where the marker sits.

    Yields:
        tuple[int, int]: The child's pid and the address of the marker inside it.
    """
    child = subprocess.Popen(
        [sys.executable, "-c", _CHILD_SOURCE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert child.stdout is not None
        address = int(child.stdout.readline())
        yield child.pid, address
    finally:
        if child.stdin is not None:
            child.stdin.close()
        _stop_child(child)
        if child.stdout is not None:
            child.stdout.close()


@pytest.fixture
def child_rig(panel: X64DbgPanel, marker_child: tuple[int, int]) -> Iterator[ChildRig]:
    """Provide the panel wired to a real bridge attached to the marker child.

    Args:
        panel: The panel under test.
        marker_child: Pid and marker address of the child.

    Yields:
        ChildRig: Panel, bridge and marker address.
    """
    pid, address = marker_child
    bridge = X64DbgBridge()
    bridge.attached_pid = pid
    panel.set_bridge(bridge)
    try:
        yield ChildRig(panel, bridge, address)
    finally:
        _priv(bridge, "_release_process_handles")()


@pytest.fixture
def piped_rig(panel: X64DbgPanel) -> Iterator[ChildRig]:
    """Provide the panel wired to a bridge that talks to a real named-pipe server child.

    Args:
        panel: The panel under test.

    Yields:
        ChildRig: Panel and the plugin-deployed bridge whose pipe name is the server's endpoint (the address is unused).
    """
    pipe_name = rf"\\.\pipe\intellicrack_critcov_x64dbg_panel02_{uuid.uuid4().hex}"
    server = subprocess.Popen(
        [sys.executable, "-m", _SERVER_MODULE, pipe_name, pipe_server.MODE_ECHO_SUCCESS],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    bridge = X64DbgBridge()
    try:
        _wait_for_pipe(pipe_name)
        setattr(bridge, "_PIPE_NAME", pipe_name)
        setattr(bridge, "_plugin_deployed", True)
        panel.set_bridge(bridge)
        yield ChildRig(panel, bridge, 0)
    finally:
        drain_bridge_workers_for(panel)
        run_bridge_coroutine(_close_pipe(bridge))
        _stop_child(server)


async def _close_pipe(bridge: X64DbgBridge) -> None:
    """Close the bridge's pipe connection.

    Args:
        bridge: Bridge whose pipe client is closed.
    """
    client = _priv(bridge, "_pipe_client")
    if client is not None:
        await client.close()


_NO_BRIDGE_SLOTS: list[str] = [
    "_on_show_module_sections",
    "_on_show_module_exports",
    "_on_load_library",
    "_on_detach",
    "_on_spawn",
    "_on_run_to",
    "_on_til_ret",
    "_on_skip",
    "_on_instr_undo",
    "_on_run_to_user_code",
    "_on_run_to_party",
    "_on_set_ip",
    "_on_save_db",
    "_on_load_db",
    "_on_clear_db",
    "_on_add_watchpoint",
    "_on_remove_watchpoint",
    "_on_search",
    "_on_trace_start",
    "_on_trace_stop",
    "_on_trace_into",
    "_on_trace_over",
    "_on_trace_coverage",
    "_on_set_trace_log_file",
    "_on_get_trace_record",
    "_on_set_trace_record",
    "_on_set_label",
    "_on_refresh_labels",
    "_on_delete_label",
    "_on_set_comment_btn",
    "_on_refresh_comments",
    "_on_delete_comment",
    "_on_refresh_memmap",
    "_on_dump_memmap_region",
    "_on_alloc_memory",
]

_IDLE_CASES: list[tuple[str, dict[str, str]]] = [
    ("_on_read_memory", {"_mem_addr_input": ""}),
    ("_on_execute_command", {"_console_input": "   "}),
    ("_on_run_to", {"_run_to_input": ""}),
    ("_on_set_ip", {"_set_ip_input": ""}),
    ("_on_add_watchpoint", {"_wp_addr_input": ""}),
    ("_on_search", {"_search_pattern_input": ""}),
    ("_on_get_trace_record", {"_trace_record_addr_input": ""}),
    ("_on_set_trace_record", {"_trace_record_addr_input": ""}),
    ("_on_set_label", {"_lbl_addr_input": "", "_lbl_text_input": "entry"}),
    ("_on_set_label", {"_lbl_addr_input": "0x401000", "_lbl_text_input": ""}),
    ("_on_set_comment_btn", {"_cmt_addr_input": "", "_cmt_text_input": "why"}),
    ("_on_set_comment_btn", {"_cmt_addr_input": "0x401000", "_cmt_text_input": ""}),
    ("_on_alloc_memory", {"_alloc_size_input": ""}),
    ("_on_show_module_sections", {}),
    ("_on_show_module_exports", {}),
    ("_on_remove_watchpoint", {}),
    ("_on_delete_label", {}),
    ("_on_delete_comment", {}),
    ("_on_dump_memmap_region", {}),
    ("_on_load_library", {}),
    ("_on_spawn", {}),
]

_UNFILLED_ROW_CASES: list[tuple[str, str, tuple[int, ...]]] = [
    ("_on_show_module_sections", "_module_table", ()),
    ("_on_show_module_exports", "_module_table", ()),
    ("_on_remove_watchpoint", "_wp_table", ()),
    ("_on_delete_label", "_lbl_table", ()),
    ("_on_delete_comment", "_cmt_table", ()),
    ("_on_dump_memmap_region", "_mmap_table", ()),
    ("_on_label_row_selected", "_lbl_table", (0, 1)),
    ("_on_comment_row_selected", "_cmt_table", (0, 1)),
]

_INVALID_CASES: list[tuple[str, dict[str, str], str, str | None]] = [
    ("_on_read_memory", {"_mem_addr_input": "0xZZ"}, "_console_output", "[!] Invalid address: 0xZZ"),
    ("_on_read_memory", {"_mem_addr_input": "12G"}, "_console_output", "[!] Invalid address: 12G"),
    ("_on_run_to", {"_run_to_input": "zz"}, "_console_output", "[!] Invalid address: zz"),
    ("_on_set_ip", {"_set_ip_input": "zz"}, "_console_output", "[!] Invalid address: zz"),
    ("_on_add_watchpoint", {"_wp_addr_input": "zz"}, "_console_output", "[!] Invalid address: zz"),
    ("_on_set_label", {"_lbl_addr_input": "zz", "_lbl_text_input": "x"}, "_console_output", "[!] Invalid address: zz"),
    ("_on_set_comment_btn", {"_cmt_addr_input": "zz", "_cmt_text_input": "x"}, "_console_output", "[!] Invalid address: zz"),
    ("_on_run_to_party", {"_run_to_party_input": "x"}, "_console_output", "[!] Invalid party: x"),
    ("_on_get_trace_record", {"_trace_record_addr_input": "0xZZ"}, "_trace_output", "[!] Invalid address: 0xZZ"),
    ("_on_set_trace_record", {"_trace_record_addr_input": "0xZZ"}, "_trace_output", "[!] Invalid address: 0xZZ"),
    ("_on_alloc_memory", {"_alloc_size_input": "abc"}, "_console_output", None),
]

_FAIL_CASES: list[FailCase] = [
    FailCase("_on_detach", {}, "[-] Detach failed: " + _NO_CONSOLE + "detach", [], ["detach"]),
    FailCase(
        "_on_load_library",
        {},
        "[-] Load Library failed: " + _NO_CONSOLE + 'loadlib "{path}"',
        [],
        ['loadlib "{path}"'],
    ),
    FailCase("_on_spawn", {}, "[-] Spawn failed: File not found: {path}", [], []),
    FailCase(
        "_on_run_to",
        {"_run_to_input": "0x401000"},
        "[-] Run To failed: " + _NO_REPLY + "run_to",
        [("run_to", {"address": "0x401000"})],
        [],
    ),
    FailCase("_on_til_ret", {}, "[-] Til Return failed: " + _NO_REPLY + "exec", [("exec", {"command": "erun"})], []),
    FailCase("_on_skip", {}, "[-] Skip failed: " + _NO_REPLY + "reg_all", [("reg_all", None)], []),
    FailCase("_on_instr_undo", {}, "[-] Undo failed: " + _NO_REPLY + "reg_all", [("reg_all", None)], []),
    FailCase(
        "_on_run_to_user_code",
        {},
        "[-] Run To User Code failed: " + _NO_CONSOLE + "RunToUserCode",
        [],
        ["RunToUserCode"],
    ),
    FailCase(
        "_on_run_to_party",
        {"_run_to_party_input": "1"},
        "[-] Run To Party failed: " + _NO_CONSOLE + "RunToParty 1",
        [],
        ["RunToParty 1"],
    ),
    FailCase(
        "_on_set_ip",
        {"_set_ip_input": "0x401000"},
        "[-] Set IP failed: " + _NO_REPLY + "exec",
        [("exec", {"command": "rip=0x401000"})],
        [],
    ),
    FailCase("_on_save_db", {}, "[-] Save DB failed: " + _NO_REPLY + "db_save", [("db_save", None)], []),
    FailCase("_on_load_db", {}, "[-] Load DB failed: " + _NO_REPLY + "db_load", [("db_load", None)], []),
    FailCase("_on_clear_db", {}, "[-] Clear DB failed: " + _NO_REPLY + "db_clear", [("db_clear", None)], []),
    FailCase(
        "_on_add_watchpoint",
        {"_wp_addr_input": "0x401000", "_wp_size_input": "8"},
        "[-] Add WP failed: " + _NO_REPLY + "wp_set",
        [("wp_set", {"address": "0x401000", "size": 8, "access": "w"})],
        [],
    ),
    FailCase(
        "_on_add_watchpoint",
        {"_wp_addr_input": "0x401000", "_wp_size_input": ""},
        "[-] Add WP failed: " + _NO_REPLY + "wp_set",
        [("wp_set", {"address": "0x401000", "size": 4, "access": "w"})],
        [],
    ),
    FailCase(
        "_on_trace_start",
        {"_trace_cond_input": "rax == 1", "_trace_log_input": "step"},
        "[-] Trace Start failed: " + _NO_REPLY + "exec",
        [("exec", {"command": 'TraceSetLog "step", "rax == 1"'})],
        [],
    ),
    FailCase(
        "_on_trace_stop",
        {},
        "[-] Trace Stop failed: " + _NO_REPLY + "exec",
        [("exec", {"command": "StopRunTrace"})],
        [],
    ),
    FailCase(
        "_on_trace_into",
        {"_trace_cond_input": "rax == 1"},
        "[-] Trace Into failed: " + _NO_CONSOLE + 'TraceIntoConditional "rax == 1", 50000',
        [],
        ['TraceIntoConditional "rax == 1", 50000'],
    ),
    FailCase(
        "_on_trace_over",
        {},
        "[-] Trace Over failed: " + _NO_CONSOLE + "TraceOverConditional 0, 50000",
        [],
        ["TraceOverConditional 0, 50000"],
    ),
    FailCase(
        "_on_trace_coverage",
        {},
        "[-] Coverage Trace failed: " + _NO_CONSOLE + "TraceIntoBeyondTraceCoverage 0, 50000",
        [],
        ["TraceIntoBeyondTraceCoverage 0, 50000"],
    ),
    FailCase(
        "_on_set_trace_log_file",
        {"_trace_logfile_input": "{path}"},
        "[-] Set Log File failed: " + _NO_CONSOLE + 'TraceSetLogFile "{path}"',
        [],
        ['TraceSetLogFile "{path}"'],
    ),
    FailCase(
        "_on_get_trace_record",
        {"_trace_record_addr_input": "0x401000"},
        "[-] Get Trace Record failed: " + _NO_REPLY + "trace_record",
        [("trace_record", {"address": "0x401000", "size": 1})],
        [],
    ),
    FailCase(
        "_on_set_trace_record",
        {"_trace_record_addr_input": "0x401000"},
        "[-] Enable Recording failed: " + _NO_REPLY + "trace_record_set",
        [("trace_record_set", {"address": "0x401000", "type": "word"})],
        [],
    ),
    FailCase(
        "_on_set_label",
        {"_lbl_addr_input": "0x401000", "_lbl_text_input": "entry"},
        "[-] Set Label failed: " + _NO_REPLY + "exec",
        [("exec", {"command": 'lblset 0x401000, "entry"'})],
        [],
    ),
    FailCase(
        "_on_set_comment_btn",
        {"_cmt_addr_input": "0x401000", "_cmt_text_input": "why"},
        "[-] Set Comment failed: " + _NO_REPLY + "exec",
        [("exec", {"command": 'cmtset 0x401000, "why"'})],
        [],
    ),
    FailCase(
        "_on_read_memory",
        {"_mem_addr_input": "0x401000", "_mem_size_input": "16"},
        "[-] Memory read failed: No process attached",
        [],
        [],
    ),
    FailCase("_on_alloc_memory", {}, "[-] Alloc failed: No process attached", [], []),
]

_OK_CASES: list[OkCase] = [
    OkCase("_on_til_ret", {}, {"exec": {}}, None, "_console_output", "[+] Execute til return", [("exec", {"command": "erun"})]),
    OkCase("_on_save_db", {}, {"db_save": {}}, None, "_console_output", "[+] Database saved", [("db_save", None)]),
    OkCase("_on_load_db", {}, {"db_load": {}}, None, "_console_output", "[+] Database loaded", [("db_load", None)]),
    OkCase("_on_clear_db", {}, {"db_clear": {}}, None, "_console_output", "[+] Database cleared", [("db_clear", None)]),
    OkCase("_on_trace_stop", {}, {"exec": {}}, None, "_trace_output", "[+] Trace stopped", [("exec", {"command": "StopRunTrace"})]),
    OkCase(
        "_on_set_ip",
        {"_set_ip_input": "0x401000"},
        {"exec": {}},
        None,
        "_console_output",
        "[+] IP set to 0x401000",
        [("exec", {"command": "rip=0x401000"})],
    ),
    OkCase(
        "_on_set_trace_log_file",
        {"_trace_logfile_input": "C:\\traces\\run.log"},
        {},
        "",
        "_trace_output",
        "[+] Trace log file set to C:\\traces\\run.log",
        [],
    ),
]


@pytest.mark.parametrize("slot", _NO_BRIDGE_SLOTS)
def test_slot_without_a_bridge_does_nothing(
    panel: X64DbgPanel,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    slot: str,
) -> None:
    """With every input valid and a row selected, a slot without a bridge changes nothing and dispatches nothing.

    Args:
        panel: Panel with no bridge.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Pytest temporary directory.
        slot: Panel slot under test.
    """
    path = tmp_path / "chosen.bin"
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _picker(str(path)))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _picker(str(path)))
    _seed_all(panel)
    before = (_console(panel), _trace(panel), _status(panel))

    _priv(panel, slot)()

    after = (_console(panel), _trace(panel), _status(panel))
    assert after == before
    assert not bridge_workers_for(panel)
    assert not path.exists()


@pytest.mark.parametrize(
    ("slot", "text_widget"),
    [("_on_read_memory", "_mem_addr_input"), ("_on_execute_command", "_console_input")],
)
def test_read_memory_and_command_without_a_bridge_announce_it(panel: X64DbgPanel, slot: str, text_widget: str) -> None:
    """Reading memory or running a command without a bridge prints the missing-bridge line and keeps the input.

    Args:
        panel: Panel with no bridge.
        slot: Panel slot under test.
        text_widget: Name of the input the slot reads.
    """
    _seed_all(panel)
    typed = _priv(panel, text_widget).text()
    lines_before = _console(panel).splitlines()

    _priv(panel, slot)()

    lines_after = _console(panel).splitlines()
    assert lines_after[-1] == _NO_BRIDGE_LINE
    assert len(lines_after) == len(lines_before) + 1
    assert _priv(panel, text_widget).text() == typed
    assert not bridge_workers_for(panel)


@pytest.mark.parametrize(("slot", "inputs"), _IDLE_CASES)
def test_slot_with_nothing_to_act_on_is_a_no_op(rig: Rig, slot: str, inputs: dict[str, str]) -> None:
    """With a bridge but an empty input or no selected row, a slot returns before touching the bridge.

    Args:
        rig: Panel wired to a recording bridge.
        slot: Panel slot under test.
        inputs: Widget attribute name to the text to type first.
    """
    panel, bridge = rig
    _fill(panel, inputs)
    before = (_console(panel), _trace(panel))

    _priv(panel, slot)()

    assert (_console(panel), _trace(panel)) == before
    assert bridge.sent_rpcs == []
    assert bridge.sent_commands == []
    assert not bridge_workers_for(panel)


@pytest.mark.parametrize(("slot", "table_name", "args"), _UNFILLED_ROW_CASES)
def test_slot_with_a_row_but_no_cells_is_a_no_op(rig: Rig, slot: str, table_name: str, args: tuple[int, ...]) -> None:
    """A selected row whose cells were never created makes the slot return without side effects.

    Args:
        rig: Panel wired to a recording bridge.
        slot: Panel slot under test.
        table_name: Table that holds the empty row.
        args: Positional arguments the slot takes (row and column for the click handlers).
    """
    panel, bridge = rig
    table = _priv(panel, table_name)
    table.setRowCount(1)
    _select_first_row(table)
    fields = ("_lbl_addr_input", "_lbl_text_input", "_cmt_addr_input", "_cmt_text_input")
    before = (_console(panel), _trace(panel), [_priv(panel, name).text() for name in fields])

    _priv(panel, slot)(*args)

    assert (_console(panel), _trace(panel), [_priv(panel, name).text() for name in fields]) == before
    assert bridge.sent_rpcs == []
    assert bridge.sent_commands == []
    assert not bridge_workers_for(panel)


@pytest.mark.parametrize("slot", ["_on_show_module_sections", "_on_show_module_exports"])
def test_module_detail_slot_with_an_empty_module_name_is_a_no_op(rig: Rig, slot: str) -> None:
    """A selected module row with an empty name neither retitles the detail table nor dispatches.

    Args:
        rig: Panel wired to a recording bridge.
        slot: Sections or Exports slot under test.
    """
    panel, bridge = rig
    module_table = _priv(panel, "_module_table")
    module_table.setRowCount(1)
    module_table.setItem(0, 0, QTableWidgetItem(""))
    _select_first_row(module_table)
    detail = _priv(panel, "_mod_detail_table")
    columns = detail.columnCount()

    _priv(panel, slot)()

    assert detail.columnCount() == columns
    assert _priv(panel, "_mod_sections_btn").isEnabled()
    assert _priv(panel, "_mod_exports_btn").isEnabled()
    assert bridge.sent_rpcs == []
    assert not bridge_workers_for(panel)


@pytest.mark.parametrize(("slot", "inputs", "output", "line"), _INVALID_CASES)
def test_invalid_input_is_reported_without_dispatch(
    rig: Rig,
    slot: str,
    inputs: dict[str, str],
    output: str,
    line: str | None,
) -> None:
    """Text that does not parse is reported (or only logged) and never reaches the bridge.

    Args:
        rig: Panel wired to a recording bridge.
        slot: Panel slot under test.
        inputs: Widget attribute name to the text to type first.
        output: Text widget that receives the report.
        line: Expected final line of that widget, or ``None`` when the slot only logs.
    """
    panel, bridge = rig
    _fill(panel, inputs)
    before = str(_priv(panel, output).toPlainText())

    _priv(panel, slot)()

    after = str(_priv(panel, output).toPlainText())
    if line is None:
        assert after == before
    else:
        assert _last_line(after) == line
    assert bridge.sent_rpcs == []
    assert bridge.sent_commands == []
    assert not bridge_workers_for(panel)


@pytest.mark.parametrize("case", _FAIL_CASES, ids=[f"{case.slot}-{index}" for index, case in enumerate(_FAIL_CASES)])
def test_failed_bridge_call_is_reported_in_the_console(
    qtbot: QtBot,
    rig: Rig,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    case: FailCase,
) -> None:
    """A slot whose bridge call fails prints the error and leaves the exact transcript the bridge built from the inputs.

    Args:
        qtbot: The pytest-qt helper.
        rig: Panel wired to a recording bridge.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Pytest temporary directory.
        case: The slot, inputs and expectations.
    """
    panel, bridge = rig
    path = str(tmp_path / "missing.exe")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _picker(path))
    _fill(panel, {name: text.replace("{path}", path) for name, text in case.inputs.items()})

    _priv(panel, case.slot)()

    _wait_console(qtbot, panel, case.needle.replace("{path}", path))
    assert bridge.sent_rpcs == case.rpcs
    assert bridge.sent_commands == [command.replace("{path}", path) for command in case.commands]


@pytest.mark.parametrize("case", _OK_CASES, ids=[f"{case.slot}-{index}" for index, case in enumerate(_OK_CASES)])
def test_successful_bridge_call_is_reported(qtbot: QtBot, rig: Rig, case: OkCase) -> None:
    """A slot whose bridge call succeeds prints the success line after sending the expected RPC.

    Args:
        qtbot: The pytest-qt helper.
        rig: Panel wired to a recording bridge.
        case: The slot, scripted replies and expectations.
    """
    panel, bridge = rig
    bridge.replies.update(case.replies)
    bridge.console_reply = case.console_reply
    _fill(panel, case.inputs)

    _priv(panel, case.slot)()

    _wait_for(qtbot, lambda: case.line in str(_priv(panel, case.output).toPlainText()))
    assert bridge.sent_rpcs[: len(case.rpcs)] == case.rpcs


def test_execute_command_echoes_the_input_and_prints_the_output(qtbot: QtBot, rig: Rig) -> None:
    """The typed command is trimmed, echoed, cleared from the field, sent, and its output printed.

    Args:
        qtbot: The pytest-qt helper.
        rig: Panel wired to a recording bridge.
    """
    panel, bridge = rig
    bridge.console_reply = "debuggee is running"
    _priv(panel, "_console_input").setText("  bpx 401000  ")

    _priv(panel, "_on_execute_command")()

    assert not _priv(panel, "_console_input").text()
    assert _last_line(_console(panel)) == "> bpx 401000"
    _wait_console(qtbot, panel, "debuggee is running")
    assert bridge.sent_commands == ["bpx 401000"]
    assert _last_line(_console(panel)) == "debuggee is running"


def test_execute_command_failure_is_reported(qtbot: QtBot, rig: Rig) -> None:
    """A console command the bridge rejects is echoed and then reported as failed.

    Args:
        qtbot: The pytest-qt helper.
        rig: Panel wired to a recording bridge.
    """
    panel, bridge = rig
    _priv(panel, "_console_input").setText("bpx 401000")

    _priv(panel, "_on_execute_command")()

    _wait_console(qtbot, panel, "[-] Command failed: " + _NO_CONSOLE + "bpx 401000")
    assert "> bpx 401000" in _console(panel)
    assert bridge.sent_commands == ["bpx 401000"]


def test_command_result_prints_only_non_empty_output(panel: X64DbgPanel) -> None:
    """An empty or missing command result adds nothing to the console; real output is appended as text.

    Args:
        panel: Panel with no bridge.
    """
    before = _console(panel)

    _priv(panel, "_on_command_result")("")
    _priv(panel, "_on_command_result")(None)
    assert _console(panel) == before

    _priv(panel, "_on_command_result")("done")
    assert _last_line(_console(panel)) == "done"


def test_breakpoint_toggle_error_reenables_both_buttons_and_reports(panel: X64DbgPanel) -> None:
    """A failed enable or disable names the action in the console and re-enables both buttons.

    Args:
        panel: Panel with no bridge.
    """
    enable = _priv(panel, "_enable_bp_btn")
    disable = _priv(panel, "_disable_bp_btn")
    enable.setEnabled(False)
    disable.setEnabled(False)

    _priv(panel, "_on_bp_toggle_error")("enable", ToolError("denied"))

    assert _last_line(_console(panel)) == "[-] Failed to enable breakpoint: denied"
    assert enable.isEnabled()
    assert disable.isEnabled()


def test_module_detail_error_reenables_both_buttons(panel: X64DbgPanel) -> None:
    """A failed module-detail fetch re-enables the Sections and Exports buttons and leaves the console alone.

    Args:
        panel: Panel with no bridge.
    """
    sections = _priv(panel, "_mod_sections_btn")
    exports = _priv(panel, "_mod_exports_btn")
    sections.setEnabled(False)
    exports.setEnabled(False)
    before = _console(panel)

    _priv(panel, "_on_mod_detail_error")("sections", ToolError("boom"))

    assert sections.isEnabled()
    assert exports.isEnabled()
    assert _console(panel) == before


def test_load_library_success_without_a_dict_reports_an_empty_base(panel: X64DbgPanel) -> None:
    """A load result that is not a dict still reports the load, with no base address, and re-enables the button.

    Args:
        panel: Panel with no bridge.
    """
    button = _priv(panel, "_load_lib_btn")
    button.setEnabled(False)

    _priv(panel, "_on_load_library_success")(None)

    assert _last_line(_console(panel)) == "[+] Library loaded at "
    assert button.isEnabled()


def test_load_library_dispatch_reports_the_base_address(
    qtbot: QtBot,
    rig: Rig,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Loading a DLL sends the quoted loadlib command, reads ``$result`` back and prints the hex base address.

    Args:
        qtbot: The pytest-qt helper.
        rig: Panel wired to a recording bridge.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Pytest temporary directory.
    """
    panel, bridge = rig
    path = str(tmp_path / "plugin.dll")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _picker(path))
    bridge.console_reply = ""
    bridge.replies["reg_get"] = "0x7ff800010000"
    button = _priv(panel, "_load_lib_btn")

    _priv(panel, "_on_load_library")()

    assert not button.isEnabled()
    _wait_console(qtbot, panel, "[+] Library loaded at 0x7ff800010000")
    assert button.isEnabled()
    assert bridge.sent_commands == [f'loadlib "{path}"']
    assert bridge.sent_rpcs[0] == ("reg_get", {"name": "$result"})


def test_register_edit_of_a_missing_row_is_ignored(rig: Rig) -> None:
    """An edit notification for a row with no cells neither dispatches nor disables the table.

    Args:
        rig: Panel wired to a recording bridge.
    """
    panel, bridge = rig
    before = _console(panel)

    _priv(panel, "_on_register_edited")(3, 1)

    assert _console(panel) == before
    assert _priv(panel, "_reg_table").isEnabled()
    assert bridge.sent_rpcs == []
    assert not bridge_workers_for(panel)


def test_register_edit_with_a_non_numeric_value_is_reported(rig: Rig) -> None:
    """Typing text that is not a number into a register cell is reported and never written.

    Args:
        rig: Panel wired to a recording bridge.
    """
    panel, bridge = rig
    table = _priv(panel, "_reg_table")
    item = _seed_row(table, "rax", "0x0")

    item.setText("zz")

    assert _last_line(_console(panel)) == "[!] Invalid value for rax: zz"
    assert table.isEnabled()
    assert bridge.sent_rpcs == []
    assert not bridge_workers_for(panel)


def test_register_edit_rejected_by_the_bridge_reenables_the_table(qtbot: QtBot, rig: Rig) -> None:
    """A register write is sent with the parsed integer; when the bridge rejects it the table is usable again.

    Args:
        qtbot: The pytest-qt helper.
        rig: Panel wired to a recording bridge.
    """
    panel, bridge = rig
    table = _priv(panel, "_reg_table")
    item = _seed_row(table, "rax", "0x0")

    item.setText("0x1F")

    assert not table.isEnabled()
    _wait_console(qtbot, panel, "[-] Failed to set rax: " + _NO_REPLY + "reg_set")
    assert table.isEnabled()
    assert bridge.sent_rpcs == [("reg_set", {"register": "rax", "value": 31})]


def test_extended_register_edit_is_ignored_without_a_bridge_or_for_the_name_column(panel: X64DbgPanel) -> None:
    """Edits of the extended-register table are ignored when there is no bridge or the edited column is not the value.

    Args:
        panel: Panel with no bridge.
    """
    _priv(panel, "_apply_extended_registers")({"xmm": ["00" * 16]})
    table = _priv(panel, "_ext_reg_table")
    before = _console(panel)

    table.item(0, 1).setText("11" * 16)
    _priv(panel, "_on_extended_register_edited")(0, 0)

    assert _console(panel) == before
    assert table.isEnabled()
    assert _priv(panel, "_ext_reg_values")["xmm0"] == "00" * 16
    assert not bridge_workers_for(panel)


def test_extended_register_edit_of_a_missing_row_is_ignored(rig: Rig) -> None:
    """An extended-register edit notification for a row with no cells does nothing.

    Args:
        rig: Panel wired to a recording bridge.
    """
    panel, bridge = rig
    before = _console(panel)

    _priv(panel, "_on_extended_register_edited")(4, 1)

    assert _console(panel) == before
    assert _priv(panel, "_ext_reg_table").isEnabled()
    assert bridge.sent_rpcs == []


def test_extended_register_edit_rejected_by_the_bridge_restores_the_value(qtbot: QtBot, rig: Rig) -> None:
    """A rejected extended-register write puts the previous value back, reports it and re-enables the table.

    Args:
        qtbot: The pytest-qt helper.
        rig: Panel wired to a recording bridge.
    """
    panel, bridge = rig
    _priv(panel, "_apply_extended_registers")({"xmm": ["00" * 16]})
    table = _priv(panel, "_ext_reg_table")
    item = table.item(0, 1)

    item.setText("11" * 16)

    assert not table.isEnabled()
    _wait_console(qtbot, panel, "[-] Failed to set xmm0: " + _NO_REPLY + "reg_set_extended")
    assert item.text() == "00" * 16
    assert table.isEnabled()
    assert _priv(panel, "_ext_reg_values")["xmm0"] == "00" * 16
    assert bridge.sent_rpcs == [("reg_set_extended", {"name": "xmm0", "value": "11" * 16})]


def test_view_refresh_failure_without_a_bridge_only_logs(panel: X64DbgPanel) -> None:
    """With no bridge a failed refresh neither clears the view nor changes the status.

    Args:
        panel: Panel with no bridge.
    """
    cleared: list[str] = []

    def clear() -> None:
        """Record that the view was cleared."""
        cleared.append("cleared")

    status = _status(panel)

    _priv(panel, "_on_view_refresh_failed")(ToolError("boom"), event="x64dbg_refresh_registers_failed", clear_view=clear)

    assert cleared == []
    assert _status(panel) == status


def test_view_refresh_failure_on_a_dead_pipe_clears_the_view_and_reports_the_lost_session(rig: Rig) -> None:
    """When the bridge pipe is down a failed refresh clears the view and shows the error with the bridge's diagnostic.

    Args:
        rig: Panel wired to a recording bridge, whose pipe was never connected.
    """
    panel, _bridge = rig
    cleared: list[str] = []

    def clear() -> None:
        """Record that the view was cleared."""
        cleared.append("cleared")

    _priv(panel, "_on_view_refresh_failed")(ToolError("boom"), event="x64dbg_refresh_registers_failed", clear_view=clear)

    assert cleared == ["cleared"]
    assert _status(panel) == f"Session lost: boom ({_DIAGNOSTIC})"


@pytest.mark.parametrize(
    ("refresh", "table_name"),
    [
        ("_refresh_registers", "_reg_table"),
        ("_refresh_debug_registers", "_dr_table"),
        ("_refresh_extended_registers", "_ext_reg_table"),
    ],
)
def test_failed_refresh_on_a_dead_pipe_clears_the_register_view(qtbot: QtBot, rig: Rig, refresh: str, table_name: str) -> None:
    """A register refresh that fails on a dead pipe empties its own table and reports the lost session.

    Args:
        qtbot: The pytest-qt helper.
        rig: Panel wired to a recording bridge, whose pipe was never connected.
        refresh: Refresh method under test.
        table_name: Table the refresh method owns.
    """
    panel, _bridge = rig
    table = _priv(panel, table_name)
    _seed_two_rows(table)
    _priv(panel, "_ext_reg_values")["xmm0"] = "00" * 16

    _priv(panel, refresh)()

    _wait_for(qtbot, lambda: _status(panel).startswith("Session lost: " + _NO_REPLY))
    assert table.rowCount() == 0
    assert _status(panel).endswith(f" ({_DIAGNOSTIC})")
    expected: dict[str, str] = {} if table_name == "_ext_reg_table" else {"xmm0": "00" * 16}
    assert _priv(panel, "_ext_reg_values") == expected


@pytest.mark.spawns_process
def test_view_refresh_failure_with_a_live_pipe_keeps_the_view(qtbot: QtBot, piped_rig: ChildRig) -> None:
    """With the bridge pipe genuinely connected a failed refresh is only logged and the view is kept.

    Args:
        qtbot: The pytest-qt helper.
        piped_rig: Panel wired to a bridge talking to a real named-pipe server.
    """
    panel, bridge, _address = piped_rig
    _fill(panel, {"_set_ip_input": "0x401000"})

    _priv(panel, "_on_set_ip")()

    _wait_console(qtbot, panel, "[+] IP set to 0x401000")
    drain_bridge_workers_for(panel)
    assert bridge.plugin_status["pipe_connected"] is True
    cleared: list[str] = []

    def clear() -> None:
        """Record that the view was cleared."""
        cleared.append("cleared")

    status = _status(panel)

    _priv(panel, "_on_view_refresh_failed")(ToolError("transient"), event="x64dbg_refresh_registers_failed", clear_view=clear)

    assert cleared == []
    assert _status(panel) == status


def test_debug_registers_clear_on_a_non_dict_and_skip_non_integer_values(panel: X64DbgPanel) -> None:
    """The debug-register table is emptied by a non-dict result and lists only integer registers otherwise.

    Args:
        panel: Panel with no bridge.
    """
    table = _priv(panel, "_dr_table")
    _seed_two_rows(table)

    _priv(panel, "_apply_debug_registers")(None)
    assert table.rowCount() == 0

    _priv(panel, "_apply_debug_registers")({"dr0": 0x401000, "dr1": "oops", "dr7": 0x400})
    assert table.rowCount() == 2
    assert [_cell(table, row, 0) for row in range(2)] == ["dr0", "dr7"]
    assert [_cell(table, row, 1) for row in range(2)] == ["0x0000000000401000", "0x0000000000000400"]


def test_extended_registers_clear_on_a_non_dict_and_skip_non_string_values(panel: X64DbgPanel) -> None:
    """The FPU/SIMD table is emptied by a non-dict result and lists only string vector values and integer x87 words.

    Args:
        panel: Panel with no bridge.
    """
    table = _priv(panel, "_ext_reg_table")
    _seed_two_rows(table)
    _priv(panel, "_ext_reg_values")["stale"] = "00"

    _priv(panel, "_apply_extended_registers")(None)
    assert table.rowCount() == 0
    assert _priv(panel, "_ext_reg_values") == {}

    _priv(panel, "_apply_extended_registers")({"xmm": ["00" * 16, 5, "11" * 16], "mxcsr": "801f0000", "x87control": 0x37F})
    names = [_cell(table, row, 0) for row in range(table.rowCount())]
    assert names == ["xmm0", "xmm2", "mxcsr", "x87control"]
    assert _cell(table, 3, 1) == "0x037F"
    assert _priv(panel, "_ext_reg_values") == {"xmm0": "00" * 16, "xmm2": "11" * 16, "mxcsr": "801f0000"}


def test_stack_rows_show_function_and_module_when_known(panel: X64DbgPanel) -> None:
    """Each stack row shows its address, return address and the function and module names that are known.

    Args:
        panel: Panel with no bridge.
    """
    frames = [
        StackFrame(0, 0x401000, 0x401050, 0x1000, 0x2000, "main", "app.exe"),
        StackFrame(1, 0x401050, 0x7FF600001000, 0, 0, "helper", None),
        StackFrame(2, 0x7FF600001000, 0x0, 0, 0, None, "ntdll.dll"),
        StackFrame(3, 0x10, 0x20, 0, 0, None, None),
    ]

    _priv(panel, "_apply_stack")(frames)

    table = _priv(panel, "_stack_table")
    assert [_cell(table, row, 0) for row in range(4)] == ["0x401000", "0x401050", "0x7FF600001000", "0x10"]
    assert [_cell(table, row, 1) for row in range(4)] == ["0x401050", "0x7FF600001000", "0x0", "0x20"]
    assert [_cell(table, row, 2) for row in range(4)] == ["main [app.exe]", "helper", "[ntdll.dll]", ""]


def test_thread_rows_show_the_thread_id_and_state(panel: X64DbgPanel) -> None:
    """Each thread the bridge reports becomes a row with its thread id and state.

    Args:
        panel: Panel with no bridge.
    """
    threads = [ThreadInfo(4242, 0x401000, 0x401010, "running"), ThreadInfo(7, 0x401000, 0x401020, "suspended")]

    _priv(panel, "_apply_threads")(threads)

    table = _priv(panel, "_thread_table")
    assert table.rowCount() == 2
    assert [_cell(table, row, 0) for row in range(2)] == ["4242", "7"]
    assert [_cell(table, row, 2) for row in range(2)] == ["running", "suspended"]


def test_memory_map_rows_show_every_region_column(panel: X64DbgPanel) -> None:
    """Each region becomes a row of hex base, hex size, protection, state, type and module name; a non-list clears the table.

    Args:
        panel: Panel with no bridge.
    """
    regions = [
        MemoryRegion(0x7FF600001000, 0x2000, "r-x", "MEM_COMMIT", "MEM_IMAGE", "app.exe"),
        MemoryRegion(0x20000, 0x10000, "rw-", "MEM_COMMIT", "MEM_PRIVATE", None),
    ]
    table = _priv(panel, "_mmap_table")

    _priv(panel, "_apply_memmap")(regions)

    assert [_cell(table, 0, column) for column in range(6)] == ["0x7FF600001000", "0x2000", "r-x", "MEM_COMMIT", "MEM_IMAGE", "app.exe"]
    assert [_cell(table, 1, column) for column in range(6)] == ["0x20000", "0x10000", "rw-", "MEM_COMMIT", "MEM_PRIVATE", ""]

    _priv(panel, "_apply_memmap")(None)
    assert table.rowCount() == 0


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(0x401000, 0x401000), ("0x1F", 31), ("zz", 0), ("", 0), (None, 0)],
)
def test_annotation_addresses_parse_to_integers_or_zero(raw: object, expected: int) -> None:
    """Integers pass through, hex strings are parsed, and anything else becomes zero.

    Args:
        raw: Address value as a label or comment dict would carry it.
        expected: Parsed address.
    """
    assert _priv(X64DbgPanel, "_parse_annot_address")(raw) == expected


def test_module_name_for_address_resolves_through_the_cached_modules(panel: X64DbgPanel) -> None:
    """An address resolves to the module whose half-open range holds it, and to nothing outside every range.

    Args:
        panel: Panel with no bridge.
    """
    modules = [
        ModuleInfo("app.exe", Path("C:/tools/app.exe"), 0x400000, 0x2000, 0x401000),
        ModuleInfo("lib.dll", Path("C:/tools/lib.dll"), 0x10000000, 0x1000, 0),
    ]
    _priv(panel, "_apply_modules")(modules)
    resolve = _priv(panel, "_module_name_for_address")

    assert resolve(0x401FFF) == "app.exe"
    assert not resolve(0x402000)
    assert not resolve(0x3FFFFF)
    assert resolve(0x10000800) == "lib.dll"


def test_selecting_a_label_row_fills_the_edit_fields(panel: X64DbgPanel) -> None:
    """Clicking a label row copies its address and text into the edit fields.

    Args:
        panel: Panel with no bridge.
    """
    _priv(panel, "_apply_labels")([{"address": "0x401000", "text": "entry point"}])

    _priv(panel, "_on_label_row_selected")(0, 1)

    assert _priv(panel, "_lbl_addr_input").text() == "0x401000"
    assert _priv(panel, "_lbl_text_input").text() == "entry point"


def test_selecting_a_comment_row_fills_the_edit_fields(panel: X64DbgPanel) -> None:
    """Clicking a comment row copies its address and text into the edit fields.

    Args:
        panel: Panel with no bridge.
    """
    _priv(panel, "_apply_comments")([{"address": "0x401234", "text": "loop body"}])

    _priv(panel, "_on_comment_row_selected")(0, 0)

    assert _priv(panel, "_cmt_addr_input").text() == "0x401234"
    assert _priv(panel, "_cmt_text_input").text() == "loop body"


@pytest.mark.parametrize(
    ("slot", "apply_name", "table_name", "button", "failure", "command"),
    [
        ("_on_delete_label", "_apply_labels", "_lbl_table", "_lbl_delete_btn", "[-] Delete Label failed: ", "labeldel 0x401000"),
        ("_on_delete_comment", "_apply_comments", "_cmt_table", "_cmt_delete_btn", "[-] Delete Comment failed: ", "commentdel 0x401000"),
    ],
)
def test_deleting_the_selected_annotation_sends_its_address(
    qtbot: QtBot,
    rig: Rig,
    slot: str,
    apply_name: str,
    table_name: str,
    button: str,
    failure: str,
    command: str,
) -> None:
    """Deleting the selected label or comment disables its button, sends the delete for its address, and recovers on failure.

    Args:
        qtbot: The pytest-qt helper.
        rig: Panel wired to a recording bridge.
        slot: Delete slot under test.
        apply_name: Method that fills the table.
        table_name: Table holding the annotation.
        button: Delete button attribute.
        failure: Prefix of the failure line.
        command: Console command the bridge must build.
    """
    panel, bridge = rig
    _priv(panel, apply_name)([{"address": "0x401000", "text": "entry"}])
    _select_first_row(_priv(panel, table_name))

    _priv(panel, slot)()

    assert not _priv(panel, button).isEnabled()
    _wait_console(qtbot, panel, failure + _NO_REPLY + "exec")
    assert _priv(panel, button).isEnabled()
    assert bridge.sent_rpcs == [("exec", {"command": command})]


def test_remove_watchpoint_with_a_non_numeric_id_is_reported(rig: Rig) -> None:
    """A watchpoint row whose stored id is not a number is reported and the button is released.

    Args:
        rig: Panel wired to a recording bridge.
    """
    panel, bridge = rig
    table = _priv(panel, "_wp_table")
    table.setRowCount(1)
    item = QTableWidgetItem("0x401000")
    item.setData(Qt.ItemDataRole.UserRole, "abc")
    table.setItem(0, 0, item)
    _select_first_row(table)

    _priv(panel, "_on_remove_watchpoint")()

    assert _last_line(_console(panel)) == "[!] Invalid watchpoint ID: abc"
    assert _priv(panel, "_remove_wp_btn").isEnabled()
    assert bridge.sent_rpcs == []
    assert not bridge_workers_for(panel)


def test_watchpoint_can_be_added_and_removed_end_to_end(qtbot: QtBot, rig: Rig) -> None:
    """Adding an execute watchpoint registers it with the bridge and lists it; removing the selected row sends its address and empties the list.

    Args:
        qtbot: The pytest-qt helper.
        rig: Panel wired to a recording bridge.
    """
    panel, bridge = rig
    bridge.replies["wp_set"] = {}
    bridge.replies["bp_list"] = []
    bridge.replies["wp_remove"] = {}
    _fill(panel, {"_wp_addr_input": "0x401000", "_wp_size_input": "8"})
    _priv(panel, "_wp_type_combo").setCurrentIndex(2)
    add_button = _priv(panel, "_add_wp_btn")
    table = _priv(panel, "_wp_table")

    _priv(panel, "_on_add_watchpoint")()

    assert not add_button.isEnabled()
    _wait_console(qtbot, panel, "[+] Watchpoint #1 set at 0x401000")
    _wait_for(qtbot, lambda: table.rowCount() == 1)
    assert bridge.sent_rpcs[0] == ("wp_set", {"address": "0x401000", "size": 8, "access": "x"})
    assert [_cell(table, 0, column) for column in range(5)] == ["0x401000", "8", "execute", "Yes", "0"]
    assert table.item(0, 0).data(Qt.ItemDataRole.UserRole) == 1
    assert add_button.isEnabled()

    _select_first_row(table)
    remove_button = _priv(panel, "_remove_wp_btn")
    _priv(panel, "_on_remove_watchpoint")()

    assert not remove_button.isEnabled()
    _wait_console(qtbot, panel, "[+] Watchpoint removed")
    _wait_for(qtbot, lambda: table.rowCount() == 0)
    assert ("wp_remove", {"address": "0x401000"}) in bridge.sent_rpcs
    assert remove_button.isEnabled()


@pytest.mark.parametrize(("mode", "pattern"), [("Hex", "AA BB"), ("Byte", "AA BB")])
def test_search_with_a_too_short_pattern_reports_the_bridge_error(qtbot: QtBot, rig: Rig, mode: str, pattern: str) -> None:
    """A Hex or Byte search shorter than the bridge's minimum fails with the bridge's own message and re-enables Search.

    Args:
        qtbot: The pytest-qt helper.
        rig: Panel wired to a recording bridge.
        mode: Search mode to select.
        pattern: Pattern to type.
    """
    panel, bridge = rig
    _priv(panel, "_search_mode_combo").setCurrentText(mode)
    _fill(panel, {"_search_pattern_input": pattern})
    button = _priv(panel, "_search_btn")

    _priv(panel, "_on_search")()

    assert not button.isEnabled()
    _wait_console(qtbot, panel, "[-] Search failed: scan_memory: pattern too short for reliable scan (got 2 bytes, need at least 16)")
    assert button.isEnabled()
    assert bridge.sent_rpcs == []


def test_search_in_yara_mode_dispatches_to_the_bridge(qtbot: QtBot, rig: Rig) -> None:
    """A YARA search without an attached process fails in the bridge and re-enables Search.

    Args:
        qtbot: The pytest-qt helper.
        rig: Panel wired to a recording bridge.
    """
    panel, _bridge = rig
    _priv(panel, "_search_mode_combo").setCurrentText("YARA")
    _fill(panel, {"_search_pattern_input": "rule r { condition: true }"})
    button = _priv(panel, "_search_btn")

    _priv(panel, "_on_search")()

    assert not button.isEnabled()
    _wait_console(qtbot, panel, "[-] Search failed: ")
    assert button.isEnabled()


def test_search_results_that_are_not_matches_get_only_an_index_row(panel: X64DbgPanel) -> None:
    """A result entry that is neither a match object nor a dict still gets a numbered row and is counted.

    Args:
        panel: Panel with no bridge.
    """
    _priv(panel, "_on_search_complete")([42])

    table = _priv(panel, "_search_table")
    assert table.rowCount() == 1
    assert _cell(table, 0, 0) == "0"
    assert table.item(0, 1) is None
    assert _last_line(_console(panel)) == "[+] Search found 1 matches"


@pytest.mark.parametrize(
    ("result", "line"),
    [
        (None, "[+] Trace started -> "),
        ({"success": True, "trace_file": "C:\\t\\run.trace64"}, "[+] Trace started -> C:\\t\\run.trace64"),
        ({"trace_file": "f"}, "[+] Trace started -> f"),
        ({"trace_file": "f", "log_text": "step", "log_condition": None}, "[+] Trace started -> f (log 'step')"),
        (
            {"trace_file": "f", "log_text": "step", "log_condition": "rax == 1"},
            "[+] Trace started -> f (log 'step' when 'rax == 1')",
        ),
    ],
)
def test_trace_start_result_reports_the_file_and_applied_log_settings(panel: X64DbgPanel, result: object, line: str) -> None:
    """The trace output names the trace file and, when the bridge echoes them, the log text and condition that took effect.

    Args:
        panel: Panel with no bridge.
        result: Result the bridge returned.
        line: Expected trace output line.
    """
    _priv(panel, "_on_trace_start_complete")(result)

    assert _last_line(_trace(panel)) == line


@pytest.mark.parametrize(
    ("chosen", "expected"),
    [("C:\\logs\\run.log", "C:\\logs\\run.log"), ("", "keep.log")],
)
def test_browse_trace_logfile_sets_the_field_only_when_a_path_is_chosen(
    panel: X64DbgPanel,
    monkeypatch: pytest.MonkeyPatch,
    chosen: str,
    expected: str,
) -> None:
    """The chosen save path fills the log-file field; cancelling leaves it as it was.

    Args:
        panel: Panel with no bridge.
        monkeypatch: Pytest monkeypatch fixture.
        chosen: Path the dialog stand-in returns.
        expected: Text the field must hold afterwards.
    """
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _picker(chosen))
    _fill(panel, {"_trace_logfile_input": "keep.log"})

    _priv(panel, "_on_browse_trace_logfile")()

    assert _priv(panel, "_trace_logfile_input").text() == expected


def test_get_trace_record_prints_the_hit_count_the_plugin_reports(qtbot: QtBot, rig: Rig) -> None:
    """The trace-record query sends the address and size and prints the plugin's hit count and record type.

    Args:
        qtbot: The pytest-qt helper.
        rig: Panel wired to a recording bridge.
    """
    panel, bridge = rig
    bridge.replies["trace_record"] = {"address": "0x401000", "page": "0x401000", "type": "word", "size": 1, "hitCount": 3, "hits": [3]}
    _fill(panel, {"_trace_record_addr_input": "0x401000"})
    button = _priv(panel, "_trace_record_btn")

    _priv(panel, "_on_get_trace_record")()

    assert not button.isEnabled()
    _wait_for(qtbot, lambda: "[+] Trace record 0x401000: hitCount=3 (record=word)" in _trace(panel))
    assert button.isEnabled()
    assert bridge.sent_rpcs == [("trace_record", {"address": "0x401000", "size": 1})]


def test_trace_record_success_without_a_dict_warns_that_nothing_is_recorded(panel: X64DbgPanel) -> None:
    """A query result that is not a dict reports zero hits on a page that records nothing, with the hint to enable recording.

    Args:
        panel: Panel with no bridge.
    """
    button = _priv(panel, "_trace_record_btn")
    button.setEnabled(False)

    _priv(panel, "_on_get_trace_record_success")(0x401000, None)

    assert _last_line(_trace(panel)) == (
        "[+] Trace record 0x401000: hitCount=0 (record=none) - this page records nothing until Enable Recording is used on it"
    )
    assert button.isEnabled()


def test_set_trace_record_arms_the_chosen_type(qtbot: QtBot, rig: Rig) -> None:
    """Arming recording sends the address and the chosen record type and prints the page the plugin reports.

    Args:
        qtbot: The pytest-qt helper.
        rig: Panel wired to a recording bridge.
    """
    panel, bridge = rig
    bridge.replies["trace_record_set"] = {"type": "byte", "page": "0x401000"}
    _priv(panel, "_trace_record_type_combo").setCurrentText("byte")
    _fill(panel, {"_trace_record_addr_input": "0x401234"})
    button = _priv(panel, "_trace_record_arm_btn")

    _priv(panel, "_on_set_trace_record")()

    assert not button.isEnabled()
    _wait_for(qtbot, lambda: "[+] Trace record 'byte' enabled on page 0x401000" in _trace(panel))
    assert button.isEnabled()
    assert bridge.sent_rpcs == [("trace_record_set", {"address": "0x401234", "type": "byte"})]


def test_trace_record_arming_without_a_dict_names_the_containing_page(panel: X64DbgPanel) -> None:
    """When the plugin returns no page the panel names the 4 KiB page that contains the address.

    Args:
        panel: Panel with no bridge.
    """
    _priv(panel, "_on_set_trace_record_success")(0x401234, "word", None)

    assert _last_line(_trace(panel)) == "[+] Trace record 'word' enabled on page 0x401000"


def test_detach_success_reports_and_reenables_the_action(panel: X64DbgPanel) -> None:
    """A finished detach shows the Detached status, prints it and re-enables the Detach action.

    Args:
        panel: Panel with no bridge.
    """
    action = _priv(panel, "_detach_btn")
    action.setEnabled(False)

    _priv(panel, "_on_detach_success")()

    assert _status(panel) == "Detached"
    assert _last_line(_console(panel)) == "[+] Detached from process"
    assert action.isEnabled()


@pytest.mark.parametrize(("result", "pid"), [(4242, 4242), (None, 0)])
def test_spawn_success_reports_the_process_id_or_zero(panel: X64DbgPanel, result: object, pid: int) -> None:
    """A finished spawn shows and prints the new process id (zero when the bridge returned none) and re-enables Spawn.

    Args:
        panel: Panel with no bridge.
        result: Result the bridge returned.
        pid: Process id the panel must show.
    """
    action = _priv(panel, "_spawn_btn")
    action.setEnabled(False)

    _priv(panel, "_on_spawn_success")("C:\\tools\\app.exe", result)

    assert _status(panel) == f"Spawned: PID {pid}"
    assert _last_line(_console(panel)) == f"[+] Spawned C:\\tools\\app.exe (PID {pid})"
    assert action.isEnabled()


@pytest.mark.parametrize(
    ("handler", "result", "line"),
    [
        ("_on_skip_success", {"old_ip": "0x401000", "new_ip": "0x401002"}, "[+] Skipped 0x401000 -> 0x401002"),
        ("_on_skip_success", {"success": True}, "[+] Skipped ? -> ?"),
        ("_on_skip_success", None, None),
        ("_on_instr_undo_success", {"old_ip": "0x401002", "new_ip": "0x401000"}, "[+] Undo 0x401002 -> 0x401000"),
        ("_on_instr_undo_success", None, None),
    ],
)
def test_skip_and_undo_results_print_the_instruction_pointer_move(
    panel: X64DbgPanel,
    handler: str,
    result: object,
    line: str | None,
) -> None:
    """A dict result prints the old and new instruction pointers; any other result prints nothing.

    Args:
        panel: Panel with no bridge.
        handler: Success handler under test.
        result: Result the bridge returned.
        line: Expected console line, or ``None`` when nothing is printed.
    """
    before = _console(panel)

    _priv(panel, handler)(result)

    if line is None:
        assert _console(panel) == before
    else:
        assert _last_line(_console(panel)) == line


@pytest.mark.parametrize(
    ("result", "reached"),
    [({"reached_ip": "0x401000"}, "0x401000"), ({"reached_ip": 4198400}, "?"), (None, "?")],
)
def test_run_to_user_code_and_party_results_print_the_reached_address(panel: X64DbgPanel, result: object, reached: str) -> None:
    """The reached address is printed when it is a string and shown as ``?`` otherwise.

    Args:
        panel: Panel with no bridge.
        result: Result the bridge returned.
        reached: Address text the panel must print.
    """
    _priv(panel, "_on_run_to_user_code_success")(result)
    assert _last_line(_console(panel)) == f"[+] Ran to user code, IP={reached}"

    _priv(panel, "_on_run_to_party_success")(1, result)
    assert _last_line(_console(panel)) == f"[+] Ran to party 1, IP={reached}"


def test_module_sections_show_the_address_and_size_the_bridge_reports(panel: X64DbgPanel) -> None:
    """A section dict as the bridge builds it fills the Address and Size columns of the detail table.

    The bridge's ``get_module_sections`` returns ``virtual_address`` and ``virtual_size`` (see ``_parse_section_entry``); the panel must
    show them.

    Args:
        panel: Panel with no bridge.
    """
    section: dict[str, object] = {
        "name": ".text",
        "virtual_address": "0x7ff600001000",
        "virtual_size": 4096,
        "raw_size": 4096,
        "characteristics": "0x60000020",
        "readable": True,
        "writable": False,
        "executable": True,
    }

    _priv(panel, "_apply_module_sections")([section])

    table = _priv(panel, "_mod_detail_table")
    assert _cell(table, 0, 0) == ".text"
    assert _cell(table, 0, 1) == "0x7ff600001000"
    assert _cell(table, 0, 2) == "4096"
    assert _cell(table, 0, 3) == "0x60000020"


@pytest.mark.spawns_process
def test_read_memory_dumps_the_child_marker_with_the_default_size(qtbot: QtBot, child_rig: ChildRig) -> None:
    """Reading a child's memory with an unparseable size falls back to 256 bytes and renders sixteen hex-dump lines.

    Args:
        qtbot: The pytest-qt helper.
        child_rig: Panel wired to a real bridge attached to the marker child.
    """
    panel, _bridge, address = child_rig
    _fill(panel, {"_mem_addr_input": f"0x{address:X}", "_mem_size_input": "abc"})
    button = _priv(panel, "_mem_read_btn")
    dump = _priv(panel, "_mem_dump")

    _priv(panel, "_on_read_memory")()

    assert not button.isEnabled()
    _wait_for(qtbot, lambda: bool(dump.toPlainText()))
    lines = str(dump.toPlainText()).splitlines()
    assert len(lines) == _DEFAULT_READ_SIZE // _BYTES_PER_LINE
    head = _MARKER[:_BYTES_PER_LINE]
    tail = _MARKER[_BYTES_PER_LINE:]
    assert lines[0].startswith(f"0x{address:08X}  {head.hex(' ').upper()}")
    assert lines[0].endswith(_MARKER_TEXT[:_BYTES_PER_LINE])
    padded = tail + bytes(_BYTES_PER_LINE - len(tail))
    assert lines[1].startswith(f"0x{address + _BYTES_PER_LINE:08X}  {padded.hex(' ').upper()}")
    assert lines[1].endswith(_MARKER_TEXT[_BYTES_PER_LINE:] + "." * (2 * _BYTES_PER_LINE - len(_MARKER_TEXT)))
    assert button.isEnabled()


@pytest.mark.spawns_process
def test_dump_selected_region_writes_the_child_bytes_to_the_chosen_file(
    qtbot: QtBot,
    child_rig: ChildRig,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Dumping the selected memory-map row saves the child's bytes for that range to the chosen path.

    Args:
        qtbot: The pytest-qt helper.
        child_rig: Panel wired to a real bridge attached to the marker child.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Pytest temporary directory.
    """
    panel, _bridge, address = child_rig
    out = tmp_path / "dump.bin"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _picker(str(out)))
    _priv(panel, "_apply_memmap")([MemoryRegion(address, 64, "rw-", "MEM_COMMIT", "MEM_MAPPED", None)])
    _select_first_row(_priv(panel, "_mmap_table"))

    _priv(panel, "_on_dump_memmap_region")()

    _wait_console(qtbot, panel, f"[+] Dumped 64 bytes to {out}")
    assert out.read_bytes() == _MARKER + bytes(64 - len(_MARKER))


def test_dump_selected_region_does_nothing_for_unparseable_cells_or_a_cancelled_dialog(
    rig: Rig,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A row whose cells are not hex, or a cancelled save dialog, ends the dump without dispatching.

    Args:
        rig: Panel wired to a recording bridge.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Pytest temporary directory.
    """
    panel, bridge = rig
    out = tmp_path / "never.bin"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _picker(str(out)))
    _priv(panel, "_apply_memmap")([MemoryRegion(0x401000, 0x1000, "r--", "MEM_COMMIT", "MEM_PRIVATE", None)])
    table = _priv(panel, "_mmap_table")
    _select_first_row(table)
    table.item(0, 0).setText("zz")
    table.item(0, 1).setText("zz")
    before = _console(panel)

    _priv(panel, "_on_dump_memmap_region")()

    assert _console(panel) == before
    assert not out.exists()
    assert not bridge_workers_for(panel)

    table.item(0, 0).setText("0x401000")
    table.item(0, 1).setText("0x1000")
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _picker(""))

    _priv(panel, "_on_dump_memmap_region")()

    assert _console(panel) == before
    assert bridge.sent_rpcs == []
    assert not bridge_workers_for(panel)


def test_dump_selected_region_failure_is_reported(
    qtbot: QtBot,
    rig: Rig,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A dump the bridge cannot read is reported and no file is created.

    Args:
        qtbot: The pytest-qt helper.
        rig: Panel wired to a recording bridge (no process attached).
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Pytest temporary directory.
    """
    panel, _bridge = rig
    out = tmp_path / "failed.bin"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _picker(str(out)))
    _priv(panel, "_apply_memmap")([MemoryRegion(0x401000, 0x1000, "r--", "MEM_COMMIT", "MEM_PRIVATE", None)])
    _select_first_row(_priv(panel, "_mmap_table"))

    _priv(panel, "_on_dump_memmap_region")()

    _wait_console(qtbot, panel, "[-] Dump Region failed: No process attached")
    assert not out.exists()


@pytest.mark.spawns_process
def test_alloc_reserves_zeroed_memory_in_the_child(qtbot: QtBot, child_rig: ChildRig) -> None:
    """Allocating through the panel commits page-aligned memory in the child that reads back as zeros.

    Args:
        qtbot: The pytest-qt helper.
        child_rig: Panel wired to a real bridge attached to the marker child.
    """
    panel, _bridge, _address = child_rig

    _priv(panel, "_on_alloc_memory")()

    _wait_console(qtbot, panel, "[+] Allocated at 0x")
    allocated = int(_last_line(_console(panel)).rsplit("0x", 1)[1], 16)
    assert allocated != 0
    assert allocated % 0x1000 == 0
    _fill(panel, {"_mem_addr_input": f"0x{allocated:X}", "_mem_size_input": "16"})
    dump = _priv(panel, "_mem_dump")

    _priv(panel, "_on_read_memory")()

    _wait_for(qtbot, lambda: bool(dump.toPlainText()))
    assert str(dump.toPlainText()).startswith(f"0x{allocated:08X}  {bytes(_BYTES_PER_LINE).hex(' ').upper()}")


@pytest.mark.spawns_process
def test_refresh_memmap_lists_the_region_that_holds_the_child_marker(qtbot: QtBot, child_rig: ChildRig) -> None:
    """Refreshing the memory map of a real child lists exactly one region that contains the marker address.

    Args:
        qtbot: The pytest-qt helper.
        child_rig: Panel wired to a real bridge attached to the marker child.
    """
    panel, _bridge, address = child_rig
    table = _priv(panel, "_mmap_table")

    _priv(panel, "_on_refresh_memmap")()

    _wait_for(qtbot, lambda: table.rowCount() > 0)
    assert table.columnCount() == 6
    holding = [
        row
        for row in range(table.rowCount())
        if int(_cell(table, row, 0), 16) <= address < int(_cell(table, row, 0), 16) + int(_cell(table, row, 1), 16)
    ]
    assert len(holding) == 1
