# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the memory, patch, process-info, assembler, thread, expression and exception handlers of the x64dbg panel.

Every test drives a real ``X64DbgPanel`` under the offscreen ``QApplication`` by calling the slots its buttons trigger. x64dbg is not
installed in the test container, so the bridge is always a real ``X64DbgBridge``: either ``ScriptedBridge``, a subclass that replaces only
the transport boundary (the named-pipe exchange and the console-command channel), or that same subclass attached to a real child process
that holds a known marker in a mapped view, so the Win32 memory calls (read, write, free, dump, page query) run for real. Expected values
come from the documented x64dbg command grammar, byte arithmetic done by hand, the plugin's hex-string address format and the real
state of the child process, never from re-running the handler under test. Qt's static file dialogs are replaced with plain functions
that return a chosen path, so no modal dialog ever opens.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast, override

import pytest
from PyQt6.QtCore import QCoreApplication, Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
)

from intellicrack.bridges.base import WatchpointInfo
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ProcessInfo, ToolError
from intellicrack.ui.panels.async_bridge import bridge_workers_for, drain_bridge_workers_for, run_bridge_coroutine
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from intellicrack.bridges.x64dbg import PipeCommandResult


type PipeReply = PipeCommandResult | ToolError

pytestmark = pytest.mark.usefixtures("qapp")

_WAIT_MS = 30_000
_Dynamic = Any
_MARKER_TEXT = "CRITCOV_X64DBG_PANEL_03"
_MARKER = _MARKER_TEXT.encode("ascii")
_CHILD_SOURCE = (
    "import ctypes, mmap, sys\n"
    f"marker = b'{_MARKER_TEXT}'\n"
    "view = mmap.mmap(-1, 65536)\n"
    "view[:len(marker)] = marker\n"
    "print(ctypes.addressof(ctypes.c_char.from_buffer(view)), flush=True)\n"
    "sys.stdin.read()\n"
)
_SAVEDATA = re.compile(r'savedata "(.+)", (0x[0-9a-fA-F]+), (0x[0-9a-fA-F]+)')
_ACCESS_VIOLATION = 0xC0000005
_ACCESS_VIOLATION_TEXT = hex(_ACCESS_VIOLATION)
_TID = 4242
_NO_BRIDGE_HANDLERS = [
    "_on_free_memory",
    "_on_set_memory_protection",
    "_on_refresh_patches",
    "_on_restore_patch",
    "_on_export_patches",
    "_on_refresh_procinfo",
    "_on_set_api_bp",
    "_on_dump_memory",
    "_on_write_memory",
    "_on_assemble",
    "_on_assemble_preview",
    "_on_nop_range",
    "_on_suspend_thread",
    "_on_resume_thread",
    "_on_switch_thread",
    "_on_rename_thread",
    "_on_create_thread",
    "_on_kill_thread",
    "_on_eval_expression",
    "_on_set_exception_config",
    "_on_remove_exception_config",
    "_on_enable_exception_config",
    "_on_disable_exception_config",
]
_EMPTY_INPUT_CASES: list[tuple[str, dict[str, str]]] = [
    ("_on_free_memory", {}),
    ("_on_set_memory_protection", {}),
    ("_on_dump_memory", {"_mem_size_input": "16"}),
    ("_on_write_memory", {"_mem_addr_input": "0x1000"}),
    ("_on_write_memory", {"_mem_write_data_input": "90"}),
    ("_on_assemble", {"_mem_addr_input": "0x1000"}),
    ("_on_assemble", {"_asm_instr_input": "nop"}),
    ("_on_assemble_preview", {"_mem_addr_input": "0x1000"}),
    ("_on_assemble_preview", {"_asm_instr_input": "nop"}),
    ("_on_nop_range", {"_nop_size_input": "2"}),
    ("_on_eval_expression", {}),
    ("_on_set_exception_config", {}),
    ("_on_create_thread", {}),
]
_INVALID_INPUT_CASES: list[tuple[str, dict[str, str], str | None]] = [
    ("_on_free_memory", {"_free_addr_input": "zzz"}, "[!] Invalid address: zzz"),
    ("_on_set_memory_protection", {"_protect_addr_input": "zzz"}, "[!] Invalid address: zzz"),
    ("_on_write_memory", {"_mem_addr_input": "0x1000", "_mem_write_data_input": "zz"}, "[!] Invalid address or hex data"),
    ("_on_write_memory", {"_mem_addr_input": "nope", "_mem_write_data_input": "90"}, "[!] Invalid address or hex data"),
    ("_on_assemble", {"_mem_addr_input": "zzz", "_asm_instr_input": "nop"}, "[!] Invalid address: zzz"),
    ("_on_assemble_preview", {"_mem_addr_input": "zzz", "_asm_instr_input": "nop"}, "[!] Invalid address: zzz"),
    ("_on_create_thread", {"_create_thread_addr_input": "zzz"}, "[!] Invalid address: zzz"),
    ("_on_set_exception_config", {"_exc_code_input": "notacode"}, "[!] Invalid exception code: notacode"),
    ("_on_remove_exception_config", {"_exc_code_input": "notacode"}, "[!] Invalid exception code: notacode"),
    ("_on_enable_exception_config", {"_exc_code_input": "notacode"}, "[!] Invalid exception code: notacode"),
    ("_on_disable_exception_config", {"_exc_code_input": "notacode"}, "[!] Invalid exception code: notacode"),
    ("_on_dump_memory", {"_mem_addr_input": "zzz"}, None),
    ("_on_dump_memory", {"_mem_addr_input": "0x1000", "_mem_size_input": "abc"}, None),
    ("_on_nop_range", {"_mem_addr_input": "zzz"}, None),
    ("_on_nop_range", {"_mem_addr_input": "0x1000", "_nop_size_input": "abc"}, None),
]


class ScriptedBridge(X64DbgBridge):
    """Real ``X64DbgBridge`` whose pipe transport answers from a script.

    Only the two methods that cross the process boundary to the debugger are replaced. ``_send_pipe_command`` returns (or raises) the
    scripted reply for the RPC name and raises a ``remote_error`` ``ToolError`` for an RPC with no scripted reply. ``_send_command``
    records the console command text and, for ``savedata``, performs the file write x64dbg itself would perform, so the production code
    that polls for the output file runs unmodified. Every caller above those two methods is the production code under test.

    Attributes:
        VERIFY_TIMEOUT: Shortened post-condition polling window so failing verifications stay fast.
        VERIFY_POLL_INTERVAL: Shortened interval between post-condition polls.
    """

    VERIFY_TIMEOUT = 0.2
    VERIFY_POLL_INTERVAL = 0.02

    def __init__(self) -> None:
        """Create the bridge with no scripted replies."""
        super().__init__()
        self.replies: dict[str, PipeReply] = {}
        self.sent_rpcs: list[tuple[str, dict[str, Any] | None]] = []
        self.sent_commands: list[str] = []

    @override
    async def _send_pipe_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> PipeCommandResult:
        """Return the scripted reply for ``command``.

        Args:
            command: RPC name requested by the production code.
            params: RPC parameters requested by the production code.

        Returns:
            PipeCommandResult: The scripted reply.

        Raises:
            ToolError: When the scripted reply is an error, or when no reply is scripted for ``command``.
        """
        await asyncio.sleep(0)
        self.sent_rpcs.append((command, params))
        if command not in self.replies:
            msg = f"no scripted reply for {command}"
            raise ToolError(msg, tool_name="x64dbg", details={"x64dbg_error_code": "remote_error"})
        reply = self.replies[command]
        if isinstance(reply, ToolError):
            raise ToolError(reply.message, tool_name=reply.tool_name, details=dict(reply.details))
        return reply

    @override
    async def _send_command(self, command: str) -> str:
        """Record the console command text and perform the file write of ``savedata``.

        Args:
            command: Console command text built by the production code.

        Returns:
            str: Always an empty command output.
        """
        await asyncio.sleep(0)
        self.sent_commands.append(command)
        saved = _SAVEDATA.fullmatch(command)
        if saved is not None:
            await asyncio.to_thread(Path(saved.group(1)).write_bytes, bytes(int(saved.group(3), 16)))
        return ""


def _remote_error() -> ToolError:
    """Build the error a plugin reports for a command that genuinely failed.

    Returns:
        ToolError: Error carrying the ``remote_error`` x64dbg error code.
    """
    return ToolError("plugin refused the command", tool_name="x64dbg", details={"x64dbg_error_code": "remote_error"})


def _priv(obj: object, name: str) -> _Dynamic:
    """Read a private attribute or method of a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.

    Returns:
        _Dynamic: The attribute value.
    """
    return getattr(obj, name)


def _set_priv(obj: object, name: str, value: object) -> None:
    """Assign a private data attribute on a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.
        value: Value to store.
    """
    setattr(obj, name, value)


def _call(owner: object, name: str, *args: object) -> object:
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


def _settle(panel: X64DbgPanel) -> None:
    """Join the panel's bridge workers and deliver their results, following chained requests.

    Args:
        panel: Panel whose workers are joined.
    """
    for _ in range(6):
        drain_bridge_workers_for(panel, timeout_ms=_WAIT_MS)
        QCoreApplication.processEvents()


def _console(panel: X64DbgPanel) -> str:
    """Read the panel's console text.

    Args:
        panel: Panel to read.

    Returns:
        str: Everything the console shows.
    """
    console = cast("QPlainTextEdit", _priv(panel, "_console_output"))
    return console.toPlainText()


def _edit(panel: X64DbgPanel, name: str) -> QLineEdit:
    """Resolve one of the panel's line edits.

    Args:
        panel: Panel that owns the widget.
        name: Attribute name of the widget.

    Returns:
        QLineEdit: The widget.
    """
    return cast("QLineEdit", _priv(panel, name))


def _button(panel: X64DbgPanel, name: str) -> QPushButton:
    """Resolve one of the panel's push buttons.

    Args:
        panel: Panel that owns the widget.
        name: Attribute name of the widget.

    Returns:
        QPushButton: The widget.
    """
    return cast("QPushButton", _priv(panel, name))


def _table(panel: X64DbgPanel, name: str) -> QTableWidget:
    """Resolve one of the panel's tables.

    Args:
        panel: Panel that owns the widget.
        name: Attribute name of the widget.

    Returns:
        QTableWidget: The widget.
    """
    return cast("QTableWidget", _priv(panel, name))


def _label(panel: X64DbgPanel, name: str) -> QLabel:
    """Resolve one of the panel's labels.

    Args:
        panel: Panel that owns the widget.
        name: Attribute name of the widget.

    Returns:
        QLabel: The widget.
    """
    return cast("QLabel", _priv(panel, name))


def _fill(panel: X64DbgPanel, fields: dict[str, str]) -> None:
    """Type text into the named line edits.

    Args:
        panel: Panel that owns the widgets.
        fields: Attribute name of each line edit mapped to the text to type.
    """
    for name, text in fields.items():
        _edit(panel, name).setText(text)


def _rows(table: QTableWidget) -> list[list[str]]:
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


def _select_thread(panel: X64DbgPanel, tid_text: str) -> None:
    """Put one row with the given thread id text into the threads table and make it current.

    Args:
        panel: Panel that owns the table.
        tid_text: Text of the TID cell.
    """
    table = _table(panel, "_thread_table")
    table.setRowCount(1)
    table.setItem(0, 0, QTableWidgetItem(tid_text))
    table.setCurrentCell(0, 0)


def _select_patch(panel: X64DbgPanel, address: int) -> None:
    """Put one patch row for ``address`` into the patches table and make it current.

    Args:
        panel: Panel that owns the table.
        address: Address stored in the row's user data.
    """
    table = _table(panel, "_patch_table")
    table.setRowCount(1)
    item = QTableWidgetItem(f"0x{address:X}")
    item.setData(Qt.ItemDataRole.UserRole, address)
    table.setItem(0, 0, item)
    table.setCurrentCell(0, 0)


def _pick(path: str) -> Callable[..., tuple[str, str]]:
    """Build a replacement for a Qt save-file dialog that answers with ``path``.

    Args:
        path: Path the stand-in dialog returns.

    Returns:
        Callable[..., tuple[str, str]]: Function with the shape of ``QFileDialog.getSaveFileName`` results.
    """

    def _picker(*_args: object, **_kwargs: object) -> tuple[str, str]:
        """Answer the dialog with the chosen path and an empty filter.

        Args:
            *_args: Positional arguments the panel passed.
            **_kwargs: Keyword arguments the panel passed.

        Returns:
            tuple[str, str]: The path and an empty filter.
        """
        return (path, "")

    return _picker


def _rpcs(bridge: ScriptedBridge, name: str) -> list[dict[str, Any] | None]:
    """Collect the parameters of every request the bridge sent for one RPC name.

    Args:
        bridge: Bridge that recorded the requests.
        name: RPC name to collect.

    Returns:
        list[dict[str, Any] | None]: Parameters of each matching request, in order.
    """
    return [params for rpc, params in bridge.sent_rpcs if rpc == name]


@pytest.fixture
def panel() -> Generator[X64DbgPanel]:
    """Build an x64dbg panel without a bridge and tear it down with its workers joined.

    Yields:
        X64DbgPanel: A freshly constructed panel.
    """
    widget = X64DbgPanel()
    try:
        yield widget
    finally:
        _settle(widget)
        widget.deleteLater()
        QCoreApplication.processEvents()


@pytest.fixture
def bridge() -> ScriptedBridge:
    """Build a scripted bridge that is not attached to any process.

    Returns:
        ScriptedBridge: A bridge with no scripted replies.
    """
    return ScriptedBridge()


@pytest.fixture
def wired_panel(panel: X64DbgPanel, bridge: ScriptedBridge) -> X64DbgPanel:
    """Give the panel the scripted bridge.

    Args:
        panel: Panel built without a bridge.
        bridge: Scripted bridge to attach.

    Returns:
        X64DbgPanel: The same panel, holding the bridge.
    """
    _set_priv(panel, "_bridge", bridge)
    return panel


@pytest.fixture
def marker_child() -> Generator[tuple[int, int]]:
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
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=10)
        if child.stdout is not None:
            child.stdout.close()


@pytest.fixture
def attached_bridge(bridge: ScriptedBridge, marker_child: tuple[int, int]) -> Generator[ScriptedBridge]:
    """Attach the scripted bridge to the marker child and release its process handles afterwards.

    Args:
        bridge: Scripted bridge to attach.
        marker_child: Pid and marker address of the child process.

    Yields:
        ScriptedBridge: The attached bridge.
    """
    bridge.attached_pid = marker_child[0]
    try:
        yield bridge
    finally:
        _call(bridge, "_release_process_handles")
        bridge.attached_pid = None


@pytest.mark.parametrize("handler", _NO_BRIDGE_HANDLERS)
def test_handlers_without_a_bridge_do_nothing(
    panel: X64DbgPanel,
    handler: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every handler returns at once when the panel has no bridge, even with all its inputs filled in.

    Args:
        panel: Panel built without a bridge.
        handler: Name of the slot under test.
        tmp_path: Directory that holds the paths the stand-in dialogs return.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _pick(str(tmp_path / "out.bin")))
    _fill(
        panel,
        {
            "_free_addr_input": "0x1000",
            "_protect_addr_input": "0x1000",
            "_mem_addr_input": "0x1000",
            "_mem_size_input": "16",
            "_mem_write_data_input": "90",
            "_asm_instr_input": "nop",
            "_nop_size_input": "2",
            "_bp_mod_input": "kernel32",
            "_bp_func_input": "CreateFileW",
            "_thread_name_input": "worker",
            "_create_thread_addr_input": "0x401000",
            "_eval_input": "rax",
            "_exc_code_input": _ACCESS_VIOLATION_TEXT,
        },
    )
    _select_thread(panel, str(_TID))
    _select_patch(panel, 0x401000)
    console_before = _console(panel)

    _call(panel, handler)

    assert _console(panel) == console_before
    assert bridge_workers_for(panel) == []
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(("handler", "fields"), _EMPTY_INPUT_CASES)
def test_missing_input_dispatches_nothing(
    wired_panel: X64DbgPanel,
    bridge: ScriptedBridge,
    handler: str,
    fields: dict[str, str],
) -> None:
    """A handler whose required input is blank returns without touching the bridge or the console.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        handler: Name of the slot under test.
        fields: The only inputs that are filled in.
    """
    _fill(wired_panel, fields)
    console_before = _console(wired_panel)

    _call(wired_panel, handler)

    assert bridge_workers_for(wired_panel) == []
    assert _console(wired_panel) == console_before
    assert bridge.sent_rpcs == []
    assert bridge.sent_commands == []


@pytest.mark.parametrize(("handler", "fields", "message"), _INVALID_INPUT_CASES)
def test_unparseable_input_is_reported_and_dispatches_nothing(
    wired_panel: X64DbgPanel,
    bridge: ScriptedBridge,
    handler: str,
    fields: dict[str, str],
    message: str | None,
) -> None:
    """Text that is not a number or hex string is rejected before any bridge call, with a console line where the panel gives one.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        handler: Name of the slot under test.
        fields: Inputs typed into the panel.
        message: Console line the panel must show, or ``None`` when it only logs.
    """
    _fill(wired_panel, {"_nop_size_input": "1", **fields})
    console_before = _console(wired_panel)

    _call(wired_panel, handler)

    assert bridge_workers_for(wired_panel) == []
    assert bridge.sent_rpcs == []
    assert bridge.sent_commands == []
    if message is None:
        assert _console(wired_panel) == console_before
    else:
        assert _console(wired_panel) == f"{console_before}\n{message}".lstrip("\n")


@pytest.mark.parametrize(
    "handler",
    ["_on_suspend_thread", "_on_resume_thread", "_on_switch_thread", "_on_rename_thread", "_on_kill_thread"],
)
@pytest.mark.parametrize("scenario", ["no_row", "no_item", "bad_tid"])
def test_thread_handlers_need_a_usable_selected_row(
    wired_panel: X64DbgPanel,
    bridge: ScriptedBridge,
    handler: str,
    scenario: str,
) -> None:
    """A thread handler does nothing without a selected row, without a TID cell, or when the TID is not an integer.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        handler: Name of the slot under test.
        scenario: Which unusable selection is arranged.
    """
    _edit(wired_panel, "_thread_name_input").setText("worker")
    table = _table(wired_panel, "_thread_table")
    table.setRowCount(0)
    if scenario != "no_row":
        table.setRowCount(1)
        if scenario == "no_item":
            table.setItem(0, 1, QTableWidgetItem("8"))
        else:
            table.setItem(0, 0, QTableWidgetItem("not-a-tid"))
        table.setCurrentCell(0, 0)
    console_before = _console(wired_panel)

    _call(wired_panel, handler)

    assert bridge_workers_for(wired_panel) == []
    assert _console(wired_panel) == console_before
    assert bridge.sent_rpcs == []
    assert bridge.sent_commands == []


def test_rename_thread_needs_a_name(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """Renaming with a valid selected thread but a blank name does nothing and leaves the button usable.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    _select_thread(wired_panel, str(_TID))
    _button(wired_panel, "_rename_thread_btn").setEnabled(True)
    _edit(wired_panel, "_thread_name_input").setText("   ")

    _call(wired_panel, "_on_rename_thread")

    assert bridge_workers_for(wired_panel) == []
    assert _button(wired_panel, "_rename_thread_btn").isEnabled()
    assert bridge.sent_commands == []


@pytest.mark.parametrize("scenario", ["no_row", "no_item"])
def test_restore_patch_needs_a_selected_patch_row(wired_panel: X64DbgPanel, bridge: ScriptedBridge, scenario: str) -> None:
    """Restoring a patch does nothing without a selected row or without an address cell in that row.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        scenario: Which unusable selection is arranged.
    """
    table = _table(wired_panel, "_patch_table")
    table.setRowCount(0)
    if scenario == "no_item":
        table.setRowCount(1)
        table.setItem(0, 1, QTableWidgetItem("116"))
        table.setCurrentCell(0, 0)

    _call(wired_panel, "_on_restore_patch")

    assert bridge_workers_for(wired_panel) == []
    assert bridge.sent_rpcs == []


def test_dump_memory_cancelled_dialog_dispatches_nothing(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """Cancelling the save dialog ends the dump before any memory is read.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    _fill(wired_panel, {"_mem_addr_input": "0x1000", "_mem_size_input": "16"})
    console_before = _console(wired_panel)

    _call(wired_panel, "_on_dump_memory")

    assert bridge_workers_for(wired_panel) == []
    assert _console(wired_panel) == console_before
    assert bridge.sent_rpcs == []


def test_export_patches_cancelled_dialog_dispatches_nothing(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """Cancelling the export dialog leaves the export button enabled and asks the bridge for nothing.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    _button(wired_panel, "_patch_export_btn").setEnabled(True)

    _call(wired_panel, "_on_export_patches")

    assert bridge_workers_for(wired_panel) == []
    assert _button(wired_panel, "_patch_export_btn").isEnabled()
    assert bridge.sent_rpcs == []


@pytest.mark.spawns_process
def test_free_memory_releases_the_allocation_in_the_child(
    wired_panel: X64DbgPanel,
    attached_bridge: ScriptedBridge,
) -> None:
    """Freeing an address allocated in the child makes that memory unreadable in the child.

    Args:
        wired_panel: Panel holding the attached bridge.
        attached_bridge: Bridge attached to the marker child.
    """
    allocated = cast("int", run_bridge_coroutine(attached_bridge.allocate_memory(4096, "rw")))
    assert run_bridge_coroutine(attached_bridge.read_memory(allocated, 4)) == bytes(4)
    _edit(wired_panel, "_free_addr_input").setText(hex(allocated))

    _call(wired_panel, "_on_free_memory")
    _settle(wired_panel)

    assert f"[+] Freed {hex(allocated)}" in _console(wired_panel)
    with pytest.raises(ToolError):
        run_bridge_coroutine(attached_bridge.read_memory(allocated, 4))


def test_free_memory_does_not_claim_success_when_the_bridge_reports_failure(wired_panel: X64DbgPanel) -> None:
    """A bridge that frees nothing (it returns ``False`` when no process is attached) must not produce a success line.

    Args:
        wired_panel: Panel holding a bridge that is attached to no process.
    """
    _edit(wired_panel, "_free_addr_input").setText("0x1000")

    _call(wired_panel, "_on_free_memory")
    _settle(wired_panel)

    assert "[+] Freed" not in _console(wired_panel)


@pytest.mark.spawns_process
def test_write_memory_writes_the_typed_bytes_into_the_child(
    wired_panel: X64DbgPanel,
    attached_bridge: ScriptedBridge,
    marker_child: tuple[int, int],
) -> None:
    """Typed hex bytes (spaces ignored) land at the typed address in the child.

    Args:
        wired_panel: Panel holding the attached bridge.
        attached_bridge: Bridge attached to the marker child.
        marker_child: Pid and marker address of the child process.
    """
    target = marker_child[1] + 0x100
    _fill(wired_panel, {"_mem_addr_input": hex(target), "_mem_write_data_input": "DE AD BE EF"})

    _call(wired_panel, "_on_write_memory")
    _settle(wired_panel)

    assert run_bridge_coroutine(attached_bridge.read_memory(target, 4)) == b"\xde\xad\xbe\xef"
    assert f"[+] Wrote 4 bytes at {hex(target)}" in _console(wired_panel)


def test_write_memory_failure_is_reported(wired_panel: X64DbgPanel) -> None:
    """Writing while no process is attached shows the bridge's failure on the console.

    Args:
        wired_panel: Panel holding a bridge that is attached to no process.
    """
    _fill(wired_panel, {"_mem_addr_input": "0x1000", "_mem_write_data_input": "90"})

    _call(wired_panel, "_on_write_memory")
    _settle(wired_panel)

    assert "[-] Write failed: No process attached" in _console(wired_panel)


@pytest.mark.spawns_process
@pytest.mark.usefixtures("attached_bridge")
@pytest.mark.parametrize(("size_text", "expected_length"), [(str(len(_MARKER)), len(_MARKER)), ("", 256)])
def test_dump_memory_saves_the_child_memory_to_the_chosen_file(
    wired_panel: X64DbgPanel,
    marker_child: tuple[int, int],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    size_text: str,
    expected_length: int,
) -> None:
    """The dump file holds exactly the requested number of bytes from the child, 256 when the size box is blank.

    Args:
        wired_panel: Panel holding the attached bridge.
        marker_child: Pid and marker address of the child process.
        tmp_path: Directory that receives the dump.
        monkeypatch: Pytest monkeypatch fixture.
        size_text: Text typed into the size box.
        expected_length: Number of bytes the dump must hold.
    """
    target = tmp_path / "dumps" / "memory.bin"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _pick(str(target)))
    _fill(wired_panel, {"_mem_addr_input": hex(marker_child[1]), "_mem_size_input": size_text})

    _call(wired_panel, "_on_dump_memory")
    _settle(wired_panel)

    assert target.read_bytes() == (_MARKER + bytes(256))[:expected_length]
    assert f"[+] Dumped to {target}" in _console(wired_panel)


def test_dump_memory_failure_is_reported(
    wired_panel: X64DbgPanel,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dump with no process attached shows the failure and writes no file.

    Args:
        wired_panel: Panel holding a bridge that is attached to no process.
        tmp_path: Directory that would receive the dump.
        monkeypatch: Pytest monkeypatch fixture.
    """
    target = tmp_path / "memory.bin"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _pick(str(target)))
    _fill(wired_panel, {"_mem_addr_input": "0x1000", "_mem_size_input": "8"})

    _call(wired_panel, "_on_dump_memory")
    _settle(wired_panel)

    assert "[-] Dump failed: No process attached" in _console(wired_panel)
    assert not target.exists()


@pytest.mark.spawns_process
@pytest.mark.parametrize(("guard", "rights_arg"), [(False, "ReadWrite"), (True, "GReadWrite")])
def test_set_memory_protection_sends_the_command_and_refreshes_the_map(
    wired_panel: X64DbgPanel,
    attached_bridge: ScriptedBridge,
    marker_child: tuple[int, int],
    *,
    guard: bool,
    rights_arg: str,
) -> None:
    """A protection change that matches the page's real rights is reported and the memory map is reloaded from the child.

    The mapped view is read-write, so asking for ``ReadWrite`` is the change the verification step accepts. The guard box prefixes the
    rights with ``G`` in the console command.

    Args:
        wired_panel: Panel holding the attached bridge.
        attached_bridge: Bridge attached to the marker child.
        marker_child: Pid and marker address of the child process.
        guard: State of the guard check box.
        rights_arg: Rights argument the console command must carry.
    """
    target = marker_child[1] + 0x10
    _edit(wired_panel, "_protect_addr_input").setText(hex(target))
    combo = cast("QComboBox", _priv(wired_panel, "_protect_rights_combo"))
    combo.setCurrentIndex(combo.findData("read_write"))
    cast("QCheckBox", _priv(wired_panel, "_protect_guard_check")).setChecked(guard)

    _call(wired_panel, "_on_set_memory_protection")
    _settle(wired_panel)

    assert attached_bridge.sent_commands == [f"setpagerights {hex(target)}, {rights_arg}"]
    assert f"[+] Protection set at {hex(target)}" in _console(wired_panel)
    covering = [row for row in _rows(_table(wired_panel, "_mmap_table")) if int(row[0], 16) <= target < int(row[0], 16) + int(row[1], 16)]
    assert len(covering) == 1
    assert covering[0][2] == "rw-"


@pytest.mark.spawns_process
def test_set_memory_protection_mismatch_is_reported_and_map_is_not_reloaded(
    wired_panel: X64DbgPanel,
    attached_bridge: ScriptedBridge,
    marker_child: tuple[int, int],
) -> None:
    """When the page still has different rights after the command, the console shows the failure and the map stays empty.

    Args:
        wired_panel: Panel holding the attached bridge.
        attached_bridge: Bridge attached to the marker child.
        marker_child: Pid and marker address of the child process.
    """
    target = marker_child[1]
    _edit(wired_panel, "_protect_addr_input").setText(hex(target))
    combo = cast("QComboBox", _priv(wired_panel, "_protect_rights_combo"))
    combo.setCurrentIndex(combo.findData("read_only"))

    _call(wired_panel, "_on_set_memory_protection")
    _settle(wired_panel)

    text = _console(wired_panel)
    assert "[-] Set Protection failed:" in text
    assert "'rw-'" in text
    assert "[+] Protection set" not in text
    assert attached_bridge.sent_commands == [f"setpagerights {hex(target)}, ReadOnly"]
    assert _table(wired_panel, "_mmap_table").rowCount() == 0


def test_refresh_patches_fills_the_table_from_the_plugin_list(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """The patches table shows one row per patch with the address, old byte and new byte the plugin reported.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.replies["patch_list"] = [
        {"address": "0x401000", "oldByte": 116, "newByte": 235},
        {"address": "0x402010", "oldByte": 15, "newByte": 144},
    ]

    _call(wired_panel, "_on_refresh_patches")
    _settle(wired_panel)

    assert _rows(_table(wired_panel, "_patch_table")) == [["0x401000", "116", "235"], ["0x402010", "15", "144"]]


def test_restore_patch_sends_the_selected_address_and_reloads_the_list(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """Restoring the selected patch asks the plugin for that address, reports it, re-enables the button and reloads the patch list.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.replies["patch_list"] = [{"address": "0x401000", "oldByte": 116, "newByte": 235}]
    bridge.replies["patch_restore"] = {"restored": True}
    _call(wired_panel, "_on_refresh_patches")
    _settle(wired_panel)
    _table(wired_panel, "_patch_table").setCurrentCell(0, 0)

    _call(wired_panel, "_on_restore_patch")
    _settle(wired_panel)

    assert _rpcs(bridge, "patch_restore") == [{"address": "0x401000"}]
    assert "[+] Patch restored at 0x401000" in _console(wired_panel)
    assert _button(wired_panel, "_patch_restore_btn").isEnabled()
    assert len(_rpcs(bridge, "patch_list")) == 2


def test_restore_patch_failure_is_reported_and_button_re_enabled(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """A refused restore shows the plugin's message, re-enables the button and does not reload the list.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.replies["patch_restore"] = _remote_error()
    _select_patch(wired_panel, 0x401000)

    _call(wired_panel, "_on_restore_patch")
    _settle(wired_panel)

    assert "[-] Restore Patch failed: plugin refused the command" in _console(wired_panel)
    assert _button(wired_panel, "_patch_restore_btn").isEnabled()
    assert _rpcs(bridge, "patch_list") == []


def test_export_patches_dumps_the_span_covering_every_patch(
    wired_panel: X64DbgPanel,
    bridge: ScriptedBridge,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The export covers the smallest span from the lowest to the highest patched byte and reports the chosen file.

    Patches at 0x401000 and 0x401005 span six bytes (0x401005 - 0x401000 + 1).

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        tmp_path: Directory that receives the export.
        monkeypatch: Pytest monkeypatch fixture.
    """
    bridge.replies["patch_list"] = [
        {"address": "0x401005", "oldByte": 1, "newByte": 2},
        {"address": "0x401000", "oldByte": 3, "newByte": 4},
    ]
    target = tmp_path / "patches.1337"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _pick(str(target)))

    _call(wired_panel, "_on_export_patches")
    _settle(wired_panel)

    assert bridge.sent_commands == [f'savedata "{target}", 0x401000, 0x6']
    assert target.stat().st_size == 6
    assert f"[+] Patches exported to {target}" in _console(wired_panel)
    assert _button(wired_panel, "_patch_export_btn").isEnabled()


def test_export_patches_without_patches_is_reported_and_button_re_enabled(
    wired_panel: X64DbgPanel,
    bridge: ScriptedBridge,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exporting when the plugin lists no patches shows why nothing was exported and writes no file.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        tmp_path: Directory that would receive the export.
        monkeypatch: Pytest monkeypatch fixture.
    """
    bridge.replies["patch_list"] = []
    target = tmp_path / "patches.1337"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _pick(str(target)))

    _call(wired_panel, "_on_export_patches")
    _settle(wired_panel)

    assert "[-] Export Patches failed: No patches are currently applied; nothing to export" in _console(wired_panel)
    assert _button(wired_panel, "_patch_export_btn").isEnabled()
    assert not target.exists()
    assert bridge.sent_commands == []


@pytest.mark.spawns_process
def test_refresh_procinfo_shows_the_attached_child(
    wired_panel: X64DbgPanel,
    attached_bridge: ScriptedBridge,
    marker_child: tuple[int, int],
) -> None:
    """The process-info labels show the child's pid, the loaded binary's name and path, and the pid of the process that spawned it.

    Args:
        wired_panel: Panel holding the attached bridge.
        attached_bridge: Bridge attached to the marker child.
        marker_child: Pid and marker address of the child process.
    """
    attached_bridge.binary_path = Path(sys.executable)

    _call(wired_panel, "_on_refresh_procinfo")
    _settle(wired_panel)

    assert _label(wired_panel, "_procinfo_pid").text() == str(marker_child[0])
    assert _label(wired_panel, "_procinfo_name").text() == Path(sys.executable).name
    assert _label(wired_panel, "_procinfo_path").text() == str(Path(sys.executable))
    assert _label(wired_panel, "_procinfo_ppid").text() == str(os.getpid())


def test_refresh_procinfo_failure_leaves_the_labels_unchanged(wired_panel: X64DbgPanel) -> None:
    """With no process attached the bridge refuses, and the labels keep what they showed.

    Args:
        wired_panel: Panel holding a bridge that is attached to no process.
    """
    names = ["_procinfo_pid", "_procinfo_name", "_procinfo_path", "_procinfo_cmdline", "_procinfo_ppid"]
    before = [_label(wired_panel, name).text() for name in names]

    _call(wired_panel, "_on_refresh_procinfo")
    _settle(wired_panel)

    assert [_label(wired_panel, name).text() for name in names] == before


def test_apply_procinfo_ignores_a_missing_result(panel: X64DbgPanel) -> None:
    """A ``None`` result changes none of the process-info labels.

    Args:
        panel: Panel built without a bridge.
    """
    names = ["_procinfo_pid", "_procinfo_name", "_procinfo_path", "_procinfo_cmdline", "_procinfo_ppid"]
    before = [_label(panel, name).text() for name in names]

    _call(panel, "_apply_procinfo", None)

    assert [_label(panel, name).text() for name in names] == before


def test_apply_procinfo_shows_dashes_for_missing_path_and_command_line(panel: X64DbgPanel) -> None:
    """A process record without a path or command line shows ``--`` for them, with matching tool tips.

    Args:
        panel: Panel built without a bridge.
    """
    info = ProcessInfo(pid=1234, name="a.exe", path=None, command_line=None, parent_pid=77, threads=[], modules=[])

    _call(panel, "_apply_procinfo", info)

    assert [_label(panel, name).text() for name in ("_procinfo_pid", "_procinfo_name", "_procinfo_ppid")] == ["1234", "a.exe", "77"]
    assert _label(panel, "_procinfo_path").text() == "--"
    assert _label(panel, "_procinfo_path").toolTip() == "--"
    assert _label(panel, "_procinfo_cmdline").text() == "--"
    assert _label(panel, "_procinfo_cmdline").toolTip() == "--"


def test_set_api_breakpoint_requires_module_and_function(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """With either name blank the console asks for both and nothing is sent.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    _fill(wired_panel, {"_bp_mod_input": "kernel32", "_bp_func_input": "   "})

    _call(wired_panel, "_on_set_api_bp")

    assert _console(wired_panel).endswith("[!] Enter module and function name")
    assert bridge_workers_for(wired_panel) == []
    assert bridge.sent_rpcs == []


def test_set_api_breakpoint_falls_back_to_bpx_for_an_unresolved_export(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """An export the debugger cannot resolve (address 0) is breakpointed with ``bpx module.function``.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.replies["eval"] = 0
    bridge.replies["exec"] = ""
    _fill(wired_panel, {"_bp_mod_input": " kernel32 ", "_bp_func_input": " CreateFileW "})

    _call(wired_panel, "_on_set_api_bp")
    _settle(wired_panel)

    assert bridge.sent_rpcs == [
        ("eval", {"expression": 'GetProcAddress(kernel32,"CreateFileW")'}),
        ("exec", {"command": "bpx kernel32.CreateFileW"}),
    ]
    assert "[+] API BP set on kernel32.CreateFileW" in _console(wired_panel)


def test_set_api_breakpoint_failure_is_reported(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """A refused ``bpx`` command is shown on the console and no success line appears.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.replies["eval"] = 0
    bridge.replies["exec"] = _remote_error()
    _fill(wired_panel, {"_bp_mod_input": "kernel32", "_bp_func_input": "CreateFileW"})

    _call(wired_panel, "_on_set_api_bp")
    _settle(wired_panel)

    text = _console(wired_panel)
    assert "[-] API BP failed: plugin refused the command" in text
    assert "[+] API BP set" not in text


def test_assemble_sends_the_instruction_to_the_plugin(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """Assembling sends the address as a hex string with the instruction text and reports it on the console.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.replies["assemble"] = {"queued": True}
    _fill(wired_panel, {"_mem_addr_input": "0x401000", "_asm_instr_input": " nop "})

    _call(wired_panel, "_on_assemble")
    _settle(wired_panel)

    assert bridge.sent_rpcs == [("assemble", {"address": "0x401000", "instruction": "nop"})]
    assert "[+] Assembled 'nop' at 0x401000" in _console(wired_panel)


def test_assemble_failure_is_reported(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """A refused assemble request shows the plugin's message and no success line.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.replies["assemble"] = _remote_error()
    _fill(wired_panel, {"_mem_addr_input": "0x401000", "_asm_instr_input": "nop"})

    _call(wired_panel, "_on_assemble")
    _settle(wired_panel)

    text = _console(wired_panel)
    assert "[-] Assemble failed: plugin refused the command" in text
    assert "[+] Assembled" not in text


@pytest.mark.parametrize(("instruction", "encoding"), [("nop", "90"), ("mov eax, 1", "b8 01 00 00 00")])
def test_assemble_preview_shows_the_encoding_without_touching_the_debugger(
    wired_panel: X64DbgPanel,
    bridge: ScriptedBridge,
    instruction: str,
    encoding: str,
) -> None:
    """The preview prints the x86 machine-code bytes of the instruction and sends nothing to the debugger.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        instruction: Instruction typed into the panel.
        encoding: Space-separated hex of its x86 encoding.
    """
    _fill(wired_panel, {"_mem_addr_input": "0x401000", "_asm_instr_input": instruction})

    _call(wired_panel, "_on_assemble_preview")
    _settle(wired_panel)

    assert f"[+] '{instruction}' at 0x401000 -> {encoding}" in _console(wired_panel)
    assert bridge.sent_rpcs == []
    assert bridge.sent_commands == []


def test_assemble_preview_shows_nothing_for_a_non_bytes_result(wired_panel: X64DbgPanel) -> None:
    """A result that is not a byte string is shown as an empty encoding.

    Args:
        wired_panel: Panel holding the scripted bridge.
    """
    _call(wired_panel, "_on_assemble_preview_success", 0x401000, "nop", None)

    assert _console(wired_panel).endswith("[+] 'nop' at 0x401000 -> ")


@pytest.mark.parametrize(("size_text", "count"), [("4", 4), ("", 1)])
def test_nop_range_sends_a_fill_command(wired_panel: X64DbgPanel, bridge: ScriptedBridge, size_text: str, count: int) -> None:
    """The NOP button fills the typed number of bytes with 0x90, one byte when the size box is blank.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        size_text: Text typed into the NOP size box.
        count: Number of bytes the fill must cover.
    """
    _fill(wired_panel, {"_mem_addr_input": "0x401000", "_nop_size_input": size_text})

    _call(wired_panel, "_on_nop_range")
    _settle(wired_panel)

    assert bridge.sent_commands == [f"fill 0x401000, {count}, 90"]
    assert f"[+] NOPed {count} bytes at 0x401000" in _console(wired_panel)


def test_eval_expression_prints_the_value_in_hex(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """The evaluated value is printed in hex next to the expression the user typed.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.replies["eval"] = "0x1F"
    _edit(wired_panel, "_eval_input").setText(" rax+1 ")

    _call(wired_panel, "_on_eval_expression")
    _settle(wired_panel)

    assert bridge.sent_rpcs == [("eval", {"expression": "rax+1"})]
    assert "[+] rax+1 = 0x1f" in _console(wired_panel)


def test_eval_expression_failure_is_reported(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """A plugin answer that is a boolean instead of a number is shown as a failure.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.replies["eval"] = True
    _edit(wired_panel, "_eval_input").setText("rax+1")

    _call(wired_panel, "_on_eval_expression")
    _settle(wired_panel)

    assert "[-] Eval failed: evaluate_expression: plugin returned bool for 'rax+1'" in _console(wired_panel)


@pytest.mark.parametrize(
    ("handling", "commands", "line"),
    [
        (
            "break",
            [f"SetExceptionBPX {_ACCESS_VIOLATION_TEXT}, first"],
            f"[+] Exception {_ACCESS_VIOLATION_TEXT} -> break",
        ),
        (
            "log",
            [
                f"SetExceptionBPX {_ACCESS_VIOLATION_TEXT}, all",
                f'SetExceptionBreakpointLog {_ACCESS_VIOLATION_TEXT}, "Exception {_ACCESS_VIOLATION_TEXT} occurred at {{cip}}"',
                f"SetExceptionBreakpointFastResume {_ACCESS_VIOLATION_TEXT}, 1",
            ],
            f"[+] Exception {_ACCESS_VIOLATION_TEXT} -> log",
        ),
    ],
)
def test_set_exception_config_sends_the_exception_breakpoint_commands(
    wired_panel: X64DbgPanel,
    bridge: ScriptedBridge,
    handling: str,
    commands: list[str],
    line: str,
) -> None:
    """Break and log handling each set the exception breakpoints x64dbg documents for them.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        handling: Handling mode chosen in the combo box.
        commands: Console commands, in order, the plugin must be asked to run.
        line: Console line the panel must show.
    """
    bridge.replies["exec"] = ""
    _edit(wired_panel, "_exc_code_input").setText("0xC0000005")
    combo = cast("QComboBox", _priv(wired_panel, "_exc_handling_combo"))
    combo.setCurrentIndex(combo.findData(handling))

    _call(wired_panel, "_on_set_exception_config")
    _settle(wired_panel)

    assert bridge.sent_rpcs == [("exec", {"command": command}) for command in commands]
    assert line in _console(wired_panel)


def test_set_exception_config_ignore_is_refused_and_reported(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """Ignore handling has no scriptable x64dbg command, so the panel shows the refusal and sends nothing.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    _edit(wired_panel, "_exc_code_input").setText("0xC0000005")
    combo = cast("QComboBox", _priv(wired_panel, "_exc_handling_combo"))
    combo.setCurrentIndex(combo.findData("ignore"))

    _call(wired_panel, "_on_set_exception_config")
    _settle(wired_panel)

    text = _console(wired_panel)
    assert "[-] Exception Config failed: x64dbg has no scriptable command" in text
    assert "[+] Exception" not in text
    assert bridge.sent_rpcs == []
    assert bridge.sent_commands == []


@pytest.mark.parametrize(
    ("handler", "command", "word"),
    [
        ("_on_remove_exception_config", "DeleteExceptionBPX", "removed"),
        ("_on_enable_exception_config", "EnableExceptionBPX", "enabled"),
        ("_on_disable_exception_config", "DisableExceptionBPX", "disabled"),
    ],
)
@pytest.mark.parametrize("with_code", [True, False])
def test_exception_breakpoint_bulk_commands(
    wired_panel: X64DbgPanel,
    bridge: ScriptedBridge,
    handler: str,
    command: str,
    word: str,
    *,
    with_code: bool,
) -> None:
    """Remove, enable and disable act on the typed exception code, or on every exception breakpoint when the code box is blank.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        handler: Name of the slot under test.
        command: x64dbg console command the slot must send.
        word: Past-tense verb the console line must use.
        with_code: Whether an exception code is typed.
    """
    _edit(wired_panel, "_exc_code_input").setText("0xC0000005" if with_code else "")

    _call(wired_panel, handler)
    _settle(wired_panel)

    if with_code:
        assert bridge.sent_commands == [f"{command} {_ACCESS_VIOLATION_TEXT}"]
        assert f"[+] Exception breakpoint(s) {word} ({_ACCESS_VIOLATION_TEXT})" in _console(wired_panel)
    else:
        assert bridge.sent_commands == [command]
        assert f"[+] Exception breakpoint(s) {word} (all)" in _console(wired_panel)


@pytest.mark.parametrize(
    ("handler", "command", "records", "line"),
    [
        ("_on_suspend_thread", f"suspendthread {_TID}", [{"threadId": _TID, "suspended": True}], f"[+] Thread {_TID} suspended"),
        ("_on_resume_thread", f"resumethread {_TID}", [{"threadId": _TID, "suspended": False}], f"[+] Thread {_TID} resumed"),
        ("_on_switch_thread", f"switchthread {_TID}", [{"threadId": _TID}], f"[+] Switched to thread {_TID}"),
        ("_on_kill_thread", f"killthread {_TID}, 0", [], f"[+] Thread {_TID} killed"),
    ],
)
def test_thread_command_is_sent_for_the_selected_tid_and_confirmed(
    wired_panel: X64DbgPanel,
    bridge: ScriptedBridge,
    handler: str,
    command: str,
    records: list[object],
    line: str,
) -> None:
    """Suspend, resume, switch and kill send their command for the selected TID and report once the thread list confirms the change.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        handler: Name of the slot under test.
        command: x64dbg console command the slot must send.
        records: Thread list the plugin reports afterwards.
        line: Console line the panel must show.
    """
    bridge.replies["thread_detail"] = records
    _select_thread(wired_panel, str(_TID))

    _call(wired_panel, handler)
    _settle(wired_panel)

    assert bridge.sent_commands == [command]
    assert line in _console(wired_panel)


@pytest.mark.parametrize(
    ("handler", "records", "operation"),
    [
        ("_on_suspend_thread", [{"threadId": _TID, "suspended": False}], "Suspend Thread"),
        ("_on_resume_thread", [{"threadId": _TID, "suspended": True}], "Resume Thread"),
        ("_on_switch_thread", [], "Switch Thread"),
        ("_on_kill_thread", [{"threadId": _TID}], "Kill Thread"),
    ],
)
def test_thread_command_not_confirmed_is_reported_as_a_failure(
    wired_panel: X64DbgPanel,
    bridge: ScriptedBridge,
    handler: str,
    records: list[object],
    operation: str,
) -> None:
    """When the thread list never shows the requested change, the console reports the operation as failed.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
        handler: Name of the slot under test.
        records: Thread list the plugin keeps reporting.
        operation: Operation name the failure line must carry.
    """
    bridge.replies["thread_detail"] = records
    _select_thread(wired_panel, str(_TID))

    _call(wired_panel, handler)
    _settle(wired_panel)

    text = _console(wired_panel)
    assert f"[-] {operation} failed:" in text
    assert f"[+] Thread {_TID}" not in text
    assert "[+] Switched" not in text


def test_rename_thread_sets_the_name_clears_the_box_and_re_enables_the_button(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """A confirmed rename is reported with the new name, empties the name box and re-enables the rename button.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.replies["thread_detail"] = [{"threadId": _TID, "name": "worker"}]
    _select_thread(wired_panel, str(_TID))
    _edit(wired_panel, "_thread_name_input").setText(" worker ")

    _call(wired_panel, "_on_rename_thread")
    _settle(wired_panel)

    assert bridge.sent_commands == [f'setthreadname {_TID}, "worker"']
    assert f"[+] Thread {_TID} renamed to 'worker'" in _console(wired_panel)
    assert not _edit(wired_panel, "_thread_name_input").text()
    assert _button(wired_panel, "_rename_thread_btn").isEnabled()


def test_rename_thread_failure_keeps_the_name_and_re_enables_the_button(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """A rename the thread list does not confirm is reported, keeps the typed name and re-enables the button.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.replies["thread_detail"] = [{"threadId": _TID, "name": "other"}]
    _select_thread(wired_panel, str(_TID))
    _edit(wired_panel, "_thread_name_input").setText("worker")

    _call(wired_panel, "_on_rename_thread")
    _settle(wired_panel)

    assert "[-] Rename Thread failed:" in _console(wired_panel)
    assert "renamed to" not in _console(wired_panel)
    assert _edit(wired_panel, "_thread_name_input").text() == "worker"
    assert _button(wired_panel, "_rename_thread_btn").isEnabled()


def test_create_thread_reports_the_new_tid(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """A created thread whose id (hex text from ``$result``) shows up in the thread list is reported by its decimal TID.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.replies["reg_get"] = "0x1F40"
    bridge.replies["thread_detail"] = [{"threadId": 8000}]
    _edit(wired_panel, "_create_thread_addr_input").setText("0x401000")

    _call(wired_panel, "_on_create_thread")
    _settle(wired_panel)

    assert bridge.sent_commands == ["createthread 0x401000, 0x0"]
    assert "[+] Thread created: tid=8000" in _console(wired_panel)
    assert not _edit(wired_panel, "_create_thread_addr_input").text()
    assert _button(wired_panel, "_create_thread_btn").isEnabled()


def test_create_thread_failure_keeps_the_address_and_re_enables_the_button(wired_panel: X64DbgPanel, bridge: ScriptedBridge) -> None:
    """When ``$result`` reads zero the creation is reported as failed, the address stays typed and the button is re-enabled.

    Args:
        wired_panel: Panel holding the scripted bridge.
        bridge: The scripted bridge.
    """
    bridge.replies["reg_get"] = "0x0"
    _edit(wired_panel, "_create_thread_addr_input").setText("0x401000")

    _call(wired_panel, "_on_create_thread")
    _settle(wired_panel)

    assert "[-] Create Thread failed:" in _console(wired_panel)
    assert "Thread created" not in _console(wired_panel)
    assert _edit(wired_panel, "_create_thread_addr_input").text() == "0x401000"
    assert _button(wired_panel, "_create_thread_btn").isEnabled()


def test_create_thread_success_with_a_non_dict_result_reports_no_tid(wired_panel: X64DbgPanel) -> None:
    """A result that is not a mapping is reported with an unknown TID instead of failing.

    Args:
        wired_panel: Panel holding the scripted bridge.
    """
    _call(wired_panel, "_on_create_thread_success", None)

    assert "[+] Thread created: tid=None" in _console(wired_panel)


def test_apply_watchpoints_fills_one_row_per_watchpoint(panel: X64DbgPanel) -> None:
    """Each watchpoint becomes a row of address, size, type, enabled flag and hit count, with its id in the address cell's user data.

    Args:
        panel: Panel built without a bridge.
    """
    watchpoints = [
        WatchpointInfo(id=3, address=0x401000, size=4, watch_type="write", enabled=True, hit_count=7),
        WatchpointInfo(id=4, address=0x402000, size=1, watch_type="read", enabled=False, hit_count=0),
    ]

    _call(panel, "_apply_watchpoints", watchpoints)

    table = _table(panel, "_wp_table")
    assert _rows(table) == [["0x401000", "4", "write", "Yes", "7"], ["0x402000", "1", "read", "No", "0"]]
    first = table.item(0, 0)
    second = table.item(1, 0)
    assert first is not None
    assert second is not None
    assert first.data(Qt.ItemDataRole.UserRole) == 3
    assert second.data(Qt.ItemDataRole.UserRole) == 4
