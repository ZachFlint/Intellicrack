# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Coverage for the Stalker summary, device, spawn, hook, module and memory handlers of the Frida panel.

Every test drives a real ``FridaPanel`` under the offscreen Qt platform. Handlers are invoked the way their buttons invoke them. A real
``FridaBridge`` that was never initialized or attached is installed with ``set_bridge``, so the coroutines the panel dispatches run on
the application's background bridge loop and fail with the bridge's own "not attached to a process" error, which the panel must show on
its console and recover from. Result handlers are fed the dataclasses the real bridge returns. Spawn and resume use a subclass of the
real bridge that records the spawn arguments, because a spawn needs a live device. Qt's static input dialogs are replaced with plain
functions that return chosen answers. Expected values come from the documented hex dump format, the Qt model state and strings written
out by hand.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple, override

import pytest
from PyQt6.QtWidgets import QInputDialog, QTableWidget

from intellicrack.bridges.base import MemorySearchResult
from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.types import (
    ExportInfo,
    FridaDeviceInfo,
    HookInfo,
    ImportInfo,
    MemoryRegion,
    ModuleDependencyInfo,
    ModuleSectionInfo,
    StalkerCallSummary,
    ToolError,
)
from intellicrack.ui.panels.async_bridge import bridge_workers_for, drain_bridge_workers_for
from intellicrack.ui.panels.frida_panel import FridaPanel
from tests.ui.conftest import SignalRecorder


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Sequence

    from PyQt6.QtWidgets import QApplication


pytestmark = pytest.mark.usefixtures("qapp")


_DRAIN_MS: int = 20_000
_NOT_ATTACHED: str = "not attached to a process"
_NO_BRIDGE: str = "[!] No Frida bridge available"
_SPAWNED_PID: int = 4242
_Dynamic = Any


class _Rig(NamedTuple):
    """A panel together with the real bridge installed on it.

    Attributes:
        panel: Panel under test.
        bridge: Bridge installed with ``set_bridge``.
    """

    panel: FridaPanel
    bridge: FridaBridge


class _SpawnCall(NamedTuple):
    """Arguments the panel passed to ``spawn``.

    Attributes:
        path: Executable path.
        args: Command-line arguments.
        env: Environment overrides.
        cwd: Working directory.
        stdio: Stdio mode.
        cancellable_id: Cancellation token identifier.
    """

    path: Path
    args: list[str] | None
    env: dict[str, str] | None
    cwd: str | None
    stdio: str | None
    cancellable_id: str | None


class _RecordingBridge(FridaBridge):
    """Real bridge whose ``spawn`` records its arguments and whose ``resume`` succeeds without a device."""

    def __init__(self) -> None:
        """Create the bridge with an empty spawn record."""
        super().__init__()
        self.spawn_calls: list[_SpawnCall] = []

    @override
    async def spawn(
        self,
        path: Path,
        args: Sequence[str] | None = None,
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        stdio: str | None = None,
        cancellable_id: str | None = None,
    ) -> int:
        """Record the spawn request instead of starting a process.

        Args:
            path: Executable path.
            args: Command-line arguments.
            env: Environment overrides.
            cwd: Working directory.
            stdio: Stdio mode.
            cancellable_id: Cancellation token identifier.

        Returns:
            int: A fixed process identifier.
        """
        self.spawn_calls.append(_SpawnCall(path, None if args is None else list(args), env, cwd, stdio, cancellable_id))
        return _SPAWNED_PID

    @override
    async def resume(self) -> None:
        """Succeed without resuming anything."""


class _RecRig(NamedTuple):
    """A panel together with the recording bridge installed on it.

    Attributes:
        panel: Panel under test.
        bridge: Recording bridge installed with ``set_bridge``.
    """

    panel: FridaPanel
    bridge: _RecordingBridge


@dataclass(frozen=True)
class _TableCase:
    """One result-table population scenario.

    Attributes:
        populate: Name of the panel method that fills the table.
        table: Name of the panel attribute holding the table.
        payload: Records the real bridge returns for this table.
        rows: Expected cell texts, row by row.
    """

    populate: str
    table: str
    payload: list[object]
    rows: list[list[str]]


def _priv(obj: object, name: str) -> _Dynamic:
    """Read a private attribute or method of a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.

    Returns:
        _Dynamic: The attribute value.
    """
    return getattr(obj, name)


def _console(panel: FridaPanel) -> str:
    """Return the panel console text.

    Args:
        panel: Panel whose console is read.

    Returns:
        str: Plain text of the console.
    """
    return str(_priv(panel, "_console").toPlainText())


def _settle(qapp: QApplication, panel: FridaPanel) -> None:
    """Join the panel's dispatched workers and deliver their queued results.

    Args:
        qapp: Application whose event queue receives the results.
        panel: Panel that dispatched the workers.
    """
    drain_bridge_workers_for(panel, _DRAIN_MS)
    qapp.processEvents()


def _teardown(qapp: QApplication, panel: FridaPanel) -> None:
    """Stop every timer and worker the panel owns and close it.

    Args:
        qapp: Application whose events are flushed.
        panel: Panel to shut down.
    """
    drain_bridge_workers_for(panel, _DRAIN_MS)
    qapp.processEvents()
    _priv(panel, "_console_drain_timer").stop()
    panel.close()
    qapp.processEvents()


def _rows(table: QTableWidget) -> list[list[str]]:
    """Read every cell of a table as text.

    Args:
        table: Table to read.

    Returns:
        list[list[str]]: Cell texts, row by row, with ``<missing>`` for a cell without an item.
    """
    result: list[list[str]] = []
    for row in range(table.rowCount()):
        cells: list[str] = []
        for column in range(table.columnCount()):
            item = table.item(row, column)
            cells.append(item.text() if item is not None else "<missing>")
        result.append(cells)
    return result


def _text_answers(answers: dict[str, tuple[str, bool]]) -> Callable[..., tuple[str, bool]]:
    """Build a ``QInputDialog.getText`` replacement that answers by dialog title.

    Args:
        answers: Answer and acceptance flag for each dialog title.

    Returns:
        Callable[..., tuple[str, bool]]: Function that looks up the answer for the title passed as second argument.
    """

    def _impl(*args: object, **kwargs: object) -> tuple[str, bool]:
        """Return the scripted answer for the dialog title.

        Args:
            *args: Dialog arguments; the second is the title.
            **kwargs: Ignored keyword arguments.

        Returns:
            tuple[str, bool]: Scripted text and acceptance flag.
        """
        del kwargs
        return answers[str(args[1])]

    return _impl


def _fixed_answer(text: str, *, accepted: bool) -> Callable[..., tuple[str, bool]]:
    """Build a dialog replacement that always returns the same text.

    Args:
        text: Text the dialog returns.
        accepted: Acceptance flag the dialog returns.

    Returns:
        Callable[..., tuple[str, bool]]: Function ignoring its arguments.
    """

    def _impl(*args: object, **kwargs: object) -> tuple[str, bool]:
        """Return the fixed answer.

        Args:
            *args: Ignored positional arguments.
            **kwargs: Ignored keyword arguments.

        Returns:
            tuple[str, bool]: Fixed text and acceptance flag.
        """
        del args, kwargs
        return (text, accepted)

    return _impl


def _device_rows(panel: FridaPanel) -> list[tuple[str, object]]:
    """Read the device combo as text and stored data.

    Args:
        panel: Panel whose device combo is read.

    Returns:
        list[tuple[str, object]]: Display text and item data of every entry.
    """
    combo = _priv(panel, "_device_combo")
    return [(str(combo.itemText(i)), combo.itemData(i)) for i in range(combo.count())]


@pytest.fixture
def panel(qapp: QApplication) -> Generator[FridaPanel]:
    """Provide a panel with no bridge installed.

    Args:
        qapp: Session application.

    Yields:
        FridaPanel: Panel under test.
    """
    created = FridaPanel()
    try:
        yield created
    finally:
        _teardown(qapp, created)


@pytest.fixture
def rig(qapp: QApplication) -> Generator[_Rig]:
    """Provide a panel with a real, uninitialized bridge installed.

    Args:
        qapp: Session application.

    Yields:
        _Rig: The panel and its bridge.
    """
    created = FridaPanel()
    bridge = FridaBridge()
    created.set_bridge(bridge)
    try:
        yield _Rig(created, bridge)
    finally:
        _teardown(qapp, created)


@pytest.fixture
def rec_rig(qapp: QApplication) -> Generator[_RecRig]:
    """Provide a panel with the recording bridge installed.

    Args:
        qapp: Session application.

    Yields:
        _RecRig: The panel and its recording bridge.
    """
    created = FridaPanel()
    bridge = _RecordingBridge()
    created.set_bridge(bridge)
    try:
        yield _RecRig(created, bridge)
    finally:
        _teardown(qapp, created)


@pytest.mark.parametrize(
    "handler",
    [
        "_on_stalker_flush",
        "_on_stalker_summary_stop",
        "refresh_devices",
        "_on_resume",
        "_on_refresh_hooks",
        "_on_refresh_modules",
        "_on_show_exports",
        "_on_show_imports",
        "_on_show_module_ranges",
        "_on_show_sections",
        "_on_show_dependencies",
        "_on_find_export_by_name",
        "_on_read_memory",
        "_on_write_memory",
        "_on_copy_memory",
        "_on_allocate_memory",
        "_on_scan_memory",
        "_on_list_regions",
    ],
)
def test_handlers_without_a_bridge_do_nothing(panel: FridaPanel, handler: str) -> None:
    """Every bridge-backed handler returns silently when no bridge is installed, even with its inputs filled.

    Args:
        panel: Panel with no bridge.
        handler: Name of the handler under test.
    """
    _priv(panel, "_module_combo").addItem("kernel32.dll")
    _priv(panel, "_find_export_name_input").setText("CreateFileW")
    _priv(panel, "_mem_read_addr").setText("0x401000")
    _priv(panel, "_mem_write_addr").setText("0x401000")
    _priv(panel, "_mem_write_data").setText("90 90")
    _priv(panel, "_mem_copy_src").setText("0x401000")
    _priv(panel, "_mem_copy_dst").setText("0x402000")
    _priv(panel, "_mem_scan_pattern").setText("90")

    _priv(panel, handler)()

    assert not _console(panel)
    assert bridge_workers_for(panel) == []
    assert _priv(panel, "_resume_btn").isEnabled() is False
    assert _priv(panel, "_refresh_modules_btn").isEnabled() is True
    assert _priv(panel, "_mem_scan_btn").isEnabled() is True
    assert _priv(panel, "_mem_regions_btn").isEnabled() is True
    assert _priv(panel, "_refresh_hooks_btn").isEnabled() is True


@pytest.mark.parametrize(
    "handler",
    ["_on_stalker_summary_start", "_on_spawn", "_on_intercept_return", "_on_replace_function", "_on_replace_function_fast"],
)
def test_handlers_without_a_bridge_report_the_missing_bridge(panel: FridaPanel, handler: str) -> None:
    """Handlers that report a missing bridge print exactly one console line and start nothing.

    Args:
        panel: Panel with no bridge.
        handler: Name of the handler under test.
    """
    _priv(panel, handler)()

    assert _console(panel) == _NO_BRIDGE
    assert bridge_workers_for(panel) == []
    assert _priv(panel, "_stalker_summary_start_btn").isEnabled() is True
    assert _priv(panel, "_spawn_btn").isEnabled() is True
    assert _priv(panel, "_hooks_table").rowCount() == 0


def test_load_module_without_a_bridge_reports_it_on_the_result_label(panel: FridaPanel) -> None:
    """Loading a module with no bridge writes the reason to the result label and its tooltip.

    Args:
        panel: Panel with no bridge.
    """
    _priv(panel, "_load_module_path_input").setText("C:\\libs\\probe.dll")

    _priv(panel, "_on_load_module")()

    label = _priv(panel, "_load_module_result")
    assert label.text() == "No bridge available"
    assert label.toolTip() == "No bridge available"
    assert _priv(panel, "_load_module_btn").isEnabled() is True


def test_load_module_with_a_blank_path_asks_for_one(rig: _Rig) -> None:
    """A blank or whitespace-only module path is rejected before anything is dispatched.

    Args:
        rig: Panel with a real bridge.
    """
    _priv(rig.panel, "_load_module_path_input").setText("   ")

    _priv(rig.panel, "_on_load_module")()

    label = _priv(rig.panel, "_load_module_result")
    assert label.text() == "Enter a module path"
    assert label.toolTip() == "Enter a module path"
    assert _priv(rig.panel, "_load_module_btn").isEnabled() is True
    assert bridge_workers_for(rig.panel) == []


def test_load_module_failure_from_the_bridge_is_shown_and_the_button_recovers(qapp: QApplication, rig: _Rig) -> None:
    """A module load on an unattached bridge disables the button while in flight, then reports the bridge's error.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
    """
    _priv(rig.panel, "_load_module_path_input").setText("  C:\\libs\\probe.dll  ")

    _priv(rig.panel, "_on_load_module")()

    assert _priv(rig.panel, "_load_module_btn").isEnabled() is False
    _settle(qapp, rig.panel)
    assert _priv(rig.panel, "_load_module_result").text() == f"Load failed: {_NOT_ATTACHED}"
    assert _priv(rig.panel, "_load_module_btn").isEnabled() is True


def test_stalker_flush_with_a_non_numeric_thread_id_is_rejected(rig: _Rig) -> None:
    """A thread id that is not an integer is reported on the console and nothing is dispatched.

    Args:
        rig: Panel with a real bridge.
    """
    _priv(rig.panel, "_stalker_tid_input").setText("abc")

    _priv(rig.panel, "_on_stalker_flush")()

    assert _console(rig.panel) == "[-] Invalid thread ID: abc"
    assert bridge_workers_for(rig.panel) == []


@pytest.mark.parametrize("tid_text", ["", "  1234 "])
def test_stalker_flush_failure_from_the_bridge_is_shown(qapp: QApplication, rig: _Rig, tid_text: str) -> None:
    """Flushing with no active trace shows the bridge's error, with or without a thread id.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
        tid_text: Text typed into the thread id field.
    """
    _priv(rig.panel, "_stalker_tid_input").setText(tid_text)

    _priv(rig.panel, "_on_stalker_flush")()
    _settle(qapp, rig.panel)

    assert _console(rig.panel) == f"[-] Stalker flush failed: {_NOT_ATTACHED}"


def test_stalker_summary_start_with_a_non_numeric_thread_id_is_rejected(rig: _Rig) -> None:
    """An invalid thread id leaves the Start Summary button enabled and dispatches nothing.

    Args:
        rig: Panel with a real bridge.
    """
    _priv(rig.panel, "_stalker_tid_input").setText("abc")

    _priv(rig.panel, "_on_stalker_summary_start")()

    assert _console(rig.panel) == "[-] Invalid thread ID: abc"
    assert _priv(rig.panel, "_stalker_summary_start_btn").isEnabled() is True
    assert bridge_workers_for(rig.panel) == []


@pytest.mark.parametrize(("tid_text", "shown"), [("", "current"), ("0", "current"), ("1234", "1234")])
def test_stalker_summary_start_announces_then_reports_the_bridge_failure(
    qapp: QApplication,
    rig: _Rig,
    tid_text: str,
    shown: str,
) -> None:
    """Starting a summary trace announces the thread, disables Start, and re-enables it with the bridge's error.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
        tid_text: Text typed into the thread id field.
        shown: Thread description expected in the announcement.
    """
    _priv(rig.panel, "_stalker_tid_input").setText(tid_text)
    start_btn = _priv(rig.panel, "_stalker_summary_start_btn")

    _priv(rig.panel, "_on_stalker_summary_start")()

    assert _console(rig.panel) == f"[*] Starting Stalker call-summary trace (tid={shown})"
    assert start_btn.isEnabled() is False
    _settle(qapp, rig.panel)
    assert _console(rig.panel).splitlines()[-1] == f"[-] Stalker call-summary start failed: {_NOT_ATTACHED}"
    assert start_btn.isEnabled() is True


def test_stalker_summary_started_enables_stop_and_disables_start(panel: FridaPanel) -> None:
    """A successful start shows the trace id and swaps the two summary buttons.

    Args:
        panel: Panel with no bridge.
    """
    _priv(panel, "_stalker_summary_stop_btn").setEnabled(False)

    _priv(panel, "_on_stalker_summary_started")("a1b2c3d4")

    assert _console(panel) == "[+] Stalker call-summary tracing started (trace_id=a1b2c3d4)"
    assert _priv(panel, "_stalker_summary_start_btn").isEnabled() is False
    assert _priv(panel, "_stalker_summary_stop_btn").isEnabled() is True


def test_stalker_summary_start_error_reenables_start(panel: FridaPanel) -> None:
    """A failed start prints the error and re-enables Start Summary.

    Args:
        panel: Panel with no bridge.
    """
    _priv(panel, "_stalker_summary_start_btn").setEnabled(False)

    _priv(panel, "_on_stalker_summary_start_error")(ToolError("boom"))

    assert _console(panel) == "[-] Stalker call-summary start failed: boom"
    assert _priv(panel, "_stalker_summary_start_btn").isEnabled() is True


def test_stalker_summary_stop_with_a_non_numeric_thread_id_keeps_stop_enabled(rig: _Rig) -> None:
    """An invalid thread id is reported, Stop stays enabled and nothing is dispatched.

    Args:
        rig: Panel with a real bridge.
    """
    _priv(rig.panel, "_stalker_tid_input").setText("abc")
    stop_btn = _priv(rig.panel, "_stalker_summary_stop_btn")
    stop_btn.setEnabled(False)

    _priv(rig.panel, "_on_stalker_summary_stop")()

    assert _console(rig.panel) == "[-] Invalid thread ID: abc"
    assert stop_btn.isEnabled() is True
    assert bridge_workers_for(rig.panel) == []


def test_stalker_summary_stop_failure_from_the_bridge_restores_the_buttons(qapp: QApplication, rig: _Rig) -> None:
    """Stopping with no trace disables Stop while in flight, then shows the error and re-enables Start.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
    """
    _priv(rig.panel, "_stalker_tid_input").setText("77")
    stop_btn = _priv(rig.panel, "_stalker_summary_stop_btn")
    start_btn = _priv(rig.panel, "_stalker_summary_start_btn")
    stop_btn.setEnabled(True)
    start_btn.setEnabled(False)

    _priv(rig.panel, "_on_stalker_summary_stop")()

    assert stop_btn.isEnabled() is False
    _settle(qapp, rig.panel)
    assert _console(rig.panel) == f"[-] Stalker call-summary stop failed: {_NOT_ATTACHED}"
    assert start_btn.isEnabled() is True
    assert stop_btn.isEnabled() is False


def test_stalker_summary_stopped_lists_every_target_and_clears_stale_output(panel: FridaPanel) -> None:
    """The stop result replaces the display with one line per target and reports the target count and duration.

    Args:
        panel: Panel with no bridge.
    """
    display = _priv(panel, "_stalker_summary_display")
    display.setPlainText("stale")
    _priv(panel, "_stalker_summary_start_btn").setEnabled(False)
    _priv(panel, "_stalker_summary_stop_btn").setEnabled(True)
    summary = StalkerCallSummary(thread_id=0, counts={"0x401000": 5, "0x402000": 3}, duration_ms=12.34)

    _priv(panel, "_on_stalker_summary_stopped")(summary)

    assert display.toPlainText() == "0x401000: 5\n0x402000: 3"
    assert _console(panel) == "[+] Stalker call-summary trace complete: 2 targets in 12.3ms"
    assert _priv(panel, "_stalker_summary_start_btn").isEnabled() is True
    assert _priv(panel, "_stalker_summary_stop_btn").isEnabled() is False


def test_stalker_summary_stopped_with_no_calls_clears_the_display(panel: FridaPanel) -> None:
    """A trace that recorded no calls empties the display and reports zero targets.

    Args:
        panel: Panel with no bridge.
    """
    display = _priv(panel, "_stalker_summary_display")
    display.setPlainText("stale")

    _priv(panel, "_on_stalker_summary_stopped")(StalkerCallSummary(thread_id=0, counts={}, duration_ms=0.04))

    assert not display.toPlainText()
    assert _console(panel) == "[+] Stalker call-summary trace complete: 0 targets in 0.0ms"


def test_stalker_summary_stop_error_swaps_the_buttons_back(panel: FridaPanel) -> None:
    """A failed stop prints the error, re-enables Start and disables Stop.

    Args:
        panel: Panel with no bridge.
    """
    _priv(panel, "_stalker_summary_start_btn").setEnabled(False)
    _priv(panel, "_stalker_summary_stop_btn").setEnabled(True)

    _priv(panel, "_on_stalker_summary_stop_error")(ToolError("denied"))

    assert _console(panel) == "[-] Stalker call-summary stop failed: denied"
    assert _priv(panel, "_stalker_summary_start_btn").isEnabled() is True
    assert _priv(panel, "_stalker_summary_stop_btn").isEnabled() is False


def test_refresh_devices_fills_the_combo_from_the_real_frida_device_list(qapp: QApplication, rig: _Rig) -> None:
    """Refreshing devices replaces the combo with one entry per enumerated device, labeled with its name and type.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
    """
    loop = asyncio.new_event_loop()
    try:
        devices = loop.run_until_complete(FridaBridge.enumerate_devices())
    finally:
        loop.close()
    expected: list[tuple[str, object]] = [
        (f"{d.name} ({d.device_type})", {"id": d.id, "type": d.device_type, "name": d.name}) for d in devices
    ]

    rig.panel.refresh_devices()
    _settle(qapp, rig.panel)

    assert _device_rows(rig.panel) == expected
    assert any(d.device_type == "local" for d in devices)


def test_populate_device_combo_keeps_the_selected_entry_across_a_refresh(panel: FridaPanel) -> None:
    """A refresh re-selects the previously selected device by its label even when its position changes.

    Args:
        panel: Panel with no bridge.
    """
    combo = _priv(panel, "_device_combo")
    first = [
        FridaDeviceInfo(id="local", name="Local System", device_type="local"),
        FridaDeviceInfo(id="socket", name="Local Socket", device_type="remote"),
    ]
    _priv(panel, "_populate_device_combo")(first)
    combo.setCurrentIndex(1)
    assert combo.currentText() == "Local Socket (remote)"

    _priv(panel, "_populate_device_combo")(
        [
            FridaDeviceInfo(id="usb1", name="Phone", device_type="usb"),
            FridaDeviceInfo(id="socket", name="Local Socket", device_type="remote"),
            FridaDeviceInfo(id="local", name="Local System", device_type="local"),
        ],
    )

    assert combo.currentIndex() == 1
    assert combo.currentText() == "Local Socket (remote)"
    assert combo.count() == 3
    assert combo.itemData(1) == {"id": "socket", "type": "remote", "name": "Local Socket"}


def test_oneshot_script_success_reports_the_result_and_restores_run(panel: FridaPanel) -> None:
    """A finished one-shot script prints its result, re-enables Run with its idle tooltip and signals completion.

    Args:
        panel: Panel with no bridge.
    """
    recorder = SignalRecorder()
    panel.script_executed.connect(recorder)
    panel.run_btn.setEnabled(False)
    panel.run_btn.setToolTip("busy")

    _priv(panel, "_on_oneshot_script_success")(14, "42")

    assert _console(panel) == "[+] Script result: 42"
    assert panel.run_btn.isEnabled() is True
    assert panel.run_btn.toolTip() == "Run the script editor contents against the attached process"
    recorder.verify_single_call()


def test_spawn_passes_every_dialog_answer_to_the_bridge_and_applies_the_result(
    qapp: QApplication,
    rec_rig: _RecRig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Spawn parses the path, arguments, working directory, environment and stdio answers and shows the spawned process.

    The environment text mixes a blank line, a line without ``=`` and a value that itself contains ``=``; only the two well-formed lines
    may survive, split at the first ``=``.

    Args:
        qapp: Session application.
        rec_rig: Panel with the recording bridge.
        monkeypatch: Fixture that replaces the Qt input dialogs.
    """
    panel = rec_rig.panel
    monkeypatch.setattr(
        QInputDialog,
        "getText",
        staticmethod(
            _text_answers(
                {
                    "Spawn Process": ("  C:\\tools\\target.exe  ", True),
                    "Arguments": ("  -a   beta  ", True),
                    "Working Directory": ("  C:\\work  ", True),
                },
            ),
        ),
    )
    monkeypatch.setattr(QInputDialog, "getMultiLineText", staticmethod(_fixed_answer("ONE=1\n\nnovalue\n  TWO=two=2  \n", accepted=True)))
    monkeypatch.setattr(QInputDialog, "getItem", staticmethod(_fixed_answer("pipe", accepted=True)))
    recorder = SignalRecorder()
    panel.tool_started.connect(recorder)
    spawn_btn = _priv(panel, "_spawn_btn")

    _priv(panel, "_on_spawn")()

    assert spawn_btn.isEnabled() is False
    _settle(qapp, panel)
    assert rec_rig.bridge.spawn_calls == [
        _SpawnCall(Path("C:\\tools\\target.exe"), ["-a", "beta"], {"ONE": "1", "TWO": "two=2"}, "C:\\work", "pipe", None),
    ]
    assert _console(panel) == f"[+] Spawned process PID {_SPAWNED_PID}"
    assert _priv(panel, "_attached_pid") == _SPAWNED_PID
    assert _priv(panel, "status_label").text() == f"Spawned (PID: {_SPAWNED_PID})"
    assert spawn_btn.isEnabled() is True
    assert _priv(panel, "_resume_btn").isEnabled() is True
    assert _priv(panel, "_attach_btn").isEnabled() is False
    assert _priv(panel, "_detach_btn").isEnabled() is True
    recorder.verify_single_call()


@pytest.mark.parametrize(
    "overrides",
    [
        {"Arguments": ("-a b", False)},
        {"Arguments": ("   ", True)},
        {"Working Directory": ("C:\\work", False)},
        {"Working Directory": ("   ", True)},
    ],
    ids=["args-cancelled", "args-blank", "cwd-cancelled", "cwd-blank"],
)
def test_spawn_ignores_cancelled_or_blank_optional_answers(
    qapp: QApplication,
    rec_rig: _RecRig,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, tuple[str, bool]],
) -> None:
    """A cancelled or blank arguments or working-directory answer reaches the bridge as ``None``.

    Args:
        qapp: Session application.
        rec_rig: Panel with the recording bridge.
        monkeypatch: Fixture that replaces the Qt input dialogs.
        overrides: Answers that replace the cancelled defaults for the named dialogs.
    """
    answers: dict[str, tuple[str, bool]] = {
        "Spawn Process": ("C:\\tools\\target.exe", True),
        "Arguments": ("", False),
        "Working Directory": ("", False),
    }
    answers.update(overrides)
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(_text_answers(answers)))
    monkeypatch.setattr(QInputDialog, "getMultiLineText", staticmethod(_fixed_answer("", accepted=False)))
    monkeypatch.setattr(QInputDialog, "getItem", staticmethod(_fixed_answer("inherit", accepted=True)))

    _priv(rec_rig.panel, "_on_spawn")()
    _settle(qapp, rec_rig.panel)

    assert rec_rig.bridge.spawn_calls == [_SpawnCall(Path("C:\\tools\\target.exe"), None, None, None, None, None)]


@pytest.mark.parametrize(
    ("env_answer", "stdio_answer"),
    [
        (("ONE=1", False), ("inherit", True)),
        (("  \n ", True), ("inherit", True)),
        (("", False), ("pipe", False)),
        (("", False), ("inherit", True)),
    ],
    ids=["env-cancelled", "env-blank", "stdio-pipe-rejected", "stdio-inherit"],
)
def test_spawn_ignores_cancelled_blank_or_inherit_environment_and_stdio(
    qapp: QApplication,
    rec_rig: _RecRig,
    monkeypatch: pytest.MonkeyPatch,
    env_answer: tuple[str, bool],
    stdio_answer: tuple[str, bool],
) -> None:
    """A cancelled or blank environment, a rejected ``pipe`` choice and ``inherit`` all reach the bridge as ``None``.

    Args:
        qapp: Session application.
        rec_rig: Panel with the recording bridge.
        monkeypatch: Fixture that replaces the Qt input dialogs.
        env_answer: Environment dialog answer and acceptance flag.
        stdio_answer: Stdio dialog answer and acceptance flag.
    """
    monkeypatch.setattr(
        QInputDialog,
        "getText",
        staticmethod(
            _text_answers(
                {"Spawn Process": ("C:\\tools\\target.exe", True), "Arguments": ("", False), "Working Directory": ("", False)},
            ),
        ),
    )
    monkeypatch.setattr(QInputDialog, "getMultiLineText", staticmethod(_fixed_answer(env_answer[0], accepted=env_answer[1])))
    monkeypatch.setattr(QInputDialog, "getItem", staticmethod(_fixed_answer(stdio_answer[0], accepted=stdio_answer[1])))

    _priv(rec_rig.panel, "_on_spawn")()
    _settle(qapp, rec_rig.panel)

    assert rec_rig.bridge.spawn_calls == [_SpawnCall(Path("C:\\tools\\target.exe"), None, None, None, None, None)]


@pytest.mark.parametrize("path_answer", [("C:\\tools\\target.exe", False), ("   ", True), ("", False)])
def test_spawn_without_a_path_stops_before_asking_anything_else(
    rec_rig: _RecRig,
    monkeypatch: pytest.MonkeyPatch,
    path_answer: tuple[str, bool],
) -> None:
    """A cancelled or blank executable path ends the spawn before any other dialog or dispatch.

    Args:
        rec_rig: Panel with the recording bridge.
        monkeypatch: Fixture that replaces the Qt input dialogs.
        path_answer: Path dialog answer and acceptance flag.
    """
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(_text_answers({"Spawn Process": path_answer})))

    _priv(rec_rig.panel, "_on_spawn")()

    assert not _console(rec_rig.panel)
    assert _priv(rec_rig.panel, "_spawn_btn").isEnabled() is True
    assert bridge_workers_for(rec_rig.panel) == []
    assert rec_rig.bridge.spawn_calls == []


def test_spawn_failure_from_the_bridge_is_shown_and_the_button_recovers(
    qapp: QApplication,
    rig: _Rig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Spawning on a bridge that has no device reports the bridge's error and re-enables Spawn.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
        monkeypatch: Fixture that replaces the Qt input dialogs.
    """
    monkeypatch.setattr(
        QInputDialog,
        "getText",
        staticmethod(
            _text_answers({"Spawn Process": ("C:\\tools\\target.exe", True), "Arguments": ("", False), "Working Directory": ("", False)}),
        ),
    )
    spawn_btn = _priv(rig.panel, "_spawn_btn")

    _priv(rig.panel, "_on_spawn")()

    assert spawn_btn.isEnabled() is False
    _settle(qapp, rig.panel)
    assert _console(rig.panel) == "[-] Spawn failed: failed to initialize Frida device"
    assert spawn_btn.isEnabled() is True
    assert _priv(rig.panel, "_attached_pid") is None


def test_resume_failure_from_the_bridge_is_shown_and_the_button_recovers(qapp: QApplication, rig: _Rig) -> None:
    """Resuming with nothing spawned disables Resume while in flight, then shows the error and re-enables it.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
    """
    resume_btn = _priv(rig.panel, "_resume_btn")
    resume_btn.setEnabled(True)

    _priv(rig.panel, "_on_resume")()

    assert resume_btn.isEnabled() is False
    _settle(qapp, rig.panel)
    assert _console(rig.panel) == f"[-] Resume failed: {_NOT_ATTACHED}"
    assert resume_btn.isEnabled() is True


def test_resume_success_sets_the_running_status_and_disables_resume(qapp: QApplication, rec_rig: _RecRig) -> None:
    """A successful resume prints a line, shows Running and leaves Resume disabled.

    Args:
        qapp: Session application.
        rec_rig: Panel with the recording bridge.
    """
    resume_btn = _priv(rec_rig.panel, "_resume_btn")
    resume_btn.setEnabled(True)
    status_label = _priv(rec_rig.panel, "status_label")
    status_label.setText("Spawned (PID: 1)")

    _priv(rec_rig.panel, "_on_resume")()
    _settle(qapp, rec_rig.panel)

    assert _console(rec_rig.panel) == "[+] Process resumed"
    assert status_label.text() == "Running"
    assert resume_btn.isEnabled() is False


@pytest.mark.parametrize("handler", ["_on_intercept_return", "_on_replace_function", "_on_replace_function_fast"])
@pytest.mark.parametrize(
    ("target_answer", "value_answer"),
    [
        (("", False), ("1", True)),
        (("   ", True), ("1", True)),
        (("kernel32.dll!Sleep", True), ("", False)),
        (("kernel32.dll!Sleep", True), ("  \n ", True)),
    ],
    ids=["target-cancelled", "target-blank", "second-cancelled", "second-blank"],
)
def test_hook_install_dialogs_abandoned_before_dispatch_leave_no_row(
    rig: _Rig,
    monkeypatch: pytest.MonkeyPatch,
    handler: str,
    target_answer: tuple[str, bool],
    value_answer: tuple[str, bool],
) -> None:
    """Cancelling or blanking a dialog ends the install before a pending row is added or a coroutine dispatched.

    The integer prompt of Intercept Return keeps the cancelled answer the test guard installs, so for that handler a valid target
    followed by any code answer ends at the cancelled return-value prompt. For the replace handlers the second dialog is the code
    prompt.

    Args:
        rig: Panel with a real bridge.
        monkeypatch: Fixture that replaces the Qt input dialogs.
        handler: Name of the install handler under test.
        target_answer: Target dialog answer and acceptance flag.
        value_answer: Code dialog answer and acceptance flag.
    """
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(_fixed_answer(target_answer[0], accepted=target_answer[1])))
    monkeypatch.setattr(QInputDialog, "getMultiLineText", staticmethod(_fixed_answer(value_answer[0], accepted=value_answer[1])))

    _priv(rig.panel, handler)()

    assert not _console(rig.panel)
    assert _priv(rig.panel, "_hooks_table").rowCount() == 0
    assert _priv(rig.panel, "_hook_ids") == []
    assert bridge_workers_for(rig.panel) == []


def test_replace_function_fast_shows_a_pending_row_then_removes_it_when_the_bridge_fails(
    qapp: QApplication,
    rig: _Rig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fast replace adds an "Installing..." row immediately and removes it with a console error when the bridge fails.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
        monkeypatch: Fixture that replaces the Qt input dialogs.
    """
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(_fixed_answer("  kernel32.dll!Sleep  ", accepted=True)))
    monkeypatch.setattr(
        QInputDialog,
        "getMultiLineText",
        staticmethod(_fixed_answer("  new NativeCallback(function () {}, 'void', [])  ", accepted=True)),
    )
    hooks = _priv(rig.panel, "_hooks_table")

    _priv(rig.panel, "_on_replace_function_fast")()

    assert _rows(hooks) == [["Resolving...", "", "kernel32.dll!Sleep", "Installing..."]]
    assert _priv(rig.panel, "_hook_ids") == ["__pending_hook_0__"]
    _settle(qapp, rig.panel)
    assert hooks.rowCount() == 0
    assert _priv(rig.panel, "_hook_ids") == []
    assert _console(rig.panel) == f"[-] Replace function (fast) failed: {_NOT_ATTACHED}"


def test_refresh_hooks_replaces_stale_rows_with_the_bridge_hook_list(qapp: QApplication, rig: _Rig) -> None:
    """Refreshing hooks clears rows the bridge no longer tracks and re-enables the Refresh button.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge that tracks no hooks.
    """
    rig.panel.add_hook_entry("0x1000", "old.dll", "stale", hook_id="old")
    refresh_btn = _priv(rig.panel, "_refresh_hooks_btn")

    _priv(rig.panel, "_on_refresh_hooks")()

    assert refresh_btn.isEnabled() is False
    _settle(qapp, rig.panel)
    assert _priv(rig.panel, "_hooks_table").rowCount() == 0
    assert _priv(rig.panel, "_hook_ids") == []
    assert refresh_btn.isEnabled() is True
    assert not _console(rig.panel)


def test_populate_hooks_splits_module_and_function_only_when_the_target_has_a_bang(panel: FridaPanel) -> None:
    """Hooks with and without a ``module!function`` target, a resolved and an unresolved address and both states fill the table.

    Args:
        panel: Panel with no bridge.
    """
    panel.add_hook_entry("0x1", "stale.dll", "stale", hook_id="stale")
    hooks = [
        HookInfo(id="h1", target="kernel32.dll!Sleep", address=0x7FF600001000, script_id="s1", active=True),
        HookInfo(id="h2", target="0x401000", address=None, script_id="s2", active=False),
    ]

    _priv(panel, "_populate_hooks_from_bridge")(hooks)

    assert _rows(_priv(panel, "_hooks_table")) == [
        ["0x7FF600001000", "kernel32.dll", "Sleep", "Active"],
        ["0x0", "", "0x401000", "Inactive"],
    ]
    assert _priv(panel, "_hook_ids") == ["h1", "h2"]
    assert _priv(panel, "_refresh_hooks_btn").isEnabled() is True


def test_refresh_hooks_error_is_shown_and_the_button_recovers(panel: FridaPanel) -> None:
    """A failed refresh prints the error and re-enables the Refresh button.

    Args:
        panel: Panel with no bridge.
    """
    _priv(panel, "_refresh_hooks_btn").setEnabled(False)

    _priv(panel, "_on_refresh_hooks_error")(ToolError("lost"))

    assert _console(panel) == "[-] Refresh hooks failed: lost"
    assert _priv(panel, "_refresh_hooks_btn").isEnabled() is True


def test_refresh_modules_failure_from_the_bridge_is_shown_and_the_button_recovers(qapp: QApplication, rig: _Rig) -> None:
    """Refreshing modules on an unattached bridge disables Refresh while in flight, then shows the error and re-enables it.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
    """
    refresh_btn = _priv(rig.panel, "_refresh_modules_btn")

    _priv(rig.panel, "_on_refresh_modules")()

    assert refresh_btn.isEnabled() is False
    _settle(qapp, rig.panel)
    assert _console(rig.panel) == f"[-] Modules operation failed: {_NOT_ATTACHED}"
    assert refresh_btn.isEnabled() is True


@pytest.mark.parametrize(
    ("handler", "label"),
    [
        ("_on_show_exports", "Exports"),
        ("_on_show_imports", "Imports"),
        ("_on_show_module_ranges", "Module ranges"),
        ("_on_show_sections", "Sections"),
        ("_on_show_dependencies", "Dependencies"),
    ],
)
def test_module_detail_buttons_need_a_selected_module(qapp: QApplication, rig: _Rig, handler: str, label: str) -> None:
    """Without a selected module nothing is dispatched; with one the bridge's failure is shown under the button's label.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
        handler: Name of the button handler under test.
        label: Label the handler prefixes to its failure line.
    """
    _priv(rig.panel, handler)()

    assert not _console(rig.panel)
    assert bridge_workers_for(rig.panel) == []

    _priv(rig.panel, "_module_combo").addItem("kernel32.dll")
    _priv(rig.panel, handler)()
    _settle(qapp, rig.panel)

    assert _console(rig.panel) == f"[-] {label} failed: {_NOT_ATTACHED}"


_TABLE_CASES: list[_TableCase] = [
    _TableCase(
        populate="_populate_exports_table",
        table="_exports_table",
        payload=[
            ExportInfo(name="CreateFileW", ordinal=0, address=0x7FFB12340000),
            ExportInfo(name="Sleep", ordinal=7, address=0x7FFB12341A20),
        ],
        rows=[["CreateFileW", "0x7FFB12340000", "0"], ["Sleep", "0x7FFB12341A20", "7"]],
    ),
    _TableCase(
        populate="_populate_imports_table",
        table="_imports_table",
        payload=[
            ImportInfo(dll="kernel32.dll", function="Sleep", ordinal=None, address=0x1000),
            ImportInfo(dll="ntdll.dll", function="NtClose", ordinal=None, address=0x2008),
        ],
        rows=[["Sleep", "kernel32.dll", "0x1000"], ["NtClose", "ntdll.dll", "0x2008"]],
    ),
    _TableCase(
        populate="_populate_module_ranges_table",
        table="_module_ranges_table",
        payload=[
            MemoryRegion(base_address=0x7FF600000000, size=4096, protection="r-x", state="committed", type="image", module_name="a.exe"),
            MemoryRegion(base_address=0x7FF600001000, size=512, protection="rw-", state="committed", type="image", module_name="a.exe"),
        ],
        rows=[["0x7FF600000000", "4096", "r-x"], ["0x7FF600001000", "512", "rw-"]],
    ),
    _TableCase(
        populate="_populate_sections_table",
        table="_sections_table",
        payload=[
            ModuleSectionInfo(id="1", name=".text", address=0x401000, size=512),
            ModuleSectionInfo(id="2", name=".data", address=0x402000, size=64),
        ],
        rows=[["1", ".text", "0x401000", "512"], ["2", ".data", "0x402000", "64"]],
    ),
    _TableCase(
        populate="_populate_dependencies_table",
        table="_dependencies_table",
        payload=[
            ModuleDependencyInfo(name="ntdll.dll", type="regular"),
            ModuleDependencyInfo(name="msvcrt.dll", type="weak"),
        ],
        rows=[["ntdll.dll", "regular"], ["msvcrt.dll", "weak"]],
    ),
]


@pytest.mark.parametrize("case", _TABLE_CASES, ids=[case.table for case in _TABLE_CASES])
def test_module_detail_tables_show_bridge_records_and_raise_their_tab(panel: FridaPanel, case: _TableCase) -> None:
    """Each module detail table is rebuilt from the bridge records and its tab is brought to the front.

    Args:
        panel: Panel with no bridge.
        case: Table, populate method, records and expected cell texts.
    """
    table = _priv(panel, case.table)
    tabs = _priv(panel, "_module_detail_tabs")
    expected_tab = tabs.indexOf(table)
    table.setRowCount(3)
    tabs.setCurrentIndex((expected_tab + 1) % tabs.count())

    _priv(panel, case.populate)(case.payload)

    assert _rows(table) == case.rows
    assert tabs.currentIndex() == expected_tab


def test_find_export_without_a_name_asks_for_one(rig: _Rig) -> None:
    """A blank export name prints a hint and dispatches nothing.

    Args:
        rig: Panel with a real bridge.
    """
    _priv(rig.panel, "_find_export_name_input").setText("   ")

    _priv(rig.panel, "_on_find_export_by_name")()

    assert _console(rig.panel) == "[!] Enter an export name"
    assert bridge_workers_for(rig.panel) == []


@pytest.mark.parametrize("module", ["", "kernel32.dll"])
def test_find_export_failure_from_the_bridge_is_shown(qapp: QApplication, rig: _Rig, module: str) -> None:
    """Looking up an export on an unattached bridge shows the bridge's error, with or without a module selected.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
        module: Module added to the combo, or empty for none.
    """
    if module:
        _priv(rig.panel, "_module_combo").addItem(module)
    _priv(rig.panel, "_find_export_name_input").setText("  CreateFileW  ")

    _priv(rig.panel, "_on_find_export_by_name")()
    _settle(qapp, rig.panel)

    assert _console(rig.panel) == f"[-] Find export failed: {_NOT_ATTACHED}"


@pytest.mark.parametrize("text", ["", "   ", "zz"])
def test_read_memory_with_an_invalid_address_is_rejected(rig: _Rig, text: str) -> None:
    """A blank or non-hex read address prints "Invalid address" and dispatches nothing.

    Args:
        rig: Panel with a real bridge.
        text: Text typed into the read address field.
    """
    _priv(rig.panel, "_mem_read_addr").setText(text)

    _priv(rig.panel, "_on_read_memory")()

    assert _console(rig.panel) == "[-] Invalid address"
    assert bridge_workers_for(rig.panel) == []


def test_read_memory_failure_from_the_bridge_is_shown(qapp: QApplication, rig: _Rig) -> None:
    """Reading from an unattached bridge shows the bridge's error and leaves the hex display empty.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
    """
    _priv(rig.panel, "_mem_read_addr").setText("0x401000")

    _priv(rig.panel, "_on_read_memory")()
    _settle(qapp, rig.panel)

    assert _console(rig.panel) == f"[-] Read failed: {_NOT_ATTACHED}"
    assert not _priv(rig.panel, "_mem_hex_display").toPlainText()


def test_read_memory_success_renders_a_sixteen_byte_hex_dump(panel: FridaPanel) -> None:
    """Bytes read at an address are shown as address, hex columns and printable-ASCII columns, sixteen bytes per line.

    Args:
        panel: Panel with no bridge.
    """
    data = b"ABCDEFGHIJKLMNOP" + b"\x00\x7f"
    hex_column_width = 16 * len("XX ")
    first_hex = " ".join(f"{b:02X}" for b in data[:16])
    second_hex = " ".join(f"{b:02X}" for b in data[16:])
    first = "00401000" + "  " + first_hex.ljust(hex_column_width) + "  " + "ABCDEFGHIJKLMNOP"
    second = "00401010" + "  " + second_hex.ljust(hex_column_width) + "  " + ".."

    _priv(panel, "_on_read_memory_success")(0x401000, data)

    assert _priv(panel, "_mem_hex_display").toPlainText() == f"{first}\n{second}"


def test_write_memory_with_an_invalid_address_is_rejected(rig: _Rig) -> None:
    """A non-hex write address prints "Invalid address" and dispatches nothing.

    Args:
        rig: Panel with a real bridge.
    """
    _priv(rig.panel, "_mem_write_addr").setText("zz")
    _priv(rig.panel, "_mem_write_data").setText("90")

    _priv(rig.panel, "_on_write_memory")()

    assert _console(rig.panel) == "[-] Invalid address"
    assert bridge_workers_for(rig.panel) == []


def test_write_memory_without_data_does_nothing(rig: _Rig) -> None:
    """An empty data field returns silently even though the address is valid.

    Args:
        rig: Panel with a real bridge.
    """
    _priv(rig.panel, "_mem_write_addr").setText("0x401000")
    _priv(rig.panel, "_mem_write_data").setText("   ")

    _priv(rig.panel, "_on_write_memory")()

    assert not _console(rig.panel)
    assert bridge_workers_for(rig.panel) == []


@pytest.mark.parametrize("data", ["zz", "909"])
def test_write_memory_with_invalid_hex_is_rejected(rig: _Rig, data: str) -> None:
    """Non-hex or odd-length data prints "Invalid hex data" and dispatches nothing.

    Args:
        rig: Panel with a real bridge.
        data: Text typed into the data field.
    """
    _priv(rig.panel, "_mem_write_addr").setText("0x401000")
    _priv(rig.panel, "_mem_write_data").setText(data)

    _priv(rig.panel, "_on_write_memory")()

    assert _console(rig.panel) == "[-] Invalid hex data"
    assert bridge_workers_for(rig.panel) == []


def test_write_memory_failure_from_the_bridge_is_shown(qapp: QApplication, rig: _Rig) -> None:
    """Writing valid data to an unattached bridge shows the bridge's error and no success line.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
    """
    _priv(rig.panel, "_mem_write_addr").setText("0x401000")
    _priv(rig.panel, "_mem_write_data").setText("90 90")

    _priv(rig.panel, "_on_write_memory")()
    _settle(qapp, rig.panel)

    assert _console(rig.panel) == f"[-] Write failed: {_NOT_ATTACHED}"


@pytest.mark.parametrize(("src", "dst"), [("", "0x2000"), ("0x1000", ""), ("zz", "zz")])
def test_copy_memory_with_an_invalid_address_is_rejected(rig: _Rig, src: str, dst: str) -> None:
    """A blank or non-hex source or destination prints one error line and dispatches nothing.

    Args:
        rig: Panel with a real bridge.
        src: Text typed into the source field.
        dst: Text typed into the destination field.
    """
    _priv(rig.panel, "_mem_copy_src").setText(src)
    _priv(rig.panel, "_mem_copy_dst").setText(dst)

    _priv(rig.panel, "_on_copy_memory")()

    assert _console(rig.panel) == "[-] Invalid source or destination address"
    assert bridge_workers_for(rig.panel) == []


def test_allocate_memory_failure_from_the_bridge_is_shown(qapp: QApplication, rig: _Rig) -> None:
    """Allocating on an unattached bridge shows the bridge's error and leaves the result label empty.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
    """
    _priv(rig.panel, "_on_allocate_memory")()
    _settle(qapp, rig.panel)

    assert _console(rig.panel) == f"[-] Allocate failed: {_NOT_ATTACHED}"
    assert not _priv(rig.panel, "_mem_alloc_result").text()


def test_scan_memory_without_a_pattern_does_nothing(rig: _Rig) -> None:
    """A blank pattern returns silently and leaves Scan enabled.

    Args:
        rig: Panel with a real bridge.
    """
    _priv(rig.panel, "_mem_scan_pattern").setText("   ")

    _priv(rig.panel, "_on_scan_memory")()

    assert not _console(rig.panel)
    assert _priv(rig.panel, "_mem_scan_btn").isEnabled() is True
    assert bridge_workers_for(rig.panel) == []


def test_scan_memory_with_an_invalid_pattern_is_rejected(rig: _Rig) -> None:
    """A non-hex pattern prints "Invalid pattern", leaves Scan enabled and dispatches nothing.

    Args:
        rig: Panel with a real bridge.
    """
    _priv(rig.panel, "_mem_scan_pattern").setText("zz")

    _priv(rig.panel, "_on_scan_memory")()

    assert _console(rig.panel) == "[-] Invalid pattern"
    assert _priv(rig.panel, "_mem_scan_btn").isEnabled() is True
    assert bridge_workers_for(rig.panel) == []


def test_scan_memory_failure_from_the_bridge_is_shown_and_scan_recovers(qapp: QApplication, rig: _Rig) -> None:
    """A wildcard pattern disables Scan while in flight; the bridge's error is then shown and Scan re-enabled.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
    """
    _priv(rig.panel, "_mem_scan_pattern").setText("48 8B ?? 90")
    scan_btn = _priv(rig.panel, "_mem_scan_btn")

    _priv(rig.panel, "_on_scan_memory")()

    assert scan_btn.isEnabled() is False
    _settle(qapp, rig.panel)
    assert _console(rig.panel) == f"[-] Scan failed: {_NOT_ATTACHED}"
    assert scan_btn.isEnabled() is True


def test_populate_scan_table_lists_matches_and_reports_the_count(panel: FridaPanel) -> None:
    """Scan matches fill the table with hex addresses and matched bytes, and Scan is re-enabled.

    Args:
        panel: Panel with no bridge.
    """
    table = _priv(panel, "_mem_scan_table")
    table.setRowCount(4)
    _priv(panel, "_mem_scan_btn").setEnabled(False)
    matches = [
        MemorySearchResult(address=0x401000, matched_bytes="48 8b 05", context_before="", context_after=""),
        MemorySearchResult(address=0x7FF600002000, matched_bytes="90 90 90", context_before="", context_after=""),
    ]

    _priv(panel, "_populate_scan_table")(matches)

    assert _rows(table) == [["0x401000", "48 8b 05"], ["0x7FF600002000", "90 90 90"]]
    assert _console(panel) == "[+] Scan complete: 2 matches"
    assert _priv(panel, "_mem_scan_btn").isEnabled() is True


def test_scan_error_is_shown_and_scan_recovers(panel: FridaPanel) -> None:
    """A failed scan prints the error and re-enables Scan.

    Args:
        panel: Panel with no bridge.
    """
    _priv(panel, "_mem_scan_btn").setEnabled(False)

    _priv(panel, "_on_scan_error")(ToolError("timeout"))

    assert _console(panel) == "[-] Scan failed: timeout"
    assert _priv(panel, "_mem_scan_btn").isEnabled() is True


def test_list_regions_failure_from_the_bridge_is_shown_and_the_button_recovers(qapp: QApplication, rig: _Rig) -> None:
    """Listing regions on an unattached bridge disables the button while in flight, then shows the error and re-enables it.

    Args:
        qapp: Session application.
        rig: Panel with a real bridge.
    """
    regions_btn = _priv(rig.panel, "_mem_regions_btn")

    _priv(rig.panel, "_on_list_regions")()

    assert regions_btn.isEnabled() is False
    _settle(qapp, rig.panel)
    assert _console(rig.panel) == f"[-] List regions failed: {_NOT_ATTACHED}"
    assert regions_btn.isEnabled() is True
