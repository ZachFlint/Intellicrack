# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the bridge wiring, guards, file pickers, run and report display, snapshot, capture and analysis slots of ``SandboxPanel``.

Every test drives a real ``SandboxPanel`` against a real ``SandboxBridge``. Slots that dispatch a bridge call are given a sandbox id the real
manager does not know, so the genuine bridge answers with the genuine ``ToolError`` that the real error handlers then display. Result
handlers are fed dictionaries built the way the bridge builds them: ``SandboxBridge._report_to_dict`` over a real ``ExecutionReport`` for run
results, and the literal result shapes of the bridge methods for everything else. Backend objects are real, unstarted ``WindowsSandbox`` and
``QEMUSandbox`` instances. Expected values come from the schemas in ``intellicrack.sandbox.base`` and ``log_helpers``, never from the panel.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QFileDialog, QInputDialog, QMenu, QTabWidget, QTreeWidget, QTreeWidgetItem
from structlog.testing import capture_logs

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.sandbox.base import (
    ApiCall,
    ClipboardEvent,
    DllLoadEvent,
    ExecutionReport,
    FileChange,
    InjectionEvent,
    IOCEntry,
    KernelObjectActivity,
    NetworkActivity,
    RegistryChange,
    ResourceSample,
    SandboxConfig,
    ServiceChange,
)
from intellicrack.sandbox.qemu import QEMUConfig, QEMUSandbox
from intellicrack.sandbox.windows import WindowsSandbox
from intellicrack.ui.panels.async_bridge import bridge_workers_for, drain_bridge_workers_for
from intellicrack.ui.panels.sandbox_panel import SandboxPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence

    from pytestqt.qtbot import QtBot


_Dynamic = Any

_WAIT_MS: int = 20_000
_MISSING_ID: str = "sbx-missing"
_NOT_FOUND: str = f"Sandbox instance not found: {_MISSING_ID}"

_SECTION_POPULATORS: list[tuple[str, str]] = [
    ("_populate_file_changes", "_file_changes_tree"),
    ("_populate_registry_changes", "_registry_changes_tree"),
    ("_populate_network_activity", "_network_tree"),
    ("_populate_api_calls", "_api_calls_tree"),
    ("_populate_dll_loads", "_dll_loads_tree"),
    ("_populate_service_changes", "_services_tree"),
    ("_populate_kernel_objects", "_kernel_objects_tree"),
    ("_populate_injection_events", "_injections_tree"),
    ("_populate_resource_samples", "_resources_tree"),
    ("_populate_clipboard_events", "_clipboard_tree"),
]

_GUARDED_SLOTS: list[tuple[str, str]] = [
    ("_on_destroy", "destroy_btn"),
    ("_on_restart", "restart_btn"),
    ("_on_take_snapshot", "snapshot_btn"),
    ("_on_restore_snapshot", "restore_btn"),
    ("_on_screenshot", "screenshot_btn"),
    ("_on_pcap_toggle", "pcap_btn"),
    ("_on_memory_dump", "memdump_btn"),
    ("_dispatch_memory_dump", "memdump_btn"),
    ("_start_windows_memory_dump", "memdump_btn"),
    ("_on_extract_files", "extract_files_btn"),
    ("_on_yara_scan", "yara_btn"),
    ("_on_extract_iocs", "iocs_btn"),
    ("_on_timeline", "timeline_btn"),
]


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


def _console(panel: SandboxPanel) -> str:
    """Read the panel's console text.

    Args:
        panel: Panel under test.

    Returns:
        str: Everything the console shows.
    """
    return str(_priv(panel, "_console_output").toPlainText())


def _tree(panel: SandboxPanel, name: str) -> QTreeWidget:
    """Look up one of the panel's result trees.

    Args:
        panel: Panel under test.
        name: Attribute name of the tree.

    Returns:
        QTreeWidget: The tree.
    """
    return cast("QTreeWidget", _priv(panel, name))


def _rows(panel: SandboxPanel, name: str) -> list[list[str]]:
    """Read every top-level row of a result tree as column texts.

    Args:
        panel: Panel under test.
        name: Attribute name of the tree.

    Returns:
        list[list[str]]: One list of column texts per row, in order.
    """
    tree = _tree(panel, name)
    rows: list[list[str]] = []
    for index in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(index)
        assert item is not None
        rows.append([item.text(column) for column in range(item.columnCount())])
    return rows


def _activate(panel: SandboxPanel, *, qemu: bool) -> None:
    """Put the panel into the state it has while a sandbox of the chosen kind is live.

    Args:
        panel: Panel under test.
        qemu: True to select the QEMU backend, False for Windows Sandbox.
    """
    panel.sandbox_type_combo.setCurrentText("QEMU" if qemu else "Windows Sandbox")
    _priv(panel, "_set_sandbox_controls_active")(active=True)


def _attach_bridge(panel: SandboxPanel, instance_id: str | None = _MISSING_ID) -> SandboxBridge:
    """Give the panel a real bridge and the id of the instance it is showing.

    Args:
        panel: Panel under test.
        instance_id: Sandbox id the panel believes it is showing.

    Returns:
        SandboxBridge: The attached bridge.
    """
    bridge = SandboxBridge()
    panel.set_bridge(bridge)
    panel.sandbox_id = instance_id
    return bridge


def _bare_report(*, stdout: str = "", stderr: str = "", exit_code: int = 0, duration: float = 0.5) -> ExecutionReport:
    """Build an execution report with every monitoring section empty.

    Args:
        stdout: Captured standard output.
        stderr: Captured standard error.
        exit_code: Process exit code.
        duration: Run duration in seconds.

    Returns:
        ExecutionReport: The report.
    """
    return ExecutionReport(result="success", exit_code=exit_code, stdout=stdout, stderr=stderr, duration_seconds=duration)


def _bridge_result(report: ExecutionReport) -> dict[str, Any]:
    """Convert a report the way ``SandboxBridge.run_binary`` hands it to a caller.

    Args:
        report: Report to convert.

    Returns:
        dict[str, Any]: The bridge's dictionary form of the report.
    """
    return cast("dict[str, Any]", _priv(SandboxBridge, "_report_to_dict")(report, _MISSING_ID))


def _deliver_report(panel: SandboxPanel, report: ExecutionReport) -> None:
    """Hand a report to the panel's run-success slot in the bridge's dictionary form.

    Args:
        panel: Panel under test.
        report: Report the run produced.
    """
    _set_priv(panel, "_pending_binary", Path("sample.exe"))
    _priv(panel, "_on_run_binary_success")(_bridge_result(report))


def _event_names(logs: Sequence[Mapping[str, object]]) -> list[str]:
    """List the event names of captured log entries.

    Args:
        logs: Entries captured by ``structlog.testing.capture_logs``.

    Returns:
        list[str]: The ``event`` of every entry, in order.
    """
    return [str(entry["event"]) for entry in logs]


def _text_answer(answer: str, *, accepted: bool, seen: list[dict[str, object]]) -> Callable[..., tuple[str, bool]]:
    """Build a stand-in for ``QInputDialog.getText`` that answers without opening a dialog.

    Args:
        answer: Text the "user" types.
        accepted: Whether the "user" confirms the dialog.
        seen: List that receives the keyword arguments of each call.

    Returns:
        Callable[..., tuple[str, bool]]: The stand-in.
    """

    def _stub(*_args: object, **kwargs: object) -> tuple[str, bool]:
        """Record the call and answer it.

        Args:
            *_args: Positional dialog arguments, ignored.
            **kwargs: Keyword dialog arguments, recorded.

        Returns:
            tuple[str, bool]: The scripted answer and acceptance.
        """
        seen.append(dict(kwargs))
        return (answer, accepted)

    return _stub


def _single_file(path: str) -> Callable[..., tuple[str, str]]:
    """Build a stand-in for ``QFileDialog.getOpenFileName``.

    Args:
        path: Path the "user" picks, or an empty string for cancel.

    Returns:
        Callable[..., tuple[str, str]]: The stand-in.
    """

    def _stub(*_args: object, **_kwargs: object) -> tuple[str, str]:
        """Answer the picker.

        Args:
            *_args: Positional dialog arguments, ignored.
            **_kwargs: Keyword dialog arguments, ignored.

        Returns:
            tuple[str, str]: The chosen path and an empty filter.
        """
        return (path, "")

    return _stub


def _many_files(paths: list[str]) -> Callable[..., tuple[list[str], str]]:
    """Build a stand-in for ``QFileDialog.getOpenFileNames``.

    Args:
        paths: Paths the "user" picks, or an empty list for cancel.

    Returns:
        Callable[..., tuple[list[str], str]]: The stand-in.
    """

    def _stub(*_args: object, **_kwargs: object) -> tuple[list[str], str]:
        """Answer the picker.

        Args:
            *_args: Positional dialog arguments, ignored.
            **_kwargs: Keyword dialog arguments, ignored.

        Returns:
            tuple[list[str], str]: The chosen paths and an empty filter.
        """
        return (list(paths), "")

    return _stub


def _one_directory(path: str) -> Callable[..., str]:
    """Build a stand-in for ``QFileDialog.getExistingDirectory``.

    Args:
        path: Directory the "user" picks, or an empty string for cancel.

    Returns:
        Callable[..., str]: The stand-in.
    """

    def _stub(*_args: object, **_kwargs: object) -> str:
        """Answer the picker.

        Args:
            *_args: Positional dialog arguments, ignored.
            **_kwargs: Keyword dialog arguments, ignored.

        Returns:
            str: The chosen directory.
        """
        return path

    return _stub


def _choose_from_companions_menu(panel: SandboxPanel, caption: str | None) -> None:
    """Arrange for the next companions menu to be answered from inside its own event loop.

    ``QMenu.exec`` returns only once the menu closes, so a zero-delay timer picks the entry by key press and always closes the menu
    afterwards, which also ends the call when no entry is chosen.

    Args:
        panel: Panel whose menu will open.
        caption: Caption of the entry to confirm, or None to dismiss the menu without choosing.
    """

    def _run() -> None:
        """Confirm the wanted entry of the newest menu and close it."""
        menus = panel.findChildren(QMenu, options=Qt.FindChildOption.FindDirectChildrenOnly)
        menu = menus[-1]
        try:
            for action in menu.actions():
                if caption is not None and action.text() == caption:
                    menu.setActiveAction(action)
                    _priv(QTest, "keyClick")(menu, Qt.Key.Key_Return)
        finally:
            menu.close()

    QTimer.singleShot(0, _run)


@pytest.fixture
def panel(qapp: QApplication) -> Iterator[SandboxPanel]:
    """Provide a real sandbox panel and join its background workers afterwards.

    Args:
        qapp: Session application required for widget construction.

    Yields:
        SandboxPanel: A freshly built panel.
    """
    widget = SandboxPanel()
    try:
        yield widget
    finally:
        _priv(widget, "_status_poll_timer").stop()
        drain_bridge_workers_for(widget)
        qapp.processEvents()


def test_cleanup_reports_the_destroy_the_bridge_refuses(panel: SandboxPanel, qtbot: QtBot) -> None:
    """Panel cleanup must log the refusal when the bridge cannot destroy the instance.

    With no capture running, ``stop_pcap`` succeeds as a no-op and the destroy of an unknown instance is what fails.

    Args:
        panel: Panel under test.
        qtbot: Event-loop driver.
    """
    _attach_bridge(panel)
    _set_priv(panel, "_pcap_capture_id", "cap-1")

    with capture_logs() as logs:
        _priv(panel, "_cleanup")()
        qtbot.waitUntil(lambda: "sandbox_cleanup_destroy_skipped" in _event_names(logs), timeout=_WAIT_MS)

    skipped = [entry for entry in logs if entry["event"] == "sandbox_cleanup_destroy_skipped"]
    assert len(skipped) == 1
    assert skipped[0]["sandbox_id"] == _MISSING_ID
    assert _NOT_FOUND in str(skipped[0]["error"])
    assert "sandbox_cleanup_pcap_stop_skipped" not in _event_names(logs)
    assert _priv(panel, "_pcap_capture_id") is None


def test_cleanup_still_destroys_after_the_pcap_stop_fails(panel: SandboxPanel, qtbot: QtBot) -> None:
    """A failed PCAP stop during cleanup must be logged and must not prevent the destroy.

    The bridge is told a capture is active for an instance it does not know, so ``stop_pcap`` raises its documented ``ToolError``.

    Args:
        panel: Panel under test.
        qtbot: Event-loop driver.
    """
    bridge = _attach_bridge(panel)
    _priv(bridge, "_active_pcap_captures")[_MISSING_ID] = "cap-1"
    _set_priv(panel, "_pcap_capture_id", "cap-1")

    with capture_logs() as logs:
        _priv(panel, "_cleanup")()
        qtbot.waitUntil(lambda: "sandbox_cleanup_destroy_skipped" in _event_names(logs), timeout=_WAIT_MS)

    names = _event_names(logs)
    assert names.index("sandbox_cleanup_pcap_stop_skipped") < names.index("sandbox_cleanup_destroy_skipped")
    stop_skipped = next(entry for entry in logs if entry["event"] == "sandbox_cleanup_pcap_stop_skipped")
    assert stop_skipped["sandbox_id"] == _MISSING_ID
    assert "Failed to stop active PCAP capture during cleanup" in str(stop_skipped["error"])
    assert _priv(panel, "_pcap_capture_id") is None


@pytest.mark.parametrize("expected_type", ["windows", "qemu"])
def test_set_sandbox_registers_the_backend_behind_a_bridge(panel: SandboxPanel, expected_type: str) -> None:
    """``set_sandbox`` must wrap the backend in a bridge whose manager holds one instance of the right type.

    Args:
        panel: Panel under test.
        expected_type: Sandbox type the registration must record.
    """
    sandbox = QEMUSandbox(SandboxConfig(), QEMUConfig()) if expected_type == "qemu" else WindowsSandbox(SandboxConfig())
    panel.set_sandbox(sandbox)

    bridge = panel.get_bridge()
    assert isinstance(bridge, SandboxBridge)
    assert bridge.manager is not None
    instances = bridge.manager.instances
    assert len(instances) == 1
    assert instances[0].sandbox is sandbox
    assert instances[0].sandbox_type == expected_type
    assert panel.sandbox_id == instances[0].id
    assert panel.get_sandbox() is sandbox


def test_get_sandbox_finds_the_instance_the_panel_shows_among_several(panel: SandboxPanel) -> None:
    """``get_sandbox`` must return the backend registered under the panel's id, skipping other instances.

    Args:
        panel: Panel under test.
    """
    bridge = SandboxBridge()
    first = WindowsSandbox(SandboxConfig())
    second = QEMUSandbox(SandboxConfig(), QEMUConfig())
    _ = bridge.register_existing_sandbox(first, "windows")
    second_id = bridge.register_existing_sandbox(second, "qemu")
    panel.set_bridge(bridge)
    panel.sandbox_id = second_id

    assert panel.get_sandbox() is second


def test_get_sandbox_falls_back_to_the_stored_sandbox(panel: SandboxPanel) -> None:
    """Without a matching bridge instance ``get_sandbox`` must return the sandbox given to ``set_sandbox``.

    Args:
        panel: Panel under test.
    """
    stored = WindowsSandbox(SandboxConfig())
    _set_priv(panel, "_sandbox", stored)
    assert panel.get_sandbox() is stored

    bridge = SandboxBridge()
    panel.set_bridge(bridge)
    assert panel.get_sandbox() is stored

    panel.sandbox_id = _MISSING_ID
    assert bridge.manager is None
    assert panel.get_sandbox() is stored

    other = QEMUSandbox(SandboxConfig(), QEMUConfig())
    _ = bridge.register_existing_sandbox(other, "qemu")
    assert bridge.manager is not None
    assert panel.get_sandbox() is stored


def test_vm_display_toggle_without_a_vnc_widget_changes_nothing(panel: SandboxPanel) -> None:
    """With no VNC widget the display toggle must return before touching the tab.

    Args:
        panel: Panel under test.
    """
    vnc = _priv(panel, "_vnc_widget")
    tabs = cast("QTabWidget", _priv(panel, "_output_tabs"))
    index = tabs.indexOf(vnc)
    _priv(panel, "_set_vm_display_enabled")(enabled=False)
    assert not tabs.isTabEnabled(index)

    _set_priv(panel, "_vnc_widget", None)
    try:
        _priv(panel, "_set_vm_display_enabled")(enabled=True)
    finally:
        _set_priv(panel, "_vnc_widget", vnc)

    assert not tabs.isTabEnabled(index)
    assert not vnc.isEnabled()


def test_vm_display_toggle_of_an_undocked_widget_leaves_other_tabs_alone(panel: SandboxPanel) -> None:
    """An undocked VNC widget must be disabled without disabling whichever tab took over its slot.

    Args:
        panel: Panel under test.
    """
    vnc = _priv(panel, "_vnc_widget")
    tabs = cast("QTabWidget", _priv(panel, "_output_tabs"))
    tabs.removeTab(tabs.indexOf(vnc))
    before = [tabs.isTabEnabled(index) for index in range(tabs.count())]
    assert all(before)

    _priv(panel, "_set_vm_display_enabled")(enabled=False)

    assert [tabs.isTabEnabled(index) for index in range(tabs.count())] == before
    assert not vnc.isEnabled()


def test_bridge_create_success_without_a_dictionary_uses_the_placeholder_id(panel: SandboxPanel) -> None:
    """A creation result that is not a dictionary must still activate the panel under the id ``active``.

    Args:
        panel: Panel under test.
    """
    created: list[str] = []
    _ = panel.sandbox_created.connect(created.append)

    _priv(panel, "_on_bridge_create_success")(None)

    assert panel.sandbox_id == "active"
    assert created == ["active"]
    assert _priv(panel, "_diff_instance_a_input").text() == "active"
    assert _priv(panel, "_status_indicator").text() == "Active"
    assert not panel.create_btn.isEnabled()
    assert panel.destroy_btn.isEnabled()


@pytest.mark.parametrize(("slot", "button"), _GUARDED_SLOTS)
@pytest.mark.parametrize("has_bridge", [False, True], ids=["no-bridge", "no-sandbox-id"])
def test_slots_refuse_to_act_without_a_bridge_and_a_sandbox_id(panel: SandboxPanel, slot: str, button: str, *, has_bridge: bool) -> None:
    """Every toolbar slot must return untouched when the bridge or the sandbox id is missing.

    Each slot's first action once it passes its guard is to disable its own control or start a worker, so an untouched control and no
    dispatched worker show that the guard returned.

    Args:
        panel: Panel under test.
        slot: Name of the slot to call.
        button: Attribute name of the control the slot would disable.
        has_bridge: True to attach a bridge but leave the sandbox id unset, False to set an id but attach no bridge.
    """
    _activate(panel, qemu=True)
    if has_bridge:
        _ = _attach_bridge(panel, None)
    else:
        panel.sandbox_id = _MISSING_ID

    _priv(panel, slot)()

    assert getattr(panel, button).isEnabled()
    assert bridge_workers_for(panel) == []
    assert not _console(panel)


def test_restart_success_without_a_dictionary_keeps_the_current_id(panel: SandboxPanel) -> None:
    """A restart result that is not a dictionary must keep the panel's id and reseed the diff selector with it.

    Args:
        panel: Panel under test.
    """
    _activate(panel, qemu=False)
    _priv(panel, "_on_restart_success")(None)
    assert panel.sandbox_id is None
    assert not _priv(panel, "_diff_instance_a_input").text()
    assert "[+] Sandbox restarted" in _console(panel)

    panel.sandbox_id = "sbx-keep"
    _priv(panel, "_on_restart_success")("not a dictionary")

    assert panel.sandbox_id == "sbx-keep"
    assert _priv(panel, "_diff_instance_a_input").text() == "sbx-keep"


def test_browse_binary_fills_the_path_field_with_the_chosen_file(
    panel: SandboxPanel,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Choosing a file in the binary picker must put its path in the field.

    Args:
        panel: Panel under test.
        tmp_path: Directory holding the chosen file.
        monkeypatch: Replaces the Qt file picker.
    """
    chosen = tmp_path / "target.exe"
    chosen.write_bytes(b"MZ")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _single_file(str(chosen)))

    _priv(panel, "_on_browse_binary")()

    assert _priv(panel, "_binary_path_input").text() == str(chosen)


def test_browse_binary_cancel_keeps_the_existing_path(panel: SandboxPanel, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cancelling the binary picker must leave the field as it was.

    Args:
        panel: Panel under test.
        monkeypatch: Replaces the Qt file picker.
    """
    _priv(panel, "_binary_path_input").setText("keep-me.exe")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _single_file(""))

    _priv(panel, "_on_browse_binary")()

    assert _priv(panel, "_binary_path_input").text() == "keep-me.exe"


def test_append_companions_keeps_existing_entries_and_skips_duplicates(panel: SandboxPanel) -> None:
    """New companions must be appended after the current ones, joined by ``;``, without repeats or blanks.

    Args:
        panel: Panel under test.
    """
    field = _priv(panel, "_companions_input")
    field.setText(" a.dll ; ;b.dll")

    _priv(panel, "_append_companions")(["b.dll", "c dir\\d.dll", "c dir\\d.dll"])

    assert field.text() == "a.dll;b.dll;c dir\\d.dll"


def test_companions_menu_files_entry_appends_the_chosen_files(panel: SandboxPanel, monkeypatch: pytest.MonkeyPatch) -> None:
    """Choosing "Files..." in the companions menu must append every file the picker returns.

    Args:
        panel: Panel under test.
        monkeypatch: Replaces the Qt file picker.
    """
    _priv(panel, "_companions_input").setText("pre.dll")
    monkeypatch.setattr(QFileDialog, "getOpenFileNames", _many_files(["x\\one.dll", "x\\two.cfg"]))
    _choose_from_companions_menu(panel, "Files...")

    _priv(panel, "_on_browse_companions")()

    assert _priv(panel, "_companions_input").text() == "pre.dll;x\\one.dll;x\\two.cfg"


def test_companions_menu_files_entry_with_no_selection_changes_nothing(panel: SandboxPanel, monkeypatch: pytest.MonkeyPatch) -> None:
    """Choosing "Files..." and picking nothing must leave the companions field alone.

    Args:
        panel: Panel under test.
        monkeypatch: Replaces the Qt file picker.
    """
    _priv(panel, "_companions_input").setText("pre.dll")
    monkeypatch.setattr(QFileDialog, "getOpenFileNames", _many_files([]))
    _choose_from_companions_menu(panel, "Files...")

    _priv(panel, "_on_browse_companions")()

    assert _priv(panel, "_companions_input").text() == "pre.dll"


def test_companions_menu_folder_entry_appends_the_chosen_folder(
    panel: SandboxPanel,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Choosing "Folder..." in the companions menu must append the folder as one entry.

    Args:
        panel: Panel under test.
        tmp_path: Directory used as the chosen folder.
        monkeypatch: Replaces the Qt directory picker.
    """
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", _one_directory(str(tmp_path)))
    _choose_from_companions_menu(panel, "Folder...")

    _priv(panel, "_on_browse_companions")()

    assert _priv(panel, "_companions_input").text() == str(tmp_path)


def test_companions_menu_folder_entry_with_no_selection_changes_nothing(panel: SandboxPanel, monkeypatch: pytest.MonkeyPatch) -> None:
    """Choosing "Folder..." and picking nothing must leave the companions field alone.

    Args:
        panel: Panel under test.
        monkeypatch: Replaces the Qt directory picker.
    """
    _priv(panel, "_companions_input").setText("pre.dll")
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", _one_directory(""))
    _choose_from_companions_menu(panel, "Folder...")

    _priv(panel, "_on_browse_companions")()

    assert _priv(panel, "_companions_input").text() == "pre.dll"


def test_companions_menu_dismissed_without_a_choice_changes_nothing(
    panel: SandboxPanel,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dismissing the companions menu must open no picker and leave the field alone.

    Args:
        panel: Panel under test.
        tmp_path: Directory the pickers would return if they were wrongly opened.
        monkeypatch: Replaces the Qt pickers.
    """
    _priv(panel, "_companions_input").setText("pre.dll")
    monkeypatch.setattr(QFileDialog, "getOpenFileNames", _many_files([str(tmp_path / "files.dll")]))
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", _one_directory(str(tmp_path)))
    _choose_from_companions_menu(panel, None)

    _priv(panel, "_on_browse_companions")()

    assert _priv(panel, "_companions_input").text() == "pre.dll"


def test_run_binary_without_a_bridge_says_so(panel: SandboxPanel) -> None:
    """Running with no bridge attached must only report that none is active.

    Args:
        panel: Panel under test.
    """
    _priv(panel, "_binary_path_input").setText("anything.exe")

    _priv(panel, "_on_run_binary")()

    assert _console(panel) == "[!] No sandbox bridge active"
    assert bridge_workers_for(panel) == []


def test_run_binary_without_a_path_refuses(panel: SandboxPanel) -> None:
    """Running with a blank path field must report the missing path and dispatch nothing.

    Args:
        panel: Panel under test.
    """
    _ = _attach_bridge(panel)
    _priv(panel, "_binary_path_input").setText("   ")

    _priv(panel, "_on_run_binary")()

    assert _console(panel) == "[!] No binary path specified"
    assert bridge_workers_for(panel) == []


def test_run_binary_with_a_missing_binary_names_it(panel: SandboxPanel, tmp_path: Path) -> None:
    """Running a path that does not exist must name it and dispatch nothing.

    Args:
        panel: Panel under test.
        tmp_path: Directory in which the binary is absent.
    """
    _ = _attach_bridge(panel)
    gone = tmp_path / "absent.exe"
    _priv(panel, "_binary_path_input").setText(str(gone))

    _priv(panel, "_on_run_binary")()

    assert _console(panel) == f"[!] Binary not found: {gone}"
    assert bridge_workers_for(panel) == []


def test_run_binary_with_missing_companions_names_each_one(panel: SandboxPanel, tmp_path: Path) -> None:
    """Running with companions that do not exist must list every missing one and dispatch nothing.

    Args:
        panel: Panel under test.
        tmp_path: Directory holding the binary and one companion.
    """
    _activate(panel, qemu=False)
    _ = _attach_bridge(panel)
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    present = tmp_path / "present.dll"
    present.write_bytes(b"MZ")
    gone_one = tmp_path / "gone_one.dll"
    gone_two = tmp_path / "gone two.dll"
    _priv(panel, "_binary_path_input").setText(str(binary))
    _priv(panel, "_companions_input").setText(f"{present}; {gone_one} ;{gone_two}")

    _priv(panel, "_on_run_binary")()

    assert _console(panel) == f"[!] Companion not found: {gone_one}, {gone_two}"
    assert _priv(panel, "_run_btn").isEnabled()
    assert bridge_workers_for(panel) == []


def test_run_binary_dispatches_against_the_shown_instance_and_reports_the_refusal(
    panel: SandboxPanel,
    qtbot: QtBot,
    tmp_path: Path,
) -> None:
    """A valid run must clear the report tabs, lock the button, address the panel's own instance and show the bridge's refusal.

    The real manager raises its documented "instance not found" error for the unknown id, which proves the id reached the bridge.

    Args:
        panel: Panel under test.
        qtbot: Event-loop driver.
        tmp_path: Directory holding the binary and a companion.
    """
    _activate(panel, qemu=False)
    _ = _attach_bridge(panel)
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    companion = tmp_path / "helper.dll"
    companion.write_bytes(b"MZ")
    _priv(panel, "_binary_path_input").setText(str(binary))
    _priv(panel, "_args_input").setText("  --flag value ")
    _priv(panel, "_companions_input").setText(str(companion))
    _tree(panel, "_file_changes_tree").addTopLevelItem(QTreeWidgetItem(["created", "stale", ""]))

    _priv(panel, "_on_run_binary")()

    assert "[*] Executing: sample.exe --flag value" in _console(panel)
    assert _rows(panel, "_file_changes_tree") == []
    assert not _priv(panel, "_run_btn").isEnabled()
    assert _priv(panel, "_pending_binary") == binary
    qtbot.waitUntil(lambda: "[-] Execution failed" in _console(panel), timeout=_WAIT_MS)
    assert _NOT_FOUND in _console(panel)
    qtbot.waitUntil(_priv(panel, "_run_btn").isEnabled, timeout=_WAIT_MS)


def test_run_success_shows_streams_exit_code_and_the_report_sections(panel: SandboxPanel) -> None:
    """A run result must announce completion, print both streams and the exit line, and fill the file, registry and network tabs.

    Args:
        panel: Panel under test.
    """
    _activate(panel, qemu=False)
    _priv(panel, "_run_btn").setEnabled(False)
    completed: list[str] = []
    _ = panel.execution_completed.connect(completed.append)
    report = _bare_report(stdout="hello out", stderr="oops", exit_code=3, duration=1.5)
    report.file_changes = [FileChange(path="C:\\drop\\a.bin", operation="created", old_path=None, timestamp="t0", size=10)]
    report.registry_changes = [
        RegistryChange(
            key="HKCU\\Software\\X",
            value_name="Run",
            operation="modified",
            value_type="REG_SZ",
            value_data="c:\\a.exe",
            timestamp="t1",
        ),
    ]
    report.network_activity = [
        NetworkActivity(
            protocol="tcp",
            direction="outbound",
            local_address="10.0.0.2",
            local_port=50000,
            remote_address="203.0.113.7",
            remote_port=8443,
            timestamp="t2",
            bytes_sent=512,
            bytes_received=2048,
        ),
    ]

    _deliver_report(panel, report)

    console = _console(panel)
    assert "[+] Execution completed" in console
    assert "[stdout] hello out" in console
    assert "[stderr] oops" in console
    assert "[*] Exit code: 3, Duration: 1.5s" in console
    assert completed == ["sample.exe"]
    assert _priv(panel, "_run_btn").isEnabled()
    assert _rows(panel, "_file_changes_tree") == [["created", "C:\\drop\\a.bin", "10 bytes"]]
    assert _rows(panel, "_registry_changes_tree") == [["modified", "HKCU\\Software\\X", "c:\\a.exe"]]
    assert _rows(panel, "_network_tree") == [["tcp", "203.0.113.7", "8443", "512/2048 bytes"]]


@pytest.mark.parametrize(
    ("stdout", "stderr"),
    [("only out", ""), ("", "only err")],
    ids=["stdout-only", "stderr-only"],
)
def test_run_success_prints_only_the_streams_that_have_content(panel: SandboxPanel, stdout: str, stderr: str) -> None:
    """An empty stream must not produce a console line.

    Args:
        panel: Panel under test.
        stdout: Captured standard output.
        stderr: Captured standard error.
    """
    _deliver_report(panel, _bare_report(stdout=stdout, stderr=stderr))

    console = _console(panel)
    assert ("[stdout] only out" in console) is bool(stdout)
    assert ("[stderr] only err" in console) is bool(stderr)
    assert (("[stdout]" in console) + ("[stderr]" in console)) == 1


def test_run_success_without_a_dictionary_only_announces_completion(panel: SandboxPanel) -> None:
    """A run result that is not a dictionary must announce completion and show no report.

    Args:
        panel: Panel under test.
    """
    _activate(panel, qemu=False)
    _priv(panel, "_run_btn").setEnabled(False)
    completed: list[str] = []
    _ = panel.execution_completed.connect(completed.append)
    _set_priv(panel, "_pending_binary", Path("sample.exe"))

    _priv(panel, "_on_run_binary_success")(None)

    assert "[+] Execution completed" in _console(panel)
    assert "Exit code" not in _console(panel)
    assert completed == ["sample.exe"]
    assert _priv(panel, "_run_btn").isEnabled()


@pytest.mark.parametrize(("method", "tree_name"), _SECTION_POPULATORS)
def test_section_populators_ignore_a_report_section_that_is_not_a_list(panel: SandboxPanel, method: str, tree_name: str) -> None:
    """A report section that is not a list must add no rows and raise nothing.

    Args:
        panel: Panel under test.
        method: Name of the populator to call.
        tree_name: Attribute name of the tree it fills.
    """
    populate = _priv(panel, method)

    for bogus in (None, "not-a-list", {"a": 1}, 7):
        populate(bogus)

    assert _rows(panel, tree_name) == []


@pytest.mark.parametrize(("method", "tree_name"), _SECTION_POPULATORS)
def test_section_populators_skip_entries_that_are_not_dictionaries(panel: SandboxPanel, method: str, tree_name: str) -> None:
    """Only dictionary entries of a report section may become rows.

    Args:
        panel: Panel under test.
        method: Name of the populator to call.
        tree_name: Attribute name of the tree it fills.
    """
    _priv(panel, method)([None, "junk", 3, {}, ["x"]])

    assert len(_rows(panel, tree_name)) == 1


def test_run_success_api_calls_show_the_process_api_and_arguments(panel: SandboxPanel) -> None:
    """The API Calls tab must show the process name, API name and arguments of the real ``ApiCall`` record.

    Args:
        panel: Panel under test.
    """
    report = _bare_report()
    report.api_calls = [
        ApiCall(
            timestamp="2026-10-04T10:00:00Z",
            process_name="evil.exe",
            pid=4242,
            api_name="CreateRemoteThread",
            module="kernel32.dll",
            arguments=["0x10", "0x0"],
            return_value="0x1c4",
        ),
    ]

    _deliver_report(panel, report)

    (row,) = _rows(panel, "_api_calls_tree")
    assert row[0] == "2026-10-04T10:00:00Z"
    assert row[1] == "evil.exe"
    assert row[2] == "CreateRemoteThread"
    assert row[3] == "kernel32.dll"
    assert "0x10" in row[4]
    assert row[5] == "0x1c4"


def test_run_success_dll_loads_show_the_process_and_base_address(panel: SandboxPanel) -> None:
    """The DLL Loads tab must show the process name and base address of the real ``DllLoadEvent`` record.

    Args:
        panel: Panel under test.
    """
    report = _bare_report()
    report.dll_loads = [
        DllLoadEvent(
            timestamp="t0",
            pid=77,
            process_name="loader.exe",
            dll_path="C:\\Windows\\System32\\ws2_32.dll",
            base_address="0x7ff800000000",
            size=4096,
            event_id=5,
            payload_schema="",
        ),
    ]

    _deliver_report(panel, report)

    (row,) = _rows(panel, "_dll_loads_tree")
    assert row[1] == "loader.exe"
    assert row[2] == "C:\\Windows\\System32\\ws2_32.dll"
    assert row[3] == "0x7ff800000000"
    assert row[4] == "4096"


def test_run_success_services_show_the_name_and_time(panel: SandboxPanel) -> None:
    """The Services tab must show the service name and timestamp of the real ``ServiceChange`` record.

    Args:
        panel: Panel under test.
    """
    report = _bare_report()
    report.service_changes = [
        ServiceChange(
            service_name="EvilSvc",
            display_name="Evil Service",
            binary_path="C:\\evil\\svc.exe",
            start_type="auto",
            operation="created",
            timestamp="2026-10-04T10:01:00Z",
        ),
    ]

    _deliver_report(panel, report)

    (row,) = _rows(panel, "_services_tree")
    assert row[0] == "created"
    assert row[1] == "EvilSvc"
    assert row[2] == "C:\\evil\\svc.exe"
    assert row[3] == "auto"
    assert row[4] == "2026-10-04T10:01:00Z"


def test_run_success_kernel_objects_show_the_type_and_process(panel: SandboxPanel) -> None:
    """The Kernel Objects tab must show the object type and process name of the real ``KernelObjectActivity`` record.

    Args:
        panel: Panel under test.
    """
    report = _bare_report()
    report.kernel_objects = [
        KernelObjectActivity(
            object_type="Mutant",
            name="Global\\evil_mutex",
            pid=4242,
            process_name="evil.exe",
            operation="create",
            timestamp="t0",
        ),
    ]

    _deliver_report(panel, report)

    (row,) = _rows(panel, "_kernel_objects_tree")
    assert row[0] == "Mutant"
    assert row[1] == "Global\\evil_mutex"
    assert row[2] == "evil.exe"
    assert row[3] == "create"
    assert row[4] == "t0"


def test_run_success_injections_show_type_source_target_and_apis(panel: SandboxPanel) -> None:
    """The Injections tab must show the type, source, target and APIs of the real ``InjectionEvent`` record.

    Args:
        panel: Panel under test.
    """
    report = _bare_report()
    report.injection_events = [
        InjectionEvent(
            timestamp="t0",
            source_pid=10,
            source_name="dropper.exe",
            target_pid=20,
            target_name="explorer.exe",
            injection_type="remote_thread",
            api_calls=["WriteProcessMemory", "CreateRemoteThread"],
        ),
    ]

    _deliver_report(panel, report)

    (row,) = _rows(panel, "_injections_tree")
    assert row[0] == "remote_thread"
    assert row[1] == "dropper.exe"
    assert row[2] == "explorer.exe"
    assert "WriteProcessMemory" in row[3]
    assert row[4] == "t0"


def test_run_success_resources_show_memory_disk_and_network_counters(panel: SandboxPanel) -> None:
    """The Resources tab must show the memory, disk and network counters of the real ``ResourceSample`` record.

    Args:
        panel: Panel under test.
    """
    report = _bare_report()
    report.resource_samples = [
        ResourceSample(
            timestamp="t0",
            cpu_percent=12.5,
            memory_mb=256.0,
            disk_read_bytes=1024,
            disk_write_bytes=2048,
            net_sent_bytes=300,
            net_recv_bytes=400,
        ),
    ]

    _deliver_report(panel, report)

    (row,) = _rows(panel, "_resources_tree")
    assert row[0] == "t0"
    assert row[1] == "12.5"
    assert row[2] == "256.0"
    assert row[3] == "1024"
    assert row[4] == "2048"
    assert row[5] == "300"
    assert row[6] == "400"


def test_run_success_clipboard_shows_the_preview_and_size(panel: SandboxPanel) -> None:
    """The Clipboard tab must show the content preview and size of the real ``ClipboardEvent`` record.

    Args:
        panel: Panel under test.
    """
    report = _bare_report()
    report.clipboard_events = [
        ClipboardEvent(
            timestamp="t0",
            operation="set",
            format="text",
            content_preview="secret text",
            size_bytes=11,
            pid=5,
            process_name="evil.exe",
        ),
    ]

    _deliver_report(panel, report)

    (row,) = _rows(panel, "_clipboard_tree")
    assert row[0] == "t0"
    assert row[1] == "set"
    assert row[2] == "text"
    assert row[3] == "secret text"
    assert row[4] == "11"


def test_take_snapshot_cancelled_dispatches_nothing(panel: SandboxPanel, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cancelling the label prompt must leave the Snapshot control enabled and start no worker.

    Args:
        panel: Panel under test.
        monkeypatch: Replaces the Qt input dialog.
    """
    _activate(panel, qemu=True)
    _ = _attach_bridge(panel)
    seen: list[dict[str, object]] = []
    monkeypatch.setattr(QInputDialog, "getText", _text_answer("ignored", accepted=False, seen=seen))

    _priv(panel, "_on_take_snapshot")()

    assert len(seen) == 1
    assert panel.snapshot_btn.isEnabled()
    assert _priv(panel, "_pending_snapshot_label") is None
    assert bridge_workers_for(panel) == []


@pytest.mark.parametrize(
    ("answer", "expected_label"),
    [("  baseline  ", "baseline"), ("   ", None)],
    ids=["typed-label", "blank-uses-default"],
)
def test_take_snapshot_dispatches_the_label_and_reports_the_refusal(
    panel: SandboxPanel,
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
    answer: str,
    expected_label: str | None,
) -> None:
    """Confirming the prompt must remember the trimmed label, lock the control and show the bridge's refusal.

    A blank answer falls back to the timestamped default the prompt was pre-filled with, which follows the format ``snapshot_%Y%m%dT%H%M%SZ``.

    Args:
        panel: Panel under test.
        qtbot: Event-loop driver.
        monkeypatch: Replaces the Qt input dialog.
        answer: Text the "user" types.
        expected_label: Label expected to be remembered, or None when the default is expected.
    """
    _activate(panel, qemu=True)
    _ = _attach_bridge(panel)
    seen: list[dict[str, object]] = []
    monkeypatch.setattr(QInputDialog, "getText", _text_answer(answer, accepted=True, seen=seen))

    _priv(panel, "_on_take_snapshot")()

    default_label = str(seen[0]["text"])
    assert re.fullmatch(r"snapshot_\d{8}T\d{6}Z", default_label)
    remembered = _priv(panel, "_pending_snapshot_label")
    assert remembered == (default_label if expected_label is None else expected_label)
    assert not panel.snapshot_btn.isEnabled()
    qtbot.waitUntil(lambda: "[-] Snapshot failed" in _console(panel), timeout=_WAIT_MS)
    assert _NOT_FOUND in _console(panel)
    qtbot.waitUntil(panel.snapshot_btn.isEnabled, timeout=_WAIT_MS)
    assert _priv(panel, "_pending_snapshot_label") is None


@pytest.mark.parametrize(
    ("result", "pending", "expected_id", "expected_label", "expected_created"),
    [
        pytest.param(
            {"snapshot_id": "snap-1", "name": "baseline", "instance_id": _MISSING_ID},
            "baseline",
            "snap-1",
            "baseline",
            None,
            id="bridge-shape",
        ),
        pytest.param(
            {"snapshot_id": "s2", "created_at": "2026-10-04T00:00:00+00:00", "label": "bridge-label"},
            "mine",
            "s2",
            "bridge-label",
            "2026-10-04T00:00:00+00:00",
            id="bridge-label-wins",
        ),
        pytest.param({"snapshot_id": "s3", "label": ""}, "mine", "s3", "mine", None, id="empty-bridge-label"),
        pytest.param({"snapshot_id": "s6"}, None, "s6", "snapshot", None, id="no-label-at-all"),
        pytest.param("snap-7", "mine", "snap-7", "mine", None, id="plain-id"),
        pytest.param(None, "mine", "unknown", "mine", None, id="no-result"),
    ],
)
def test_take_snapshot_success_adds_a_row_and_restores_the_control(
    panel: SandboxPanel,
    result: object,
    pending: str | None,
    expected_id: str,
    expected_label: str,
    expected_created: str | None,
) -> None:
    """A snapshot result must become one Snapshots row with the bridge's id, a label and a creation time.

    Args:
        panel: Panel under test.
        result: Value the bridge returned.
        pending: Label the panel remembered when the snapshot was requested.
        expected_id: Snapshot id the row must show.
        expected_label: Label the row must show.
        expected_created: Creation time the row must show, or None when the panel must stamp the current time.
    """
    _activate(panel, qemu=True)
    panel.snapshot_btn.setEnabled(False)
    _set_priv(panel, "_pending_snapshot_label", pending)

    _priv(panel, "_on_take_snapshot_success")(result)

    ((row_id, row_label, row_created),) = _rows(panel, "_snapshots_tree")
    assert row_id == expected_id
    assert row_label == expected_label
    if expected_created is None:
        assert datetime.fromisoformat(row_created).tzinfo is not None
    else:
        assert row_created == expected_created
    assert f"[+] Snapshot taken: {expected_id}" in _console(panel)
    assert panel.snapshot_btn.isEnabled()
    assert _priv(panel, "_pending_snapshot_label") is None


def test_restore_snapshot_without_a_selection_says_so(panel: SandboxPanel) -> None:
    """Restoring with no snapshot selected must report it and dispatch nothing.

    Args:
        panel: Panel under test.
    """
    _activate(panel, qemu=True)
    _ = _attach_bridge(panel)

    _priv(panel, "_on_restore_snapshot")()

    assert _console(panel) == "[!] No snapshot selected"
    assert panel.restore_btn.isEnabled()
    assert bridge_workers_for(panel) == []


def test_restore_snapshot_dispatches_the_selected_id_and_reports_the_refusal(panel: SandboxPanel, qtbot: QtBot) -> None:
    """Restoring the selected snapshot must remember its id, lock the control and show the bridge's refusal.

    Args:
        panel: Panel under test.
        qtbot: Event-loop driver.
    """
    _activate(panel, qemu=True)
    _ = _attach_bridge(panel)
    tree = _tree(panel, "_snapshots_tree")
    first = QTreeWidgetItem(["snap-a", "A", "t0"])
    second = QTreeWidgetItem(["snap-b", "B", "t1"])
    tree.addTopLevelItem(first)
    tree.addTopLevelItem(second)
    tree.setCurrentItem(second)

    _priv(panel, "_on_restore_snapshot")()

    assert _priv(panel, "_pending_snapshot_id") == "snap-b"
    assert not panel.restore_btn.isEnabled()
    qtbot.waitUntil(lambda: "[-] Restore failed" in _console(panel), timeout=_WAIT_MS)
    assert _NOT_FOUND in _console(panel)
    qtbot.waitUntil(panel.restore_btn.isEnabled, timeout=_WAIT_MS)


def test_restore_snapshot_success_reports_the_id_and_clears_the_report_tabs(panel: SandboxPanel) -> None:
    """A completed restore must name the snapshot, empty the report tabs and re-enable the control.

    Args:
        panel: Panel under test.
    """
    _activate(panel, qemu=True)
    panel.restore_btn.setEnabled(False)
    _set_priv(panel, "_pending_snapshot_id", "snap-a")
    _tree(panel, "_file_changes_tree").addTopLevelItem(QTreeWidgetItem(["created", "stale", ""]))

    _priv(panel, "_on_restore_snapshot_success")({"success": True, "instance_id": _MISSING_ID, "snapshot_id": "snap-a"})

    assert "[+] Restored snapshot: snap-a" in _console(panel)
    assert _rows(panel, "_file_changes_tree") == []
    assert panel.restore_btn.isEnabled()


@pytest.mark.parametrize(
    ("result", "expected_path"),
    [
        pytest.param({"instance_id": _MISSING_ID, "screenshot_path": "C:\\shots\\vm.png"}, "C:\\shots\\vm.png", id="dictionary"),
        pytest.param(None, "", id="no-dictionary"),
    ],
)
def test_screenshot_success_reports_the_saved_path(panel: SandboxPanel, result: object, expected_path: str) -> None:
    """A screenshot result must report the saved path and re-enable the control.

    Args:
        panel: Panel under test.
        result: Value the bridge returned.
        expected_path: Path the console line must carry.
    """
    _activate(panel, qemu=True)
    panel.screenshot_btn.setEnabled(False)

    _priv(panel, "_on_screenshot_success")(result)

    assert f"[+] Screenshot saved: {expected_path}" in _console(panel)
    assert panel.screenshot_btn.isEnabled()


def test_pcap_toggle_starts_a_capture_and_reports_the_refusal(panel: SandboxPanel, qtbot: QtBot) -> None:
    """With no capture running the toggle must start one: lock the control, then show the bridge's refusal and re-enable.

    Args:
        panel: Panel under test.
        qtbot: Event-loop driver.
    """
    _activate(panel, qemu=True)
    _ = _attach_bridge(panel)

    _priv(panel, "_on_pcap_toggle")()

    assert not panel.pcap_btn.isEnabled()
    qtbot.waitUntil(lambda: "[-] PCAP start failed" in _console(panel), timeout=_WAIT_MS)
    assert _NOT_FOUND in _console(panel)
    qtbot.waitUntil(panel.pcap_btn.isEnabled, timeout=_WAIT_MS)
    assert _priv(panel, "_pcap_capture_id") is None
    assert panel.pcap_btn.text() == "PCAP Start"


def test_pcap_toggle_stops_a_running_capture_and_resets_after_the_refusal(panel: SandboxPanel, qtbot: QtBot) -> None:
    """With a capture running the toggle must stop it; when the bridge refuses, the panel must still return to "PCAP Start".

    Args:
        panel: Panel under test.
        qtbot: Event-loop driver.
    """
    _activate(panel, qemu=True)
    _ = _attach_bridge(panel)
    _set_priv(panel, "_pcap_capture_id", "cap-9")
    panel.pcap_btn.setText("PCAP Stop")

    _priv(panel, "_on_pcap_toggle")()

    assert not panel.pcap_btn.isEnabled()
    qtbot.waitUntil(lambda: "[-] PCAP stop failed" in _console(panel), timeout=_WAIT_MS)
    assert _NOT_FOUND in _console(panel)
    qtbot.waitUntil(panel.pcap_btn.isEnabled, timeout=_WAIT_MS)
    assert _priv(panel, "_pcap_capture_id") is None
    assert panel.pcap_btn.text() == "PCAP Start"


@pytest.mark.parametrize(
    ("result", "expected_id"),
    [
        pytest.param({"instance_id": _MISSING_ID, "capture_id": "cap-3"}, "cap-3", id="dictionary"),
        pytest.param(None, "active", id="no-dictionary"),
    ],
)
def test_pcap_start_success_remembers_the_capture_and_flips_the_label(panel: SandboxPanel, result: object, expected_id: str) -> None:
    """A started capture must be remembered, announced and offered for stopping.

    Args:
        panel: Panel under test.
        result: Value the bridge returned.
        expected_id: Capture id the panel must remember.
    """
    _activate(panel, qemu=True)
    panel.pcap_btn.setEnabled(False)

    _priv(panel, "_on_pcap_start_success")(result)

    assert _priv(panel, "_pcap_capture_id") == expected_id
    assert f"[+] PCAP capture started: {expected_id}" in _console(panel)
    assert panel.pcap_btn.text() == "PCAP Stop"
    assert panel.pcap_btn.isEnabled()


@pytest.mark.parametrize(
    ("result", "expected_path"),
    [
        pytest.param(
            {"instance_id": _MISSING_ID, "capture_id": "cap-3", "pcap_path": "C:\\caps\\cap-3.pcap"},
            "C:\\caps\\cap-3.pcap",
            id="dictionary",
        ),
        pytest.param(None, "", id="no-dictionary"),
    ],
)
def test_pcap_stop_success_forgets_the_capture_and_flips_the_label_back(panel: SandboxPanel, result: object, expected_path: str) -> None:
    """A stopped capture must be announced with its file, forgotten and offered for starting again.

    Args:
        panel: Panel under test.
        result: Value the bridge returned.
        expected_path: Path the console line must carry.
    """
    _activate(panel, qemu=True)
    _set_priv(panel, "_pcap_capture_id", "cap-3")
    panel.pcap_btn.setText("PCAP Stop")
    panel.pcap_btn.setEnabled(False)

    _priv(panel, "_on_pcap_stop_success")(result)

    assert f"[+] PCAP capture stopped, saved: {expected_path}" in _console(panel)
    assert _priv(panel, "_pcap_capture_id") is None
    assert panel.pcap_btn.text() == "PCAP Start"
    assert panel.pcap_btn.isEnabled()


@pytest.mark.parametrize(
    ("result", "expected_path"),
    [
        pytest.param(
            {"instance_id": _MISSING_ID, "dump_path": "C:\\dumps\\vm.raw", "target_pid": None},
            "C:\\dumps\\vm.raw",
            id="dictionary",
        ),
        pytest.param(None, "", id="no-dictionary"),
    ],
)
def test_memory_dump_success_reports_the_dump_file(panel: SandboxPanel, result: object, expected_path: str) -> None:
    """A memory dump result must report the dump file and re-enable the control.

    Args:
        panel: Panel under test.
        result: Value the bridge returned.
        expected_path: Path the console line must carry.
    """
    _activate(panel, qemu=False)
    panel.memdump_btn.setEnabled(False)

    _priv(panel, "_on_memory_dump_success")(result)

    assert f"[+] Memory dump saved: {expected_path}" in _console(panel)
    assert panel.memdump_btn.isEnabled()


@pytest.mark.parametrize(
    ("result", "expected_path"),
    [
        pytest.param({"instance_id": _MISSING_ID, "zip_path": "C:\\drop\\files.zip"}, "C:\\drop\\files.zip", id="dictionary"),
        pytest.param(None, "", id="no-dictionary"),
    ],
)
def test_extract_files_success_reports_the_archive(panel: SandboxPanel, result: object, expected_path: str) -> None:
    """A dropped-files result must report the archive and re-enable the control.

    Args:
        panel: Panel under test.
        result: Value the bridge returned.
        expected_path: Path the console line must carry.
    """
    _activate(panel, qemu=True)
    panel.extract_files_btn.setEnabled(False)

    _priv(panel, "_on_extract_files_success")(result)

    assert f"[+] Dropped files extracted: {expected_path}" in _console(panel)
    assert panel.extract_files_btn.isEnabled()


@pytest.mark.parametrize(
    ("slot", "button", "failure_line"),
    [
        pytest.param("_on_extract_files", "extract_files_btn", "[-] File extraction failed", id="extract-files"),
        pytest.param("_on_yara_scan", "yara_btn", "[-] YARA scan failed", id="yara"),
        pytest.param("_on_extract_iocs", "iocs_btn", "[-] IOC extraction failed", id="iocs"),
        pytest.param("_on_timeline", "timeline_btn", "[-] Timeline generation failed", id="timeline"),
    ],
)
def test_analysis_slots_dispatch_and_report_the_bridge_refusal(
    panel: SandboxPanel,
    qtbot: QtBot,
    slot: str,
    button: str,
    failure_line: str,
) -> None:
    """Each capture and analysis slot must lock its control, dispatch, and show the bridge's refusal before re-enabling it.

    Args:
        panel: Panel under test.
        qtbot: Event-loop driver.
        slot: Name of the slot to call.
        button: Attribute name of its control.
        failure_line: Console prefix its error handler writes.
    """
    _activate(panel, qemu=True)
    _ = _attach_bridge(panel)

    _priv(panel, slot)()

    control = getattr(panel, button)
    assert not control.isEnabled()
    qtbot.waitUntil(lambda: failure_line in _console(panel), timeout=_WAIT_MS)
    assert _NOT_FOUND in _console(panel)
    qtbot.waitUntil(control.isEnabled, timeout=_WAIT_MS)


def _yara_match(rule: str, source: str) -> dict[str, object]:
    """Build a YARA match in the shape ``log_helpers.format_yara_match`` returns.

    Args:
        rule: Rule name.
        source: Scanned file path.

    Returns:
        dict[str, object]: The match dictionary.
    """
    return {"rule": rule, "namespace": "default", "tags": [], "strings": [], "source": source, "scan_type": "files"}


def test_yara_success_logs_each_dictionary_match_and_counts_every_entry(panel: SandboxPanel) -> None:
    """A YARA result must log one line per dictionary match and count every entry in the summary.

    Args:
        panel: Panel under test.
    """
    _activate(panel, qemu=False)
    panel.yara_btn.setEnabled(False)
    matches: list[object] = [_yara_match("RuleA", "C:\\a.bin"), "junk", _yara_match("RuleB", "C:\\b.bin")]

    _priv(panel, "_on_yara_scan_success")({"instance_id": _MISSING_ID, "matches": matches, "match_count": 3})

    lines = _console(panel).splitlines()
    yara_lines = [line for line in lines if line.startswith("[YARA]")]
    assert [line.split(":")[0] for line in yara_lines] == ["[YARA] RuleA", "[YARA] RuleB"]
    assert "[+] YARA scan complete: 3 matches" in lines
    assert panel.yara_btn.isEnabled()


@pytest.mark.parametrize(
    "result",
    [None, {"matches": "not-a-list"}, {"instance_id": _MISSING_ID}],
    ids=["no-dictionary", "matches-not-a-list", "no-matches-key"],
)
def test_yara_success_without_a_match_list_reports_zero(panel: SandboxPanel, result: object) -> None:
    """A YARA result without a list of matches must report zero matches.

    Args:
        panel: Panel under test.
        result: Value the bridge returned.
    """
    _priv(panel, "_on_yara_scan_success")(result)

    assert "[+] YARA scan complete: 0 matches" in _console(panel)
    assert "[YARA]" not in _console(panel)


def test_yara_success_logs_the_scanned_file_of_each_match(panel: SandboxPanel) -> None:
    """The YARA console line must name the file a match came from, which the bridge reports under ``source``.

    Args:
        panel: Panel under test.
    """
    _priv(panel, "_on_yara_scan_success")({
        "instance_id": _MISSING_ID,
        "matches": [_yara_match("PackedBinary", "C:\\drop\\a.bin")],
        "match_count": 1,
    })

    (line,) = [line for line in _console(panel).splitlines() if line.startswith("[YARA]")]
    assert "C:\\drop\\a.bin" in line


def test_iocs_success_replaces_the_rows_with_the_dictionary_entries(panel: SandboxPanel) -> None:
    """An IOC result must replace the tab's rows with one row per dictionary entry and report their count.

    Args:
        panel: Panel under test.
    """
    _activate(panel, qemu=False)
    panel.iocs_btn.setEnabled(False)
    _tree(panel, "_iocs_tree").addTopLevelItem(QTreeWidgetItem(["stale", "stale", "stale", "stale"]))
    iocs: list[object] = [
        IOCEntry(ioc_type="ipv4", value="203.0.113.7", source="network", context="outbound tcp", timestamp="t0"),
        "junk",
        IOCEntry(ioc_type="domain", value="evil.example", source="registry", context="Run key", timestamp="t1"),
    ]

    _priv(panel, "_on_extract_iocs_success")({"instance_id": _MISSING_ID, "iocs": iocs, "count": 2})

    assert _rows(panel, "_iocs_tree") == [
        ["ipv4", "203.0.113.7", "network", "outbound tcp"],
        ["domain", "evil.example", "registry", "Run key"],
    ]
    assert "[+] IOC extraction complete: 2 indicators" in _console(panel)
    assert panel.iocs_btn.isEnabled()


@pytest.mark.parametrize(
    "result",
    [None, {"iocs": "not-a-list"}, {"instance_id": _MISSING_ID}],
    ids=["no-dictionary", "iocs-not-a-list", "no-iocs-key"],
)
def test_iocs_success_without_a_list_clears_the_tab_and_reports_zero(panel: SandboxPanel, result: object) -> None:
    """An IOC result without a list of entries must still clear the tab and report zero indicators.

    Args:
        panel: Panel under test.
        result: Value the bridge returned.
    """
    _tree(panel, "_iocs_tree").addTopLevelItem(QTreeWidgetItem(["stale", "stale", "stale", "stale"]))

    _priv(panel, "_on_extract_iocs_success")(result)

    assert _rows(panel, "_iocs_tree") == []
    assert "[+] IOC extraction complete: 0 indicators" in _console(panel)
