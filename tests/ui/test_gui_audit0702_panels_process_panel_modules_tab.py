# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""GUI-audit regression gates for :mod:`intellicrack.ui.panels.process_panel.modules_tab`.

Finding H37: the module tree's ``Path`` column had no header resize
configuration and no per-item tooltip, so full on-disk module paths were
clipped to the default interactive width with no way to widen or hover to
read them. The fix stretches the ``Path`` column, resizes the other columns
to their content, and sets a per-item tooltip carrying the full path.

Finding M57: the COM server table's ``Loaded Path`` column (the last
column) was left at the ``QHeaderView`` default ``Interactive`` mode with no
tooltip, unlike ``DLL Path`` which stretched. The fix stretches both path
columns and gives every path cell a full-value tooltip.

Finding M58: the DLL-injection log's ``Details`` column received raw
exception text on injection failure with no resize mode or tooltip. The fix
stretches the ``Details`` column and reuses the ``DLL Path``/``Details``
cells' tooltip so long error text stays readable on hover.

Each test drives the real :class:`ModulesTab` widget and its production
callback closures with real result data (a real ``ModuleInfo`` dataclass, a
real dict payload, and a real exception instance). Only the async dispatch
shim (``run_bridge_coroutine_logged``) is replaced with a synchronous
capture stub, mirroring the project's established gate pattern (see
``test_gui_audit_debugger_stack_viewer.py``), so the tests stay deterministic
and thread-free while exercising the actual production UI-population code.
"""

from __future__ import annotations

from pathlib import Path as FsPath
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QHeaderView, QMessageBox

from intellicrack.bridges.process import ProcessBridge
from intellicrack.core.types import ModuleInfo
from intellicrack.ui.panels.process_panel import modules_tab
from intellicrack.ui.panels.process_panel.modules_tab import ModulesTab


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from PyQt6.QtWidgets import QApplication


_LONG_MODULE_PATH: FsPath = FsPath(
    "C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\VeryLongSubdirectoryNameUsedForTestingPurposes\\MSOFFICE.DLL",
)
_LONG_COM_DLL_PATH: str = (
    "C:\\Windows\\WinSxS\\amd64_microsoft.windows.something_31bf3856ad364e35_10.0.19041.1_none_abcdefabcdefabcd\\comdlg32.dll"
)
_LONG_COM_LOADED_PATH: str = "C:\\Windows\\System32\\comdlg32.dll (redirected from WinSxS manifest)"
_LONG_ERROR_MESSAGE: str = (
    "Access is denied: could not open target process handle with PROCESS_VM_WRITE|PROCESS_VM_OPERATION for injection (WinError 5)"
)
_LONG_INJECT_PATH: str = "C:\\Program Files\\Common Files\\Very\\Long\\Nested\\Directory\\Structure\\injected.dll"


@pytest.fixture
def tab(qapp: QApplication) -> Generator[ModulesTab]:
    """Build a real :class:`ModulesTab` bound to a live, unattached bridge.

    Args:
        qapp: Session ``QApplication`` fixture ensuring Qt is initialised.

    Yields:
        Generator[ModulesTab]: A ``ModulesTab`` wired to a real
        :class:`ProcessBridge` instance and a fake attached PID.
    """
    del qapp
    widget = ModulesTab()
    widget.set_bridge(ProcessBridge())
    widget.set_attached_pid(4242)
    yield widget
    widget.deleteLater()


def _install_fake_dispatch(monkeypatch: pytest.MonkeyPatch) -> dict[str, Callable[[object], None] | None]:
    """Replace the async bridge dispatcher with a synchronous capture stub.

    The real coroutine produced by the live bridge method is closed
    unawaited, and the real ``on_success``/``on_error`` closures defined
    inside the production method under test are captured so the test can
    invoke them directly with real result data.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        dict[str, Callable[[object], None] | None]: Mutable box populated
        with the captured ``on_success`` and ``on_error`` callables once the
        production method dispatches through the stub.
    """
    captured: dict[str, Callable[[object], None] | None] = {"on_success": None, "on_error": None}

    def _fake(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: object = None,
        *,
        event: str,
        logger: object,
        level: str = "debug",
        **context: object,
    ) -> None:
        del parent, event, logger, level, context
        coro.close()
        captured["on_success"] = on_success
        captured["on_error"] = on_error

    monkeypatch.setattr(modules_tab, "run_bridge_coroutine_logged", _fake)
    return captured


def _auto_confirm_message_box(monkeypatch: pytest.MonkeyPatch) -> list[tuple[object, ...]]:
    """Replace ``QMessageBox.warning`` with a recorder that always confirms.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        list[tuple[object, ...]]: Recorded positional arguments of each call.
    """
    calls: list[tuple[object, ...]] = []

    def _fake_warning(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        calls.append(args)
        return QMessageBox.StandardButton.Yes

    monkeypatch.setattr(QMessageBox, "warning", staticmethod(_fake_warning))
    return calls


class TestH37ModulePathColumn:
    """H37: the module tree's Path column stretches and paths get tooltips."""

    def test_h37_header_resize_modes(self, tab: ModulesTab) -> None:
        """The Path column stretches; every other column resizes to content.

        Pre-fix there was no ``header().setSectionResizeMode`` call at all,
        so every column (including index 3, ``Path``) sat at the
        ``QHeaderView`` default ``Interactive`` mode.

        Args:
            tab: The ``ModulesTab`` under test.
        """
        header = tab._mod_tree.header()
        assert header is not None
        assert header.sectionResizeMode(3) == QHeaderView.ResizeMode.Stretch, (
            "Path column (index 3) must stretch to fill the available width"
        )
        for idx in (0, 1, 2, 4):
            assert header.sectionResizeMode(idx) == QHeaderView.ResizeMode.ResizeToContents, (
                f"column {idx} must resize to its content width, not stay Interactive"
            )

    def test_h37_refresh_modules_populates_path_text_and_tooltip(
        self,
        tab: ModulesTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Refreshing modules writes the full path and a matching tooltip.

        Pre-fix ``_refresh_modules`` built the ``QTreeWidgetItem`` with no
        ``setToolTip`` call, so a real long on-disk DLL path had no hover
        recovery once the interactive-width column clipped it.

        Args:
            tab: The ``ModulesTab`` under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        captured = _install_fake_dispatch(monkeypatch)
        tab._refresh_modules()
        on_success = captured["on_success"]
        assert on_success is not None, "refresh must dispatch get_modules through the async worker"

        module = ModuleInfo(
            name="MSOFFICE.DLL",
            path=_LONG_MODULE_PATH,
            base_address=0x7FFE0000,
            size=1048576,
            entry_point=0x7FFE1000,
        )
        on_success([module])

        assert tab._mod_tree.topLevelItemCount() == 1
        item = tab._mod_tree.topLevelItem(0)
        assert item is not None
        expected_path = str(_LONG_MODULE_PATH)
        assert item.text(3) == expected_path, "Path column must show the full on-disk path"
        assert item.toolTip(3) == expected_path, (
            "Path column must carry a full-path tooltip so a clipped Stretch column stays readable on hover"
        )
        assert tab._mod_count.text() == "1 modules"


class TestM57ComTableLoadedPath:
    """M57: the COM table's DLL Path and Loaded Path columns stretch and get tooltips."""

    def test_m57_header_resize_modes(self, tab: ModulesTab) -> None:
        """Both path columns stretch; CLSID resizes to content.

        Pre-fix only column 1 (``DLL Path``) was set to ``Stretch``; column
        2 (``Loaded Path``, the last column) was left at the ``Interactive``
        default because ``QTableWidget.stretchLastSection`` defaults to
        ``False``.

        Args:
            tab: The ``ModulesTab`` under test.
        """
        header = tab._com_table.horizontalHeader()
        assert header is not None
        assert header.sectionResizeMode(0) == QHeaderView.ResizeMode.ResizeToContents
        assert header.sectionResizeMode(1) == QHeaderView.ResizeMode.Stretch, "DLL Path column must stretch"
        assert header.sectionResizeMode(2) == QHeaderView.ResizeMode.Stretch, (
            "Loaded Path column (the last column) must stretch instead of staying Interactive"
        )

    def test_m57_refresh_com_populates_tooltips_on_long_paths(
        self,
        tab: ModulesTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Inspecting COM servers writes full-value tooltips on both path cells.

        Pre-fix ``_refresh_com`` populated ``DLL Path`` and ``Loaded Path``
        with plain ``QTableWidgetItem`` instances carrying no tooltip.

        Args:
            tab: The ``ModulesTab`` under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        captured = _install_fake_dispatch(monkeypatch)
        tab._refresh_com()
        on_success = captured["on_success"]
        assert on_success is not None, "Inspect COM must dispatch enumerate_com_servers through the async worker"

        server = {
            "clsid": "{00000000-0000-0000-C000-000000000046}",
            "dll_path": _LONG_COM_DLL_PATH,
            "loaded_path": _LONG_COM_LOADED_PATH,
        }
        on_success([server])

        assert tab._com_table.rowCount() == 1
        dll_item = tab._com_table.item(0, 1)
        loaded_item = tab._com_table.item(0, 2)
        assert dll_item is not None
        assert loaded_item is not None
        assert dll_item.text() == _LONG_COM_DLL_PATH
        assert dll_item.toolTip() == _LONG_COM_DLL_PATH, "DLL Path cell must carry a full-value tooltip"
        assert loaded_item.text() == _LONG_COM_LOADED_PATH
        assert loaded_item.toolTip() == _LONG_COM_LOADED_PATH, (
            "Loaded Path cell must carry a full-value tooltip so the clipped Interactive-width column stays readable on hover"
        )


class TestM58InjectLogDetails:
    """M58: the DLL-injection log's Details column stretches and gets tooltips."""

    def test_m58_header_resize_modes(self, tab: ModulesTab) -> None:
        """The Details column stretches; Status resizes to content.

        Pre-fix only column 0 (``DLL Path``) was set to ``Stretch``; column
        2 (``Details``) was left at the ``Interactive`` default.

        Args:
            tab: The ``ModulesTab`` under test.
        """
        header = tab._inject_log.horizontalHeader()
        assert header is not None
        assert header.sectionResizeMode(0) == QHeaderView.ResizeMode.Stretch
        assert header.sectionResizeMode(1) == QHeaderView.ResizeMode.ResizeToContents
        assert header.sectionResizeMode(2) == QHeaderView.ResizeMode.Stretch, (
            "Details column must stretch instead of staying at the Interactive default"
        )

    def test_m58_injection_failure_sets_details_tooltip(
        self,
        tab: ModulesTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failed injection writes the raw exception text with a matching tooltip.

        Pre-fix the failure handler wrote ``QTableWidgetItem(str(exc))``
        directly into the ``Details`` column with no ``setToolTip`` call, so
        a long raw exception message had no hover recovery once clipped.

        Args:
            tab: The ``ModulesTab`` under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _auto_confirm_message_box(monkeypatch)
        captured = _install_fake_dispatch(monkeypatch)
        tab._inject_path.setText("C:\\payloads\\probe.dll")
        tab._on_inject()

        on_error = captured["on_error"]
        assert on_error is not None, "Inject must dispatch inject_dll through the async worker"

        on_error(RuntimeError(_LONG_ERROR_MESSAGE))

        assert tab._inject_log.rowCount() == 1
        details_item = tab._inject_log.item(0, 2)
        assert details_item is not None
        assert details_item.text() == _LONG_ERROR_MESSAGE
        assert details_item.toolTip() == _LONG_ERROR_MESSAGE, (
            "Details cell must carry a full-value tooltip so a long raw exception message stays readable on hover"
        )

    def test_m58_injection_success_also_tooltips_the_dll_path_cell(
        self,
        tab: ModulesTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A successful injection also tooltips the DLL Path cell via the shared helper.

        Both the success and failure handlers were changed to route their
        ``DLL Path`` cell through the same ``_tooltip_item`` helper that
        fixes the ``Details`` column, so the shared mechanism is exercised
        on the success path too.

        Args:
            tab: The ``ModulesTab`` under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _auto_confirm_message_box(monkeypatch)
        captured = _install_fake_dispatch(monkeypatch)
        tab._inject_path.setText(_LONG_INJECT_PATH)
        tab._on_inject()

        on_success = captured["on_success"]
        assert on_success is not None, "Inject must dispatch inject_dll through the async worker"

        injection_succeeded = True
        on_success(injection_succeeded)

        assert tab._inject_log.rowCount() == 1
        path_item = tab._inject_log.item(0, 0)
        assert path_item is not None
        assert path_item.text() == _LONG_INJECT_PATH
        assert path_item.toolTip() == _LONG_INJECT_PATH, "DLL Path cell must carry a full-value tooltip on the success row too"
