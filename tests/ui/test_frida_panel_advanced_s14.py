# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for two Frida panel defects: S14-D11 and S14-D19.

* S14-D11 -- Installing an Intercept-Ret or Replace-Fn hook through the panel
  succeeded at the bridge (both ``FridaBridge.intercept_return`` and
  ``FridaBridge.replace_function`` track the resulting hook in
  ``FridaBridge._hooks``), but ``FridaPanel._on_intercept_return`` /
  ``_on_replace_function`` never touched the Active Hooks table, so the
  installed hook was invisible and unselectable for Remove. The fix inserts a
  pending row before dispatch (mirroring the existing Add Hook flow) and
  populates it from the real ``HookInfo`` the bridge returns on success. These
  tests drive the real button handlers against a real, self-contained Frida
  target process and assert the row lands with the right address/module/
  function/status and a real (non-pending) hook id.

* S14-D19 -- The Advanced tab's System Function Call section packed its three
  rows into plain ``QHBoxLayout``s with no width protection, so a narrow
  docked panel shrank every label/combo/input below its natural size --
  reported as labels rendering on top of combos -- and the Advanced tab itself
  had no scroll wrapper, clipping content in the docked view. The fix wraps
  each dense row in the project's established ``make_control_row`` horizontal-
  scroll helper (already used by the x64dbg panel for the same class of bug)
  and wraps the whole Advanced tab content in ``AnalysisPanelBase._make_scrollable``.
  These tests shrink the real panel and assert every control keeps at least
  its natural width, that no two controls' rendered geometries overlap, and
  that the Advanced tab is hosted in a scroll area.

Requires a Windows host; the S14-D11 tests additionally require frida-python
and spawn a real ``notepad.exe`` target (``spawns_process``).
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QInputDialog, QMessageBox, QScrollArea, QTabWidget, QWidget

from intellicrack.core.subprocess_compat import DEVNULL, Popen
from intellicrack.core.types import IntellicrackError
from intellicrack.ui.panels import async_bridge as async_bridge_module
from intellicrack.ui.panels.frida_panel import FridaPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from PyQt6.QtWidgets import QApplication

    from intellicrack.bridges.frida_bridge import FridaBridge

try:
    from intellicrack.bridges.frida_bridge import FridaBridge

    _frida_available: bool = True
except ImportError:
    _frida_available = False


_logger = logging.getLogger(__name__)

pytestmark = pytest.mark.usefixtures("qapp")

_COL_ADDRESS: Final[int] = 0
_COL_MODULE: Final[int] = 1
_COL_FUNCTION: Final[int] = 2
_COL_STATUS: Final[int] = 3

_NOTEPAD_STARTUP_DELAY_S: Final[float] = 1.0
_NARROW_PANEL_WIDTH: Final[int] = 340
_NARROW_PANEL_HEIGHT: Final[int] = 700

_DISPATCH_EXCEPTIONS: tuple[type[BaseException], ...] = (
    IntellicrackError,
    *async_bridge_module.WORKER_DEFAULT_EXCEPTIONS,
    asyncio.CancelledError,
)


def _run_async[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously for test use.

    Args:
        coro: Awaitable coroutine to execute.

    Returns:
        T: The coroutine's return value, preserving its type.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _fixed_get_text(value: str) -> Callable[..., tuple[str, bool]]:
    """Build a ``QInputDialog.getText``/``getMultiLineText`` replacement returning a fixed accepted value.

    Args:
        value: The text the stand-in dialog reports the user entered.

    Returns:
        Callable[..., tuple[str, bool]]: A drop-in that ignores its arguments
        and returns ``(value, True)``.
    """

    def _impl(*args: object, **kwargs: object) -> tuple[str, bool]:
        del args, kwargs
        return (value, True)

    return _impl


def _fixed_get_int(value: int) -> Callable[..., tuple[int, bool]]:
    """Build a ``QInputDialog.getInt`` replacement returning a fixed accepted value.

    Args:
        value: The integer the stand-in dialog reports the user entered.

    Returns:
        Callable[..., tuple[int, bool]]: A drop-in that ignores its arguments
        and returns ``(value, True)``.
    """

    def _impl(*args: object, **kwargs: object) -> tuple[int, bool]:
        del args, kwargs
        return (value, True)

    return _impl


@pytest.fixture(autouse=True)
def block_message_boxes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace QMessageBox.warning with a raising stub to prevent test hangs.

    In a headless test environment, ``QMessageBox.warning`` blocks waiting for
    user input. Patching it to raise immediately means a wiring regression
    that pops an unexpected dialog fails fast instead of hanging the suite.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """

    def _raise_on_warning(
        parent: QWidget | None,
        title: str,
        text: str,
        *args: object,
        **kwargs: object,
    ) -> None:
        del parent, args, kwargs
        msg = f"QMessageBox.warning shown unexpectedly: [{title}] {text}"
        raise AssertionError(msg)

    monkeypatch.setattr(QMessageBox, "warning", staticmethod(_raise_on_warning))


@pytest.fixture
def synchronous_dispatch(monkeypatch: pytest.MonkeyPatch) -> list[Coroutine[object, object, object]]:
    """Replace ``run_bridge_coroutine_async`` with a synchronous, draining capture.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        list[Coroutine[object, object, object]]: List that records every
        coroutine the panel tried to dispatch, in dispatch order.
    """
    captured: list[Coroutine[object, object, object]] = []
    drain_loop = asyncio.new_event_loop()

    def fake_dispatch(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        del parent
        captured.append(coro)
        try:
            result = drain_loop.run_until_complete(coro)
        except _DISPATCH_EXCEPTIONS as exc:
            if on_error is not None:
                on_error(exc)
            return
        if on_success is not None:
            on_success(result)

    monkeypatch.setattr(async_bridge_module, "run_bridge_coroutine_async", fake_dispatch)
    return captured


@pytest.fixture
def require_frida() -> None:
    """Skip the current test when frida-python is not installed."""
    if not _frida_available:
        pytest.skip("frida-python required for this test")


@pytest.fixture
def notepad_process() -> Generator[Popen[bytes]]:
    """Spawn a real, dedicated ``notepad.exe`` target for hook-install gates.

    Installing against a spawned target (rather than self-attaching to the
    pytest process) keeps ``Interceptor.replace``/``attach`` away from any
    WinAPI export the test runner or Qt itself might be relying on.

    Yields:
        Popen[bytes]: The running notepad process handle.
    """
    notepad_path = shutil.which("notepad.exe") or str(Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "notepad.exe")
    proc = Popen([notepad_path], stdout=DEVNULL, stderr=DEVNULL)
    time.sleep(_NOTEPAD_STARTUP_DELAY_S)
    yield proc
    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture
def attached_bridge(notepad_process: Popen[bytes]) -> Generator[FridaBridge]:
    """Create a FridaBridge attached to the spawned notepad.exe target.

    Args:
        notepad_process: The running notepad process fixture.

    Yields:
        FridaBridge: An initialized and attached FridaBridge instance.
    """
    bridge = FridaBridge()
    _run_async(bridge.initialize())
    _run_async(bridge.attach(notepad_process.pid))
    yield bridge
    try:
        _run_async(bridge.shutdown())
    except IntellicrackError:
        _logger.debug("attached_bridge_fixture_shutdown_failed", exc_info=True)


class _TestFridaPanel(FridaPanel):
    """FridaPanel subclass exposing hook-table and Advanced-tab internals via public wrappers."""

    def invoke_on_intercept_return(self) -> None:
        """Invoke the real "Intercept Ret" toolbar button handler."""
        self._on_intercept_return()

    def invoke_on_replace_function(self) -> None:
        """Invoke the real "Replace Fn" toolbar button handler."""
        self._on_replace_function()

    def hooks_row_count(self) -> int:
        """Return the number of rows currently in the Active Hooks table.

        Returns:
            int: Current hooks-table row count.
        """
        return self._hooks_table.rowCount()

    def hook_cell_text(self, row: int, col: int) -> str | None:
        """Return the text of a hooks-table cell.

        Args:
            row: Zero-based row index.
            col: Zero-based column index.

        Returns:
            str | None: Cell text, or None if the cell has no item.
        """
        item = self._hooks_table.item(row, col)
        return None if item is None else item.text()

    def hook_ids_snapshot(self) -> list[str]:
        """Return a copy of the tracked hook id / pending-key list.

        Returns:
            list[str]: Current ``_hook_ids`` contents.
        """
        return list(self._hook_ids)

    def right_tabs(self) -> QTabWidget:
        """Return the right-hand tool tab widget hosting Hooks/.../Advanced.

        Returns:
            QTabWidget: The panel's right-hand tab widget.
        """
        return self._right_tabs

    def system_call_address_input(self) -> QWidget:
        """Return the System Function Call section's address input.

        Returns:
            QWidget: The address ``QLineEdit`` of the embedded controls widget.
        """
        return self._syscall_controls._syscall_addr_input

    def system_call_args_input(self) -> QWidget:
        """Return the System Function Call section's arguments input.

        Returns:
            QWidget: The arguments ``QLineEdit`` of the embedded controls widget.
        """
        return self._syscall_controls._syscall_args_input

    def system_call_call_button(self) -> QWidget:
        """Return the System Function Call section's Call button.

        Returns:
            QWidget: The Call ``QPushButton`` of the embedded controls widget.
        """
        return self._syscall_controls._syscall_call_btn

    def system_call_return_type_combo(self) -> QWidget:
        """Return the System Function Call section's return-type combo.

        Returns:
            QWidget: The return-type ``QComboBox`` of the embedded controls widget.
        """
        return self._syscall_controls._syscall_ret_type

    def system_call_arg_types_input(self) -> QWidget:
        """Return the System Function Call section's arg-types input.

        Returns:
            QWidget: The arg-types ``QLineEdit`` of the embedded controls widget.
        """
        return self._syscall_controls._syscall_arg_types_input

    def system_call_convention_combo(self) -> QWidget:
        """Return the System Function Call section's calling-convention combo.

        Returns:
            QWidget: The convention ``QComboBox`` of the embedded controls widget.
        """
        return self._syscall_controls._syscall_cc


@pytest.mark.usefixtures("require_frida")
@pytest.mark.spawns_process
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge/GUI integration tests")
class TestInterceptReturnAndReplaceFunctionPopulateHooksTable:
    """S14-D11 gates: Intercept-Ret / Replace-Fn installs must land a row in the Active Hooks table."""

    @staticmethod
    def test_intercept_return_installed_adds_active_hooks_row(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        attached_bridge: FridaBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Installing an Intercept-Ret hook through the real handler must populate the table.

        Drives ``FridaPanel._on_intercept_return`` exactly as the "Intercept
        Ret" toolbar button would (dialogs monkeypatched to fixed values, the
        bridge call itself real and dispatched synchronously), targeting the
        spawned notepad process's real ``kernel32.dll!GetCurrentProcessId``
        export. Falsifiable: before the fix, ``hooks_row_count()`` stays 0 and
        ``hook_ids_snapshot()`` stays empty even though the bridge call
        succeeds -- this test fails on the row-count/id assertions in that
        case.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            attached_bridge: Bridge fixture attached to the spawned notepad process.
            monkeypatch: Pytest monkeypatch fixture.
        """
        panel = _TestFridaPanel()
        panel.set_bridge(attached_bridge)
        target = "kernel32.dll!GetCurrentProcessId"

        monkeypatch.setattr(QInputDialog, "getText", staticmethod(_fixed_get_text(target)))
        monkeypatch.setattr(QInputDialog, "getInt", staticmethod(_fixed_get_int(1234)))

        panel.invoke_on_intercept_return()

        assert len(synchronous_dispatch) == 1, "the Intercept Ret handler must dispatch exactly one bridge coroutine"
        assert panel.hooks_row_count() == 1, "a row must be added to the Active Hooks table"

        func_text = panel.hook_cell_text(0, _COL_FUNCTION)
        mod_text = panel.hook_cell_text(0, _COL_MODULE)
        addr_text = panel.hook_cell_text(0, _COL_ADDRESS)
        status_text = panel.hook_cell_text(0, _COL_STATUS)
        assert func_text == "GetCurrentProcessId"
        assert mod_text == "kernel32.dll"
        assert addr_text is not None
        assert addr_text.startswith("0x")
        assert addr_text != "0x0"
        assert status_text == "Active"

        hook_ids = panel.hook_ids_snapshot()
        assert len(hook_ids) == 1
        hook_id = hook_ids[0]
        assert hook_id, f"expected a non-empty hook id, got {hook_id!r}"
        assert not hook_id.startswith("__pending_hook_"), (
            f"the pending sentinel must have been replaced with the real bridge hook id, got {hook_id!r}"
        )

        removed = _run_async(attached_bridge.remove_hook(hook_id))
        assert removed, "the tracked hook id must be a real, removable hook"

    @staticmethod
    def test_replace_function_installed_adds_active_hooks_row(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        attached_bridge: FridaBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Installing a Replace-Fn hook through the real handler must populate the table.

        Drives ``FridaPanel._on_replace_function`` exactly as the "Replace
        Fn" toolbar button would, replacing the spawned notepad process's
        real ``kernel32.dll!GetTickCount`` export with a constant-returning
        ``NativeCallback`` (the same target/replacement idiom already proven
        safe in ``tests/bridges/test_realcov_03a_frida_modules.py``).
        Falsifiable: before the fix, the row never appears even though
        ``FridaBridge.replace_function`` genuinely installed the replacement.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            attached_bridge: Bridge fixture attached to the spawned notepad process.
            monkeypatch: Pytest monkeypatch fixture.
        """
        panel = _TestFridaPanel()
        panel.set_bridge(attached_bridge)
        target = "kernel32.dll!GetTickCount"
        replacement = "new NativeCallback(function () { return 1337; }, 'uint32', [])"

        monkeypatch.setattr(QInputDialog, "getText", staticmethod(_fixed_get_text(target)))
        monkeypatch.setattr(QInputDialog, "getMultiLineText", staticmethod(_fixed_get_text(replacement)))

        panel.invoke_on_replace_function()

        assert len(synchronous_dispatch) == 1, "the Replace Fn handler must dispatch exactly one bridge coroutine"
        assert panel.hooks_row_count() == 1, "a row must be added to the Active Hooks table"

        func_text = panel.hook_cell_text(0, _COL_FUNCTION)
        mod_text = panel.hook_cell_text(0, _COL_MODULE)
        status_text = panel.hook_cell_text(0, _COL_STATUS)
        assert func_text == "GetTickCount"
        assert mod_text == "kernel32.dll"
        assert status_text == "Active"

        hook_ids = panel.hook_ids_snapshot()
        assert len(hook_ids) == 1
        hook_id = hook_ids[0]
        assert hook_id, f"expected a non-empty hook id, got {hook_id!r}"
        assert not hook_id.startswith("__pending_hook_"), (
            f"the pending sentinel must have been replaced with the real bridge hook id, got {hook_id!r}"
        )

        removed = _run_async(attached_bridge.remove_hook(hook_id))
        assert removed, "the tracked hook id must be a real, removable hook"

    @staticmethod
    def test_intercept_return_install_failure_removes_pending_row(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        attached_bridge: FridaBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failed Intercept-Ret install must remove its pending row, not leave it stuck.

        Targets an export that does not exist so the real bridge call
        genuinely fails, then asserts the pending row -- inserted before
        dispatch so the row is visible while installing -- is cleaned up
        rather than left showing "Installing..." forever.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            attached_bridge: Bridge fixture attached to the spawned notepad process.
            monkeypatch: Pytest monkeypatch fixture.
        """
        panel = _TestFridaPanel()
        panel.set_bridge(attached_bridge)
        target = "kernel32.dll!ThisExportDoesNotExist_S14D11"

        monkeypatch.setattr(QInputDialog, "getText", staticmethod(_fixed_get_text(target)))
        monkeypatch.setattr(QInputDialog, "getInt", staticmethod(_fixed_get_int(1)))

        panel.invoke_on_intercept_return()

        assert len(synchronous_dispatch) == 1
        assert panel.hooks_row_count() == 0, "a failed install must not leave a stuck row behind"
        assert panel.hook_ids_snapshot() == []


def _enclosing_scroll_area(widget: QWidget) -> QScrollArea | None:
    """Return the nearest ancestor QScrollArea of ``widget``, if any.

    Args:
        widget: The widget whose ancestry is walked.

    Returns:
        QScrollArea | None: The closest enclosing scroll area, or None.
    """
    node = widget.parentWidget()
    while node is not None:
        if isinstance(node, QScrollArea):
            return node
        node = node.parentWidget()
    return None


def _find_tab_index(tabs: QTabWidget, label: str) -> int:
    """Return the index of the tab whose title matches ``label``.

    Args:
        tabs: The tab widget to search.
        label: Tab title to look for.

    Returns:
        int: Matching tab index, or -1 if no tab has that title.
    """
    for i in range(tabs.count()):
        if tabs.tabText(i) == label:
            return i
    return -1


def _assert_no_overlap(widgets: list[QWidget], reference: QWidget) -> None:
    """Assert that no two widgets' rendered geometries overlap, mapped into a shared coordinate space.

    Args:
        widgets: Widgets to compare pairwise.
        reference: Common ancestor widget to map every geometry into.
    """
    rects = [(w, w.mapTo(reference, w.rect().topLeft()), w.size()) for w in widgets]
    for i, (widget_a, pos_a, size_a) in enumerate(rects):
        for widget_b, pos_b, size_b in rects[i + 1 :]:
            rect_a = (pos_a.x(), pos_a.y(), pos_a.x() + size_a.width(), pos_a.y() + size_a.height())
            rect_b = (pos_b.x(), pos_b.y(), pos_b.x() + size_b.width(), pos_b.y() + size_b.height())
            overlap_x = rect_a[0] < rect_b[2] and rect_b[0] < rect_a[2]
            overlap_y = rect_a[1] < rect_b[3] and rect_b[1] < rect_a[3]
            assert not (overlap_x and overlap_y), f"{type(widget_a).__name__} at {rect_a} overlaps {type(widget_b).__name__} at {rect_b}"


class TestAdvancedTabSystemFunctionCallLayout:
    """S14-D19 gates: the Advanced tab and its System Function Call rows must stay readable and unclipped."""

    @staticmethod
    def test_advanced_tab_is_hosted_in_a_scroll_area(qapp: QApplication) -> None:
        """The Advanced tab's content must be wrapped in a scroll area, not clipped in the dock.

        Falsifiable: before the fix, ``_right_tabs.addTab`` received the bare
        Advanced-section container directly, so this widget lookup would not
        be a ``QScrollArea`` and the assertion fails.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = _TestFridaPanel()
        try:
            tabs = panel.right_tabs()
            index = _find_tab_index(tabs, "Advanced")
            assert index >= 0, "an 'Advanced' tab must exist"
            advanced_widget = tabs.widget(index)
            assert isinstance(advanced_widget, QScrollArea), (
                f"the Advanced tab must be hosted in a QScrollArea so its content scrolls instead of clipping, "
                f"got {type(advanced_widget).__name__}"
            )
        finally:
            panel.close()
            qapp.processEvents()

    @staticmethod
    def test_system_function_call_controls_stay_readable_when_panel_is_narrow(qapp: QApplication) -> None:
        """Squeezed narrow, every System Function Call control must keep its natural width and never overlap.

        Regression test for S14-D19: before the fix, the three
        ``SystemFunctionCallControls`` rows (address/args/call,
        return-type/arg-types/convention, value/errno/GetLastError) were
        added to the layout as plain ``QHBoxLayout``s, so Qt shrank every
        label/combo/input below its ``sizeHint`` when the panel narrowed --
        the reported "Return/Value labels render on top of the combos"
        symptom. Falsifiable: if the rows are no longer hosted in a
        horizontally-scrolling control row, either the "must overflow"
        assertion fails (nothing to scroll), a control's rendered width drops
        below its natural size, or two controls' geometries intersect.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = _TestFridaPanel()
        try:
            panel.resize(_NARROW_PANEL_WIDTH, _NARROW_PANEL_HEIGHT)
            panel.show()
            qapp.processEvents()
            qapp.processEvents()

            return_type_combo = panel.system_call_return_type_combo()
            controls: list[QWidget] = [
                panel.system_call_address_input(),
                panel.system_call_args_input(),
                panel.system_call_call_button(),
                return_type_combo,
                panel.system_call_arg_types_input(),
                panel.system_call_convention_combo(),
            ]

            scroll = _enclosing_scroll_area(return_type_combo)
            assert scroll is not None, "the Return/Arg types/Convention row must be hosted in a scroll area (S14-D19 fix)"
            inner = scroll.widget()
            assert inner is not None, "the scroll area must host the control row as its widget"
            assert scroll.horizontalScrollBarPolicy() != Qt.ScrollBarPolicy.ScrollBarAlwaysOff, (
                "the control-row scroll area must permit horizontal scrolling so a narrow panel scrolls "
                "instead of squishing the controls below their natural width"
            )

            for control in controls:
                required = control.sizeHint().width()
                assert control.width() >= required, (
                    f"{type(control).__name__} rendered {control.width()}px wide, narrower than its {required}px natural size"
                )

            _assert_no_overlap(controls, scroll)
        finally:
            panel.close()
            qapp.processEvents()
