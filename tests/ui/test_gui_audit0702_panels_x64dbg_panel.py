# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""GUI audit regression gates for ``intellicrack.ui.panels.x64dbg_panel``.

Covers the 2026-07-02 audit findings for ``x64dbg_panel.py``:

* H13 -- ``_cleanup`` must dispatch the teardown ``stop()`` RPC through
  ``run_bridge_coroutine`` with a bounded ``timeout_s`` so a hung debugger
  IPC pipe cannot freeze the Qt event loop forever.
* H28 -- the toolbar status label must be assigned to the base class's
  ``self.status_label`` (not a shadowing ``self._status_label``), so every
  ``_set_status`` call actually reaches the widget the user sees.
* M31 -- switching the module-detail table from Sections to Exports must
  reset the column count to the Exports schema instead of leaving a stale,
  always-empty 4th column behind.
* M64 -- the main/top splitters must be non-collapsible and their child
  panes must carry minimum sizes so a drag cannot hide the disassembly view,
  inspect tabs, or bottom tab area entirely.
* M65 -- the Process Info Path/Command Line labels must word-wrap long
  values instead of clipping them with no way to read the full text.
* L17 -- the module table must stretch only the variable-length Path
  column (short columns size to content) and Path cells must carry a
  tooltip with the untruncated value.

All tests drive a real :class:`X64DbgPanel` under an offscreen
``QApplication``. Bridge-backed call sites are exercised with lightweight
stand-in bridges and a synchronous/no-op dispatch stub so the panel's real
synchronous setup logic runs deterministically without needing a live
debugger connection or a completed background-thread round trip.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, cast

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QHeaderView, QLabel, QSplitter, QTableWidget

from intellicrack.bridges.base import BridgeState
from intellicrack.ui.panels import x64dbg_panel as x64dbg_panel_module
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel


if TYPE_CHECKING:
    from collections.abc import Coroutine

    import pytest
    from PyQt6.QtWidgets import QApplication

    from intellicrack.bridges.x64dbg import X64DbgBridge


class _ModuleInfoStub:
    """Minimal stand-in exposing the attributes ``_apply_modules`` reads via ``getattr``."""

    def __init__(self, *, name: str, base_address: int, size: int, path: str) -> None:
        """Store module fields the panel reads by attribute name.

        Args:
            name: Module file name.
            base_address: Module base address.
            size: Module image size in bytes.
            path: Full on-disk module path.
        """
        self.name = name
        self.base_address = base_address
        self.size = size
        self.path = path


class _ProcessInfoStub:
    """Minimal stand-in exposing the attributes ``_apply_procinfo`` reads via ``getattr``."""

    def __init__(self, *, pid: int, name: str, path: str, command_line: str, parent_pid: int) -> None:
        """Store process-info fields the panel reads by attribute name.

        Args:
            pid: Process id.
            name: Process image name.
            path: Full on-disk executable path.
            command_line: Full process command line.
            parent_pid: Parent process id.
        """
        self.pid = pid
        self.name = name
        self.path = path
        self.command_line = command_line
        self.parent_pid = parent_pid


class _RecordingStopBridge:
    """Stand-in bridge with a ready state and an inert ``stop`` coroutine."""

    def __init__(self) -> None:
        """Initialise a connected, tool-running bridge state."""
        self.state = BridgeState(connected=True, tool_running=True)

    async def stop(self) -> None:
        """Do nothing; the coroutine object is closed unrun by the test recorder."""


class _HangingStopBridge:
    """Stand-in bridge whose ``stop`` coroutine sleeps far past any cleanup timeout."""

    def __init__(self) -> None:
        """Initialise a connected, tool-running bridge state."""
        self.state = BridgeState(connected=True, tool_running=True)

    async def stop(self) -> None:
        """Sleep well past any reasonable cleanup timeout to simulate a hung RPC."""
        await asyncio.sleep(30)


class _TimeoutRecorder:
    """Callable recorder standing in for ``run_bridge_coroutine``.

    Captures the ``timeout_s`` keyword argument each call receives and
    closes the coroutine without executing it, so the panel's teardown call
    site can be asserted against without a real background event loop.
    """

    def __init__(self) -> None:
        """Initialise an empty capture list."""
        self.timeouts: list[float | None] = []

    def __call__(self, coro: Coroutine[object, object, object], /, *, timeout_s: float | None = None) -> None:
        """Record ``timeout_s`` and discard the coroutine unrun.

        Args:
            coro: The bridge coroutine the call site produced; closed unrun.
            timeout_s: The timeout keyword the call site passed.
        """
        self.timeouts.append(timeout_s)
        coro.close()


class _ModuleDetailBridgeStub:
    """Stand-in bridge exposing the module-detail coroutine methods the panel calls."""

    async def get_module_sections(self, module_name: str) -> list[dict[str, object]]:
        """Return no sections; the dispatch is discarded by the test's no-op driver.

        Args:
            module_name: Name of the module (unused).

        Returns:
            list[dict[str, object]]: Always empty.
        """
        del module_name
        return []

    async def get_module_exports(self, module_name: str) -> list[dict[str, object]]:
        """Return no exports; the dispatch is discarded by the test's no-op driver.

        Args:
            module_name: Name of the module (unused).

        Returns:
            list[dict[str, object]]: Always empty.
        """
        del module_name
        return []


def _noop_dispatch(
    coro: Coroutine[object, object, object],
    on_success: object = None,
    on_error: object = None,
    parent: object = None,
    **_kwargs: object,
) -> None:
    """Discard a dispatched bridge coroutine without running or awaiting it.

    Stands in for ``run_bridge_coroutine_logged`` so tests can exercise the
    synchronous header/column-count setup in ``_on_show_module_sections`` /
    ``_on_show_module_exports`` without needing a real background dispatch
    thread to complete.

    Args:
        coro: Coroutine produced by the bridge call; closed unrun.
        on_success: Unused success callback.
        on_error: Unused error callback.
        parent: Unused Qt parent argument.
        **_kwargs: Remaining wrapper keyword arguments (event, logger, etc.).
    """
    del on_success, on_error, parent
    coro.close()


def _header_texts(table: QTableWidget, *, count: int) -> list[str]:
    """Read the first ``count`` horizontal header labels of ``table``.

    Args:
        table: The table whose header labels are read.
        count: Number of leading columns to read.

    Returns:
        list[str]: The header text of columns ``0..count-1``.
    """
    texts: list[str] = []
    for index in range(count):
        item = table.horizontalHeaderItem(index)
        assert item is not None, f"column {index} has no header item"
        texts.append(item.text())
    return texts


def _assert_wraps_within_width(label: QLabel, width: int) -> None:
    """Assert a label wraps its current text within ``width`` pixels.

    Constrains the label to a narrow width and checks that the wrapped
    height for that width spans multiple text lines; a label without word
    wrap reports a fixed single-line ``heightForWidth`` regardless of width,
    which is the pre-fix clipping failure mode.

    Args:
        label: The label under test, already populated with long text.
        width: Width, in pixels, to constrain the label to.
    """
    assert label.wordWrap() is True, "label must have word wrap enabled"
    label.resize(width, 20)
    line_height = label.fontMetrics().height()
    wrapped_height = label.heightForWidth(width)
    assert wrapped_height > line_height, (
        f"label did not wrap its long text across multiple lines at width={width} "
        f"(heightForWidth={wrapped_height}, single line={line_height})"
    )


class TestH13CleanupUsesBoundedTeardownTimeout:
    """H13: teardown's ``stop()`` RPC must not be able to block forever."""

    @staticmethod
    def test_h13_cleanup_dispatches_stop_with_a_bounded_timeout(
        monkeypatch: pytest.MonkeyPatch,
        qapp: QApplication,
    ) -> None:
        """``_cleanup`` must call ``run_bridge_coroutine`` with a non-``None`` ``timeout_s``.

        Regression: pre-fix, ``_cleanup`` called
        ``run_bridge_coroutine(self._bridge.stop())`` with no ``timeout_s``
        keyword at all, so the recorder installed here would observe
        ``timeout_s=None`` (its default) -- an unbounded wait.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
            qapp: The shared offscreen QApplication fixture.
        """
        _ = qapp
        recorder = _TimeoutRecorder()
        monkeypatch.setattr(x64dbg_panel_module, "run_bridge_coroutine", recorder)
        panel = X64DbgPanel()
        try:
            panel._bridge = cast("X64DbgBridge", _RecordingStopBridge())
            panel._cleanup()

            assert recorder.timeouts == [x64dbg_panel_module._CLEANUP_STOP_TIMEOUT_S]
            assert recorder.timeouts[0] is not None, (
                "run_bridge_coroutine was invoked with timeout_s=None; the teardown RPC can still block the GUI thread forever"
            )
        finally:
            panel.deleteLater()

    @staticmethod
    def test_h13_cleanup_returns_promptly_when_bridge_stop_hangs(
        monkeypatch: pytest.MonkeyPatch,
        qapp: QApplication,
    ) -> None:
        """``_cleanup`` must return within the bounded timeout even if ``stop()`` hangs.

        Uses the real ``run_bridge_coroutine`` dispatcher (not a stub) with
        the panel's cleanup timeout constant shrunk to a fraction of a
        second, and a bridge whose ``stop()`` sleeps for 30 seconds. Proves
        the caught ``TimeoutError`` path actually bounds the wall-clock
        wait instead of the caller blocking until the coroutine completes.

        Regression: pre-fix, ``_CLEANUP_STOP_TIMEOUT_S`` did not exist and
        the call site passed no ``timeout_s`` at all, so
        ``future.result(timeout=None)`` would have blocked for the full 30
        seconds (or forever, for a genuinely hung RPC) instead of returning
        in a fraction of a second.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
            qapp: The shared offscreen QApplication fixture.
        """
        _ = qapp
        monkeypatch.setattr(x64dbg_panel_module, "_CLEANUP_STOP_TIMEOUT_S", 0.2)
        panel = X64DbgPanel()
        try:
            panel._bridge = cast("X64DbgBridge", _HangingStopBridge())
            started = time.monotonic()
            panel._cleanup()
            elapsed = time.monotonic() - started

            assert elapsed < 5.0, (
                f"_cleanup blocked for {elapsed:.2f}s waiting on a hung bridge.stop(); the teardown RPC has no effective bound"
            )
        finally:
            panel.deleteLater()


class TestH28StatusLabelWiredToBaseClassAttribute:
    """H28: status text must reach the base class's ``status_label``, not a shadow attribute."""

    @staticmethod
    def test_h28_toolbar_label_is_exposed_as_base_class_status_label(qapp: QApplication) -> None:
        """The toolbar status ``QLabel`` must be assigned to ``self.status_label``.

        Regression: pre-fix the label was stored as ``self._status_label``
        (a private, panel-only attribute), so
        ``AnalysisPanelBase.status_label`` stayed at its ``__init__``-time
        value of ``None`` for the panel's entire lifetime.

        Args:
            qapp: The shared offscreen QApplication fixture.
        """
        _ = qapp
        panel = X64DbgPanel()
        try:
            assert panel.status_label is not None, "status_label was never assigned; every _set_status call is a permanent silent no-op"
            assert isinstance(panel.status_label, QLabel)
            assert panel.status_label.text() == "No bridge configured"
        finally:
            panel.deleteLater()

    @staticmethod
    def test_h28_set_status_updates_the_real_visible_label_text(qapp: QApplication) -> None:
        """``_set_status`` must change the text of the actual toolbar label the user sees.

        Drives the exact call every debugger-state handler makes (load,
        attach, run, pause, stop, restart, detach, spawn all funnel through
        ``self._set_status``) and asserts the visible toolbar label's text
        changes as a result.

        Args:
            qapp: The shared offscreen QApplication fixture.
        """
        _ = qapp
        panel = X64DbgPanel()
        try:
            panel._set_status("Attached: PID 4321")

            assert panel.status_label is not None
            assert panel.status_label.text() == "Attached: PID 4321", (
                "toolbar status label text did not update; _set_status is writing to the wrong attribute"
            )
        finally:
            panel.deleteLater()


class TestM31ModuleDetailColumnCountResetsPerView:
    """M31: switching Sections -> Exports must not leave a stale 4th column."""

    @staticmethod
    def test_m31_exports_view_drops_the_stale_sections_column(
        monkeypatch: pytest.MonkeyPatch,
        qapp: QApplication,
    ) -> None:
        """After viewing Sections then Exports, the detail table must have exactly 3 columns.

        Regression: pre-fix, ``_on_show_module_exports`` only called
        ``setHorizontalHeaderLabels`` with 3 strings on a table still fixed
        at 4 columns from construction/the Sections view, leaving column
        3's header text (``"Characteristics"``) and every exports row's 4th
        cell permanently stale and blank.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
            qapp: The shared offscreen QApplication fixture.
        """
        _ = qapp
        monkeypatch.setattr(x64dbg_panel_module, "run_bridge_coroutine_logged", _noop_dispatch)
        panel = X64DbgPanel()
        try:
            panel._bridge = cast("X64DbgBridge", _ModuleDetailBridgeStub())
            panel._apply_modules(
                [
                    _ModuleInfoStub(
                        name="kernel32.dll",
                        base_address=0x7FFE_0000,
                        size=0x10_0000,
                        path="C:\\Windows\\System32\\kernel32.dll",
                    ),
                ],
            )
            panel._module_table.setCurrentCell(0, 0)

            panel._on_show_module_sections()
            assert panel._mod_detail_table.columnCount() == 4
            sections_headers = _header_texts(panel._mod_detail_table, count=4)
            assert sections_headers == list(x64dbg_panel_module._SECTION_DETAIL_COLUMNS)

            panel._on_show_module_exports()
            assert panel._mod_detail_table.columnCount() == 3, (
                "module detail table still has 4 columns after switching to Exports; the stale Sections column was not dropped"
            )
            exports_headers = _header_texts(panel._mod_detail_table, count=3)
            assert exports_headers == list(x64dbg_panel_module._EXPORT_DETAIL_COLUMNS)
        finally:
            panel.deleteLater()

    @staticmethod
    def test_m31_export_rows_populate_real_data_in_the_reset_table(
        monkeypatch: pytest.MonkeyPatch,
        qapp: QApplication,
    ) -> None:
        """Exports must populate real name/ordinal/address data into the reset 3-column table.

        Confirms the fixed ``_apply_module_exports`` writes correct data
        into the exact columns the reset (3-column) header expects, rather
        than the fix merely hiding an extra column while leaving the data
        mapping broken.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
            qapp: The shared offscreen QApplication fixture.
        """
        _ = qapp
        monkeypatch.setattr(x64dbg_panel_module, "run_bridge_coroutine_logged", _noop_dispatch)
        panel = X64DbgPanel()
        try:
            panel._bridge = cast("X64DbgBridge", _ModuleDetailBridgeStub())
            panel._apply_modules(
                [
                    _ModuleInfoStub(
                        name="ntdll.dll",
                        base_address=0x7FFE_1000,
                        size=0x18_0000,
                        path="C:\\Windows\\System32\\ntdll.dll",
                    ),
                ],
            )
            panel._module_table.setCurrentCell(0, 0)

            panel._on_show_module_sections()
            panel._on_show_module_exports()
            panel._apply_module_exports([{"name": "NtCreateFile", "ordinal": 12, "address": "0x77001000"}])

            assert panel._mod_detail_table.columnCount() == 3
            name_item = panel._mod_detail_table.item(0, 0)
            ordinal_item = panel._mod_detail_table.item(0, 1)
            address_item = panel._mod_detail_table.item(0, 2)
            assert name_item is not None
            assert ordinal_item is not None
            assert address_item is not None
            assert name_item.text() == "NtCreateFile"
            assert ordinal_item.text() == "12"
            assert address_item.text() == "0x77001000"
        finally:
            panel.deleteLater()


class TestM64SplittersNonCollapsibleWithMinimumPaneSizes:
    """M64: main/top splitters must forbid collapsing a pane to zero size."""

    @staticmethod
    def test_m64_main_and_top_splitters_are_non_collapsible(qapp: QApplication) -> None:
        """Both the vertical main splitter and horizontal top splitter must be non-collapsible.

        Regression: neither splitter called ``setChildrenCollapsible(False)``,
        so dragging a handle to the edge could collapse the disassembly
        view, the inspect-tabs column, or the bottom tab area to 0px with
        no visible affordance to recover it.

        Args:
            qapp: The shared offscreen QApplication fixture.
        """
        _ = qapp
        panel = X64DbgPanel()
        try:
            splitters = panel.findChildren(QSplitter)
            assert splitters, "the x64dbg panel must contain splitters"

            vertical = [s for s in splitters if s.orientation() == Qt.Orientation.Vertical]
            horizontal = [s for s in splitters if s.orientation() == Qt.Orientation.Horizontal]
            assert vertical, "expected a vertical main splitter (top area / bottom tabs)"
            assert horizontal, "expected a horizontal top splitter (disassembly / inspect tabs)"

            for splitter in vertical + horizontal:
                assert splitter.childrenCollapsible() is False, (
                    f"splitter {splitter.objectName() or splitter} allows a pane to collapse to zero size"
                )
        finally:
            panel.deleteLater()

    @staticmethod
    def test_m64_top_splitter_panes_carry_a_minimum_width(qapp: QApplication) -> None:
        """The disassembly and inspect-tabs panes must each carry a positive minimum width.

        Regression: pre-fix, ``top_splitter.addWidget`` was called directly
        on freshly-built child widgets with no ``setMinimumWidth`` call, so
        Qt's default collapsible-to-zero behaviour had no floor to stop at.

        Args:
            qapp: The shared offscreen QApplication fixture.
        """
        _ = qapp
        panel = X64DbgPanel()
        try:
            horizontal = [s for s in panel.findChildren(QSplitter) if s.orientation() == Qt.Orientation.Horizontal]
            assert len(horizontal) == 1, "expected exactly one horizontal top splitter"
            top_splitter = horizontal[0]
            assert top_splitter.count() == 2, "top splitter must host the disassembly view and inspect tabs"

            for index in range(2):
                pane = top_splitter.widget(index)
                assert pane is not None
                assert pane.minimumWidth() >= x64dbg_panel_module._MIN_PANE_WIDTH, (
                    f"top_splitter pane {index} has no effective minimum width ({pane.minimumWidth()}px)"
                )
        finally:
            panel.deleteLater()

    @staticmethod
    def test_m64_bottom_tabs_pane_carries_a_minimum_height(qapp: QApplication) -> None:
        """The bottom tab area (breakpoints/memory/console/etc.) must carry a minimum height.

        Regression: pre-fix, ``main_splitter.addWidget(self._create_bottom_tabs())``
        set no minimum height, so the entire bottom tab area could be
        dragged to zero height and disappear.

        Args:
            qapp: The shared offscreen QApplication fixture.
        """
        _ = qapp
        panel = X64DbgPanel()
        try:
            vertical = [s for s in panel.findChildren(QSplitter) if s.orientation() == Qt.Orientation.Vertical]
            assert len(vertical) == 1, "expected exactly one vertical main splitter"
            main_splitter = vertical[0]
            assert main_splitter.count() == 2, "main splitter must host the top area and the bottom tabs"

            bottom_pane = main_splitter.widget(1)
            assert bottom_pane is not None
            assert bottom_pane.minimumHeight() >= x64dbg_panel_module._MIN_PANE_HEIGHT, (
                f"bottom tabs pane has no effective minimum height ({bottom_pane.minimumHeight()}px)"
            )
        finally:
            panel.deleteLater()


class TestM65ProcInfoLabelsWordWrapLongText:
    """M65: Process Info Path/Command Line labels must wrap instead of clipping."""

    @staticmethod
    def test_m65_word_wrap_enabled_on_construction(qapp: QApplication) -> None:
        """``_procinfo_path`` and ``_procinfo_cmdline`` must have word wrap enabled at construction.

        Regression: pre-fix, both were bare ``QLabel("--")`` instances with
        no ``setWordWrap(True)`` call, so long values would be hard-clipped
        at the pane boundary instead of wrapping.

        Args:
            qapp: The shared offscreen QApplication fixture.
        """
        _ = qapp
        panel = X64DbgPanel()
        try:
            assert panel._procinfo_path.wordWrap() is True
            assert panel._procinfo_cmdline.wordWrap() is True
        finally:
            panel.deleteLater()

    @staticmethod
    def test_m65_apply_procinfo_sets_full_text_and_tooltip_for_long_values(qapp: QApplication) -> None:
        """A long real path/command line must populate the labels in full and wrap at a narrow width.

        Drives the real ``_apply_procinfo`` handler with a long,
        realistic path and command line (as the bridge's ``ProcessInfo``
        would supply for an installer invoked with several long
        quoted arguments), then asserts the full text reaches the label and
        tooltip, and that the label actually wraps rather than reporting a
        fixed single-line height regardless of width.

        Args:
            qapp: The shared offscreen QApplication fixture.
        """
        _ = qapp
        panel = X64DbgPanel()
        try:
            long_path = "C:\\Program Files\\SomeVendor\\LongApplicationName\\bin\\x64\\native_component_x64.exe"
            long_cmdline = (
                f'"{long_path}" --install-dir="C:\\Program Files\\SomeVendor\\LongApplicationName" '
                "--silent --log-level=verbose --config=production --telemetry=disabled"
            )
            result = _ProcessInfoStub(
                pid=4321,
                name="native_component_x64.exe",
                path=long_path,
                command_line=long_cmdline,
                parent_pid=100,
            )

            panel._apply_procinfo(result)

            assert panel._procinfo_path.text() == long_path
            assert panel._procinfo_path.toolTip() == long_path
            assert panel._procinfo_cmdline.text() == long_cmdline
            assert panel._procinfo_cmdline.toolTip() == long_cmdline

            _assert_wraps_within_width(panel._procinfo_path, width=140)
            _assert_wraps_within_width(panel._procinfo_cmdline, width=140)
        finally:
            panel.deleteLater()


class TestL17ModuleTablePathColumnStretchesAndTooltips:
    """L17: the module table must stretch only Path and tooltip its cells."""

    @staticmethod
    def test_l17_path_column_stretches_other_columns_size_to_content(qapp: QApplication) -> None:
        """Only the "Path" column uses Stretch resize mode; Name/Base/Size size to content.

        Regression: pre-fix, a single header-wide
        ``setSectionResizeMode(Stretch)`` call put all 4 columns in Stretch
        mode uniformly, so the short, fixed-width Base and Size columns
        claimed the same width share as the variable-length Path column.

        Args:
            qapp: The shared offscreen QApplication fixture.
        """
        _ = qapp
        panel = X64DbgPanel()
        try:
            header = panel._module_table.horizontalHeader()
            assert header is not None

            path_index = x64dbg_panel_module._MODULE_COLUMNS.index("Path")
            assert header.sectionResizeMode(path_index) == QHeaderView.ResizeMode.Stretch, "Path column must stretch"
            for column in range(len(x64dbg_panel_module._MODULE_COLUMNS)):
                if column == path_index:
                    continue
                assert header.sectionResizeMode(column) == QHeaderView.ResizeMode.ResizeToContents, (
                    f"column {column} must size to its content, not stretch uniformly with Path"
                )
        finally:
            panel.deleteLater()

    @staticmethod
    def test_l17_path_cell_carries_the_full_untruncated_path_as_a_tooltip(qapp: QApplication) -> None:
        """A long module path must be recoverable in full via the Path cell's tooltip.

        Regression: pre-fix, ``QTableWidgetItem(str(getattr(mod, "path", "")))``
        set no tooltip at all, so an elided Path cell left the full path
        unrecoverable from the UI without external tooling.

        Args:
            qapp: The shared offscreen QApplication fixture.
        """
        _ = qapp
        panel = X64DbgPanel()
        try:
            long_path = "C:\\Program Files\\SomeVendor\\LongApplicationName\\bin\\x64\\dependency.dll"
            panel._apply_modules(
                [
                    _ModuleInfoStub(
                        name="dependency.dll",
                        base_address=0x7FFE_0000,
                        size=0x2_0000,
                        path=long_path,
                    ),
                ],
            )

            path_index = x64dbg_panel_module._MODULE_COLUMNS.index("Path")
            path_item = panel._module_table.item(0, path_index)
            assert path_item is not None
            assert path_item.text() == long_path
            assert path_item.toolTip() == long_path, "Path cell tooltip does not carry the full, un-elided value"
        finally:
            panel.deleteLater()
