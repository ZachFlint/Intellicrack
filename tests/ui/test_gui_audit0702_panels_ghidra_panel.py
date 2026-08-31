# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""GUI audit regression gates for ``intellicrack.ui.panels.ghidra_panel``.

Covers the 2026-07-02 audit findings for ``ghidra_panel.py``:

* H3 -- ``_cleanup`` must bound its wait on ``GhidraBridge.shutdown()`` to
  ``_CLEANUP_SHUTDOWN_TIMEOUT_S`` instead of blocking the GUI thread forever
  (``run_bridge_coroutine`` with ``timeout_s=None``) when the bridge hangs.
* M46 -- the Labels/Bookmarks vertical splitter must be non-collapsible, like
  every other splitter in the panel, so neither pane can be dragged to zero
  height.
* M47 -- the structure-fields summary label must word-wrap and mirror its
  full text into a tooltip instead of clipping an unbounded field list.
* L10 -- the functions sidebar tree's Name column must resize to its
  contents (and re-fit on every repopulation) instead of staying pinned to
  the header label's width for long/mangled symbol names.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtGui import QFontMetrics
from PyQt6.QtWidgets import QApplication, QHeaderView, QInputDialog, QSplitter, QWidget

from intellicrack.bridges.base import BridgeState
from intellicrack.ui.panels import ghidra_panel as ghidra_panel_module
from intellicrack.ui.panels.ghidra_panel import GhidraPanel


if TYPE_CHECKING:
    from intellicrack.bridges.ghidra import GhidraBridge


class _HangingShutdownBridge:
    """Stand-in bridge exposing the exact ``_cleanup`` contract with a real, hanging ``shutdown``.

    ``_cleanup`` only reads ``state.is_ready()`` and awaits ``shutdown()``, so
    this stand-in provides nothing beyond that contract. ``shutdown`` performs
    a genuine ``asyncio.sleep`` far longer than the (patched) cleanup timeout,
    reproducing the "stalled headless RPC socket" scenario H3 describes
    without needing a real Ghidra process.
    """

    def __init__(self, hang_s: float) -> None:
        """Initialise a connected, tool-running bridge state and a hang duration.

        Args:
            hang_s: Seconds the real ``shutdown`` coroutine sleeps before
                completing.
        """
        self.state = BridgeState(connected=True, tool_running=True)
        self._hang_s = hang_s
        self.shutdown_started: bool = False
        self.shutdown_completed: bool = False

    async def shutdown(self) -> None:
        """Sleep for ``hang_s`` seconds, recording start and completion."""
        self.shutdown_started = True
        await asyncio.sleep(self._hang_s)
        self.shutdown_completed = True


@dataclass
class _FakeFunction:
    """Minimal real object exposing the attributes ``_apply_functions`` reads via ``getattr``.

    Attributes:
        name: Function symbol name.
        address: Function start address.
        size: Function size in bytes.
    """

    name: str
    address: int
    size: int


def _ancestor_splitter(widget: QWidget) -> QSplitter:
    """Walk a widget's parent chain to find its nearest ``QSplitter`` ancestor.

    Args:
        widget: Widget to start the upward walk from.

    Returns:
        QSplitter: The nearest ancestor splitter.
    """
    parent = widget.parentWidget()
    while parent is not None and not isinstance(parent, QSplitter):
        parent = parent.parentWidget()
    assert parent is not None, f"{widget!r} has no QSplitter ancestor"
    return parent


@pytest.mark.usefixtures("qapp")
class TestH3CleanupHonorsShutdownTimeout:
    """H3: panel teardown must not block the GUI thread forever on a hung bridge shutdown."""

    @staticmethod
    def test_stop_tool_returns_within_the_configured_timeout_when_shutdown_hangs(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``stop_tool`` must bound teardown to ``_CLEANUP_SHUTDOWN_TIMEOUT_S``, not hang forever.

        Regression: pre-fix, ``_cleanup`` called
        ``run_bridge_coroutine(self._bridge.shutdown())`` with no ``timeout_s``,
        which blocks the GUI thread on ``future.result(timeout=None)`` for as
        long as the bridge's real ``shutdown()`` coroutine takes -- unbounded.
        With a stand-in bridge whose ``shutdown()`` genuinely sleeps for 2
        seconds (a real ``asyncio.sleep``, not a mock of the timeout
        mechanism), the pre-fix call blocks for the full 2s; the fixed call
        must return in well under 2s once ``timeout_s`` is honoured, and the
        hung coroutine must still be mid-flight (not completed) when it does.

        Args:
            monkeypatch: Pytest monkeypatch fixture used to shrink the
                cleanup timeout constant so the test runs quickly.
        """
        monkeypatch.setattr(ghidra_panel_module, "_CLEANUP_SHUTDOWN_TIMEOUT_S", 0.3)
        panel = GhidraPanel()
        try:
            bridge = _HangingShutdownBridge(hang_s=2.0)
            panel._bridge = cast("GhidraBridge", bridge)

            start = time.monotonic()
            result = panel.stop_tool()
            elapsed = time.monotonic() - start

            assert result is True
            assert elapsed < 1.0, (
                f"stop_tool() blocked the GUI thread for {elapsed:.2f}s waiting on a hung "
                "bridge shutdown instead of honoring the cleanup timeout"
            )
            assert bridge.shutdown_started is True, "shutdown() was never invoked"
            assert bridge.shutdown_completed is False, (
                "shutdown() completed before stop_tool() returned, so the timeout ceiling was never exercised"
            )
        finally:
            panel.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestM46LabelsBookmarksSplitterNotCollapsible:
    """M46: the Labels/Bookmarks splitter must forbid collapsing either pane to zero."""

    @staticmethod
    def test_splitter_flag_is_non_collapsible_and_shared_by_both_tables() -> None:
        """The vertical splitter hosting labels and bookmarks must set ``childrenCollapsible(False)``.

        Regression: pre-fix, the splitter built in ``_create_labels_bookmarks_tab``
        never called ``setChildrenCollapsible(False)`` (unlike ``main_splitter``
        and ``left_splitter``), so it kept Qt's collapsible-by-default behaviour.
        """
        panel = GhidraPanel()
        try:
            splitter = _ancestor_splitter(panel._labels_table)
            assert _ancestor_splitter(panel._bookmarks_table) is splitter, (
                "labels and bookmarks tables must live in the same vertical splitter"
            )
            assert splitter.childrenCollapsible() is False, "Labels/Bookmarks splitter allows a pane to collapse to zero height"
        finally:
            panel.deleteLater()

    @staticmethod
    def test_programmatic_zero_size_request_does_not_collapse_the_labels_pane() -> None:
        """Requesting zero height for the labels pane must clamp to its minimum size, not collapse it.

        Drives the real Qt splitter layout: with ``childrenCollapsible(False)``,
        ``setSizes([0, big])`` clamps the first pane to its minimum size hint;
        with the pre-fix default (``True``), the same call drives it to exactly
        zero. This exercises genuine Qt layout behaviour, not just the flag.
        """
        panel = GhidraPanel()
        try:
            panel.resize(900, 700)
            panel.show()
            QApplication.processEvents()

            splitter = _ancestor_splitter(panel._labels_table)
            assert panel._data_tabs is not None
            panel._data_tabs.setCurrentWidget(splitter)
            QApplication.processEvents()

            baseline_total = sum(splitter.sizes()) or 1000
            splitter.setSizes([0, baseline_total * 10])
            QApplication.processEvents()

            sizes = splitter.sizes()
            assert sizes[0] > 0, f"labels pane collapsed to {sizes[0]}px despite setChildrenCollapsible(False)"
        finally:
            panel.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestM47StructFieldsLabelWrapsAndTooltips:
    """M47: the structure-fields summary label must wrap and tooltip an unbounded field list."""

    @staticmethod
    def test_label_has_word_wrap_enabled_at_construction() -> None:
        """``_struct_fields_label`` must have word wrap enabled at construction.

        Regression: pre-fix, the bare ``QLabel("")`` never called
        ``setWordWrap(True)``, so a long comma-joined field list would be
        clipped to the vertical layout's width with no way to read the rest.
        """
        panel = GhidraPanel()
        try:
            assert panel._struct_fields_label.wordWrap() is True
        finally:
            panel.deleteLater()

    @staticmethod
    def test_adding_many_fields_populates_full_text_and_matching_tooltip(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Adding many structure fields must expose the full list via both text and tooltip.

        Drives the real ``_on_add_struct_field`` handler (with
        ``QInputDialog.getText`` patched to supply deterministic field
        name/type pairs instead of blocking on a modal dialog) for a
        realistic ``IMAGE_NT_HEADERS``-sized field list, then asserts the
        resulting label text contains every field and the tooltip mirrors it
        exactly -- the fallback the fix adds for whatever word-wrap still
        does not make visible.

        Args:
            monkeypatch: Pytest monkeypatch fixture used to stub the modal
                ``QInputDialog.getText`` prompt with deterministic responses.
        """
        panel = GhidraPanel()
        try:
            fields: list[tuple[str, str]] = [
                ("magic", "uint32"),
                ("machine", "uint16"),
                ("numberOfSections", "uint16"),
                ("timeDateStamp", "uint32"),
                ("pointerToSymbolTable", "uint32"),
                ("numberOfSymbols", "uint32"),
                ("sizeOfOptionalHeader", "uint16"),
                ("characteristics", "uint16"),
                ("majorLinkerVersion", "uint8"),
                ("minorLinkerVersion", "uint8"),
                ("sizeOfCode", "uint32"),
                ("sizeOfInitializedData", "uint32"),
                ("sizeOfUninitializedData", "uint32"),
                ("addressOfEntryPoint", "uint32"),
                ("baseOfCode", "uint32"),
            ]
            responses: list[tuple[str, bool]] = []
            for field_name, field_type in fields:
                responses.extend([(field_name, True), (field_type, True)])
            response_iter = iter(responses)

            def fake_get_text(*_args: object, **_kwargs: object) -> tuple[str, bool]:
                """Return the next scripted (text, ok) response for ``QInputDialog.getText``.

                Args:
                    *_args: Ignored positional arguments Qt would pass.
                    **_kwargs: Ignored keyword arguments Qt would pass.

                Returns:
                    tuple[str, bool]: The next scripted response.
                """
                return next(response_iter)

            monkeypatch.setattr(QInputDialog, "getText", staticmethod(fake_get_text))

            for _ in fields:
                panel._on_add_struct_field()

            expected_fields_str = ", ".join(f"{n}:{t}" for n, t in fields)
            expected_text = f"Fields: {expected_fields_str}"

            text = panel._struct_fields_label.text()
            tooltip = panel._struct_fields_label.toolTip()
            assert text == expected_text, "label text does not contain the full, unbounded field list"
            assert tooltip == expected_text, "tooltip does not mirror the full label text"
            assert panel._struct_fields_label.wordWrap() is True
        finally:
            panel.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestL10FunctionTreeResizesNameColumnToContents:
    """L10: the functions sidebar Name column must resize to fit long function names."""

    @staticmethod
    def test_name_column_header_uses_resize_to_contents_mode() -> None:
        """The functions tree header must set column 0 to ``ResizeToContents``.

        Regression: pre-fix, no ``setSectionResizeMode`` call existed for
        ``_func_tree``, so Qt's default ``Interactive`` mode sized the column
        from the header label ("Name") rather than the populated data.
        """
        panel = GhidraPanel()
        try:
            header = panel._func_tree.header()
            assert header is not None
            assert header.sectionResizeMode(0) == QHeaderView.ResizeMode.ResizeToContents
        finally:
            panel.deleteLater()

    @staticmethod
    def test_populating_long_mangled_names_widens_column_and_sets_tooltip() -> None:
        """Populating the tree with a long mangled symbol must widen column 0 to fit it, with a tooltip fallback.

        Drives the real ``_apply_functions`` population path with a
        realistic decorated Windows COM symbol name, then measures the
        rendered column width against the text's real font-metric width to
        prove the name is not clipped, and asserts the per-item tooltip
        carries the full name as a fallback.
        """
        panel = GhidraPanel()
        try:
            panel.resize(900, 700)
            panel.show()
            QApplication.processEvents()

            long_name = "?CreateInstanceHelper@ClassFactoryImpl@@UEAAJPEAUIUnknown@@0PEAPEAX@Z"
            panel._apply_functions([_FakeFunction(name=long_name, address=0x1000, size=64)])
            QApplication.processEvents()

            assert panel._func_tree.topLevelItemCount() == 1
            item = panel._func_tree.topLevelItem(0)
            assert item is not None
            assert item.text(0) == long_name
            assert item.toolTip(0) == long_name, "tree item must carry the full name as a tooltip fallback"

            font_metrics = QFontMetrics(panel._func_tree.font())
            text_width = font_metrics.horizontalAdvance(long_name)
            column_width = panel._func_tree.columnWidth(0)
            assert column_width >= text_width, (
                f"Name column ({column_width}px) is narrower than the rendered text ({text_width}px); the long function name is clipped"
            )
        finally:
            panel.deleteLater()

    @staticmethod
    def test_repopulating_the_tree_re_fits_the_column_each_time() -> None:
        """Every ``_apply_functions`` call must re-run ``resizeColumnToContents``, not just the first.

        Regression: without the fix, nothing ever widened the column, so a
        short initial list followed by a refresh with long names would leave
        the column pinned at its narrow initial width.
        """
        panel = GhidraPanel()
        try:
            panel.resize(900, 700)
            panel.show()
            QApplication.processEvents()

            panel._apply_functions([_FakeFunction(name="main", address=0x1000, size=16)])
            QApplication.processEvents()
            narrow_width = panel._func_tree.columnWidth(0)

            long_name = "?CreateInstanceHelper@ClassFactoryImpl@@UEAAJPEAUIUnknown@@0PEAPEAX@Z"
            panel._apply_functions([_FakeFunction(name=long_name, address=0x2000, size=64)])
            QApplication.processEvents()
            wide_width = panel._func_tree.columnWidth(0)

            assert wide_width > narrow_width, "the Name column did not widen on refresh; it stayed pinned to the earlier, shorter content"
        finally:
            panel.deleteLater()
