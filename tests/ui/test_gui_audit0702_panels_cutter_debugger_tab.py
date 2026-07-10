# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""GUI-audit regression gates for :mod:`intellicrack.ui.panels.cutter_debugger_tab`.

* ``H34``: the modules table gave every column (including ``Path``) a uniform
  ``QHeaderView.ResizeMode.Stretch``, dividing the table width equally among
  five columns regardless of content, so long module paths were squeezed into
  roughly a fifth of the table and never got a tooltip fallback. The fix
  resizes the four short/fixed-format columns (``Name``, ``Base``, ``Size``,
  ``Entry Point``) to their content and gives the remaining width to ``Path``
  via ``Stretch``, and sets a tooltip on the path cell.
* ``L5``: ``_status_label`` never called ``setWordWrap(True)`` and never set a
  tooltip, so long bridge-exception text (attach/detach/step/breakpoint
  failures) was silently clipped at the panel edge with no way to read it. The
  fix wraps the label and mirrors every status update into its tooltip via a
  new ``_set_status`` helper used at every call site.

Both findings are pure layout/content defects exercised on a real
:class:`DebuggerTab` under an offscreen ``QApplication`` -- no bridge network
round trip is required since the population/status-update methods under test
operate on already-resolved Python objects.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QApplication, QHeaderView, QTabWidget

from intellicrack.core.types import ModuleInfo
from intellicrack.ui.panels.cutter_debugger_tab import DebuggerTab


if TYPE_CHECKING:
    from collections.abc import Iterator

import pytest


def _select_modules_tab(tab: DebuggerTab) -> None:
    """Make the "Modules" sub-tab the current page so it receives real layout.

    ``QTabWidget`` only lays out its currently visible page; hidden pages keep
    a stale default geometry. Column-width assertions therefore require the
    Modules page to actually be selected before measuring.

    Args:
        tab: The debugger tab whose bottom ``QTabWidget`` should be switched.
    """
    tabs = tab.findChild(QTabWidget)
    assert tabs is not None
    for index in range(tabs.count()):
        if tabs.tabText(index) == "Modules":
            tabs.setCurrentIndex(index)
            break
    QApplication.processEvents()


@pytest.fixture
def debugger_tab(qapp: QApplication) -> Iterator[DebuggerTab]:
    """Create a shown, sized :class:`DebuggerTab` for layout measurement.

    Args:
        qapp: Session ``QApplication`` fixture ensuring Qt is initialised.

    Yields:
        DebuggerTab: A freshly constructed, visible debugger tab.
    """
    _ = qapp
    tab = DebuggerTab()
    tab.resize(1800, 700)
    tab.show()
    QApplication.processEvents()
    yield tab
    tab.deleteLater()


def _sample_modules() -> list[ModuleInfo]:
    """Build real :class:`ModuleInfo` records including one long module path.

    Base addresses, sizes, and entry points are kept short (a handful of hex
    digits) so the Name/Base/Size/Entry Point columns have compact content
    widths, isolating the width comparison to the one column whose content
    genuinely varies in length: Path.

    Returns:
        list[ModuleInfo]: One module with a short path and one with a long,
        deeply nested path representative of a real third-party install.
    """
    return [
        ModuleInfo(
            name="ntdll.dll",
            path=Path("C:/Windows/System32/ntdll.dll"),
            base_address=0x1000_0000,
            size=4096,
            entry_point=0x1000,
        ),
        ModuleInfo(
            name="protect.dll",
            path=Path(
                "C:/Program Files (x86)/SomeVendor/SomeLongApplicationName/plugins/licensing/protect.dll",
            ),
            base_address=0x2000,
            size=8192,
            entry_point=0x2010,
        ),
    ]


class TestH34ModulesTableColumnSizing:
    """H34: the modules table must not divide width equally across columns."""

    def test_h34_short_columns_use_resize_to_contents_and_path_uses_stretch(self, debugger_tab: DebuggerTab) -> None:
        """The header must size Name/Base/Size/Entry Point to content and stretch Path.

        Pre-fix every section (including Path) used uniform
        ``QHeaderView.ResizeMode.Stretch``, so this structural check on the
        first four sections fails against the pre-fix code.

        Args:
            debugger_tab: The debugger tab under test.
        """
        header = debugger_tab._modules_table.horizontalHeader()
        assert header is not None
        for column, label in enumerate(["Name", "Base", "Size", "Entry Point"]):
            assert header.sectionResizeMode(column) == QHeaderView.ResizeMode.ResizeToContents, (
                f"column {column} ({label}) is not sized to its content"
            )
        assert header.sectionResizeMode(4) == QHeaderView.ResizeMode.Stretch, "Path column must absorb the remaining width"

    def test_h34_long_path_column_gets_majority_of_table_width(self, debugger_tab: DebuggerTab) -> None:
        """After population, the Path column must dominate each individual short column's width.

        Pre-fix (uniform Stretch on all five columns) every section is forced
        to the same width regardless of content, so Path would be equal to
        -- never exceeding -- each of Name/Base/Size/Entry Point. Post-fix the
        four short columns shrink to their compact content and Path absorbs
        the entire remainder, so Path must strictly exceed each of them.

        Args:
            debugger_tab: The debugger tab under test.
        """
        _select_modules_tab(debugger_tab)
        table = debugger_tab._modules_table
        modules = _sample_modules()
        debugger_tab._apply_modules(modules)
        QApplication.processEvents()

        assert table.rowCount() == len(modules)

        column_widths = [table.columnWidth(column) for column in range(4)]
        path_width = table.columnWidth(4)

        assert path_width > 0
        for column, width in enumerate(column_widths):
            assert path_width > width, (
                f"Path column ({path_width}px) does not exceed column {column}'s width ({width}px); "
                "columns still appear to be divided equally instead of Path absorbing the remainder"
            )

    def test_h34_path_cell_carries_full_path_as_tooltip(self, debugger_tab: DebuggerTab) -> None:
        """The Path cell must expose the full, untruncated path via tooltip.

        Pre-fix no ``setToolTip`` call existed anywhere in module population,
        so the tooltip was always the empty string regardless of content.

        Args:
            debugger_tab: The debugger tab under test.
        """
        modules = _sample_modules()
        debugger_tab._apply_modules(modules)
        QApplication.processEvents()

        long_path = str(modules[1].path)
        path_item = debugger_tab._modules_table.item(1, 4)
        assert path_item is not None
        assert path_item.text() == long_path
        assert path_item.toolTip() == long_path, "Path cell tooltip does not mirror the full path text"


class TestL5StatusLabelWordWrap:
    """L5: the status label must wrap and expose overflow text via tooltip."""

    def test_l5_status_label_has_word_wrap_enabled(self, debugger_tab: DebuggerTab) -> None:
        """``_status_label`` must have word wrap enabled at construction time.

        Pre-fix ``setWordWrap`` was never called, so this defaults to
        ``False`` and this assertion fails against the pre-fix widget.

        Args:
            debugger_tab: The debugger tab under test.
        """
        assert debugger_tab._status_label.wordWrap() is True

    def test_l5_attach_error_sets_tooltip_matching_long_status_text(self, debugger_tab: DebuggerTab) -> None:
        """A real attach failure must mirror its full text into the label tooltip.

        Drives the real ``_on_attach_error`` handler with a genuine
        ``OSError`` whose ``str()`` is long, exactly the scenario the finding
        describes (a long OS-level socket error). Pre-fix the label had no
        tooltip mechanism, so ``toolTip()`` would remain the empty string
        instead of mirroring the status text.

        Args:
            debugger_tab: The debugger tab under test.
        """
        long_error = OSError(
            10061,
            "No connection could be made because the target machine actively refused the "
            "rizin remote debug RPC connection on port 9998 after multiple retries",
        )
        debugger_tab._on_attach_error(long_error)
        expected = f"Attach failed: {long_error}"

        assert debugger_tab._status_label.text() == expected
        assert debugger_tab._status_label.toolTip() == expected, "status tooltip does not mirror the failure text"

    def test_l5_word_wrap_actually_grows_height_for_narrow_constrained_width(self, debugger_tab: DebuggerTab) -> None:
        """Word wrap must make the label grow vertically instead of clipping horizontally.

        Constrains the label to a narrow width and compares
        ``heightForWidth`` with word wrap on (the fixed behaviour) against
        word wrap off (the pre-fix behaviour) for the same long status text.
        Only the wrapped configuration reports a height tall enough for
        multiple text lines; the unwrapped configuration reports the same
        single-line height regardless of width, which is exactly how the
        pre-fix label silently clipped long exception text.

        Args:
            debugger_tab: The debugger tab under test.
        """
        label = debugger_tab._status_label
        long_text = (
            "Breakpoint operation failed: rizin RPC returned malformed JSON payload while "
            "resolving symbol table offsets for the requested breakpoint address range"
        )
        debugger_tab._set_status(long_text)
        QApplication.processEvents()

        narrow_width = 140
        wrapped_height = label.heightForWidth(narrow_width)

        label.setWordWrap(False)
        unwrapped_height = label.heightForWidth(narrow_width)
        label.setWordWrap(True)

        single_line_height = label.fontMetrics().height()
        assert wrapped_height >= single_line_height * 2, "label did not grow to multiple lines for long text at a narrow width"
        assert unwrapped_height <= single_line_height * 1.5, "unwrapped heightForWidth unexpectedly reports multi-line height"
