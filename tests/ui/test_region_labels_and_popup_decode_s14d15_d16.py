# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for audit defect S14-D15 (region/module count labels show total, not filtered).

Covers ``MemoryTab`` (``src/intellicrack/ui/panels/process_panel/memory_tab.py``)
and ``ModulesTab`` (``src/intellicrack/ui/panels/process_panel/modules_tab.py``):
after a filter is applied to the Regions table or the Modules tree, the
"N regions" / "N modules" count label must reflect the currently VISIBLE
row count, not the unfiltered backing-list total.

S14-D16 (attach auto-popup Regions dialog shows raw hex Protection/State and
defaults the read to a MEM_FREE row) is NOT covered here. That popup is built
in ``MainWindow._on_process_regions_listed`` in ``src/intellicrack/ui/app.py``,
not in ``memory_tab.py`` or ``modules_tab.py`` -- confirmed by a full read of
both files plus a repository-wide search for the dialog construction site.
Neither file contains a Protection/State decode helper to reuse: the Region
Map's readable Protection/State text comes from the bridge's
``get_memory_map(resolve_names=True)`` call already returning decoded
strings, not from any local decode routine. Since the task scope for this
change was restricted to ``memory_tab.py``, ``modules_tab.py``, and this test
file (with ``bridges/process.py`` and all other source files explicitly
out of bounds), S14-D16 could not be fixed here and is intentionally left
untested rather than faked against code these two files do not contain.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
)

from intellicrack.ui.panels import async_bridge as _async_bridge_mod
from intellicrack.ui.panels.process_panel.memory_tab import MemoryTab
from intellicrack.ui.panels.process_panel.modules_tab import ModulesTab


if TYPE_CHECKING:
    from collections.abc import Callable

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture
def memory_tab(qapp: QApplication) -> MemoryTab:
    """Create a real ``MemoryTab`` instance for testing.

    Args:
        qapp: QApplication fixture -- required to ensure Qt is initialised.

    Returns:
        MemoryTab: A fresh ``MemoryTab`` widget.
    """
    assert isinstance(qapp, QApplication)
    return MemoryTab()


@pytest.fixture
def modules_tab(qapp: QApplication) -> ModulesTab:
    """Create a real ``ModulesTab`` instance for testing.

    Args:
        qapp: QApplication fixture -- required to ensure Qt is initialised.

    Returns:
        ModulesTab: A fresh ``ModulesTab`` widget.
    """
    assert isinstance(qapp, QApplication)
    return ModulesTab()


def _region_table(tab: MemoryTab) -> QTableWidget:
    """Return the region-map ``QTableWidget`` of a ``MemoryTab``.

    Args:
        tab: MemoryTab whose region table is requested.

    Returns:
        QTableWidget: The live region-map table widget.
    """
    widget = getattr(tab, "_region_table")
    assert isinstance(widget, QTableWidget)
    return widget


def _region_filter(tab: MemoryTab) -> QLineEdit:
    """Return the region-filter ``QLineEdit`` of a ``MemoryTab``.

    Args:
        tab: MemoryTab whose region filter field is requested.

    Returns:
        QLineEdit: The live region-filter input widget.
    """
    widget = getattr(tab, "_region_filter")
    assert isinstance(widget, QLineEdit)
    return widget


def _region_count_label(tab: MemoryTab) -> QLabel:
    """Return the region count ``QLabel`` of a ``MemoryTab``.

    Args:
        tab: MemoryTab whose region count label is requested.

    Returns:
        QLabel: The live region-count label widget.
    """
    widget = getattr(tab, "_region_count")
    assert isinstance(widget, QLabel)
    return widget


def _mod_tree(tab: ModulesTab) -> QTreeWidget:
    """Return the module ``QTreeWidget`` of a ``ModulesTab``.

    Args:
        tab: ModulesTab whose module tree is requested.

    Returns:
        QTreeWidget: The live module-tree widget.
    """
    widget = getattr(tab, "_mod_tree")
    assert isinstance(widget, QTreeWidget)
    return widget


def _mod_filter(tab: ModulesTab) -> QLineEdit:
    """Return the module-filter ``QLineEdit`` of a ``ModulesTab``.

    Args:
        tab: ModulesTab whose module filter field is requested.

    Returns:
        QLineEdit: The live module-filter input widget.
    """
    widget = getattr(tab, "_mod_filter")
    assert isinstance(widget, QLineEdit)
    return widget


def _mod_count_label(tab: ModulesTab) -> QLabel:
    """Return the module count ``QLabel`` of a ``ModulesTab``.

    Args:
        tab: ModulesTab whose module count label is requested.

    Returns:
        QLabel: The live module-count label widget.
    """
    widget = getattr(tab, "_mod_count")
    assert isinstance(widget, QLabel)
    return widget


def _set_private(obj: object, attr_name: str, value: object) -> None:
    """Assign a value to a named private attribute.

    Args:
        obj: Object to mutate.
        attr_name: Attribute name to set.
        value: Value to assign.
    """
    setattr(obj, attr_name, value)


def _capture_dispatch(
    captured: list[Callable[[object], None]],
) -> Callable[[object, object, object, object], None]:
    """Build a fake ``run_bridge_coroutine_async`` that captures ``on_success``.

    Args:
        captured: List that the produced fake appends the ``on_success``
            callback to.

    Returns:
        Callable[[object, object, object, object], None]: A drop-in
        replacement for ``run_bridge_coroutine_async`` with the same
        positional signature (``coro``, ``on_success``, ``on_error``, ``parent``).
    """

    def _fake(_coro: object, on_success: object, _on_error: object, _parent: object) -> None:
        assert callable(on_success)
        captured.append(cast("Callable[[object], None]", on_success))

    return _fake


class TestRegionCountReflectsFilteredRows:
    """S14-D15: MemoryTab's '_region_count' label tracks visible, not total, rows."""

    def test_filter_updates_region_count_to_visible_rows(self, memory_tab: MemoryTab) -> None:
        """Applying a filter that hides rows updates the count to the visible total.

        Populates the region table with 4 rows where only 1 module name
        contains "ntdll", then drives the filter through the real
        ``_on_region_filter_changed`` slot (the production ``textChanged``
        handler) and asserts the label shows the filtered count -- not the
        4-row unfiltered total that a reverted fix would leave in place.

        Args:
            memory_tab: MemoryTab fixture.
        """
        table = _region_table(memory_tab)
        table.setSortingEnabled(False)
        table.setRowCount(4)
        names = ["ntdll.dll", "kernel32.dll", "user32.dll", "advapi32.dll"]
        for row, name in enumerate(names):
            table.setItem(row, 0, QTableWidgetItem(f"0x{row:016X}"))
            table.setItem(row, 5, QTableWidgetItem(name))

        label = _region_count_label(memory_tab)

        _region_filter(memory_tab).setText("ntdll")

        visible_rows = sum(1 for row in range(table.rowCount()) if not table.isRowHidden(row))
        assert visible_rows == 1, "sanity check: filter must hide 3 of 4 rows"
        assert label.text() == "1 regions", (
            f"Expected count label to show the FILTERED count '1 regions' after filtering to ntdll.dll; "
            f"got {label.text()!r} -- S14-D15 not fixed (label still shows the unfiltered total)"
        )

    def test_clearing_filter_restores_full_count(self, memory_tab: MemoryTab) -> None:
        """Clearing the filter after a narrower match restores the full visible count.

        Args:
            memory_tab: MemoryTab fixture.
        """
        table = _region_table(memory_tab)
        table.setSortingEnabled(False)
        table.setRowCount(3)
        for row in range(3):
            table.setItem(row, 0, QTableWidgetItem(f"0x{row:016X}"))
            table.setItem(row, 5, QTableWidgetItem("ntdll.dll" if row == 0 else "kernel32.dll"))

        label = _region_count_label(memory_tab)
        region_filter = _region_filter(memory_tab)

        region_filter.setText("ntdll")
        assert label.text() == "1 regions"

        region_filter.setText("")
        assert label.text() == "3 regions", f"Expected '3 regions' once the filter is cleared; got {label.text()!r}"

    def test_refresh_regions_count_reflects_preexisting_filter(
        self,
        memory_tab: MemoryTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A full refresh with a filter already typed shows the filtered count, not the raw bridge total.

        This exercises the production data path end-to-end: ``_refresh_regions``
        dispatches ``bridge.get_memory_map`` through
        ``run_bridge_coroutine_async`` (faked here to capture ``on_success``),
        and the captured callback is invoked with 5 synthetic region objects.
        Only 2 belong to "target.dll". A reverted fix that sets the label from
        ``len(typed_result)`` before applying the filter would leave the label
        at "5 regions"; the fixed code must show "2 regions".

        Args:
            memory_tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(memory_tab, "_bridge", SimpleNamespace(get_memory_map=lambda **_kw: object()))
        _set_private(memory_tab, "_attached_pid", 4321)

        captured: list[Callable[[object], None]] = []
        monkeypatch.setattr(_async_bridge_mod, "run_bridge_coroutine_async", _capture_dispatch(captured))

        _region_filter(memory_tab).setText("target.dll")

        refresh = getattr(memory_tab, "_refresh_regions")
        refresh()

        assert captured, "run_bridge_coroutine_async must be dispatched by _refresh_regions"

        regions = [
            SimpleNamespace(base_address=0x0, size=0x1000, protection="", state="MEM_FREE", type="", module_name=None),
            SimpleNamespace(
                base_address=0x7FF600000000,
                size=0x2000,
                protection="PAGE_EXECUTE_READ",
                state="MEM_COMMIT",
                type="MEM_IMAGE",
                module_name="target.dll",
            ),
            SimpleNamespace(
                base_address=0x7FF600002000,
                size=0x1000,
                protection="PAGE_READWRITE",
                state="MEM_COMMIT",
                type="MEM_IMAGE",
                module_name="target.dll",
            ),
            SimpleNamespace(
                base_address=0x7FFE00000000,
                size=0x1000,
                protection="PAGE_READONLY",
                state="MEM_COMMIT",
                type="MEM_IMAGE",
                module_name="ntdll.dll",
            ),
            SimpleNamespace(
                base_address=0x7FFE10000000,
                size=0x1000,
                protection="PAGE_READONLY",
                state="MEM_COMMIT",
                type="MEM_IMAGE",
                module_name="kernel32.dll",
            ),
        ]
        captured[0](regions)

        label = _region_count_label(memory_tab)
        assert label.text() == "2 regions", (
            f"Expected filtered count '2 regions' (target.dll rows) after refresh with a pre-set filter; "
            f"got {label.text()!r} -- S14-D15 not fixed"
        )


class TestModuleCountReflectsFilteredRows:
    """S14-D15: ModulesTab's '_mod_count' label tracks visible, not total, rows."""

    def test_filter_updates_module_count_to_visible_rows(self, modules_tab: ModulesTab) -> None:
        """Applying a filter that hides tree items updates the count to the visible total.

        Args:
            modules_tab: ModulesTab fixture.
        """
        tree = _mod_tree(modules_tab)
        names = ["ntdll.dll", "kernel32.dll", "user32.dll"]
        for name in names:
            QTreeWidgetItem(tree, [name, "0x0", "0 bytes", "", "0x0"])

        label = _mod_count_label(modules_tab)

        _mod_filter(modules_tab).setText("ntdll")

        root = tree.invisibleRootItem()
        assert root is not None
        visible = 0
        for i in range(root.childCount()):
            child = root.child(i)
            if child is not None and not child.isHidden():
                visible += 1
        assert visible == 1, "sanity check: filter must hide 2 of 3 modules"
        assert label.text() == "1 modules", (
            f"Expected count label to show the FILTERED count '1 modules' after filtering to ntdll.dll; "
            f"got {label.text()!r} -- S14-D15 not fixed (label still shows the unfiltered total)"
        )

    def test_refresh_modules_count_reflects_preexisting_filter(
        self,
        modules_tab: ModulesTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A full refresh with a filter already typed shows the filtered count, not the raw bridge total.

        Exercises ``_refresh_modules`` end-to-end via a faked
        ``run_bridge_coroutine_async`` capturing ``on_success``, then invokes
        it with 4 synthetic module objects while a "target" filter is set that
        matches only 1 of them. A reverted fix would leave the label at
        "4 modules"; the fixed code must show "1 modules".

        Args:
            modules_tab: ModulesTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(modules_tab, "_bridge", SimpleNamespace(get_modules=lambda _pid: object()))
        _set_private(modules_tab, "_attached_pid", 4321)

        captured: list[Callable[[object], None]] = []
        monkeypatch.setattr(_async_bridge_mod, "run_bridge_coroutine_async", _capture_dispatch(captured))

        _mod_filter(modules_tab).setText("target")

        refresh = getattr(modules_tab, "_refresh_modules")
        refresh()

        assert captured, "run_bridge_coroutine_async must be dispatched by _refresh_modules"

        modules = [
            SimpleNamespace(name="target.dll", base_address=0x7FF600000000, size=0x1000, path="C:\\target.dll", entry_point=0x7FF600001000),
            SimpleNamespace(name="ntdll.dll", base_address=0x7FFE00000000, size=0x2000, path="C:\\Windows\\ntdll.dll", entry_point=0x0),
            SimpleNamespace(
                name="kernel32.dll",
                base_address=0x7FFE10000000,
                size=0x2000,
                path="C:\\Windows\\kernel32.dll",
                entry_point=0x0,
            ),
            SimpleNamespace(name="user32.dll", base_address=0x7FFE20000000, size=0x2000, path="C:\\Windows\\user32.dll", entry_point=0x0),
        ]
        captured[0](modules)

        label = _mod_count_label(modules_tab)
        assert label.text() == "1 modules", (
            f"Expected filtered count '1 modules' (target.dll only) after refresh with a pre-set filter; "
            f"got {label.text()!r} -- S14-D15 not fixed"
        )
