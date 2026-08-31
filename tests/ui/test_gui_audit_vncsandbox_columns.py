# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for the sandbox result-tree column-sizing audit finding.

Finding (LOW): the ~15 sandbox result trees (File/Registry changes, six-column
API calls, DLL loads, ...) never sized their columns, so long paths, registry
keys and argument blobs were clipped with no way to read them.

These tests assert the fix: every result tree configures its columns for
``ResizeToContents`` so content is shown in full, and the shared helper applies
that mode to each column.
"""

from __future__ import annotations

import pytest
from PyQt6.QtWidgets import QHeaderView, QTreeWidget, QTreeWidgetItem

from intellicrack.ui.panels import sandbox_panel
from intellicrack.ui.panels.sandbox_panel import SandboxPanel


LONG_PATH = "C:\\Users\\analyst\\AppData\\Local\\Temp\\" + ("nested\\" * 30) + "payload_sample_binary.dll"


def _configure(tree: QTreeWidget) -> None:
    """Invoke the panel's private column-sizing helper on ``tree``.

    Access is via ``getattr`` so the module-private helper can be exercised
    without a direct private import.

    Args:
        tree: The tree widget to configure.
    """
    getattr(sandbox_panel, "_configure_result_columns")(tree)


@pytest.mark.usefixtures("qapp")
class TestColumnHelper:
    """The shared column-sizing helper must size every column to its content."""

    @staticmethod
    def test_helper_sets_resize_to_contents_on_all_columns() -> None:
        """_configure_result_columns must set ResizeToContents on every column."""
        tree = QTreeWidget()
        tree.setColumnCount(3)
        tree.setHeaderLabels(["Operation", "Path", "Details"])

        _configure(tree)

        header = tree.header()
        assert header is not None
        for column in range(3):
            assert header.sectionResizeMode(column) == QHeaderView.ResizeMode.ResizeToContents

    @staticmethod
    def test_long_path_column_grows_to_content() -> None:
        """A long path must widen its column instead of being clipped at a fixed width."""
        short_tree = QTreeWidget()
        short_tree.setColumnCount(3)
        short_tree.setHeaderLabels(["Operation", "Path", "Details"])
        _configure(short_tree)
        _ = QTreeWidgetItem(short_tree, ["write", "C:\\a.txt", "ok"])

        long_tree = QTreeWidget()
        long_tree.setColumnCount(3)
        long_tree.setHeaderLabels(["Operation", "Path", "Details"])
        _configure(long_tree)
        _ = QTreeWidgetItem(long_tree, ["write", LONG_PATH, "ok"])

        assert long_tree.columnWidth(1) > short_tree.columnWidth(1)


@pytest.mark.usefixtures("qapp")
class TestSandboxPanelColumns:
    """The sandbox panel must apply content sizing to its result trees."""

    @staticmethod
    def test_result_trees_use_resize_to_contents() -> None:
        """Representative result trees must have ResizeToContents column sizing."""
        panel = SandboxPanel()

        for attr_name in ("_file_changes_tree", "_api_calls_tree", "_dll_loads_tree"):
            tree = getattr(panel, attr_name)
            header = tree.header()
            assert header is not None
            assert header.sectionResizeMode(0) == QHeaderView.ResizeMode.ResizeToContents
