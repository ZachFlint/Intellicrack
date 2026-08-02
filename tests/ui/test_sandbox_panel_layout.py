# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the sandbox panel layout hardening.

Guards the fixes that stop the sandbox panel from smashing its controls when
docked narrow: the execution-control cluster is wrapped in a scroll area, the
timeout/memory spin boxes and the path/argument/command/profile/diff fields
carry readable minimum widths, and the toolbar's many action buttons are
grouped into dropdown menus whose actions remain individually enable-toggled
and connected to their handlers.
"""

from __future__ import annotations

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QScrollArea, QSplitter, QTabWidget, QToolButton

from intellicrack.ui.overflow_toolbar import OverflowToolBar
from intellicrack.ui.panels.sandbox_panel import SandboxPanel


_MIN_SPIN_WIDTH = 110
_MIN_FIELD_WIDTH = 160


@pytest.mark.usefixtures("qapp")
class TestSandboxContentSplitter:
    """The controls/output divider must be a genuinely resizable vertical splitter."""

    @staticmethod
    def test_content_is_two_pane_non_collapsible_vertical_splitter() -> None:
        """The panel content must be a vertical QSplitter with two non-collapsible panes."""
        panel = SandboxPanel()
        splitter = panel.findChild(QSplitter)
        assert splitter is not None, "sandbox content must be built around a QSplitter"
        assert splitter.orientation() == Qt.Orientation.Vertical
        assert splitter.count() == 2, "splitter must divide the control cluster from the output tabs"
        assert not splitter.childrenCollapsible(), "neither pane may collapse to nothing"

    @staticmethod
    def test_splitter_panes_can_be_redistributed() -> None:
        """Dragging must be possible: the two panes carry min sizes that leave slack to move."""
        panel = SandboxPanel()
        splitter = panel.findChild(QSplitter)
        assert splitter is not None
        top = splitter.widget(0)
        bottom = splitter.widget(1)
        assert isinstance(top, QScrollArea)
        assert isinstance(bottom, QTabWidget)
        available = 900
        splitter.resize(600, available)
        slack = available - (top.minimumSizeHint().height() + bottom.minimumSizeHint().height())
        assert slack > 0, "panes' minimum heights must leave room for the handle to travel"
        splitter.setSizes([700, 200])
        assert splitter.sizes()[0] > splitter.sizes()[1], "explicit resize must redistribute pane heights"


@pytest.mark.usefixtures("qapp")
class TestSandboxControlClusterScroll:
    """The execution-control cluster must be scroll-wrapped so it never clips."""

    @staticmethod
    def test_control_cluster_wrapped_in_scroll_area() -> None:
        """The panel must contain a QScrollArea wrapping its execution controls."""
        panel = SandboxPanel()
        assert panel.findChild(QScrollArea) is not None, "execution controls must be wrapped in a scroll area"


@pytest.mark.usefixtures("qapp")
class TestSandboxInputMinimumWidths:
    """Numeric and text inputs must reserve enough width that their contents are legible."""

    @staticmethod
    def test_spinboxes_have_minimum_width() -> None:
        """Timeout and memory spin boxes must not collapse below a readable width."""
        panel = SandboxPanel()
        assert panel._timeout_spin.minimumWidth() >= _MIN_SPIN_WIDTH
        assert panel._memory_limit_spin.minimumWidth() >= _MIN_SPIN_WIDTH

    @staticmethod
    def test_text_fields_have_minimum_width() -> None:
        """Every execution/analysis text field must reserve a readable minimum width."""
        panel = SandboxPanel()
        fields = (
            panel._binary_path_input,
            panel._args_input,
            panel._cmd_input,
            panel._anti_evasion_profile_input,
            panel._diff_instance_a_input,
            panel._diff_instance_b_input,
        )
        for field in fields:
            assert field.minimumWidth() >= _MIN_FIELD_WIDTH


@pytest.mark.usefixtures("qapp")
class TestSandboxToolbarGrouping:
    """The crowded toolbar must be grouped into dropdown menus, not a flat button pile."""

    @staticmethod
    def test_toolbar_exposes_grouped_menu_buttons() -> None:
        """The toolbar must carry the five grouped dropdown buttons."""
        panel = SandboxPanel()
        toolbar = panel.findChild(OverflowToolBar)
        assert toolbar is not None
        menu_titles = {button.text() for button in toolbar.findChildren(QToolButton) if button.objectName() == "tool_menu_button"}
        assert {"Snapshots", "Capture", "Analysis", "Transfer", "VM Control"} <= menu_titles

    @staticmethod
    def test_grouped_controls_are_connected_actions() -> None:
        """Every grouped control must be a QAction wired to exactly one handler."""
        panel = SandboxPanel()
        grouped = (
            panel.snapshot_btn,
            panel.restore_btn,
            panel.delete_snap_btn,
            panel.screenshot_btn,
            panel.pcap_btn,
            panel.memdump_btn,
            panel.extract_files_btn,
            panel.yara_btn,
            panel.iocs_btn,
            panel.timeline_btn,
            panel.behaviors_btn,
            panel.copy_in_btn,
            panel.copy_out_btn,
            panel.continue_btn,
            panel.pause_btn,
        )
        for action in grouped:
            assert isinstance(action, QAction)
            assert action.receivers(action.triggered) >= 1, "grouped action must be connected to its handler"


@pytest.mark.usefixtures("qapp")
class TestSandboxGroupedEnableState:
    """Grouping must preserve the sandbox-active enable/disable wiring."""

    @staticmethod
    def test_grouped_actions_start_disabled() -> None:
        """Grouped controls must be disabled until a sandbox is active."""
        panel = SandboxPanel()
        assert not panel.snapshot_btn.isEnabled()
        assert not panel.pcap_btn.isEnabled()
        assert not panel.copy_in_btn.isEnabled()
        assert not panel.continue_btn.isEnabled()

    @staticmethod
    def test_activate_then_deactivate_toggles_grouped_actions() -> None:
        """Activating then deactivating the sandbox must enable then disable the grouped actions.

        QEMU is selected because the snapshot and VM-control actions are gated
        on the backend that actually implements them (S17-D10).
        """
        panel = SandboxPanel()
        panel.sandbox_type_combo.setCurrentText("QEMU")

        panel._set_sandbox_controls_active(active=True)
        assert panel.snapshot_btn.isEnabled()
        assert panel.restore_btn.isEnabled()
        assert panel.delete_snap_btn.isEnabled()
        assert panel.screenshot_btn.isEnabled()
        assert panel.pcap_btn.isEnabled()
        assert panel.behaviors_btn.isEnabled()
        assert panel.copy_out_btn.isEnabled()
        assert panel.pause_btn.isEnabled()

        panel._set_sandbox_controls_active(active=False)
        assert not panel.snapshot_btn.isEnabled()
        assert not panel.pause_btn.isEnabled()
