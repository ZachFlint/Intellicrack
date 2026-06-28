# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for sandbox panel fixes (Fixes 1 partial, 4).

Validates:
- Fix 1: Non-blocking bridge call infrastructure in sandbox panel
- Fix 4: Sandbox type combo wiring and Docker removal
"""

from __future__ import annotations

import pytest

from intellicrack.sandbox.manager import SandboxManager
from intellicrack.ui.panels.sandbox_panel import SandboxPanel


@pytest.mark.usefixtures("qapp")
class TestSandboxComboWiring:
    """Fix 4: Sandbox type combo box wiring tests."""

    @staticmethod
    def test_combo_has_two_items() -> None:
        """Verify combo box contains exactly the two expected sandbox type entries in order."""
        panel = SandboxPanel()
        combo = panel.sandbox_type_combo
        items = [combo.itemText(i) for i in range(combo.count())]
        assert items == ["Windows Sandbox", "QEMU"]

    @staticmethod
    def test_combo_items_are_correct() -> None:
        """Verify combo box item texts match exactly Windows Sandbox then QEMU with no extras."""
        panel = SandboxPanel()
        combo = panel.sandbox_type_combo
        items = [combo.itemText(i) for i in range(combo.count())]
        assert items == ["Windows Sandbox", "QEMU"]

    @staticmethod
    def test_docker_not_in_combo() -> None:
        """Verify Docker is not present in the combo box."""
        panel = SandboxPanel()
        combo = panel.sandbox_type_combo
        items = [combo.itemText(i) for i in range(combo.count())]
        assert "Docker" not in items

    @staticmethod
    def test_selected_sandbox_type_windows() -> None:
        """Verify Windows Sandbox combo selection maps to the 'windows' sandbox type."""
        panel = SandboxPanel()
        panel.sandbox_type_combo.setCurrentText("Windows Sandbox")
        result = panel._selected_sandbox_type()
        assert result == "windows"

    @staticmethod
    def test_selected_sandbox_type_qemu() -> None:
        """Verify QEMU combo selection maps to the 'qemu' sandbox type."""
        panel = SandboxPanel()
        panel.sandbox_type_combo.setCurrentText("QEMU")
        result = panel._selected_sandbox_type()
        assert result == "qemu"

    @staticmethod
    def test_selected_sandbox_type_non_qemu_text_falls_back_to_windows() -> None:
        """Verify any non-QEMU combo text maps to 'windows' via the else-fallback branch.

        Temporarily adds a Docker entry to the combo, selects it, and asserts
        that _selected_sandbox_type returns 'windows' because only 'QEMU' maps
        to 'qemu' — all other texts use the else branch.
        """
        panel = SandboxPanel()
        panel.sandbox_type_combo.addItem("Docker")
        panel.sandbox_type_combo.setCurrentText("Docker")
        assert panel.sandbox_type_combo.currentText() == "Docker"
        result = panel._selected_sandbox_type()
        assert result == "windows"


@pytest.mark.usefixtures("qapp")
class TestSandboxManagerWiring:
    """Fix 4: SandboxManager integration tests."""

    @staticmethod
    def test_set_sandbox_manager_stores_reference() -> None:
        """Verify set_sandbox_manager stores the manager instance."""
        panel = SandboxPanel()
        assert panel._sandbox_manager is None

        manager = SandboxManager()
        panel.set_sandbox_manager(manager)
        assert panel._sandbox_manager is manager

    @staticmethod
    def test_no_backend_shows_warning() -> None:
        """Verify create with no bridge configured logs a warning."""
        panel = SandboxPanel()
        panel._sandbox = None
        panel._sandbox_manager = None
        panel._bridge = None

        panel._on_create()

        output_text = panel._console_output.toPlainText()
        assert "No sandbox bridge configured" in output_text


@pytest.mark.usefixtures("qapp")
class TestSandboxControlState:
    """Fix 1: Button state management tests."""

    @staticmethod
    def test_initial_button_states() -> None:
        """Verify buttons have correct initial enabled/disabled state."""
        panel = SandboxPanel()

        assert panel.create_btn.isEnabled()
        assert not panel.destroy_btn.isEnabled()
        assert not panel.restart_btn.isEnabled()
        assert not panel._run_btn.isEnabled()
        assert not panel.snapshot_btn.isEnabled()
        assert not panel.restore_btn.isEnabled()

    @staticmethod
    def test_set_controls_active_enables_buttons() -> None:
        """Verify _set_sandbox_controls_active(active=True) enables sandbox buttons."""
        panel = SandboxPanel()
        panel._set_sandbox_controls_active(active=True)

        assert not panel.create_btn.isEnabled()
        assert panel.destroy_btn.isEnabled()
        assert panel.restart_btn.isEnabled()
        assert panel._run_btn.isEnabled()
        assert panel.snapshot_btn.isEnabled()
        assert panel.restore_btn.isEnabled()

    @staticmethod
    def test_set_controls_inactive_disables_buttons() -> None:
        """Verify _set_sandbox_controls_active(active=False) disables sandbox buttons."""
        panel = SandboxPanel()
        panel._set_sandbox_controls_active(active=True)
        panel._set_sandbox_controls_active(active=False)

        assert panel.create_btn.isEnabled()
        assert not panel.destroy_btn.isEnabled()
        assert not panel.restart_btn.isEnabled()


@pytest.mark.usefixtures("qapp")
class TestSandboxPanelLifecycle:
    """Tests for sandbox panel start/stop lifecycle."""

    @staticmethod
    def test_start_tool_returns_true() -> None:
        """Verify start_tool returns True."""
        panel = SandboxPanel()
        assert panel.start_tool() is True

    @staticmethod
    def test_stop_tool_returns_true() -> None:
        """Verify stop_tool returns True without active sandbox."""
        panel = SandboxPanel()
        assert panel.stop_tool() is True

    @staticmethod
    def test_create_success_handler_updates_ui() -> None:
        """Verify _on_create_success properly updates the UI state."""
        panel = SandboxPanel()

        panel._on_create_success(None)

        assert panel._status_indicator.text() == "Active"
        assert panel.destroy_btn.isEnabled()
        assert panel._run_btn.isEnabled()

    @staticmethod
    def test_destroy_success_handler_updates_ui() -> None:
        """Verify _on_destroy_success properly resets the UI state."""
        panel = SandboxPanel()
        panel._set_sandbox_controls_active(active=True)

        panel._on_destroy_success(None)

        assert panel._status_indicator.text() == "Inactive"
        assert panel.sandbox_id is None
        assert not panel.destroy_btn.isEnabled()
