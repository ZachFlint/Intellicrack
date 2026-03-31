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

from intellicrack.ui.panels.sandbox_panel import SandboxPanel


EXPECTED_COMBO_COUNT = 2


@pytest.mark.usefixtures("qapp")
class TestSandboxComboWiring:
    """Fix 4: Sandbox type combo box wiring tests."""

    @staticmethod
    def test_combo_has_two_items() -> None:
        """Verify combo box has exactly Windows Sandbox and QEMU."""
        panel = SandboxPanel()
        combo = panel.sandbox_type_combo
        assert combo.count() == EXPECTED_COMBO_COUNT

    @staticmethod
    def test_combo_items_are_correct() -> None:
        """Verify combo box items are Windows Sandbox and QEMU only."""
        panel = SandboxPanel()
        combo = panel.sandbox_type_combo
        items = [combo.itemText(i) for i in range(combo.count())]
        assert "Windows Sandbox" in items
        assert "QEMU" in items

    @staticmethod
    def test_docker_not_in_combo() -> None:
        """Verify Docker is not present in the combo box."""
        panel = SandboxPanel()
        combo = panel.sandbox_type_combo
        items = [combo.itemText(i) for i in range(combo.count())]
        assert "Docker" not in items

    @staticmethod
    def test_selected_sandbox_type_windows() -> None:
        """Verify Windows Sandbox selection returns 'windows' type."""
        panel = SandboxPanel()
        panel.sandbox_type_combo.setCurrentText("Windows Sandbox")
        result = panel.selected_sandbox_type()
        assert result == "windows"

    @staticmethod
    def test_selected_sandbox_type_qemu() -> None:
        """Verify QEMU selection returns 'qemu' type."""
        panel = SandboxPanel()
        panel.sandbox_type_combo.setCurrentText("QEMU")
        result = panel.selected_sandbox_type()
        assert result == "qemu"


@pytest.mark.usefixtures("qapp")
class TestSandboxManagerWiring:
    """Fix 4: SandboxManager integration tests."""

    @staticmethod
    def test_set_sandbox_manager_stores_reference() -> None:
        """Verify set_sandbox_manager stores the manager instance."""
        panel = SandboxPanel()
        assert panel.sandbox_manager is None

        sentinel = object()
        if hasattr(panel, "set_sandbox_manager"):
            panel.set_sandbox_manager(sentinel)
        assert panel.sandbox_manager is sentinel

    @staticmethod
    def test_no_backend_shows_warning() -> None:
        """Verify create with no backend or manager logs warning."""
        panel = SandboxPanel()
        panel.sandbox = None
        panel.sandbox_manager = None

        panel.on_create()

        output_text = panel.console_output.toPlainText()
        assert "No sandbox backend configured" in output_text


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
        assert not panel.run_btn.isEnabled()
        assert not panel.snapshot_btn.isEnabled()
        assert not panel.restore_btn.isEnabled()

    @staticmethod
    def test_set_controls_active_enables_buttons() -> None:
        """Verify _set_sandbox_controls_active(True) enables sandbox buttons."""
        panel = SandboxPanel()
        panel.set_sandbox_controls_active(True)

        assert not panel.create_btn.isEnabled()
        assert panel.destroy_btn.isEnabled()
        assert panel.restart_btn.isEnabled()
        assert panel.run_btn.isEnabled()
        assert panel.snapshot_btn.isEnabled()
        assert panel.restore_btn.isEnabled()

    @staticmethod
    def test_set_controls_inactive_disables_buttons() -> None:
        """Verify _set_sandbox_controls_active(False) disables sandbox buttons."""
        panel = SandboxPanel()
        panel.set_sandbox_controls_active(True)
        panel.set_sandbox_controls_active(False)

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

        panel.on_create_success(None)

        assert panel.status_indicator.text() == "Active"
        assert panel.destroy_btn.isEnabled()
        assert panel.run_btn.isEnabled()

    @staticmethod
    def test_destroy_success_handler_updates_ui() -> None:
        """Verify _on_destroy_success properly resets the UI state."""
        panel = SandboxPanel()
        panel.set_sandbox_controls_active(True)

        panel.on_destroy_success(None)

        assert panel.status_indicator.text() == "Inactive"
        assert panel.sandbox_id is None
        assert not panel.destroy_btn.isEnabled()
