"""Tests for ToolOutputPanel and related widgets logic.

Tests interactivity, signal emission, and integration of function list
and cross-reference panels.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.tools import FunctionListPanel, ToolOutputPanel, XRefPanel


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Provide QApplication for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


class TestFunctionListPanel:
    """Tests for FunctionListPanel interactivity."""

    def test_function_selected_signal(self, qapp: QApplication) -> None:
        """Verify function_selected signal is emitted on double click."""
        del qapp
        panel = FunctionListPanel()
        mock_slot = MagicMock()
        panel.function_selected.connect(mock_slot)

        functions = [("main", 0x401000), ("test", 0x402000)]
        panel.set_functions(functions)

        # Simulate double click on first item
        item = panel._list_widget.item(0)
        assert item is not None
        panel._on_item_double_clicked(item)

        mock_slot.assert_called_once_with("main", 0x401000)


class TestXRefPanel:
    """Tests for XRefPanel interactivity."""

    def test_xref_selected_signal(self, qapp: QApplication) -> None:
        """Verify xref_selected signal is emitted on click."""
        del qapp
        panel = XRefPanel()
        mock_slot = MagicMock()
        panel.xref_selected.connect(mock_slot)

        incoming = [(0x401000, "call main")]
        outgoing = [(0x402000, "jump test")]
        panel.set_xrefs(incoming, outgoing)

        # Simulate click on an address item (child of "=== References TO ===")
        root = panel._xref_display.topLevelItem(0)
        assert root is not None
        assert root.text(0) == "=== References TO ==="

        child = root.child(0)
        assert child is not None
        panel._on_item_clicked(child, 0)

        mock_slot.assert_called_once_with(0x401000)


class TestToolOutputPanelIntegration:
    """Tests for ToolOutputPanel signal integration."""

    def test_address_clicked_propagation(self, qapp: QApplication) -> None:
        """Verify signals from sub-panels propagate to address_clicked."""
        del qapp
        panel = ToolOutputPanel()
        mock_slot = MagicMock()
        panel.address_clicked.connect(mock_slot)

        # Emit signal from function list
        panel._func_list.function_selected.emit("main", 0x401000)
        mock_slot.assert_any_call(0x401000)

        # Emit signal from xref panel
        panel._xref_panel.xref_selected.emit(0x402000)
        mock_slot.assert_any_call(0x402000)


class TestMainWindowIntegration:
    """Tests for MainWindow handling of tool panel signals."""

    def test_on_address_clicked_updates_ui(self, qapp: QApplication) -> None:
        """Verify MainWindow handles address_clicked signal."""
        del qapp
        mock_config = MagicMock()
        from unittest.mock import AsyncMock

        mock_orchestrator = MagicMock()
        mock_orchestrator.shutdown = AsyncMock()

        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)

            # Simulate address clicked in tool panel
            window._tool_panel.address_clicked.emit(0x401000)

            # Verify address label updated
            assert "0x00401000" in window._tool_panel._address_label.text()
            window.close()
