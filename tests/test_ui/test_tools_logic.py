"""Tests for ToolOutputPanel and related widgets logic.

Tests interactivity, signal emission, and integration of function list
and cross-reference panels.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.app import MainWindow
from intellicrack.ui.tools import FunctionListPanel, ToolOutputPanel, XRefPanel


_ADDR_MAIN: int = 0x401000
_ADDR_TEST: int = 0x402000


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Provide QApplication for tests.

    Returns:
        QApplication instance for widget testing.
    """
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


class TestFunctionListPanel:
    """Tests for FunctionListPanel interactivity."""

    @staticmethod
    def test_function_selected_signal(_qapp: QApplication) -> None:
        """Verify function_selected signal is emitted on double click."""
        panel = FunctionListPanel()
        mock_slot = MagicMock()
        panel.function_selected.connect(mock_slot)

        functions = [("main", _ADDR_MAIN), ("test", _ADDR_TEST)]
        panel.set_functions(functions)

        item = panel._list_widget.item(0)
        assert item is not None
        panel._on_item_double_clicked(item)

        mock_slot.assert_called_once_with("main", _ADDR_MAIN)


class TestXRefPanel:
    """Tests for XRefPanel interactivity."""

    @staticmethod
    def test_xref_selected_signal(_qapp: QApplication) -> None:
        """Verify xref_selected signal is emitted on click."""
        panel = XRefPanel()
        mock_slot = MagicMock()
        panel.xref_selected.connect(mock_slot)

        incoming = [(_ADDR_MAIN, "call main")]
        outgoing = [(_ADDR_TEST, "jump test")]
        panel.set_xrefs(incoming, outgoing)

        root = panel._xref_display.topLevelItem(0)
        assert root is not None
        assert root.text(0) == "=== References TO ==="

        child = root.child(0)
        assert child is not None
        panel._on_item_clicked(child, 0)

        mock_slot.assert_called_once_with(_ADDR_MAIN)


class TestToolOutputPanelIntegration:
    """Tests for ToolOutputPanel signal integration."""

    @staticmethod
    def test_address_clicked_propagation(_qapp: QApplication) -> None:
        """Verify signals from sub-panels propagate to address_clicked."""
        panel = ToolOutputPanel()
        mock_slot = MagicMock()
        panel.address_clicked.connect(mock_slot)

        panel._func_list.function_selected.emit("main", _ADDR_MAIN)
        mock_slot.assert_any_call(_ADDR_MAIN)

        panel._xref_panel.xref_selected.emit(_ADDR_TEST)
        mock_slot.assert_any_call(_ADDR_TEST)


class TestMainWindowIntegration:
    """Tests for MainWindow handling of tool panel signals."""

    @staticmethod
    def test_on_address_clicked_updates_ui(_qapp: QApplication) -> None:
        """Verify MainWindow handles address_clicked signal."""
        mock_config = MagicMock()
        mock_orchestrator = MagicMock()
        mock_orchestrator.shutdown = AsyncMock()

        with patch("intellicrack.ui.app.SandboxManager"):
            window = MainWindow(mock_config, mock_orchestrator)

            window._tool_panel.address_clicked.emit(_ADDR_MAIN)

            assert "0x00401000" in window._tool_panel._address_label.text()
            window.close()
