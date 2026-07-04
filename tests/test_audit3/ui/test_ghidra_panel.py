# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for GhidraPanel audit3 F-0005 remediation.

Verifies that the labels refresh action requires a valid user-supplied address
and never silently substitutes 0 when the input is empty or unparsable.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtWidgets import QLineEdit, QPushButton

from intellicrack.bridges.base import BridgeState
from intellicrack.ui.panels import ghidra_panel as ghidra_module
from intellicrack.ui.panels.ghidra_panel import GhidraPanel


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from intellicrack.bridges.ghidra import GhidraBridge


class _RecordingBridge:
    """Recording stub that captures get_labels invocations."""

    calls: list[int]
    state: BridgeState

    def __init__(self) -> None:
        """Initialise an empty call log and a ready BridgeState."""
        self.calls = []
        self.state = BridgeState(connected=True, tool_running=True)

    async def get_labels(self, address: int, radius: int = 0x100) -> list[dict[str, Any]]:
        """Record an invocation and return an empty label list.

        Args:
            address: Address argument supplied by the panel.
            radius: Search radius (recorded only via the call counter).

        Returns:
            list[dict[str, Any]]: Always an empty list; the panel only needs a coroutine.
        """
        del radius
        self.calls.append(address)
        return []


def _attach_bridge(panel: GhidraPanel, bridge: _RecordingBridge) -> None:
    """Attach a recording bridge to the panel.

    Bypasses set_bridge's nominal type signature using cast so the recording
    stub can satisfy the runtime contract without subclassing the full
    GhidraBridge surface.

    Args:
        panel: The GhidraPanel under test.
        bridge: The recording stub to attach.
    """
    panel.set_bridge(cast("GhidraBridge", bridge))


def _install_sync_run_async(
    panel: GhidraPanel,
    captured: list[Coroutine[Any, Any, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Patch run_bridge_coroutine_logged with a synchronous capture-and-drive sink.

    The real implementation hands the coroutine off to a background thread;
    tests need deterministic, in-thread observation. Each captured coroutine is
    driven to completion synchronously via asyncio.new_event_loop().run_until_complete
    so the bridge stub records the call and no "coroutine was never awaited"
    warning is emitted. The legacy _run_async indirection is also patched for
    any call site that still routes through the panel base class.

    Args:
        panel: The GhidraPanel under test.
        captured: List that receives every coroutine handed to the dispatcher.
        monkeypatch: Pytest monkeypatch fixture used to restore the module-level
            ``run_bridge_coroutine_logged`` reference after the test.
    """

    def _capture_logged(
        coro: Coroutine[Any, Any, Any],
        on_success: object = None,
        on_error: object = None,
        parent: object = None,
        **kwargs: object,
    ) -> None:
        """Capture and synchronously drive the coroutine to completion.

        Args:
            coro: Coroutine produced by the bridge call.
            on_success: Unused success callback.
            on_error: Unused error callback.
            parent: Unused Qt parent argument.
            **kwargs: Remaining wrapper arguments (event, logger, level, context).
        """
        del on_success, on_error, parent, kwargs
        captured.append(coro)
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(coro)
        finally:
            loop.close()

    def _capture_legacy(
        coro: Coroutine[Any, Any, Any],
        on_success: object = None,
        on_error: object = None,
    ) -> None:
        """Capture coroutines dispatched through the legacy panel ``_run_async``.

        Args:
            coro: Coroutine produced by the bridge call.
            on_success: Unused success callback.
            on_error: Unused error callback.
        """
        del on_success, on_error
        captured.append(coro)
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(coro)
        finally:
            loop.close()

    monkeypatch.setattr(ghidra_module, "run_bridge_coroutine_logged", _capture_logged)
    setattr(panel, "_run_async", _capture_legacy)


def _get_label_addr_input(panel: GhidraPanel) -> QLineEdit:
    """Locate the labels-tab address input widget by objectName.

    Args:
        panel: The GhidraPanel under test.

    Returns:
        QLineEdit: The address-input QLineEdit named ``label_addr_input``.
    """
    widget = panel.findChild(QLineEdit, "label_addr_input")
    assert widget is not None, "GhidraPanel must expose a QLineEdit named 'label_addr_input'"
    return widget


def _click_refresh_labels(panel: GhidraPanel) -> None:
    """Trigger the Refresh Labels button via its connected signal.

    Args:
        panel: The GhidraPanel under test.
    """
    button = panel.findChild(QPushButton, "refresh_labels_btn")
    assert button is not None, "GhidraPanel must expose a QPushButton named 'refresh_labels_btn'"
    button.click()


@pytest.mark.usefixtures("qapp")
class TestGhidraPanelRefreshLabels:
    """Audit3 F-0005: empty/invalid address must not invoke the bridge."""

    @staticmethod
    def test_empty_address_does_not_call_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
        """Empty input must short-circuit and not produce a get_labels call.

        Args:
            monkeypatch: Pytest monkeypatch fixture for patching the bridge dispatcher.
        """
        panel = GhidraPanel()
        bridge = _RecordingBridge()
        _attach_bridge(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_run_async(panel, captured, monkeypatch)

        _get_label_addr_input(panel).setText("")
        _click_refresh_labels(panel)

        assert bridge.calls == []
        assert not captured

    @staticmethod
    def test_empty_address_sets_status_error(monkeypatch: pytest.MonkeyPatch) -> None:
        """Empty input must surface a UI error via the status label.

        Args:
            monkeypatch: Pytest monkeypatch fixture for patching the bridge dispatcher.
        """
        panel = GhidraPanel()
        bridge = _RecordingBridge()
        _attach_bridge(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_run_async(panel, captured, monkeypatch)

        _get_label_addr_input(panel).setText("   ")
        _click_refresh_labels(panel)

        assert panel.status_label is not None
        text = panel.status_label.text()
        assert "address" in text.lower()
        assert "0x0" not in text
        assert bridge.calls == []

    @staticmethod
    def test_invalid_address_does_not_call_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
        """Unparsable input must short-circuit and not produce a get_labels call.

        Args:
            monkeypatch: Pytest monkeypatch fixture for patching the bridge dispatcher.
        """
        panel = GhidraPanel()
        bridge = _RecordingBridge()
        _attach_bridge(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_run_async(panel, captured, monkeypatch)

        _get_label_addr_input(panel).setText("not-a-hex-address")
        _click_refresh_labels(panel)

        assert bridge.calls == []
        assert not captured
        assert panel.status_label is not None
        assert "invalid" in panel.status_label.text().lower()

    @staticmethod
    def test_valid_hex_address_invokes_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-empty hex address must be passed verbatim to the bridge.

        Args:
            monkeypatch: Pytest monkeypatch fixture for patching the bridge dispatcher.
        """
        panel = GhidraPanel()
        bridge = _RecordingBridge()
        _attach_bridge(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_run_async(panel, captured, monkeypatch)

        _get_label_addr_input(panel).setText("0x401000")
        _click_refresh_labels(panel)

        assert bridge.calls == [0x401000]
        assert len(captured) == 1

    @staticmethod
    def test_valid_decimal_address_invokes_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-empty decimal address must be parsed and forwarded.

        Args:
            monkeypatch: Pytest monkeypatch fixture for patching the bridge dispatcher.
        """
        panel = GhidraPanel()
        bridge = _RecordingBridge()
        _attach_bridge(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_run_async(panel, captured, monkeypatch)

        _get_label_addr_input(panel).setText("4198400")
        _click_refresh_labels(panel)

        assert bridge.calls == [4198400]
        assert len(captured) == 1
