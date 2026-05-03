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

from intellicrack.bridges.base import BridgeState
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.ui.panels.ghidra_panel import GhidraPanel


if TYPE_CHECKING:
    from collections.abc import Coroutine


class _RecordingBridge:
    """Recording stub that captures get_labels invocations.

    Attributes:
        calls: Ordered list of address arguments passed to get_labels.
        state: Bridge readiness state mirroring the real BridgeState contract.
    """

    def __init__(self) -> None:
        """Initialise an empty call log and a ready BridgeState."""
        self.calls: list[int] = []
        self.state: BridgeState = BridgeState(connected=True, tool_running=True)

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


def _install_sync_run_async(panel: GhidraPanel, captured: list[Coroutine[Any, Any, Any]]) -> None:
    """Replace the panel's _run_async with a synchronous capture-and-drive sink.

    The real implementation hands the coroutine off to a background thread;
    tests need deterministic, in-thread observation. Each captured coroutine is
    driven to completion synchronously via asyncio.new_event_loop().run_until_complete
    so the bridge stub records the call and no "coroutine was never awaited"
    warning is emitted.

    Args:
        panel: The GhidraPanel under test.
        captured: List that receives every coroutine handed to _run_async.
    """

    def _capture(
        coro: Coroutine[Any, Any, Any],
        on_success: object = None,
        on_error: object = None,
    ) -> None:
        """Capture and synchronously drive the coroutine to completion.

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

    panel._run_async = _capture


@pytest.mark.usefixtures("qapp")
class TestGhidraPanelRefreshLabels:
    """Audit3 F-0005: empty/invalid address must not invoke the bridge."""

    @staticmethod
    def test_empty_address_does_not_call_bridge() -> None:
        """Empty input must short-circuit and not produce a get_labels call."""
        panel = GhidraPanel()
        bridge = _RecordingBridge()
        _attach_bridge(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_run_async(panel, captured)

        panel._label_addr_input.setText("")
        panel._on_refresh_labels()

        assert bridge.calls == []
        assert captured == []

    @staticmethod
    def test_empty_address_sets_status_error() -> None:
        """Empty input must surface a UI error via the status label."""
        panel = GhidraPanel()
        bridge = _RecordingBridge()
        _attach_bridge(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_run_async(panel, captured)

        panel._label_addr_input.setText("   ")
        panel._on_refresh_labels()

        assert panel.status_label is not None
        text = panel.status_label.text()
        assert "address" in text.lower()
        assert "0x0" not in text
        assert bridge.calls == []

    @staticmethod
    def test_invalid_address_does_not_call_bridge() -> None:
        """Unparsable input must short-circuit and not produce a get_labels call."""
        panel = GhidraPanel()
        bridge = _RecordingBridge()
        _attach_bridge(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_run_async(panel, captured)

        panel._label_addr_input.setText("not-a-hex-address")
        panel._on_refresh_labels()

        assert bridge.calls == []
        assert captured == []
        assert panel.status_label is not None
        assert "invalid" in panel.status_label.text().lower()

    @staticmethod
    def test_valid_hex_address_invokes_bridge() -> None:
        """A non-empty hex address must be passed verbatim to the bridge."""
        panel = GhidraPanel()
        bridge = _RecordingBridge()
        _attach_bridge(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_run_async(panel, captured)

        panel._label_addr_input.setText("0x401000")
        panel._on_refresh_labels()

        assert bridge.calls == [0x401000]
        assert len(captured) == 1

    @staticmethod
    def test_valid_decimal_address_invokes_bridge() -> None:
        """A non-empty decimal address must be parsed and forwarded."""
        panel = GhidraPanel()
        bridge = _RecordingBridge()
        _attach_bridge(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_run_async(panel, captured)

        panel._label_addr_input.setText("4198400")
        panel._on_refresh_labels()

        assert bridge.calls == [4198400]
        assert len(captured) == 1
