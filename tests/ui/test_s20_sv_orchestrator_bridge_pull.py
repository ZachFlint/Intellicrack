# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for S20-D04: the Stack Viewer must pull already-live bridges.

Before the fix, ``X64DbgStackSource.is_connected``/``FridaStackSource.is_connected``
only ever consulted a bridge previously handed in through ``set_bridge`` -- the
push-based path fired by :mod:`intellicrack.ui.tools` when a NEW x64dbg/Frida
panel tab is created. Opening View -> Stack Viewer while an x64dbg session was
already paused and Frida was already attached (bridges connected *before* the
Stack Viewer panel existed) left both sources permanently reporting "Not
connected" and ``stack_frames_refreshed frame_count=0``, because nothing ever
pulled the bridges that were already live.

The fix wires a live, duck-typed "bridge provider" onto the built-in
``"x64dbg"``/``"Frida"`` sources whenever :meth:`StackViewerPanel.add_source` is
handed an orchestrator/registry-like object (the reserved name ``"orchestrator"``,
as used by ``ToolOutputPanel.add_stack_panel``) instead of a real
``StackDataSource``. That provider is re-invoked on every connection check and
refresh -- never cached -- so an already-connected bridge is detected
immediately and a later bridge swap or detach is reflected on the very next
check. The same wiring also produces a genuinely functional
``OrchestratorStackSource`` for the previously untested ``"orchestrator"`` combo
entry instead of one that raises when selected.

These tests build the real ``StackViewerPanel`` widget and drive it through the
exact ``add_source("orchestrator", provider)`` call site
``ToolOutputPanel.add_stack_panel`` uses, with minimal fake bridge/provider
objects standing in only for the external x64dbg/Frida bridge classes (which
require a live debugging session to construct for real).
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import TYPE_CHECKING, Final

from intellicrack.ui.panels.stack_viewer import StackViewerPanel


if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtWidgets import QApplication


_MAX_WAIT_S: Final[float] = 6.0
_POLL_INTERVAL_S: Final[float] = 0.02


def _pump_until(qapp: QApplication, predicate: Callable[[], bool], timeout_s: float = _MAX_WAIT_S) -> bool:
    """Pump the Qt event loop until ``predicate`` is satisfied or ``timeout_s`` elapses.

    Args:
        qapp: The QApplication instance whose event loop is pumped, so the
            cross-thread ``BridgeCallWorker`` result signal can be delivered.
        predicate: Zero-argument callable polled after each pump.
        timeout_s: Maximum wall-clock seconds to keep pumping.

    Returns:
        bool: True if ``predicate`` became truthy before the deadline.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        qapp.processEvents()
        time.sleep(_POLL_INTERVAL_S)
    return bool(predicate())


class _FakeReadyState:
    """Stand-in for ``X64DbgBridgeState``, exposing only ``is_ready``."""

    def __init__(self, *, ready: bool) -> None:
        """Initialize the fake state with a fixed readiness value.

        Args:
            ready: The value ``is_ready`` should report.
        """
        self._ready = ready

    def is_ready(self) -> bool:
        """Report the fixed readiness value configured at construction.

        Returns:
            bool: The ``ready`` value passed to the constructor.
        """
        return self._ready


class _FakeX64DbgBridge:
    """Minimal stand-in for ``X64DbgBridge`` exercising the real stack-source contract."""

    def __init__(self, *, ready: bool, frame_count: int = 0) -> None:
        """Initialize the fake bridge with a fixed readiness and frame count.

        Args:
            ready: Whether ``state.is_ready()`` should report True.
            frame_count: Number of synthetic stack frames ``get_stack_trace``
                returns on each call.
        """
        self.state = _FakeReadyState(ready=ready)
        self.stack_trace_calls = 0
        self._frame_count = frame_count

    async def get_stack_trace(self) -> list[SimpleNamespace]:
        """Return synthetic raw stack-trace entries, counting the call.

        Returns:
            list[SimpleNamespace]: One entry per configured frame, each
            carrying the attributes ``X64DbgStackSource.frames_from_raw``
            reads via ``getattr``.
        """
        self.stack_trace_calls += 1
        return [
            SimpleNamespace(
                return_address=0x1000 + i,
                function_name=f"func_{i}",
                module_name="test.exe",
                offset=0,
                frame_pointer=0,
                stack_pointer=0,
            )
            for i in range(self._frame_count)
        ]


class _FakeAttachedState:
    """Stand-in for ``FridaBridgeState``, exposing only ``process_attached``."""

    def __init__(self, *, attached: bool) -> None:
        """Initialize the fake state with a fixed attachment value.

        Args:
            attached: The value ``process_attached`` should report.
        """
        self.process_attached = attached


class _FakeFridaBridge:
    """Minimal stand-in for ``FridaBridge`` exercising the real stack-source contract."""

    def __init__(self, *, attached: bool) -> None:
        """Initialize the fake bridge with a fixed attachment state.

        Args:
            attached: Whether ``state.process_attached`` should report True.
        """
        self.state = _FakeAttachedState(attached=attached)
        self.backtrace_calls = 0

    async def get_backtrace(self) -> list[SimpleNamespace]:
        """Return an empty synthetic backtrace, counting the call.

        Returns:
            list[SimpleNamespace]: Always empty; only the call count and the
            live-connection wiring matter to these tests.
        """
        self.backtrace_calls += 1
        return []


class _FakeOrchestrator:
    """Stand-in for the ``ToolOutputPanel`` host passed to ``add_source("orchestrator", ...)``.

    Exposes only the two public attributes the Stack Viewer actually reads
    (``x64dbg_bridge``/``frida_bridge``), deliberately implementing none of
    :class:`StackDataSource` so a regression that treats this object as a
    selectable source directly (instead of wiring it as a bridge provider)
    is caught by an ``AttributeError`` rather than silently degrading.
    """

    def __init__(self, x64dbg_bridge: object | None = None, frida_bridge: object | None = None) -> None:
        """Initialize the fake orchestrator with optional live bridges.

        Args:
            x64dbg_bridge: The live x64dbg bridge to expose, or None.
            frida_bridge: The live Frida bridge to expose, or None.
        """
        self.x64dbg_bridge = x64dbg_bridge
        self.frida_bridge = frida_bridge


def test_orchestrator_wiring_detects_already_connected_x64dbg_bridge(qapp: QApplication) -> None:
    """Opening the panel while x64dbg is already paused must show Connected without a signal.

    Args:
        qapp: Session QApplication fixture from ``tests/ui/conftest.py``.
    """
    panel = StackViewerPanel()
    assert panel.status_label.text() == "Not connected", "sanity: a fresh panel starts disconnected"

    bridge = _FakeX64DbgBridge(ready=True)
    provider = _FakeOrchestrator(x64dbg_bridge=bridge)

    panel.add_source("orchestrator", provider)

    assert panel.status_label.text() == "Connected", (
        "an x64dbg bridge that was already live before the Stack Viewer opened must be detected on open, not only via a future signal"
    )
    qapp.processEvents()


def test_orchestrator_wiring_detects_already_connected_frida_bridge(qapp: QApplication) -> None:
    """Switching Source to Frida while it is already attached must show Connected.

    Args:
        qapp: Session QApplication fixture from ``tests/ui/conftest.py``.
    """
    panel = StackViewerPanel()
    bridge = _FakeFridaBridge(attached=True)
    provider = _FakeOrchestrator(frida_bridge=bridge)

    panel.add_source("orchestrator", provider)
    panel._source_combo.setCurrentText("Frida")

    assert panel.status_label.text() == "Connected", (
        "a Frida bridge already attached before the Stack Viewer opened must be detected when Source=Frida is selected"
    )
    qapp.processEvents()


def test_x64dbg_status_does_not_cache_a_stale_bridge(qapp: QApplication) -> None:
    """A bridge detach must be reflected on the very next check, not masked by a cached reference.

    Args:
        qapp: Session QApplication fixture from ``tests/ui/conftest.py``.
    """
    panel = StackViewerPanel()
    bridge = _FakeX64DbgBridge(ready=True)
    provider = _FakeOrchestrator(x64dbg_bridge=bridge)
    panel.add_source("orchestrator", provider)
    assert panel.status_label.text() == "Connected"

    provider.x64dbg_bridge = None
    panel._update_status()

    assert panel.status_label.text() == "Not connected", (
        "the live bridge must be re-pulled from the orchestrator on every check, not cached from the first successful pull"
    )
    qapp.processEvents()


def test_orchestrator_combo_source_is_selectable_without_crashing(qapp: QApplication) -> None:
    """The previously-untested 'orchestrator' combo entry must work, not raise, when selected.

    Args:
        qapp: Session QApplication fixture from ``tests/ui/conftest.py``.
    """
    panel = StackViewerPanel()
    bridge = _FakeX64DbgBridge(ready=True)
    provider = _FakeOrchestrator(x64dbg_bridge=bridge)
    panel.add_source("orchestrator", provider)

    combo_items = [panel._source_combo.itemText(i) for i in range(panel._source_combo.count())]
    assert "orchestrator" in combo_items

    panel._source_combo.setCurrentText("orchestrator")

    assert panel.status_label.text() == "Connected", (
        "selecting 'orchestrator' must reflect the live x64dbg bridge instead of crashing on a bare provider object"
    )
    qapp.processEvents()


def test_add_source_orchestrator_fetches_real_stack_frames_on_open(qapp: QApplication) -> None:
    """Opening the panel with x64dbg already paused must actually fetch and render frames.

    Args:
        qapp: Session QApplication fixture from ``tests/ui/conftest.py``.
    """
    panel = StackViewerPanel()
    bridge = _FakeX64DbgBridge(ready=True, frame_count=3)
    provider = _FakeOrchestrator(x64dbg_bridge=bridge)

    panel.add_source("orchestrator", provider)

    fetched = _pump_until(qapp, lambda: panel._frame_table.rowCount() == 3)

    assert fetched, "the x64dbg stack trace was not fetched and rendered after opening the panel"
    assert panel._frame_count_label.text() == "3 frames"
    assert bridge.stack_trace_calls >= 1, "get_stack_trace must actually be invoked, not skipped due to coro=None"
