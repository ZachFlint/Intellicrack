# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gate for the Ghidra Load-before-headless P2 fix.

Before this fix, clicking "Connect" succeeded even when no headless/GUI
Ghidra bridge server was listening on the target port: the upstream
``ghidra_bridge.GhidraBridge`` client is lazy and never touches the network
in its constructor unless a ``namespace`` is supplied, so
:meth:`GhidraBridge.initialize` reported ``state.connected`` /
``state.tool_running`` as ``True`` on a bridge that had never actually
talked to a server. The panel's toolbar sync then enabled "Load Binary",
and clicking it triggered the first real RPC call, which performed the
deferred socket connect and raised a raw ``ConnectionRefusedError``
(``[WinError 10061] ... actively refused it``) wrapped only as
``"Remote execution failed: ..."``.

:meth:`GhidraBridge.initialize` now performs a real TCP liveness probe
(:meth:`GhidraBridge._probe_bridge_port`) before reporting the bridge as
connected, so a bridge server that never started is caught at Connect time
with clear guidance instead of leaking the raw OS error out of Load.

These gates exercise the real ``GhidraBridge`` and ``GhidraPanel`` objects
against a genuinely closed TCP port (no server, no mocks).
"""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QApplication, QPushButton

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError
from intellicrack.ui.panels import ghidra_panel as ghidra_module
from intellicrack.ui.panels.ghidra_panel import GhidraPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication]:
    """Provide a QApplication instance for the test module.

    Qt requires exactly one QApplication instance per process; this fixture
    creates one for the module (or reuses an existing instance) so
    GhidraPanel can be constructed without conflicting on the singleton.

    Yields:
        QApplication: The application instance.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


def _reserve_closed_port() -> int:
    """Reserve an ephemeral TCP port and immediately release it.

    Binds a socket to an OS-assigned free port on the loopback interface
    and closes it right away, yielding a port number that is free at the
    moment of the call and that no test-controlled process is listening on.

    Returns:
        int: A TCP port number with no active listener.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _sync_run_bridge_coroutine_logged(
    coro: Coroutine[Any, Any, Any],
    on_success: Callable[[object], None] | None = None,
    on_error: Callable[[BaseException], None] | None = None,
    parent: object = None,
    **kwargs: object,
) -> None:
    """Synchronously drive a bridge coroutine and invoke its callbacks.

    Stands in for ``run_bridge_coroutine_logged`` (which normally hands the
    coroutine to a background thread and marshals the callback back onto
    the Qt event loop) so panel tests can observe the real
    ``_on_connect_success`` / ``_on_connect_error`` state transitions
    deterministically, in-thread.

    Args:
        coro: Coroutine produced by the bridge call.
        on_success: Callback invoked with the coroutine's result on success.
        on_error: Callback invoked with the raised exception on failure.
        parent: Unused Qt parent argument, kept for signature compatibility.
        **kwargs: Remaining wrapper arguments (event, logger, level).
    """
    del parent, kwargs
    loop = asyncio.new_event_loop()
    try:
        try:
            result = loop.run_until_complete(coro)
        except ToolError as exc:
            if on_error is not None:
                on_error(exc)
        else:
            if on_success is not None:
                on_success(result)
    finally:
        loop.close()


class TestInitializeGatesOnRealLivenessProbe:
    """GhidraBridge.initialize must not report readiness against a dead port."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_initialize_raises_clear_message_when_bridge_unreachable() -> None:
        """Connect must fail with clear guidance, not a raw WinError, when nothing listens.

        Falsifiable: reverting the ``_probe_bridge_port`` gate in
        ``GhidraBridge.initialize`` makes the lazy ``ghidra_bridge.GhidraBridge``
        client construction succeed unconditionally, so no ``ToolError`` is
        raised here and this test goes red.
        """
        bridge = GhidraBridge()
        closed_port = _reserve_closed_port()
        bridge.set_port(closed_port)

        with pytest.raises(ToolError) as exc_info:
            await bridge.initialize()

        message = str(exc_info.value)
        assert "WinError" not in message
        assert "actively refused" not in message
        assert "not reachable" in message
        assert str(closed_port) in message
        assert "headless" in message.lower()

        assert bridge.state.connected is False
        assert bridge.state.tool_running is False
        assert bridge.state.is_ready() is False
        assert bridge.state.last_error == message


@pytest.mark.usefixtures("qapp")
class TestPanelBlocksLoadBeforeBridgeIsReady:
    """GhidraPanel must not let Load Binary through against an unready bridge."""

    @staticmethod
    def test_load_binary_blocked_after_connect_to_unreachable_port(monkeypatch: pytest.MonkeyPatch) -> None:
        """Simulate a real Connect click against a dead port, then confirm Load is blocked.

        Uses a real ``GhidraPanel`` and a real ``GhidraBridge`` (no bridge
        mocks). Only the async dispatcher is replaced with a synchronous
        driver so the panel's real ``_on_connect`` / ``_on_connect_error`` /
        ``_sync_toolbar_state`` code paths run in-thread.

        Falsifiable: reverting the ``initialize`` liveness-probe gate makes
        Connect succeed against the dead port, which flips the Load button
        enabled and makes ``panel.load_binary`` proceed instead of
        short-circuiting, so this test goes red.

        Args:
            monkeypatch: Pytest monkeypatch fixture for patching the bridge
                coroutine dispatcher.
        """
        monkeypatch.setattr(ghidra_module, "run_bridge_coroutine_logged", _sync_run_bridge_coroutine_logged)

        panel = GhidraPanel()
        bridge = GhidraBridge()
        closed_port = _reserve_closed_port()
        bridge.set_port(closed_port)
        panel.set_bridge(bridge)

        connect_btn = getattr(panel, "_connect_btn", None)
        assert isinstance(connect_btn, QPushButton)
        assert connect_btn.isEnabled() is True
        connect_btn.click()

        load_btn = getattr(panel, "_load_btn", None)
        assert isinstance(load_btn, QPushButton)
        assert load_btn.isEnabled() is False
        assert "start headless" in load_btn.toolTip().lower()

        status_label = getattr(panel, "status_label", None)
        assert status_label is not None
        status_text = status_label.text()
        assert "WinError" not in status_text
        assert "not reachable" in status_text

        loaded = panel.load_binary(Path("nonexistent_for_gate_test.bin"))

        assert loaded is False
        assert load_btn.isEnabled() is False
