# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Shared fixtures and pipe-boundary test double for the x64dbg bridge-completeness gates.

The real x64dbg debugger process and its bridge plugin cannot run inside the
Docker test sandbox (no interactive Windows debugger session, no target
binary under active debugging). Every test in this package therefore drives
the REAL, unmodified ``X64DbgBridge``/``X64DbgPanel``/``X64DbgAdvancedTab``
production code and only substitutes the single genuine external boundary
that cannot execute in the sandbox: the named-pipe transport to the x64dbg
plugin (``NamedPipeClient.send_command``). Everything upstream of that
transport call -- RPC command selection, parameter framing, response
parsing, local-state bookkeeping, GUI wiring, and table rendering -- is real
production code and is what each test's assertions are falsified by.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QApplication


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from intellicrack.bridges.x64dbg import X64DbgBridge


def priv[T](obj: object, name: str, typ: type[T]) -> T:
    """Access a private attribute on ``obj`` with a precise static type.

    Test modules in this package deliberately reach into
    ``X64DbgPanel``'s private widgets (``_lbl_table``, ``_bp_cond_input``,
    etc.) to assert on real GUI wiring; this helper centralizes the
    ``getattr``-plus-``isinstance``-narrowing pattern so every call site is
    both ``reportPrivateUsage``-clean and precisely typed.

    Args:
        obj: The object to read the attribute from.
        name: The attribute name.
        typ: The expected static type of the attribute.

    Returns:
        T: The attribute value, verified and narrowed to ``typ``.
    """
    value = getattr(obj, name)
    assert isinstance(value, typ), f"{name!r} is a {type(value).__name__}, expected {typ.__name__}"
    return value


@pytest.fixture(scope="session")
def qapp() -> Generator[QApplication]:
    """Provide a QApplication instance for the test session.

    Qt requires exactly one QApplication instance per process; this
    fixture creates one for the entire session and yields it so every
    widget-construction test in this package can run without re-creating
    (or conflicting on) the singleton application instance.

    Yields:
        QApplication: The application instance.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class FakePipeClient:
    """In-process substitute for ``NamedPipeClient`` at the plugin-pipe boundary.

    Records every ``(command, params)`` pair sent by the bridge and returns
    a canned response produced by a caller-supplied responder callable. This
    is the same test-double shape already established for this bridge in
    ``tests/test_bridges/test_x64dbg_wave2b_breakpoints.py``; it substitutes
    only the pipe transport, never the bridge method whose behavior a test
    is gating.
    """

    def __init__(self, responder: Callable[[str, dict[str, Any] | None], dict[str, Any]]) -> None:
        """Initialize with a scripted responder callable.

        Args:
            responder: Maps ``(command, params)`` to the fake plugin response dict.
        """
        self._responder = responder
        self.sent: list[tuple[str, dict[str, Any] | None]] = []

    @property
    def is_connected(self) -> bool:
        """Report the fake pipe as always connected.

        Returns:
            bool: Always ``True``.
        """
        return True

    async def send_command(self, command: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Record the request and return the scripted response.

        Args:
            command: RPC command name forwarded by the bridge.
            params: Optional parameter dict forwarded by the bridge.

        Returns:
            dict[str, Any]: Canned response from the responder.
        """
        self.sent.append((command, params))
        return self._responder(command, params)


class PlaceholderProcess:
    """Sentinel value that satisfies the ``self._process is not None`` guards.

    ``X64DbgBridge._send_command`` raises ``ToolError("x64dbg not running")``
    when ``_process is None``; this sentinel lets methods that route through
    ``_send_command`` reach the fake pipe layer without spawning x64dbg.exe.
    """


def install_fake_pipe(
    bridge: X64DbgBridge,
    responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
) -> FakePipeClient:
    """Attach a ``FakePipeClient`` to ``bridge`` and mark the plugin deployed.

    Args:
        bridge: Bridge instance under test.
        responder: Callable returning a canned response for each command.

    Returns:
        FakePipeClient: The freshly attached fake, useful for assertions on the ``sent`` list.
    """
    fake = FakePipeClient(responder)
    setattr(bridge, "_pipe_client", fake)
    setattr(bridge, "_plugin_deployed", True)
    setattr(bridge, "_process", PlaceholderProcess())
    return fake


def ok(result: object = None) -> dict[str, Any]:
    """Build a successful canned plugin response envelope.

    Args:
        result: Payload to place under the ``result`` key.

    Returns:
        dict[str, Any]: A ``{"id": 1, "success": True, "result": result}`` envelope.
    """
    return {"id": 1, "success": True, "result": result}


def pump_until(qapp: QApplication, predicate: Callable[[], bool], timeout_s: float = 5.0) -> None:
    """Pump the Qt event loop until ``predicate()`` is truthy or the timeout elapses.

    Cross-thread async bridge results (delivered via ``run_bridge_coroutine_logged``
    / ``BridgeCallWorker`` signals from the background asyncio thread) only reach
    their Qt slots while the main-thread event loop is processing events, so GUI
    wiring tests must pump the loop while waiting for a handler's side effect.

    Args:
        qapp: The Qt application instance whose event loop to drive.
        predicate: Zero-argument callable returning a truthy value when done.
        timeout_s: Maximum number of seconds to wait.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        qapp.processEvents()
        time.sleep(0.02)
