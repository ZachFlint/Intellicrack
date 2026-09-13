# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for S20-D03: trace/animate verification must not miss fast settles.

Reproduced live: with cmd.exe paused at a valid state, ``Trace Into``/``Trace
Over`` failed with "debugger never entered running state ... within 5.0s"
even though the trace genuinely ran (RIP advanced), and ``Animate Stop``
failed with "debugger still running ... within 5.0s" even though animation
demonstrably stopped. The shared root cause: the old verification polled
``status`` on a fixed interval and only accepted the transient running (or
paused) state it happened to catch inside that window - a conditional trace
or an animate-stop that settles between two polls reports only the paused
state on both sides of the transition, so the poll can report "never
happened" for a command that genuinely ran to completion.

``X64DbgBridge._await_run_completion`` fixes this by racing the plugin's
asynchronous ``paused`` event (delivered via ``_handle_event`` and
``_resolve_step_waiters``, already used by ``step_into``/``step_over``/
``step_out``) against the ``status`` poll: whichever settles first wins.
These tests script a fake pipe client whose ``status`` responder *never*
reports the expected transition at all (simulating a poll that would run out
its whole window without ever observing it) while the "exec" call that sends
the trace/animate command also fires the ``paused`` event synchronously,
standing in for the plugin's real push notification arriving before the poll
ever gets a look. A revert of ``trace_into``/``trace_over``/``animate_stop``
to call ``_wait_for_running_state`` directly (dropping the event race) makes
every positive test below fail, because ``status`` alone never reports the
expected state within ``VERIFY_TIMEOUT``.

The negative control (``test_trace_into_raises_when_neither_event_nor_status_settle``)
guards the other direction: a genuinely stuck debugger - no paused event, and
``status`` never reporting the expected transition - must still raise
``ToolError``. The fix must close the false-negative race without turning
verification into an unconditional success.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolError


_Responder = Callable[[str, dict[str, Any] | None], dict[str, Any]]

_TIGHT_VERIFY_TIMEOUT: float = 0.3
_TIGHT_VERIFY_POLL_INTERVAL: float = 0.05
_PAUSED_EVENT_ADDRESS: str = "0x00007ff600001000"


class _FakePipeClient:
    """In-process replacement for ``NamedPipeClient`` used by this module.

    Mirrors the fake used by ``tests/bridges/test_x64dbg_audit7_f0001.py``
    (reproduced here rather than imported, since that file belongs to a
    different domain and must not be modified or depended on). Exposes only
    what ``X64DbgBridge._send_pipe_command`` calls: the ``is_connected``
    property and ``send_command``.
    """

    def __init__(self, responder: _Responder) -> None:
        """Initialize the fake pipe client.

        Args:
            responder: Callable that maps ``(command, params)`` to the
                response dict the named-pipe layer would have returned.
        """
        self._responder = responder

    @property
    def is_connected(self) -> bool:
        """Always report connected.

        Returns:
            bool: ``True`` - the fake is permanently "connected".
        """
        return True

    async def send_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return the scripted response for one command.

        Args:
            command: RPC command name.
            params: Optional parameters dict.

        Returns:
            dict[str, Any]: The response dict produced by ``responder``.
        """
        return self._responder(command, params)


class _PlaceholderProcess:
    """Sentinel stand-in used to satisfy ``self._process is not None`` checks.

    ``_raise_if_process_exited`` calls ``self._process.poll()`` on every
    bridge command (D19's mid-session liveness probe), so this stand-in must
    implement ``poll()`` with the same contract as
    ``subprocess.Popen.poll()``: ``None`` means the process is still
    running. Returning anything else here would make every bridge call in
    this module raise ``ToolError`` before ever reaching the trace/animate
    verification logic under test.
    """

    def poll(self) -> int | None:
        """Report that the placeholder process is still running.

        Returns:
            int | None: Always ``None``, matching
            ``subprocess.Popen.poll()``'s contract for a live process.
        """
        return None


def _install_fake_pipe(bridge: X64DbgBridge, responder: _Responder) -> None:
    """Attach a fake pipe client to ``bridge`` and mark the plugin deployed.

    Args:
        bridge: Bridge instance under test.
        responder: Per-command response generator.
    """
    setattr(bridge, "_pipe_client", _FakePipeClient(responder))
    setattr(bridge, "_plugin_deployed", True)
    setattr(bridge, "_process", _PlaceholderProcess())
    bridge.VERIFY_TIMEOUT = _TIGHT_VERIFY_TIMEOUT
    bridge.VERIFY_POLL_INTERVAL = _TIGHT_VERIFY_POLL_INTERVAL


def _fire_paused_event(bridge: X64DbgBridge) -> None:
    """Simulate the plugin's asynchronous ``paused`` push notification.

    Reaches the bridge's internal event dispatch (``_handle_event``) through
    ``getattr`` rather than a direct attribute access, since it is a private
    implementation detail the bridge exposes no public equivalent for from
    outside its own named-pipe reader thread.

    Args:
        bridge: Bridge instance under test.
    """
    handle_event = getattr(bridge, "_handle_event")
    handle_event({"event": "paused", "address": _PAUSED_EVENT_ADDRESS})


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Construct a fresh, unattached bridge instance.

    Returns:
        X64DbgBridge: A bridge with no attached PID.
    """
    return X64DbgBridge()


@pytest.mark.asyncio
async def test_trace_into_verifies_via_paused_event_when_status_never_shows_running(
    bridge: X64DbgBridge,
) -> None:
    """A trace that settles faster than any poll can observe must still verify.

    ``status`` always reports ``paused`` (never ``running``) - the exact
    shape of a conditional trace that starts and finishes between two polls
    - while the plugin's ``paused`` event fires the instant the command is
    sent. ``trace_into`` must resolve through the event rather than the
    poll and report success.

    Args:
        bridge: Fixture bridge instance.
    """

    def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
        if command == "exec":
            _fire_paused_event(bridge)
            return {"id": 1, "success": True, "result": None}
        if command == "status":
            return {"id": 1, "success": True, "result": {"debugging": True, "paused": True, "initialized": True}}
        msg = f"unexpected command: {command}"
        raise AssertionError(msg)

    _install_fake_pipe(bridge, responder)
    result = await bridge.trace_into(max_steps=50)
    assert result["success"] is True
    assert result["verified"] is True


@pytest.mark.asyncio
async def test_trace_over_verifies_via_paused_event_when_status_never_shows_running(
    bridge: X64DbgBridge,
) -> None:
    """Same race as trace_into, exercised through ``trace_over``.

    Args:
        bridge: Fixture bridge instance.
    """

    def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
        if command == "exec":
            _fire_paused_event(bridge)
            return {"id": 1, "success": True, "result": None}
        if command == "status":
            return {"id": 1, "success": True, "result": {"debugging": True, "paused": True, "initialized": True}}
        msg = f"unexpected command: {command}"
        raise AssertionError(msg)

    _install_fake_pipe(bridge, responder)
    result = await bridge.trace_over(max_steps=50)
    assert result["success"] is True
    assert result["verified"] is True


@pytest.mark.asyncio
async def test_animate_stop_verifies_via_paused_event_when_status_never_shows_paused(
    bridge: X64DbgBridge,
) -> None:
    """Animate stop that settles between micro-steps must still verify.

    ``status`` always reports ``running`` (never ``paused``) - reproducing
    the live symptom "debugger still running ... within 5.0s" - while the
    plugin's ``paused`` event fires the instant ``pause`` is sent.
    ``animate_stop`` must resolve through the event rather than the poll.

    Args:
        bridge: Fixture bridge instance.
    """

    def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
        if command == "exec":
            _fire_paused_event(bridge)
            return {"id": 1, "success": True, "result": None}
        if command == "status":
            return {"id": 1, "success": True, "result": {"debugging": True, "paused": False, "initialized": True}}
        msg = f"unexpected command: {command}"
        raise AssertionError(msg)

    _install_fake_pipe(bridge, responder)
    result = await bridge.animate_stop()
    assert result["success"] is True
    assert result["verified"] is True


@pytest.mark.asyncio
async def test_trace_into_raises_when_neither_event_nor_status_settle(bridge: X64DbgBridge) -> None:
    """A genuinely stuck trace must still raise, event race notwithstanding.

    No ``paused`` event ever fires and ``status`` never reports running, so
    the fix must not mask a real failure: ``trace_into`` must still raise
    ``ToolError`` once the verification window elapses.

    Args:
        bridge: Fixture bridge instance.
    """

    def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
        if command == "exec":
            return {"id": 1, "success": True, "result": None}
        if command == "status":
            return {"id": 1, "success": True, "result": {"debugging": True, "paused": True, "initialized": True}}
        msg = f"unexpected command: {command}"
        raise AssertionError(msg)

    _install_fake_pipe(bridge, responder)
    with pytest.raises(ToolError, match="trace_into verification failed"):
        await bridge.trace_into(max_steps=50)
