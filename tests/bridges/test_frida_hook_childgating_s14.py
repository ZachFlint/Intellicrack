# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for FridaBridge default-hook-callback and child-gating defects.

Covers two real defects fixed in ``FridaBridge``:

* S14-D07 -- The managed "Add hook" flow (``FridaPanel._on_add_hook``) calls
  ``FridaBridge.hook_function(target)`` with no ``on_enter``/``on_leave``
  callbacks. The agent used to install a completely empty ``onEnter``/
  ``onLeave`` pair in that case, so the hook attached successfully but never
  emitted anything -- it looked installed in the Hooks table but silently did
  nothing on every invocation. The fix installs a default logging callback
  (``onEnter``/``onLeave`` both ``send()`` a ``hook_fire`` message with the
  target address, a few argument pointers, and the return value) whenever no
  custom callback code is supplied, so the hook is observable through the
  console even without custom JS.
* S14-D18 -- Enabling Advanced > Child Gating on Windows fails because Frida's
  local device does not support spawn gating on this platform
  (``frida.NotSupportedError: 'not yet supported on this OS'``), but the
  bridge used to swallow that real error text and raise a bare
  ``ToolError("child gating operation failed")``, masking the platform
  limitation behind a generic message. The fix attaches the real Frida error
  text to ``ToolError.details['reason']`` so the UI (and this test) can see
  the actual cause instead of a generic failure.

Both tests drive a REAL Frida runtime attached to the current test process
(no external process is spawned, so no ``spawns_process`` marker is needed --
matching the ``self_attached_bridge`` idiom already used in
``tests/bridges/test_frida_scan_unload_s14.py`` and
``tests/bridges/test_frida_bridge.py``). Requires frida-python and a Windows
host.
"""

from __future__ import annotations

import asyncio
import ctypes
import logging
import os
import sys
import threading
import time
from typing import TYPE_CHECKING, Final, cast


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from intellicrack.core.types import HookInfo

import pytest

from intellicrack.core.types import ToolError


frida = pytest.importorskip("frida", reason="frida-python required for bridge tests")

from intellicrack.bridges.frida_bridge import FridaBridge  # noqa: E402


_logger = logging.getLogger(__name__)

_MESSAGE_WAIT_TIMEOUT_S: Final[float] = 10.0
_MESSAGE_POLL_INTERVAL_S: Final[float] = 0.05
_HOOK_INVOKE_COUNT: Final[int] = 5
_EXPECTED_CHILD_GATING_REASON: Final[str] = "not yet supported on this os"


def _run_async[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously for test use.

    Args:
        coro: Awaitable coroutine to execute.

    Returns:
        T: The coroutine's return value, preserving its type.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture
def self_attached_bridge() -> Generator[FridaBridge]:
    """Create a FridaBridge attached to the current test process.

    Yields:
        FridaBridge: An initialized and attached FridaBridge instance.
    """
    bridge = FridaBridge()
    _run_async(bridge.initialize())
    _run_async(bridge.attach(os.getpid()))
    yield bridge
    try:
        _run_async(bridge.shutdown())
    except ToolError:
        _logger.debug("self_attached_bridge_fixture_shutdown_failed", exc_info=True)


def _wait_until(predicate: Callable[[], bool], timeout: float = _MESSAGE_WAIT_TIMEOUT_S) -> bool:
    """Poll ``predicate`` until it returns truthy or the timeout elapses.

    Args:
        predicate: Zero-argument callable returning a truthy value once the
            awaited condition is satisfied.
        timeout: Maximum number of seconds to poll before giving up.

    Returns:
        bool: The final (possibly falsy) result of invoking ``predicate``.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(_MESSAGE_POLL_INTERVAL_S)
    return predicate()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
def test_add_hook_default_callback_fires_on_invocation(self_attached_bridge: FridaBridge) -> None:
    """Verify a hook installed with no explicit callbacks still logs on every invocation.

    Regression test for S14-D07: the managed "Add hook" flow installs a hook
    via ``hook_function(target)`` with no ``on_enter``/``on_leave`` JS. The
    previous agent template defaulted those to empty no-op functions, so the
    hook attached but never emitted anything. This test hooks a real WinAPI
    export (``kernel32.dll!GetCurrentProcessId``) in the current (self-
    attached) process with no callbacks, drives real invocations of that
    export via ctypes, and asserts that ``hook_fire`` ``send()`` messages
    for both the ``enter`` and ``leave`` phases actually arrive through the
    bridge's message handler -- including a ``leave`` message whose
    ``retval`` matches the real PID returned by the hooked call. Falsifiable:
    if the agent still installs an empty callback, no ``hook_fire`` message
    is ever emitted and the wait times out / the assertions fail.

    Args:
        self_attached_bridge: Bridge fixture attached to the current test process.
    """
    messages: list[dict[str, object]] = []
    messages_lock = threading.Lock()

    def _capture(message: dict[str, object]) -> None:
        """Record every message the bridge dispatches to the registered handler.

        Args:
            message: Frida message dictionary forwarded by the bridge.
        """
        with messages_lock:
            messages.append(message)

    self_attached_bridge.set_message_handler(_capture)

    hook: HookInfo = _run_async(self_attached_bridge.hook_function("kernel32.dll!GetCurrentProcessId"))
    assert hook.active, f"hook must be active after installation, got active={hook.active}"

    try:
        expected_pid = os.getpid()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        for _ in range(_HOOK_INVOKE_COUNT):
            returned_pid: int = kernel32.GetCurrentProcessId()
            assert returned_pid == expected_pid, (
                f"sanity check failed: GetCurrentProcessId returned {returned_pid}, expected {expected_pid}"
            )

        def _hook_fire_payloads() -> list[dict[str, object]]:
            """Filter captured messages down to this hook's ``hook_fire`` payloads.

            Returns:
                list[dict[str, object]]: Matching ``send`` payload dictionaries.
            """
            with messages_lock:
                snapshot = list(messages)
            fires: list[dict[str, object]] = []
            for msg in snapshot:
                if msg.get("type") != "send":
                    continue
                payload = msg.get("payload")
                if not isinstance(payload, dict):
                    continue
                payload_dict = cast("dict[str, object]", payload)
                if payload_dict.get("type") == "hook_fire" and payload_dict.get("hook_id") == hook.id:
                    fires.append(payload_dict)
            return fires

        arrived = _wait_until(lambda: len(_hook_fire_payloads()) >= 2)
        fires = _hook_fire_payloads()
        assert arrived, f"expected hook_fire messages for hook {hook.id!r} within {_MESSAGE_WAIT_TIMEOUT_S}s, got {len(fires)}: {fires}"

        enter_fires = [f for f in fires if f.get("phase") == "enter"]
        leave_fires = [f for f in fires if f.get("phase") == "leave"]
        assert enter_fires, f"no 'enter' phase hook_fire messages captured, got phases {[f.get('phase') for f in fires]}"
        assert leave_fires, f"no 'leave' phase hook_fire messages captured, got phases {[f.get('phase') for f in fires]}"

        expected_retval_hex = hex(expected_pid)
        matching_retval = [f for f in leave_fires if str(f.get("retval", "")).lower() == expected_retval_hex]
        assert matching_retval, (
            f"expected a leave hook_fire with retval == {expected_retval_hex} (pid {expected_pid}), "
            f"got retvals {[f.get('retval') for f in leave_fires]}"
        )
    finally:
        removed = _run_async(self_attached_bridge.remove_hook(hook.id))
        assert removed, f"remove_hook must return True during cleanup, got {removed}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
def test_enable_child_gating_surfaces_real_platform_reason(self_attached_bridge: FridaBridge) -> None:
    """Verify enabling child gating on Windows surfaces the real Frida failure reason.

    Regression test for S14-D18: on this Windows build, Frida's local device
    raises ``frida.NotSupportedError('not yet supported on this OS')`` from
    ``Device.enable_spawn_gating()`` -- confirmed directly against the real
    ``frida`` package before writing this assertion. The previous bridge
    code discarded that text and raised a bare
    ``ToolError("child gating operation failed")``, so the UI only ever
    showed the generic message and never the platform-limitation reason.
    This test calls the real bridge method and asserts the raised
    ``ToolError`` carries the actual Frida reason text in
    ``details['reason']``. Falsifiable: if the bridge still swallows the
    message, ``details`` is empty (or lacks 'reason') and the assertions
    fail; if Frida ever silently starts supporting spawn gating on this
    build, no exception is raised at all and the ``pytest.raises`` block
    fails loudly instead of masking a behavior change.

    Args:
        self_attached_bridge: Bridge fixture attached to the current test process.
    """
    with pytest.raises(ToolError) as exc_info:
        _run_async(self_attached_bridge.enable_child_gating())

    reason = exc_info.value.details.get("reason")
    assert isinstance(reason, str), f"ToolError.details['reason'] must be a string, got {exc_info.value.details!r}"
    assert reason, f"ToolError.details must carry a non-empty 'reason' string, got {exc_info.value.details!r}"
    assert reason.lower() == _EXPECTED_CHILD_GATING_REASON, (
        f"expected the real Frida platform-limitation text {_EXPECTED_CHILD_GATING_REASON!r}, got {reason!r} -- "
        "a generic/masked message would fail this exact-text comparison"
    )
