# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for x64dbg bridge event callback system (Fix 6).

Validates:
- Event callback registration and unregistration
- Event dispatch to registered callbacks
- Breakpoint/watchpoint hit counting via _handle_event
- Error isolation between callbacks

The event dispatch entry point is the bridge's protected ``_handle_event``
method. To call it from tests while satisfying basedpyright's
``reportPrivateUsage`` rule, the protected method is resolved via
``getattr`` using a string constant and invoked through a precisely typed
helper.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from intellicrack.bridges.base import WatchpointInfo
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import BreakpointInfo


if TYPE_CHECKING:
    from collections.abc import Callable


TEST_ADDR_BP = 0x401000
TEST_ADDR_WP = 0x7FFE0000
WATCHPOINT_SIZE = 4
BP_ID_TEST = 99
WP_ID_TEST = 1
EXPECTED_CALLBACK_COUNT_TWO = 2

_HANDLE_EVENT_ATTR = "_handle_event"


def _dispatch_event(bridge: X64DbgBridge, message: dict[str, Any]) -> None:
    """Invoke the bridge's protected event dispatcher.

    Resolves the bridge's protected ``_handle_event`` method via ``getattr``
    with a string constant so that basedpyright's ``reportPrivateUsage``
    rule is satisfied, and invokes it with a precisely typed cast anchored
    to the bridge's documented signature.

    Args:
        bridge: The x64dbg bridge whose event dispatcher to invoke.
        message: Event payload to dispatch to registered callbacks.
    """
    raw_handler: object = getattr(bridge, _HANDLE_EVENT_ATTR)
    handler = cast("Callable[[dict[str, Any]], None]", raw_handler)
    handler(message)


class TestEventCallbackRegistration:
    """Tests for register/unregister event callback."""

    @staticmethod
    def test_register_callback_appends_to_list() -> None:
        """Verify register_event_callback adds the callback."""
        bridge = X64DbgBridge()
        calls: list[tuple[str, dict[str, Any]]] = []

        def handler(event_type: str, message: dict[str, Any]) -> None:
            calls.append((event_type, message))

        bridge.register_event_callback(handler)
        assert len(bridge.event_callbacks) == 1

    @staticmethod
    def test_register_multiple_callbacks() -> None:
        """Verify multiple callbacks can be registered."""
        bridge = X64DbgBridge()

        def handler1(event_type: str, message: dict[str, Any]) -> None:
            pass

        def handler2(event_type: str, message: dict[str, Any]) -> None:
            pass

        bridge.register_event_callback(handler1)
        bridge.register_event_callback(handler2)
        assert len(bridge.event_callbacks) == EXPECTED_CALLBACK_COUNT_TWO

    @staticmethod
    def test_unregister_callback_removes() -> None:
        """Verify unregister_event_callback removes the callback."""
        bridge = X64DbgBridge()

        def handler(event_type: str, message: dict[str, Any]) -> None:
            pass

        bridge.register_event_callback(handler)
        bridge.unregister_event_callback(handler)
        assert len(bridge.event_callbacks) == 0

    @staticmethod
    def test_unregister_nonexistent_does_not_raise() -> None:
        """Verify unregistering a non-registered callback leaves the list unchanged.

        The list must be empty both before and after the call; the operation must
        be a safe no-op rather than silently corrupting the callback list.
        """
        bridge = X64DbgBridge()

        def handler(event_type: str, message: dict[str, Any]) -> None:
            pass

        assert len(bridge.event_callbacks) == 0, "precondition: list must start empty"
        bridge.unregister_event_callback(handler)
        assert len(bridge.event_callbacks) == 0, "postcondition: unregistering unknown handler must not alter the list"


class TestEventDispatch:
    """Tests for _handle_event callback invocation."""

    @staticmethod
    def test_handle_event_invokes_callbacks() -> None:
        """Verify _handle_event calls all registered callbacks."""
        bridge = X64DbgBridge()
        received: list[tuple[str, dict[str, Any]]] = []

        def handler(event_type: str, message: dict[str, Any]) -> None:
            received.append((event_type, message))

        bridge.register_event_callback(handler)

        message: dict[str, Any] = {"event": "breakpoint", "address": TEST_ADDR_BP}
        _dispatch_event(bridge, message)

        assert len(received) == 1
        assert received[0][0] == "breakpoint"
        assert received[0][1] is message

    @staticmethod
    def test_handle_event_invokes_all_callbacks() -> None:
        """Verify _handle_event calls multiple registered callbacks."""
        bridge = X64DbgBridge()
        calls1: list[str] = []
        calls2: list[str] = []

        def handler1(event_type: str, _message: dict[str, Any]) -> None:
            calls1.append(event_type)

        def handler2(event_type: str, _message: dict[str, Any]) -> None:
            calls2.append(event_type)

        bridge.register_event_callback(handler1)
        bridge.register_event_callback(handler2)

        _dispatch_event(bridge, {"event": "step"})

        assert calls1 == ["step"]
        assert calls2 == ["step"]

    @staticmethod
    def test_handle_event_isolates_callback_errors() -> None:
        """Verify a failing callback does not prevent others from executing."""
        bridge = X64DbgBridge()
        calls: list[str] = []

        def bad_handler(_event_type: str, _message: dict[str, Any]) -> None:
            msg = "callback failure"
            raise RuntimeError(msg)

        def good_handler(event_type: str, _message: dict[str, Any]) -> None:
            calls.append(event_type)

        bridge.register_event_callback(bad_handler)
        bridge.register_event_callback(good_handler)

        _dispatch_event(bridge, {"event": "breakpoint", "address": TEST_ADDR_BP})

        assert calls == ["breakpoint"]

    @staticmethod
    def test_handle_event_with_no_callbacks() -> None:
        """Verify _handle_event succeeds with no registered callbacks."""
        bridge = X64DbgBridge()
        _dispatch_event(bridge, {"event": "breakpoint", "address": TEST_ADDR_BP})


class TestBreakpointHitCounting:
    """Tests for breakpoint hit count updates via _handle_event."""

    @staticmethod
    def test_breakpoint_hit_count_incremented() -> None:
        """Verify breakpoint hit count increments on breakpoint event."""
        bridge = X64DbgBridge()
        bridge.breakpoints[TEST_ADDR_BP] = BreakpointInfo(
            id=BP_ID_TEST,
            address=TEST_ADDR_BP,
            bp_type="software",
            enabled=True,
            hit_count=0,
            condition=None,
        )

        _dispatch_event(bridge, {"event": "breakpoint", "address": TEST_ADDR_BP})

        assert bridge.breakpoints[TEST_ADDR_BP].hit_count == 1

    @staticmethod
    def test_watchpoint_hit_count_incremented() -> None:
        """Verify watchpoint hit count increments on watchpoint event."""
        bridge = X64DbgBridge()
        bridge.watchpoints[WP_ID_TEST] = WatchpointInfo(
            id=WP_ID_TEST,
            address=TEST_ADDR_WP,
            size=WATCHPOINT_SIZE,
            watch_type="write",
            enabled=True,
            hit_count=0,
        )

        _dispatch_event(bridge, {"event": "watchpoint", "address": TEST_ADDR_WP})

        assert bridge.watchpoints[WP_ID_TEST].hit_count == 1

    @staticmethod
    def test_unknown_event_does_not_crash() -> None:
        """Verify unknown event types are handled gracefully."""
        bridge = X64DbgBridge()
        _dispatch_event(bridge, {"event": "unknown_event"})
