# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for FridaBridge device-wide spawn-gating signal wiring.

Covers finding T1-1: ``FridaBridge.enable_child_gating`` /
``disable_child_gating`` arm and disarm Frida's DEVICE-WIDE spawn gating
(``Device.enable_spawn_gating`` / ``Device.disable_spawn_gating``), which
suspends every new process the device observes -- a disruptive, device-wide
side effect. The previous implementation subscribed to the SESSION-scoped
``"child-added"`` signal instead of the device's own ``"spawn-added"`` /
``"spawn-removed"`` signals, so the real Frida ``Device`` class never
delivered any event to that handler: gating was genuinely switched on, but
every gated process stayed invisible to ``get_pending_children`` and
unresumable through ``resume_child``, with no recovery path.

The fix (a) subscribes to the device's ``"spawn-added"`` / ``"spawn-removed"``
signals instead of ``"child-added"``, (b) makes ``get_pending_children`` query
``Device.enumerate_pending_spawn`` directly instead of relying solely on the
event-populated cache, and (c) keeps the resume path passing the real pid
through to ``Device.resume``. It also fixes a handler-leak: repeated
enable/disable cycles used to leave the previous ``"child-added"`` listener
attached forever (the disable path never called ``Device.off``), which would
have caused duplicate listener registration under a naive spawn-added fix.

These tests drive the REAL ``FridaBridge`` child-gating methods
(``enable_child_gating``, ``disable_child_gating``, ``get_pending_children``,
``resume_child``) against a hand-written device double that mirrors the
exact ``on``/``off``/``enable_spawn_gating``/``disable_spawn_gating``/
``enumerate_pending_spawn``/``resume`` contract of ``frida.Device`` with
genuine state (a real per-signal listener registry and a real pending-spawn
map), rather than a ``Mock`` whose return values are merely configured and
echoed back. Only the external Frida transport is substituted; every line of
bridge logic under test (signal names, closures, bookkeeping, resume
plumbing) executes unmodified. No real Frida device or spawn-gating support
is required, so this suite is unaffected by platforms (including this
project's own Windows sandbox) where the real Frida local device raises
``frida.NotSupportedError`` from ``enable_spawn_gating`` -- see
``tests/bridges/test_frida_hook_childgating_s14.py`` for that discriminator.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Final, cast


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from intellicrack.bridges.frida_bridge import FridaBridge

import pytest

from intellicrack.core.types import ToolError


try:
    from intellicrack.bridges.frida_bridge import FridaBridge

    _frida_available: bool = True
except ImportError:
    _frida_available = False


_logger = logging.getLogger(__name__)

_SPAWN_ADDED: Final[str] = "spawn-added"
_SPAWN_REMOVED: Final[str] = "spawn-removed"
_LEGACY_CHILD_ADDED: Final[str] = "child-added"


@pytest.fixture(autouse=True)
def require_frida() -> None:
    """Skip every test in this module when frida-python is not installed."""
    if not _frida_available:
        pytest.skip("frida-python required for bridge tests")


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


def _spawn_added_pids(messages: list[dict[str, object]]) -> list[object]:
    """Extract the ``pid`` from every dispatched ``spawn_added`` message payload.

    Args:
        messages: Captured bridge dispatch messages.

    Returns:
        list[object]: The ``pid`` value from each ``spawn_added`` payload, in order.
    """
    pids: list[object] = []
    for message in messages:
        payload = message.get("payload")
        if not isinstance(payload, dict):
            continue
        payload_dict = cast("dict[str, object]", payload)
        if payload_dict.get("type") == "spawn_added":
            pids.append(payload_dict.get("pid"))
    return pids


class _FakeSpawn:
    """Minimal stand-in for ``frida.Spawn``: exposes ``pid`` and ``identifier``."""

    def __init__(self, pid: int, identifier: str) -> None:
        """Initialize the fake spawn record.

        Args:
            pid: Process ID of the synthetic pending spawn.
            identifier: Application identifier reported for the spawn.
        """
        self.pid = pid
        self.identifier = identifier


class _SpawnGatingDevice:
    """Device double reproducing ``frida.Device``'s spawn-gating contract.

    ``on``/``off`` maintain a genuine per-signal listener registry (mirroring
    ``GObject``'s real multi-listener semantics), and
    ``enable_spawn_gating``/``disable_spawn_gating``/``enumerate_pending_spawn``/
    ``resume`` track real pending-spawn state so :meth:`simulate_spawn` can
    deliver a synthetic ``spawn-added`` event exactly like a real device
    would, and :meth:`resume` genuinely removes the spawn and fires
    ``spawn-removed`` -- no return value is pre-canned; every method mutates
    and reads the same real ``dict``/``list`` state the assertions inspect.
    """

    def __init__(self) -> None:
        """Initialize empty listener registry and pending-spawn state."""
        self.listeners: dict[str, list[Callable[[object], None]]] = {}
        self.gating_enabled: bool = False
        self.pending: dict[int, _FakeSpawn] = {}
        self.resumed_pids: list[int] = []

    def on(self, signal: str, callback: Callable[[object], None]) -> None:
        """Register a callback for ``signal``, mirroring ``frida.core.Device.on``.

        Args:
            signal: Device signal name (e.g. ``"spawn-added"``).
            callback: Callable invoked with the signal's payload object.
        """
        self.listeners.setdefault(signal, []).append(callback)

    def off(self, signal: str, callback: Callable[[object], None]) -> None:
        """Remove a previously registered callback, mirroring ``Device.off``.

        Args:
            signal: Device signal name the callback was registered under.
            callback: The exact callback instance to remove.
        """
        registered = self.listeners.get(signal, [])
        if callback in registered:
            registered.remove(callback)

    def enable_spawn_gating(self) -> None:
        """Arm device-wide spawn gating, mirroring ``Device.enable_spawn_gating``."""
        self.gating_enabled = True

    def disable_spawn_gating(self) -> None:
        """Disarm device-wide spawn gating, mirroring ``Device.disable_spawn_gating``."""
        self.gating_enabled = False

    def enumerate_pending_spawn(self) -> list[_FakeSpawn]:
        """Return the current ground-truth pending spawns.

        Returns:
            list[_FakeSpawn]: Snapshot of every currently pending spawn.
        """
        return list(self.pending.values())

    def resume(self, pid: int) -> None:
        """Resume ``pid``, removing it from the pending set and firing ``spawn-removed``.

        Args:
            pid: PID of the pending spawn to resume.
        """
        self.resumed_pids.append(pid)
        spawn = self.pending.pop(pid, None)
        if spawn is not None:
            for callback in list(self.listeners.get(_SPAWN_REMOVED, [])):
                callback(spawn)

    def simulate_spawn(self, pid: int, identifier: str = "") -> None:
        """Simulate the device observing and gating a new process launch.

        Adds ``pid`` to the ground-truth pending set and fires every
        registered ``spawn-added`` callback, exactly like a real device would
        when spawn gating is enabled.

        Args:
            pid: PID of the synthetic spawned process.
            identifier: Application identifier to attach to the spawn.
        """
        spawn = _FakeSpawn(pid, identifier)
        self.pending[pid] = spawn
        for callback in list(self.listeners.get(_SPAWN_ADDED, [])):
            callback(spawn)


def test_enable_child_gating_arms_device_and_registers_spawn_signals() -> None:
    """Verify ``enable_child_gating`` arms device-wide gating via the correct signals.

    Regression test for T1-1(a): the bridge must keep calling
    ``Device.enable_spawn_gating`` (the decided, lower-risk fix keeps the
    device-wide behavior) while listening on the device's own
    ``"spawn-added"``/``"spawn-removed"`` signals -- not the session-scoped
    ``"child-added"`` signal a real ``frida.Device`` never emits. Falsifiable:
    if the fix were reverted to ``device.on("child-added", ...)``, the
    ``spawn-added``/``spawn-removed`` listener lists would be empty and this
    assertion would fail; if ``enable_spawn_gating`` stopped being called,
    ``gating_enabled`` would stay ``False``.
    """
    bridge = FridaBridge()
    device = _SpawnGatingDevice()
    setattr(bridge, "_device", device)

    _run_async(bridge.enable_child_gating())

    assert device.gating_enabled, "enable_child_gating must arm the device-wide Device.enable_spawn_gating toggle"
    assert device.listeners.get(_SPAWN_ADDED), "a handler must be registered on the device's real 'spawn-added' signal"
    assert device.listeners.get(_SPAWN_REMOVED), "a handler must be registered on the device's real 'spawn-removed' signal"
    assert not device.listeners.get(_LEGACY_CHILD_ADDED), (
        "no handler may be registered on the session-scoped 'child-added' signal, which a real Device never emits for spawn gating"
    )


def test_get_pending_children_returns_simulated_spawn_and_dispatches_message() -> None:
    """Verify a simulated ``spawn-added`` event surfaces through ``get_pending_children``.

    Drives the full add path: ``enable_child_gating`` registers the real
    closures, ``device.simulate_spawn`` fires them exactly like a real
    device would, and ``get_pending_children`` must report the pid. Also
    confirms the ``spawn_added`` dispatch message reaches
    ``set_message_handler`` with the correct pid. Falsifiable: if the
    registered callback were a no-op (or registered under the wrong
    signal, as in T1-1's original defect), neither the returned list nor
    the captured message would contain the simulated pid.
    """
    bridge = FridaBridge()
    device = _SpawnGatingDevice()
    setattr(bridge, "_device", device)

    captured: list[dict[str, object]] = []
    bridge.set_message_handler(captured.append)

    _run_async(bridge.enable_child_gating())
    device.simulate_spawn(pid=4242, identifier="com.example.app")

    pending = _run_async(bridge.get_pending_children())
    matching = [child for child in pending if child.pid == 4242]
    assert matching, f"expected pid 4242 among pending children, got {[c.pid for c in pending]}"

    dispatched_pids = _spawn_added_pids(captured)
    assert 4242 in dispatched_pids, f"expected a dispatched spawn_added message for pid 4242, got pids {dispatched_pids}"


def test_get_pending_children_reflects_device_state_even_when_event_never_fired() -> None:
    """Verify ``get_pending_children`` is correct even if a device event was missed.

    Regression test for T1-1(b): populates the device double's ground-truth
    pending-spawn map directly, WITHOUT going through ``simulate_spawn``
    (so no ``spawn-added`` callback ever fires -- exactly the "missed
    event" scenario the fix targets, for example a spawn that arrived
    before the signal handlers were registered). ``get_pending_children``
    must still report it because it queries
    ``Device.enumerate_pending_spawn`` directly. Falsifiable: the previous
    implementation returned only the in-memory event-populated cache
    (``list(self._gated_children)``); since no event ever fired here, that
    cache would be empty and this assertion would fail.
    """
    bridge = FridaBridge()
    device = _SpawnGatingDevice()
    setattr(bridge, "_device", device)
    _run_async(bridge.enable_child_gating())

    device.pending[9999] = _FakeSpawn(9999, "missed.event.app")

    pending = _run_async(bridge.get_pending_children())
    matching = [child for child in pending if child.pid == 9999]
    assert matching, (
        f"get_pending_children must query the device directly and report pid 9999 even though no 'spawn-added' "
        f"event ever fired for it, got {[c.pid for c in pending]}"
    )


def test_get_pending_children_raises_toolerror_without_device() -> None:
    """Verify ``get_pending_children`` raises when no Frida device is available.

    Regression coverage for the device guard added alongside T1-1(b): the
    previous implementation unconditionally returned the (always-empty,
    since child-added never fired) cache regardless of device state, so a
    caller with no device attached silently got ``[]`` instead of a clear
    error. Falsifiable: if the guard were removed, this call would return
    an empty list instead of raising and ``pytest.raises`` would fail with
    "DID NOT RAISE".
    """
    bridge = FridaBridge()

    with pytest.raises(ToolError):
        _run_async(bridge.get_pending_children())


def test_resume_child_calls_device_resume_and_untracks_pid() -> None:
    """Verify ``resume_child`` resumes the exact pid via ``Device.resume``.

    Regression test for T1-1(c): drives a real gated spawn end to end
    (enable gating, simulate a spawn, resume it) and asserts the device
    double's ``resume`` was invoked with the correct pid, and that the
    pid is no longer reported by a subsequent ``get_pending_children``
    call. Falsifiable: if ``resume_child`` called the wrong device method
    or passed the wrong argument, ``device.resumed_pids`` would not equal
    ``[777]``; if it failed to untrack the pid, it would still appear in
    the follow-up ``get_pending_children`` result.
    """
    bridge = FridaBridge()
    device = _SpawnGatingDevice()
    setattr(bridge, "_device", device)
    _run_async(bridge.enable_child_gating())
    device.simulate_spawn(pid=777, identifier="resume.me")

    _run_async(bridge.resume_child(777))

    assert device.resumed_pids == [777], f"expected Device.resume to be called with pid 777 exactly once, got {device.resumed_pids}"
    pending = _run_async(bridge.get_pending_children())
    assert not any(child.pid == 777 for child in pending), f"pid 777 must no longer be pending after resume, got {[c.pid for c in pending]}"


def test_reenable_child_gating_after_disable_does_not_duplicate_handlers() -> None:
    """Verify disable/re-enable does not stack duplicate device listeners.

    A disable path that never detaches its listeners would leave the
    previous ``spawn-added``/``spawn-removed`` callbacks attached forever;
    the next ``enable_child_gating`` call would then register a second
    pair alongside them, so a single simulated spawn would dispatch its
    ``spawn_added`` message twice. Falsifiable: if ``disable_child_gating``
    (or the shared detach helper) stopped calling ``Device.off``, the
    listener lists would grow to length 2 after this enable/disable/enable
    cycle instead of staying at 1, and the final simulated spawn would be
    dispatched twice instead of once (a duplicate this check would miss if
    it instead inspected ``get_pending_children``, since both the device
    double's pending map and the handler's own dedup-by-pid guard collapse
    same-pid entries regardless of how many listeners are registered).
    """
    bridge = FridaBridge()
    device = _SpawnGatingDevice()
    setattr(bridge, "_device", device)

    _run_async(bridge.enable_child_gating())
    _run_async(bridge.disable_child_gating())
    _run_async(bridge.enable_child_gating())

    assert len(device.listeners.get(_SPAWN_ADDED, [])) == 1, (
        f"expected exactly one 'spawn-added' listener after a disable/re-enable cycle, got {len(device.listeners.get(_SPAWN_ADDED, []))}"
    )
    assert len(device.listeners.get(_SPAWN_REMOVED, [])) == 1, (
        f"expected exactly one 'spawn-removed' listener after a disable/re-enable cycle, "
        f"got {len(device.listeners.get(_SPAWN_REMOVED, []))}"
    )

    captured: list[dict[str, object]] = []
    bridge.set_message_handler(captured.append)
    device.simulate_spawn(pid=321, identifier="dup.check")

    dispatched_pids = _spawn_added_pids(captured)
    occurrences = dispatched_pids.count(321)
    assert occurrences == 1, (
        f"a duplicated 'spawn-added' handler would dispatch pid 321 more than once, got {occurrences}: {dispatched_pids}"
    )
