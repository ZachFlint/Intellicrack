# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Every Frida call the bridge makes is bounded when the agent or its target stops answering.

Frida's Python API waits for a native reply with no limit, so a target that is frozen or an agent whose
script thread is stuck used to hold the caller until Frida gave up after 25 seconds, or forever for
attach, detach and shutdown. These tests make a real ``notepad.exe`` unresponsive in the two ways
measured in the sandbox (a script handler that never returns, and freezing the whole process) and
check that each bound ends the call with a ``ToolError`` that names the call, that the bridge's view of
the session matches what it can know afterwards, and that a fresh bridge on a fresh target still works.
"""

from __future__ import annotations

import asyncio
import importlib
import queue
import time
from typing import TYPE_CHECKING, Final, cast

import pytest

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.subprocess_compat import DEVNULL, Popen
from intellicrack.core.types import ToolError
from tests._helpers.frida_targets import notepad_executable, resume_process, suspend_process, wait_for_gui_process_ready
from tests._helpers.process_cleanup import kill_pid_tree


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator


pytestmark = pytest.mark.spawns_process

_BRIDGE_MODULE: Final = importlib.import_module("intellicrack.bridges.frida_bridge")
_SPIN_SCRIPT: Final[str] = "recv('spin', function () { send('spinning'); while (true) {} });"
_SPINNING: Final[str] = "spinning"
_MARGIN_SECONDS: Final[float] = 5.0
_FAST_SECONDS: Final[float] = 1.0
_SPIN_WAIT_SECONDS: Final[float] = 10.0


def _constant(name: str) -> float:
    """Read one of the bridge's named time limits.

    Args:
        name: Module-level constant name in ``frida_bridge``.

    Returns:
        float: Its value in seconds.
    """
    return float(getattr(_BRIDGE_MODULE, name))


def _private(bridge: FridaBridge, name: str) -> object:
    """Read a private attribute of a bridge, to check what it believes about its session.

    Args:
        bridge: The bridge to inspect.
        name: Attribute name.

    Returns:
        object: The attribute's value.
    """
    return getattr(bridge, name)


def _async_method(bridge: FridaBridge, name: str) -> Callable[..., Coroutine[object, object, object]]:
    """Look up a (possibly private) coroutine method of a bridge by name.

    Args:
        bridge: The bridge that owns the method.
        name: Method name.

    Returns:
        Callable[..., Coroutine[object, object, object]]: The bound coroutine method.
    """
    return cast("Callable[..., Coroutine[object, object, object]]", getattr(bridge, name))


def _spin_agent(bridge: FridaBridge) -> None:
    """Make the agent's script thread busy for good, and return once it has started spinning.

    The script reports ``spinning`` before it enters its endless loop, so every call made after that
    message arrives finds the thread busy.

    Args:
        bridge: A bridge attached to the target.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    bridge.set_message_handler(messages.put)
    script_id = asyncio.run(bridge.execute_persistent_script(_SPIN_SCRIPT))
    asyncio.run(bridge.post_message(script_id, '{"type": "spin"}'))
    deadline = time.monotonic() + _SPIN_WAIT_SECONDS
    while time.monotonic() < deadline:
        try:
            message = messages.get(timeout=_FAST_SECONDS)
        except queue.Empty:
            continue
        if message.get("payload") == _SPINNING:
            return
    pytest.fail("the spin script never reported that it started spinning")


def _fresh_bridge_works(target: Popen[bytes]) -> None:
    """Prove that a new bridge attached to a new target answers a real query.

    Args:
        target: A freshly spawned, ready notepad.
    """
    bridge = FridaBridge()
    asyncio.run(bridge.initialize())
    try:
        asyncio.run(bridge.attach(target.pid))
        assert asyncio.run(bridge.find_base_address("kernel32.dll")) > 0
    finally:
        kill_pid_tree(target.pid)
        asyncio.run(bridge.shutdown())


@pytest.fixture
def second_notepad() -> Generator[Popen[bytes]]:
    """Spawn a second private notepad for the bridge that must work after the first one's agent died.

    Yields:
        Popen[bytes]: The running notepad process.
    """
    process = Popen([notepad_executable()], stdout=DEVNULL, stderr=DEVNULL)
    try:
        wait_for_gui_process_ready(process)
        yield process
    finally:
        kill_pid_tree(process.pid)
        process.wait(timeout=5)


def test_an_agent_call_that_is_never_answered_raises_by_name_and_later_agent_calls_fail_at_once(
    notepad_bridge: FridaBridge,
    frida_notepad: Popen[bytes],
) -> None:
    """A stuck agent ends a call at its limit with a named error; the next agent call is refused at once; device calls still run.

    Falsifiable: without the bound the first call waits out Frida's own 25 second timeout, without the
    unresponsive mark the second call waits just as long, and without the device/agent split the
    process listing would be refused too.

    Args:
        notepad_bridge: Bridge attached to the private notepad.
        frida_notepad: The private notepad process.
    """
    limit = _constant("_FRIDA_AGENT_CALL_TIMEOUT")
    grace = _constant("_FRIDA_CANCEL_GRACE")
    _spin_agent(notepad_bridge)

    started = time.monotonic()
    with pytest.raises(ToolError) as first:
        asyncio.run(notepad_bridge.find_base_address("kernel32.dll"))
    first_elapsed = time.monotonic() - started

    assert "Session.create_script" in first.value.message
    assert "did not answer" in first.value.message
    assert limit - 1.0 <= first_elapsed < limit + grace + _MARGIN_SECONDS, f"the first call took {first_elapsed:.1f}s on a {limit:g}s limit"

    started = time.monotonic()
    with pytest.raises(ToolError) as second:
        asyncio.run(notepad_bridge.find_base_address("kernel32.dll"))
    second_elapsed = time.monotonic() - started

    assert "was not attempted because Session.create_script" in second.value.message
    assert second_elapsed < _FAST_SECONDS, f"the second call should be refused at once, took {second_elapsed:.1f}s"
    assert frida_notepad.pid in {entry.pid for entry in asyncio.run(notepad_bridge.enumerate_processes())}


def test_shutdown_of_a_stuck_agent_returns_within_its_bound_and_leaves_a_reusable_bridge(
    notepad_bridge: FridaBridge,
    second_notepad: Popen[bytes],
) -> None:
    """Shutdown cannot be held by an agent that never answers; the bridge it leaves behind holds nothing and works again.

    Falsifiable: without the bounds the unload of the spinning script and the detach never return, so
    the call blows through the shutdown bound; without the final clear the registries would still list
    the dead session.

    Args:
        notepad_bridge: Bridge attached to the private notepad.
        second_notepad: A second target for the reused bridge.
    """
    bound = _constant("_SHUTDOWN_TIMEOUT")
    _spin_agent(notepad_bridge)

    started = time.monotonic()
    asyncio.run(notepad_bridge.shutdown())
    elapsed = time.monotonic() - started

    assert elapsed < bound, f"shutdown took {elapsed:.1f}s against a {bound:g}s bound"
    assert _private(notepad_bridge, "_session") is None
    assert _private(notepad_bridge, "_scripts") == {}
    assert notepad_bridge.state.process_attached is False

    asyncio.run(notepad_bridge.initialize())
    asyncio.run(notepad_bridge.attach(second_notepad.pid))
    assert asyncio.run(notepad_bridge.find_base_address("kernel32.dll")) > 0


def test_attach_to_a_frozen_target_raises_by_name_and_leaves_the_bridge_unattached(
    notepad_bridge: FridaBridge,
    frida_notepad: Popen[bytes],
    second_notepad: Popen[bytes],
) -> None:
    """Attaching to a process whose threads are all frozen ends at the device limit with a named error.

    A first session is attached before the freeze, because attaching to an unfrozen or never-attached
    process still succeeds (the injected thread runs); the second session is the one that hangs.

    Falsifiable: without the bound this attach never returns. Afterwards a bridge on a different,
    healthy target must still work, which shows the abandoned attach left nothing behind that
    poisons the process.

    Args:
        notepad_bridge: Bridge already attached to the private notepad.
        frida_notepad: The private notepad process.
        second_notepad: A healthy target for the final check.
    """
    limit = _constant("_FRIDA_DEVICE_CALL_TIMEOUT")
    grace = _constant("_FRIDA_CANCEL_GRACE")
    other = FridaBridge()
    asyncio.run(other.initialize())
    handle = suspend_process(frida_notepad.pid)
    try:
        started = time.monotonic()
        with pytest.raises(ToolError) as excinfo:
            asyncio.run(other.attach(frida_notepad.pid))
        elapsed = time.monotonic() - started
    finally:
        resume_process(handle)

    assert "Device.attach" in excinfo.value.message
    assert "did not answer" in excinfo.value.message
    assert limit - 1.0 <= elapsed < limit + grace + _MARGIN_SECONDS, f"attach took {elapsed:.1f}s on a {limit:g}s limit"
    assert other.state.process_attached is False
    assert _private(other, "_session") is None
    asyncio.run(other.shutdown())
    _fresh_bridge_works(second_notepad)
    assert notepad_bridge.state.process_attached is True


def test_detach_from_a_frozen_session_raises_by_name_and_forgets_the_session(
    notepad_bridge: FridaBridge,
    frida_notepad: Popen[bytes],
) -> None:
    """A detach the frozen target never answers raises, yet the bridge no longer claims a session or scripts.

    Falsifiable: without the bound the detach never returns; without the ``finally`` the failed detach
    would leave ``process_attached`` true and the session reference set.

    Args:
        notepad_bridge: Bridge attached to the private notepad.
        frida_notepad: The private notepad process.
    """
    script_id = asyncio.run(notepad_bridge.execute_persistent_script("send('loaded');"))
    handle = suspend_process(frida_notepad.pid)
    try:
        with pytest.raises(ToolError) as excinfo:
            asyncio.run(notepad_bridge.detach())
    finally:
        resume_process(handle)

    assert "Session.detach" in excinfo.value.message
    assert notepad_bridge.state.process_attached is False
    assert _private(notepad_bridge, "_session") is None
    assert script_id not in cast("dict[str, object]", _private(notepad_bridge, "_scripts"))


def test_unload_of_a_script_on_a_stuck_agent_raises_by_name_and_forgets_the_script(notepad_bridge: FridaBridge) -> None:
    """An unload the agent never answers raises, and the script is gone from the bridge's registry anyway.

    Falsifiable: without the bound the unload waits out Frida's 25 seconds and the error would be
    swallowed, so ``pytest.raises`` fails; without the ``finally`` the script id stays registered.

    Args:
        notepad_bridge: Bridge attached to the private notepad.
    """
    quiet_id = asyncio.run(notepad_bridge.execute_persistent_script("send('quiet');"))
    _spin_agent(notepad_bridge)

    with pytest.raises(ToolError) as excinfo:
        asyncio.run(notepad_bridge.unload_script(quiet_id))

    assert "Script.unload" in excinfo.value.message
    assert quiet_id not in cast("dict[str, object]", _private(notepad_bridge, "_scripts"))


def test_listing_threads_on_a_stuck_agent_raises_by_name_and_marks_the_agent(notepad_bridge: FridaBridge) -> None:
    """The thread-listing helper's reply that never comes ends at the agent limit with a named error.

    Falsifiable: without the wait's bound the call hangs until the agent answers.

    Args:
        notepad_bridge: Bridge attached to the private notepad.
    """
    limit = _constant("_FRIDA_AGENT_CALL_TIMEOUT")
    assert asyncio.run(notepad_bridge.enumerate_threads())
    _spin_agent(notepad_bridge)

    started = time.monotonic()
    with pytest.raises(ToolError) as excinfo:
        asyncio.run(notepad_bridge.enumerate_threads())
    elapsed = time.monotonic() - started

    assert "thread enumeration" in excinfo.value.message
    assert "did not answer" in excinfo.value.message
    assert limit - 1.0 <= elapsed < limit + _MARGIN_SECONDS, f"the listing took {elapsed:.1f}s on a {limit:g}s limit"
    assert _private(notepad_bridge, "_agent_unresponsive_operation") == "thread enumeration"


def test_cancelling_a_waiting_call_cancels_the_frida_call_too(notepad_bridge: FridaBridge) -> None:
    """A caller that gives up on a call (its task is cancelled) does not leave the Frida call running unscoped.

    The call goes to a stuck agent and is cancelled by an outer ``wait_for``; the outer timeout is
    raised at once, long before the bridge's own limit, and the bridge keeps no mark because it never
    concluded anything about the agent.

    Falsifiable: a call that ignored cancellation would hold the loop for the bridge's own limit.

    Args:
        notepad_bridge: Bridge attached to the private notepad.
    """
    outer = 1.0
    limit = _constant("_FRIDA_AGENT_CALL_TIMEOUT")
    _spin_agent(notepad_bridge)

    started = time.monotonic()
    with pytest.raises(TimeoutError):
        asyncio.run(asyncio.wait_for(notepad_bridge.find_base_address("kernel32.dll"), timeout=outer))
    elapsed = time.monotonic() - started

    assert elapsed < limit - _MARGIN_SECONDS, f"the outer timeout took {elapsed:.1f}s"
    assert _private(notepad_bridge, "_agent_unresponsive_operation") is None


def test_a_limit_the_caller_chose_is_reported_without_marking_the_agent(notepad_bridge: FridaBridge) -> None:
    """A script that runs for ever at load time hits the caller's own limit; that proves nothing about the agent.

    Falsifiable: marking the session on a caller-chosen limit would refuse every later agent call
    after one slow user script.

    Args:
        notepad_bridge: Bridge attached to the private notepad.
    """
    caller_limit = _constant("_FRIDA_AGENT_CALL_TIMEOUT") + 1.0

    with pytest.raises(ToolError) as excinfo:
        asyncio.run(_async_method(notepad_bridge, "_execute_script_and_wait")("while (true) {}", max_wait=caller_limit))

    assert "Script.load" in excinfo.value.message
    assert _private(notepad_bridge, "_agent_unresponsive_operation") is None
