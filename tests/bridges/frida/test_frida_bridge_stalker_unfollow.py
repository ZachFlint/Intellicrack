# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""``stalker_unfollow`` returns a trace only when the agent confirmed it, and raises when it did not.

The injected Stalker script answers an unfollow request with ``stalker_unfollowed`` once
``Stalker.unfollow`` and ``Stalker.flush`` have returned. When the agent stops answering, the bridge used
to wait out Frida's own timeout, swallow it, unload the script and return an empty trace as if the
unfollow had worked. These tests follow a real worker thread in a real ``notepad.exe`` and check the
contract against an agent that answers, one that stopped answering, and one whose script reports a
failure.
"""

from __future__ import annotations

import asyncio
import queue
import threading
import time
from typing import TYPE_CHECKING, Final, cast

import pytest

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.types import StalkerTrace, ToolError
from tests._helpers.frida_targets import COUNTER_ADDRESS_PLACEHOLDER, WORKER_THREAD_SCRIPT


if TYPE_CHECKING:
    from collections.abc import Callable


pytestmark = pytest.mark.spawns_process

_SPIN_SCRIPT: Final[str] = "recv('spin', function () { send('spinning'); while (true) {} });"
_SPINNING: Final[str] = "spinning"
_WAIT_SECONDS: Final[float] = 15.0
_POLL_SECONDS: Final[float] = 0.1
_FAST_SECONDS: Final[float] = 3.0
_MARGIN_SECONDS: Final[float] = 6.0
_ACK_LIMIT_SECONDS: Final[float] = 10.0
_EVENT_LIMIT: Final[int] = 500
_GHOST_TID: Final[int] = 9
_ERROR_TID: Final[int] = 7


def _private(bridge: FridaBridge, name: str) -> object:
    """Read a private attribute of a bridge, to check what it believes after a call.

    Args:
        bridge: The bridge to inspect.
        name: Attribute name.

    Returns:
        object: The attribute's value.
    """
    return getattr(bridge, name)


def _start_worker(bridge: FridaBridge) -> int:
    """Start a busy worker thread in the target and return the id the worker reported about itself.

    The id comes from the worker script's own message, not from listing the process's threads:
    following a thread that was found by a listing wedged the agent in a few percent of follows in the
    sandbox, and following one learned from its own message did not once in about 310.

    Args:
        bridge: A bridge attached to the target.

    Returns:
        int: The worker thread's id.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    bridge.set_message_handler(messages.put)
    counter = asyncio.run(bridge.allocate_memory(8))
    asyncio.run(bridge.execute_persistent_script(WORKER_THREAD_SCRIPT.replace(COUNTER_ADDRESS_PLACEHOLDER, hex(counter))))
    deadline = time.monotonic() + _WAIT_SECONDS
    while time.monotonic() < deadline:
        try:
            message = messages.get(timeout=_POLL_SECONDS)
        except queue.Empty:
            continue
        payload = message.get("payload")
        fields = cast("dict[str, object]", payload) if isinstance(payload, dict) else {}
        if fields.get("type") == "worker":
            return int(cast("int", fields["tid"]))
    pytest.fail("the worker thread never reported its id")


def _spin_when_told(bridge: FridaBridge) -> str:
    """Load a script that makes the agent's script thread busy for good when it is sent a ``spin`` message.

    Args:
        bridge: A bridge attached to the target.

    Returns:
        str: The id of the loaded script, to post the message to later.
    """
    return asyncio.run(bridge.execute_persistent_script(_SPIN_SCRIPT))


def _spin_now(bridge: FridaBridge, spin_id: str) -> None:
    """Send the ``spin`` message and wait until the script reports it is spinning.

    Args:
        bridge: A bridge attached to the target.
        spin_id: Id returned by :func:`_spin_when_told`.
    """
    messages: queue.Queue[dict[str, object]] = queue.Queue()
    bridge.set_message_handler(messages.put)
    asyncio.run(bridge.post_message(spin_id, '{"type": "spin"}'))
    deadline = time.monotonic() + _WAIT_SECONDS
    while time.monotonic() < deadline:
        try:
            message = messages.get(timeout=1.0)
        except queue.Empty:
            continue
        if message.get("payload") == _SPINNING:
            return
    pytest.fail("the spin script never reported that it started spinning")


def test_unfollow_raises_instead_of_returning_an_empty_trace_when_the_agent_does_not_acknowledge(notepad_bridge: FridaBridge) -> None:
    """An agent that stopped answering makes ``stalker_unfollow`` raise, and the unconfirmed trace is discarded.

    Falsifiable: the old code waited out Frida's timeout, swallowed it and returned an empty
    ``StalkerTrace`` as success, so ``pytest.raises`` fails.

    Args:
        notepad_bridge: Bridge attached to a private notepad.
    """
    tid = _start_worker(notepad_bridge)
    spin_id = _spin_when_told(notepad_bridge)
    script_id = asyncio.run(notepad_bridge.stalker_follow(thread_id=tid, events="call", limit=_EVENT_LIMIT))
    _spin_now(notepad_bridge, spin_id)

    started = time.monotonic()
    with pytest.raises(ToolError) as excinfo:
        asyncio.run(notepad_bridge.stalker_unfollow(thread_id=tid))
    elapsed = time.monotonic() - started

    assert "not acknowledged" in excinfo.value.message
    assert "did not answer" in excinfo.value.message
    assert _ACK_LIMIT_SECONDS - 1.0 <= elapsed < _ACK_LIMIT_SECONDS + _MARGIN_SECONDS
    assert tid not in cast("dict[int, str]", _private(notepad_bridge, "_stalker_scripts"))
    assert tid not in cast("dict[int, object]", _private(notepad_bridge, "_stalker_traces"))
    assert script_id not in cast("dict[str, object]", _private(notepad_bridge, "_scripts"))


def test_unfollow_after_the_script_stopped_itself_returns_its_trace_without_waiting_again(notepad_bridge: FridaBridge) -> None:
    """A trace that reached its event limit already acknowledged its own unfollow, so the explicit unfollow does not wait.

    Falsifiable: a bridge that always waited for a fresh acknowledgement would wait out the whole
    limit here, because the script ignores a second unfollow request once it has stopped.

    Args:
        notepad_bridge: Bridge attached to a private notepad.
    """
    tid = _start_worker(notepad_bridge)
    script_id = asyncio.run(notepad_bridge.stalker_follow(thread_id=tid, events="call", limit=1))
    status = cast("dict[str, tuple[threading.Event, dict[str, str]]]", _private(notepad_bridge, "_stalker_unfollow_status"))
    assert status[script_id][0].wait(_WAIT_SECONDS), "the script never stopped itself at its event limit"

    started = time.monotonic()
    trace = asyncio.run(notepad_bridge.stalker_unfollow(thread_id=tid))
    elapsed = time.monotonic() - started

    assert isinstance(trace, StalkerTrace)
    assert trace.event_count >= 1
    assert elapsed < _FAST_SECONDS, f"the unfollow waited {elapsed:.1f}s for an acknowledgement that had already come"


def test_unfollow_raises_with_the_reason_the_script_gave_when_its_own_unfollow_failed(notepad_bridge: FridaBridge) -> None:
    """A script that reports its unfollow failed makes ``stalker_unfollow`` raise with that reason.

    The registration is made by hand around a real loaded script, with a real event already set and
    the script's error recorded, because no real target makes ``Stalker.unfollow`` throw.

    Falsifiable: a bridge that looked only at the event and not at the recorded error would return an
    empty trace for a failed unfollow.

    Args:
        notepad_bridge: Bridge attached to a private notepad.
    """
    script_id = asyncio.run(notepad_bridge.execute_persistent_script("send('registered');"))
    reply = threading.Event()
    reply.set()
    cast("dict[int, str]", _private(notepad_bridge, "_stalker_scripts"))[_ERROR_TID] = script_id
    cast("dict[str, tuple[threading.Event, dict[str, str]]]", _private(notepad_bridge, "_stalker_unfollow_status"))[script_id] = (
        reply,
        {"error": "boom"},
    )

    with pytest.raises(ToolError) as excinfo:
        asyncio.run(notepad_bridge.stalker_unfollow(thread_id=_ERROR_TID))

    assert excinfo.value.details == {"thread_id": _ERROR_TID, "reason": "boom"}
    assert script_id not in cast("dict[str, object]", _private(notepad_bridge, "_scripts"))


def test_unfollow_raises_when_the_unfollow_was_acknowledged_but_the_script_cannot_be_unloaded(notepad_bridge: FridaBridge) -> None:
    """An acknowledged unfollow whose script then cannot be unloaded raises, and nothing of the trace is kept.

    The trace reaches its event limit and acknowledges its own unfollow, then the agent is made to stop
    answering, so the explicit unfollow has nothing left to wait for but the unload. In the sandbox this
    was the signature of every residual wedge: a followed thread that produced no event, an
    acknowledgement, and an unload that never came back, reported as an empty trace.

    Falsifiable: the first version of ``stalker_unfollow`` swallowed the unload timeout and returned
    the trace, so ``pytest.raises`` fails.

    Args:
        notepad_bridge: Bridge attached to a private notepad.
    """
    tid = _start_worker(notepad_bridge)
    spin_id = _spin_when_told(notepad_bridge)
    script_id = asyncio.run(notepad_bridge.stalker_follow(thread_id=tid, events="call", limit=1))
    status = cast("dict[str, tuple[threading.Event, dict[str, str]]]", _private(notepad_bridge, "_stalker_unfollow_status"))
    assert status[script_id][0].wait(_WAIT_SECONDS), "the script never stopped itself at its event limit"
    _spin_now(notepad_bridge, spin_id)

    started = time.monotonic()
    with pytest.raises(ToolError) as excinfo:
        asyncio.run(notepad_bridge.stalker_unfollow(thread_id=tid))
    elapsed = time.monotonic() - started

    assert "Script.unload" in excinfo.value.message
    assert "did not answer" in excinfo.value.message
    assert _ACK_LIMIT_SECONDS - 1.0 <= elapsed < _ACK_LIMIT_SECONDS + _MARGIN_SECONDS
    assert tid not in cast("dict[int, str]", _private(notepad_bridge, "_stalker_scripts"))
    assert tid not in cast("dict[int, object]", _private(notepad_bridge, "_stalker_traces"))
    assert script_id not in cast("dict[str, object]", _private(notepad_bridge, "_scripts"))


def test_an_acknowledged_unfollow_that_unloads_cleanly_returns_its_trace_even_with_no_events(notepad_bridge: FridaBridge) -> None:
    """An unfollow that was acknowledged and unloaded without trouble is a valid result when the trace holds no events.

    The registration is made by hand around a real loaded script with a real, already set event,
    because a real followed thread always produces events in this target.

    Falsifiable: a bridge that treated every empty trace as a failure would raise here.

    Args:
        notepad_bridge: Bridge attached to a private notepad.
    """
    script_id = asyncio.run(notepad_bridge.execute_persistent_script("send('registered');"))
    reply = threading.Event()
    reply.set()
    cast("dict[int, str]", _private(notepad_bridge, "_stalker_scripts"))[_ERROR_TID] = script_id
    cast("dict[str, tuple[threading.Event, dict[str, str]]]", _private(notepad_bridge, "_stalker_unfollow_status"))[script_id] = (reply, {})
    cast("dict[int, list[object]]", _private(notepad_bridge, "_stalker_traces"))[_ERROR_TID] = []

    trace = asyncio.run(notepad_bridge.stalker_unfollow(thread_id=_ERROR_TID))

    assert isinstance(trace, StalkerTrace)
    assert trace.event_count == 0
    assert script_id not in cast("dict[str, object]", _private(notepad_bridge, "_scripts"))


def test_unfollow_of_a_registration_whose_script_is_gone_returns_an_empty_trace(notepad_bridge: FridaBridge) -> None:
    """A registration with no script left has nothing to unfollow, which is an empty trace and not an error.

    Falsifiable: dereferencing the missing script would raise instead of returning.

    Args:
        notepad_bridge: Bridge attached to a private notepad.
    """
    cast("dict[int, str]", _private(notepad_bridge, "_stalker_scripts"))[_GHOST_TID] = "ghost"

    trace = asyncio.run(notepad_bridge.stalker_unfollow(thread_id=_GHOST_TID))

    assert trace.event_count == 0
    assert _GHOST_TID not in cast("dict[int, str]", _private(notepad_bridge, "_stalker_scripts"))


def test_the_unfollow_message_recorder_marks_acknowledgements_and_errors() -> None:
    """The recorder sets the reply on ``stalker_unfollowed`` and on ``stalker_unfollow_error`` (keeping the error), and ignores other types.

    Falsifiable: a recorder that ignored the error type would leave the reply unset on a failed
    unfollow, so the caller would wait out the whole limit.
    """
    record = cast(
        "Callable[[object, dict[str, object], threading.Event, dict[str, str]], None]",
        getattr(FridaBridge, "_note_stalker_unfollow_message"),
    )

    other_reply = threading.Event()
    other_info: dict[str, str] = {}
    record("stalker_batch", {"type": "stalker_batch"}, other_reply, other_info)
    assert not other_reply.is_set()
    assert other_info == {}

    done_reply = threading.Event()
    done_info: dict[str, str] = {}
    record("stalker_unfollowed", {"type": "stalker_unfollowed"}, done_reply, done_info)
    assert done_reply.is_set()
    assert done_info == {}

    failed_reply = threading.Event()
    failed_info: dict[str, str] = {}
    record("stalker_unfollow_error", {"type": "stalker_unfollow_error", "error": "no such thread"}, failed_reply, failed_info)
    assert failed_reply.is_set()
    assert failed_info == {"error": "no such thread"}
