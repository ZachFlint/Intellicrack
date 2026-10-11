# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""``enumerate_threads`` is answered by one helper script that lives as long as the session does.

The bridge used to answer ``enumerate_threads`` with a script it created and unloaded for the call.
In the sandbox, following a thread that had just been created, straight after such a call, left the
agent unresponsive in a third to a half of the sequences: ``Stalker.follow`` hung, or the later unfollow
was acknowledged and the script could not be unloaded. The cause is the unload of a script that has just
listed the threads, and keeping one helper loaded for the life of the session removed all but a residual
of a few percent that belongs to following a thread found by a listing at all (measured at 4 in 81 with
the helper, against 0 in about 310 for threads whose id came from their own message).

That residual is a rate and cannot be asserted deterministically, so these tests assert the mechanism
that removed the large effect: listings share one helper, no listing unloads anything, the helper is not
a user script, a destroyed helper is replaced and a detached session leaves none behind.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Final, cast

import pytest


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.bridges.frida_bridge import FridaBridge


pytestmark = pytest.mark.spawns_process

_LISTINGS: Final[int] = 5


def _private(bridge: FridaBridge, name: str) -> object:
    """Read a private attribute of a bridge.

    Args:
        bridge: The bridge to inspect.
        name: Attribute name.

    Returns:
        object: The attribute's value.
    """
    return getattr(bridge, name)


def test_repeated_thread_listings_share_one_helper_and_unload_nothing(notepad_bridge: FridaBridge) -> None:
    """Five listings on one session use the same helper script, which is neither unloaded nor a user script.

    Falsifiable: a bridge that created a script for each listing and unloaded it afterwards has no
    helper at all (``_thread_helper`` stays ``None``), which is also what made following a thread found
    by a listing wedge the agent.

    Args:
        notepad_bridge: Bridge attached to a private notepad.
    """
    first = asyncio.run(notepad_bridge.enumerate_threads())
    helper = _private(notepad_bridge, "_thread_helper")
    assert helper is not None
    destroyed: list[str] = []
    cast("Callable[[str, Callable[[], None]], None]", getattr(helper, "on"))("destroyed", lambda: destroyed.append("destroyed"))

    listings = [asyncio.run(notepad_bridge.enumerate_threads()) for _ in range(_LISTINGS)]

    assert first
    assert all(listing for listing in listings)
    assert all(thread.tid > 0 for listing in listings for thread in listing)
    assert all(len({thread.tid for thread in listing}) == len(listing) for listing in listings)
    assert _private(notepad_bridge, "_thread_helper") is helper
    assert destroyed == []
    assert cast("dict[str, object]", _private(notepad_bridge, "_scripts")) == {}


def test_thread_listing_replaces_a_destroyed_helper_and_leaves_none_after_detach(notepad_bridge: FridaBridge) -> None:
    """Stopping every user script leaves the helper alone, a destroyed helper is replaced, and a detach forgets it.

    Falsifiable: registering the helper among the user scripts would let "Stop All Scripts" unload it
    while the bridge still held it, and keeping the reference after a detach would hand the next
    session a helper that belongs to the old one.

    Args:
        notepad_bridge: Bridge attached to a private notepad.
    """
    assert asyncio.run(notepad_bridge.enumerate_threads())
    helper = _private(notepad_bridge, "_thread_helper")
    assert helper is not None

    asyncio.run(notepad_bridge.unload_all_scripts())
    assert _private(notepad_bridge, "_thread_helper") is helper

    cast("Callable[[], None]", getattr(helper, "unload"))()
    assert asyncio.run(notepad_bridge.enumerate_threads())
    replacement = _private(notepad_bridge, "_thread_helper")
    assert replacement is not None
    assert replacement is not helper

    asyncio.run(notepad_bridge.detach(kill_spawned=False))
    assert _private(notepad_bridge, "_thread_helper") is None
