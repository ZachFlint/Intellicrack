# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Bounded polling of state that only an outside party can change.

An ``asyncio.Event`` is the right tool when the code under test owns the signal.
Some gates observe state that nothing in the test can signal: a production
client's connection flag flipped by its own reader task when the peer closes the
socket, or a log file written by a separate real process. Those gates have to
look at the state itself, and this module is the one place that does so with a
hard deadline, so a regression fails the assertion that follows the wait rather
than hanging the run.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Callable


async def wait_until(condition: Callable[[], bool], *, budget: float, interval: float) -> float:
    """Poll ``condition`` until it holds or ``budget`` seconds have passed.

    The condition is evaluated once before any sleep, so state that already
    holds costs no waiting. Running out of budget is not an error here: the
    caller's own assertion on the state is the gate, which keeps the failure
    message naming the thing that did not happen.

    Args:
        condition: Zero-argument predicate over externally owned state.
        budget: Maximum seconds to wait before giving up.
        interval: Seconds to sleep between evaluations of ``condition``.

    Returns:
        float: Seconds spent waiting, whether or not ``condition`` came to hold.
    """
    started = time.monotonic()
    while not condition():
        if time.monotonic() - started >= budget:
            break
        await asyncio.sleep(interval)
    return time.monotonic() - started
