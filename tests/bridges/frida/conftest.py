# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Fixtures for the Frida bridge tests that drive a real ``notepad.exe`` through a real agent."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.subprocess_compat import DEVNULL, Popen
from tests._helpers.frida_targets import notepad_executable, wait_for_gui_process_ready
from tests._helpers.process_cleanup import kill_pid_tree


if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture
def frida_notepad() -> Generator[Popen[bytes]]:
    """Spawn a private ``notepad.exe`` once it has finished starting, and kill it afterwards.

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


@pytest.fixture
def notepad_bridge(frida_notepad: Popen[bytes]) -> Generator[FridaBridge]:
    """Attach a fresh bridge to the private notepad; on teardown kill the target first, then shut the bridge down.

    The target dies before the shutdown so that a target or agent a test froze cannot hold the teardown.

    Args:
        frida_notepad: The private notepad process.

    Yields:
        FridaBridge: An initialized bridge attached to ``frida_notepad``.
    """
    bridge = FridaBridge()
    asyncio.run(bridge.initialize())
    asyncio.run(bridge.attach(frida_notepad.pid))
    try:
        yield bridge
    finally:
        kill_pid_tree(frida_notepad.pid)
        asyncio.run(bridge.shutdown())
