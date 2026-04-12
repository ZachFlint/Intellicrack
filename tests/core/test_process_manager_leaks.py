# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for process cleanup and leak detection."""

from __future__ import annotations

import asyncio
import subprocess
import sys
from collections.abc import Callable
from typing import cast

import psutil
import pytest

from intellicrack.core.process_manager import ProcessManager, ProcessType


def _sync_cleanup(pm: ProcessManager) -> Callable[[], None]:
    """Return the synchronous cleanup callable of a ProcessManager.

    Args:
        pm: The ProcessManager instance to clean up.

    Returns:
        Callable[[], None]: Bound ``_sync_cleanup`` method reference.
    """
    return cast(Callable[[], None], getattr(pm, "_sync_cleanup"))


@pytest.mark.asyncio
async def test_process_tree_cleanup() -> None:
    """Verify that ProcessManager kills process trees (parent + children)."""
    # 1. Prepare scripts
    # Child: sleeps for 60s
    child_code = "import time; time.sleep(60)"

    # Parent: spawns child, prints child PID, then sleeps 60s
    parent_code = f"""
import subprocess
import sys
import time
# Spawn child
p = subprocess.Popen([sys.executable, "-c", {child_code!r}])
# Print child PID so test knows it
print(p.pid)
sys.stdout.flush()
# Sleep to keep parent alive
time.sleep(60)
"""

    # 2. Start parent process using asyncio
    process = await asyncio.create_subprocess_exec(sys.executable, "-c", parent_code, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    parent_pid = process.pid

    # 3. Read child PID from parent's stdout
    assert process.stdout is not None
    try:
        line = await asyncio.wait_for(process.stdout.readline(), timeout=5.0)
        child_pid = int(line.strip())
    except (TimeoutError, ValueError):
        process.kill()
        pytest.fail("Failed to get child PID from parent process")

    # Verify both are running
    assert psutil.pid_exists(parent_pid), "Parent should be running"
    assert psutil.pid_exists(child_pid), "Child should be running"

    # 4. Register with ProcessManager
    pm = ProcessManager.get_instance()
    pm.register(process, "test_parent_tree", ProcessType.ASYNC_SUBPROCESS)

    # 5. Terminate via ProcessManager
    # This triggers _terminate_subprocess -> _terminate_tree_with_psutil
    await pm.terminate_process(parent_pid)

    # 6. Verify cleanup
    # Give a small buffer for OS to update process table
    await asyncio.sleep(0.5)

    assert not psutil.pid_exists(parent_pid), "Parent process leaked"
    assert not psutil.pid_exists(child_pid), "Child process leaked (zombie)"


@pytest.mark.asyncio
async def test_sync_cleanup_tree() -> None:
    """Verify that _sync_cleanup (atexit) kills process trees."""
    # 1. Prepare scripts
    child_code = "import time; time.sleep(60)"
    parent_code = f"""
import subprocess
import sys
import time
p = subprocess.Popen([sys.executable, "-c", {child_code!r}])
print(p.pid)
sys.stdout.flush()
time.sleep(60)
"""

    # 2. Start parent
    process = await asyncio.create_subprocess_exec(sys.executable, "-c", parent_code, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    parent_pid = process.pid

    # 3. Get child PID
    assert process.stdout is not None
    try:
        line = await asyncio.wait_for(process.stdout.readline(), timeout=5.0)
        child_pid = int(line.strip())
    except (TimeoutError, ValueError):
        process.kill()
        pytest.fail("Failed to get child PID")

    # 4. Register
    pm = ProcessManager.get_instance()
    # Reset to ensure clean state
    ProcessManager.reset_instance()
    pm = ProcessManager.get_instance()

    pm.register(process, "test_parent_sync", ProcessType.ASYNC_SUBPROCESS)

    # 5. Call sync cleanup (simulating atexit)
    # We run it in a thread because it's blocking
    await asyncio.to_thread(_sync_cleanup(pm))

    # 6. Verify
    await asyncio.sleep(0.5)
    assert not psutil.pid_exists(parent_pid), "Parent process leaked in sync cleanup"
    assert not psutil.pid_exists(child_pid), "Child process leaked in sync cleanup"
