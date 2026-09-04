# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gate for the Cutter timeout pipe-poisoning containment.

When an ``_r2_cmd`` call times out, ``asyncio.wait_for`` abandons the coroutine
but cannot stop the OS thread that ``asyncio.to_thread`` handed the blocking
``cmd`` call to. That orphaned worker keeps reading and writing the single
analysis pipe after the lock is released, so any command issued afterwards
races it on the shared pipe -- the framing corruption that produced the
field-observed cascade of downstream ``r2_command_timeout`` warnings and
``rizin_json_unrecoverable`` parse failures.

The containment fix makes a timeout tear the session down
(``_discard_r2_session_locked``): it nulls the connection slot so no later
command can touch the dirty pipe, terminates the rizin child by PID to unblock
the orphaned worker, and leaves the bridge in a clean "reload required" state.

These gates drive the real bridge through a genuine timeout:

* ``test_timeout_poisons_session_and_rejects_next_command`` -- a real blocking
  pipe double forces a timeout, then asserts the session is discarded
  (``bridge.r2 is None``) and the *next* command is rejected up front with
  "no binary loaded" instead of being run against the corrupted pipe. Against
  the pre-fix code the pipe is left connected, so the session is not ``None``
  and the next command hits the pipe again (a second timeout) -- both
  assertions go RED.
* ``test_timeout_terminates_corrupted_child`` -- registers a real child
  process as the session's rizin PID and asserts the timeout path actually
  terminates it (the mechanism that unblocks the orphaned worker). The pre-fix
  code never kills it, so the process stays alive and the wait times out RED.
"""

from __future__ import annotations

import asyncio
import contextlib
import subprocess
import sys
import threading
from typing import TYPE_CHECKING, Any, Final, cast

import pytest

from intellicrack.bridges import cutter as cutter_mod
from intellicrack.bridges.cutter import CutterBridge
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Iterator


pytestmark = pytest.mark.asyncio

_TINY_TIMEOUT: Final[float] = 0.05
_WORKER_RELEASE_CAP: Final[float] = 15.0


class _BlockingPipe:
    """Analysis-pipe double whose ``cmd`` blocks like a wedged rizin child.

    ``cmd`` records the command, then blocks on an internal event until the
    test releases it (or a safety cap elapses), reproducing the real hazard:
    the blocking call outlives the coroutine's timeout and keeps the worker
    thread alive on the pipe.
    """

    def __init__(self) -> None:
        """Initialize the call log and the release gate."""
        self.commands: list[str] = []
        self._release = threading.Event()

    def cmd(self, command: str) -> str:
        """Record the command and block until released or the safety cap.

        Args:
            command: The rizin/r2 command issued by the bridge.

        Returns:
            str: An empty JSON array once unblocked (value is discarded by the
            timed-out caller).
        """
        self.commands.append(command)
        self._release.wait(timeout=_WORKER_RELEASE_CAP)
        return "[]"

    def release(self) -> None:
        """Unblock any worker parked inside :meth:`cmd`."""
        self._release.set()

    def quit(self) -> None:
        """Satisfy the pipe teardown contract and unblock the worker."""
        self._release.set()


@pytest.fixture
def blocking_pipe() -> Iterator[_BlockingPipe]:
    """Provide a blocking pipe double, always released at teardown.

    Yields:
        _BlockingPipe: A fresh pipe double whose parked worker thread is
        guaranteed to be released after the test.
    """
    pipe = _BlockingPipe()
    try:
        yield pipe
    finally:
        pipe.release()


async def test_timeout_poisons_session_and_rejects_next_command(
    monkeypatch: pytest.MonkeyPatch,
    blocking_pipe: _BlockingPipe,
) -> None:
    """A timed-out command must discard the session, not leave a dirty pipe.

    With the module command default squeezed to :data:`_TINY_TIMEOUT` and the
    pipe blocking well past it, ``get_callgraph`` times out. The fix must then
    null the connection slot and reject the *next* command up front with
    "no binary loaded" -- proving no follow-up command is ever run against the
    corrupted pipe. Against the pre-fix code the session stays connected, so
    both assertions fail.

    Args:
        monkeypatch: Fixture used to shrink the module command default.
        blocking_pipe: The blocking analysis-pipe double.
    """
    monkeypatch.setattr(cutter_mod, "R2_COMMAND_TIMEOUT", _TINY_TIMEOUT)

    bridge = CutterBridge()
    bridge.r2 = cast("Any", blocking_pipe)

    with pytest.raises(ToolError):
        await bridge.get_callgraph()

    assert bridge.r2 is None, "timed-out session must be discarded, not left connected to the dirty pipe"

    with pytest.raises(ToolError) as next_exc:
        await bridge.get_callgraph()
    assert "no binary loaded" in str(next_exc.value), (
        "after a timeout the next command must be rejected up front, not run against the corrupted pipe"
    )


@pytest.fixture
def corrupted_child() -> Iterator[subprocess.Popen[bytes]]:
    """Spawn a real child process registered as a session's rizin PID.

    Yields:
        subprocess.Popen[bytes]: A live child process registered with the
        process manager as an external-tool PID. It is killed and unregistered
        at teardown if the test did not already terminate it.
    """
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    manager = ProcessManager.get_instance()
    manager.register_external_pid(
        child.pid,
        name="test-cutter-corrupted-child",
        process_type=ProcessType.EXTERNAL_TOOL,
        metadata={"binary": "timeout-containment-gate"},
    )
    try:
        yield child
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5.0)
        with contextlib.suppress(OSError, RuntimeError, ValueError, KeyError):
            manager.unregister_external_pid(child.pid)


@pytest.mark.spawns_process
async def test_timeout_terminates_corrupted_child(
    monkeypatch: pytest.MonkeyPatch,
    blocking_pipe: _BlockingPipe,
    corrupted_child: subprocess.Popen[bytes],
) -> None:
    """The timeout path must terminate the corrupted session's rizin child.

    Uses a real, long-lived child process as the bridge's rizin PID, then
    forces a command timeout. The containment must terminate that child (the
    real mechanism that closes the pipe handles and unblocks the orphaned
    worker). The pre-fix code never touches the child, so it stays alive and
    the wait times out -- RED.

    Args:
        monkeypatch: Fixture used to shrink the module command default.
        blocking_pipe: The blocking analysis-pipe double.
        corrupted_child: The real child process registered as the rizin PID.
    """
    monkeypatch.setattr(cutter_mod, "R2_COMMAND_TIMEOUT", _TINY_TIMEOUT)

    bridge = CutterBridge()
    setattr(bridge, "_r2_pid", corrupted_child.pid)
    bridge.r2 = cast("Any", blocking_pipe)

    with pytest.raises(ToolError):
        await bridge.get_callgraph()

    await asyncio.to_thread(corrupted_child.wait, _WORKER_RELEASE_CAP)
    assert corrupted_child.returncode is not None, "corrupted rizin child must be terminated by the timeout teardown"
