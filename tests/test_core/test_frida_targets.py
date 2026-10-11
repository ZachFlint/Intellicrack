# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the Frida target helpers in :mod:`tests._helpers.frida_targets`.

A deadline helper that never fires, or a readiness wait that returns before the
child has said it is ready, would silently put the hang or the startup race back
into every Frida module that relies on them, so each is exercised against a real
stuck coroutine and real child processes.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from tests._helpers.frida_targets import (
    clear_hung_calls,
    end_target_then_shutdown,
    run_bounded,
    wait_for_gui_process_ready,
    wait_for_stdout_line,
)


if TYPE_CHECKING:
    from collections.abc import Generator


_DEADLINE_SECONDS = 0.5
_READY_LINE = b"child-ready"
_READY_SOURCE = f"import sys, time\nsys.stdout.write('{_READY_LINE.decode()}\\n')\nsys.stdout.flush()\ntime.sleep(60)\n"
_WRONG_LINE_SOURCE = "import sys, time\nsys.stdout.write('something-else\\n')\nsys.stdout.flush()\ntime.sleep(60)\n"
_SILENT_SOURCE = "import time\ntime.sleep(60)\n"
_STOP_TIMEOUT_SECONDS = 10.0
_SHORT_READY_TIMEOUT_SECONDS = 1.0
_ANSWER = 42
_NOTEPAD_READY_CEILING_SECONDS = 10.0
_SWALLOW_POLL_SECONDS = 0.05
_GIVE_UP_MARGIN_SECONDS = 5.0


@pytest.fixture(autouse=True)
def fresh_hung_call_record() -> Generator[None]:
    """Start and finish each test with no recorded missed deadlines.

    Yields:
        None: Control to the test.
    """
    clear_hung_calls()
    yield
    clear_hung_calls()


def _spawn(source: str) -> Popen[bytes]:
    """Start a Python child with a piped stdout.

    Args:
        source: Program text for the child.

    Returns:
        Popen[bytes]: The running child.
    """
    return Popen([sys.executable, "-c", source], stdout=PIPE, stderr=DEVNULL)


def _release(child: Popen[bytes]) -> None:
    """Stop a child and close its pipe.

    Args:
        child: The child to release.
    """
    child.terminate()
    child.wait(timeout=_STOP_TIMEOUT_SECONDS)
    if child.stdout is not None:
        child.stdout.close()


def test_run_bounded_returns_the_coroutine_result() -> None:
    """A coroutine that finishes in time hands its value back unchanged."""

    async def answer() -> int:
        """Return a fixed value.

        Returns:
            int: The fixed value.
        """
        await asyncio.sleep(0)
        return _ANSWER

    assert run_bounded(answer()) == _ANSWER


class _FakeBridge:
    """Stand-in for a ``FridaBridge``: one call can block in a thread, the others answer at once."""

    def __init__(self, release: threading.Event) -> None:
        """Remember the event that frees the blocking call.

        Args:
            release: Event the blocking call waits on in a worker thread.
        """
        self._release = release
        self.pings = 0
        self.closed = False

    async def stuck(self) -> None:
        """Block a worker thread until the test releases it."""
        await asyncio.to_thread(self._release.wait)

    async def blocks_its_own_loop(self) -> None:
        """Block the event loop thread itself, so no timer or cancellation can ever run on that loop."""
        self._release.wait()

    async def swallows_cancellation(self) -> None:
        """Keep running whenever the loop tries to cancel it, until the test releases it."""
        while not self._release.is_set():
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.sleep(_SWALLOW_POLL_SECONDS)

    async def ping(self) -> int:
        """Answer immediately and count the call.

        Returns:
            int: A fixed value.
        """
        await asyncio.sleep(0)
        self.pings += 1
        return _ANSWER

    async def shutdown(self) -> None:
        """Mark the bridge closed."""
        await asyncio.sleep(0)
        self.closed = True


def test_run_bounded_fails_a_call_that_never_returns_and_refuses_that_bridge_afterwards() -> None:
    """A call stuck in a thread fails at its deadline and later calls on the same bridge are refused unrun.

    Falsifiable: without the deadline the first call waits for the released
    thread forever, and without the record the second call would run and count
    a ping instead of being refused with the first call's name.
    """
    release = threading.Event()
    bridge = _FakeBridge(release)

    try:
        with pytest.raises(pytest.fail.Exception, match="did not return within"):
            run_bounded(bridge.stuck(), timeout=_DEADLINE_SECONDS, what="stalker_unfollow")
        with pytest.raises(pytest.fail.Exception, match="stalker_unfollow"):
            run_bounded(bridge.ping())
    finally:
        release.set()

    assert bridge.pings == 0, "a call made after a missed deadline must be refused, not run"


@pytest.mark.parametrize("method_name", ["blocks_its_own_loop", "swallows_cancellation"])
def test_run_bounded_gives_up_on_a_coroutine_that_cannot_be_cancelled(method_name: str) -> None:
    """A coroutine that blocks its loop or swallows cancellation still fails at the limit.

    The call runs on its own thread, so neither behavior can keep the caller
    waiting past ``timeout``, and the abandoned call leaves the bridge marked stuck.

    Falsifiable: a bound that ran the coroutine on the calling thread and relied
    on cancelling it would never return for the first case and would wait out the
    coroutine for the second, so the elapsed-time assertion (or the whole run)
    fails.

    Args:
        method_name: Which uncancellable behavior of the fake bridge to run.
    """
    release = threading.Event()
    bridge = _FakeBridge(release)
    started = time.monotonic()

    try:
        with pytest.raises(pytest.fail.Exception, match="did not return within"):
            run_bounded(getattr(bridge, method_name)(), timeout=_DEADLINE_SECONDS)
        elapsed = time.monotonic() - started
        with pytest.raises(pytest.fail.Exception, match="was not attempted"):
            run_bounded(bridge.ping())
    finally:
        release.set()

    assert elapsed < _DEADLINE_SECONDS + _GIVE_UP_MARGIN_SECONDS, f"the caller waited {elapsed:g}s on a {_DEADLINE_SECONDS:g}s limit"
    assert bridge.pings == 0


def test_a_stuck_bridge_does_not_stop_another_bridge_or_unowned_calls() -> None:
    """Only the bridge whose call missed its deadline is refused; a second bridge and a free coroutine still run.

    Falsifiable: a record that covered the whole process would refuse the second
    bridge's ping and the free coroutine, which is the cascade this scoping removed.
    """
    release = threading.Event()
    stuck_bridge = _FakeBridge(release)
    healthy_bridge = _FakeBridge(release)

    async def free_call() -> int:
        """Answer without belonging to any bridge.

        Returns:
            int: A fixed value.
        """
        await asyncio.sleep(0)
        return _ANSWER

    try:
        with pytest.raises(pytest.fail.Exception, match="did not return within"):
            run_bounded(stuck_bridge.stuck(), timeout=_DEADLINE_SECONDS)
        assert run_bounded(healthy_bridge.ping()) == _ANSWER
        assert run_bounded(free_call()) == _ANSWER
    finally:
        release.set()

    assert healthy_bridge.pings == 1


@pytest.mark.spawns_process
def test_end_target_then_shutdown_kills_the_target_and_shuts_a_stuck_bridge_down() -> None:
    """Teardown ends the target process and still shuts a bridge down after that bridge was marked stuck.

    Falsifiable: a teardown that obeyed the stuck record would raise instead of
    shutting the bridge down, and one that skipped the kill would leave the
    target running.
    """
    release = threading.Event()
    bridge = _FakeBridge(release)
    child = _spawn(_SILENT_SOURCE)
    try:
        with pytest.raises(pytest.fail.Exception, match="did not return within"):
            run_bounded(bridge.stuck(), timeout=_DEADLINE_SECONDS)

        end_target_then_shutdown(child, bridge)

        assert child.poll() is not None, "the target process must be killed first"
        assert bridge.closed, "the bridge must be shut down even though it was marked stuck"
    finally:
        release.set()
        _release(child)


def _notepad_path() -> str:
    """Locate the ``notepad.exe`` the Frida modules attach to.

    Returns:
        str: Path to ``notepad.exe``.
    """
    return shutil.which("notepad.exe") or str(Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "notepad.exe")


@pytest.mark.spawns_process
def test_wait_for_gui_process_ready_returns_for_a_live_notepad() -> None:
    """A freshly spawned notepad becomes ready well inside the deadline and keeps running.

    In the container ``WaitForInputIdle`` returned for notepad in 15 to 46 ms, so
    a result near the 30 s deadline would mean the wait no longer sees the process go idle.
    """
    notepad = Popen([_notepad_path()], stdout=DEVNULL, stderr=DEVNULL)
    try:
        elapsed = wait_for_gui_process_ready(notepad)
        assert 0.0 <= elapsed < _NOTEPAD_READY_CEILING_SECONDS, f"notepad took {elapsed:g}s to report ready"
        assert notepad.poll() is None, "notepad must still be running once it is ready"
    finally:
        notepad.terminate()
        notepad.wait(timeout=_STOP_TIMEOUT_SECONDS)


@pytest.mark.spawns_process
def test_wait_for_gui_process_ready_fails_for_a_process_that_already_exited() -> None:
    """A process that is gone is reported as exited, not waited on until the deadline.

    Falsifiable: a wait that ignored the process state would either return as
    though the dead process were ready or sit out the 30 s deadline.
    """
    notepad = Popen([_notepad_path()], stdout=DEVNULL, stderr=DEVNULL)
    notepad.terminate()
    notepad.wait(timeout=_STOP_TIMEOUT_SECONDS)

    with pytest.raises(pytest.fail.Exception, match="exited with code"):
        wait_for_gui_process_ready(notepad)


def test_wait_for_stdout_line_returns_once_the_child_reports_ready() -> None:
    """A child that prints its readiness line releases the wait."""
    child = _spawn(_READY_SOURCE)
    try:
        elapsed = wait_for_stdout_line(child, _READY_LINE)
        assert child.poll() is None, "the child must still be running after reporting ready"
        assert elapsed >= 0.0
    finally:
        _release(child)


def test_wait_for_stdout_line_fails_and_stops_a_child_that_never_reports() -> None:
    """A child that stays silent fails the wait at its deadline and is terminated.

    Falsifiable: a wait that returned without a line, or one that left the silent
    child running, fails the first or the last assertion.
    """
    child = _spawn(_SILENT_SOURCE)
    try:
        with pytest.raises(pytest.fail.Exception, match="printed no readiness line"):
            wait_for_stdout_line(child, _READY_LINE, timeout=_SHORT_READY_TIMEOUT_SECONDS)
        child.wait(timeout=_STOP_TIMEOUT_SECONDS)
        assert child.poll() is not None, "a child that never reported ready must be stopped"
    finally:
        _release(child)


def test_wait_for_stdout_line_rejects_a_different_first_line() -> None:
    """A child whose first line is not the readiness line fails the wait."""
    child = _spawn(_WRONG_LINE_SOURCE)
    try:
        with pytest.raises(pytest.fail.Exception, match="instead of its readiness line"):
            wait_for_stdout_line(child, _READY_LINE)
    finally:
        _release(child)
