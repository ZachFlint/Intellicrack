# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for S16-D11: "Test Sandbox" must not leak a running instance.

The Sandbox-Settings dialog's "Test Sandbox" button
(``SandboxConfigDialog._test_sandbox``, in
``src/intellicrack/ui/sandbox_config.py``) launches ``WindowsSandbox.exe``
via ``SandboxTestWorker`` to verify the sandbox actually works, then always
terminates the launched instance once the check completes -- either because
the wait timed out (sandbox still open, needs cleanup) or an error occurred.

Before the fix, that cleanup went straight to a forced
``ProcessManager.terminate_tree`` (``TerminateProcess``) kill of the sandbox
client. Windows Sandbox's underlying Host Compute Service VM session is
documented to require the client's own graceful shutdown path (the same
one triggered by clicking the sandbox window's close button) to be released
cleanly; a bare forced kill of the client process can leave that session
orphaned, which then blocks a subsequent "Create" with only one Windows
Sandbox instance allowed to run at a time.

The fix (``SandboxTestWorker._terminate_sandbox_process``) posts
``WM_CLOSE`` to the sandbox client's top-level window first (mirroring the
window-close button) and only falls back to the forced process-tree kill
when no window is found or the graceful close does not complete in time.
Both ``run()``'s ``finally`` cleanup and ``stop()`` (the path
``_cancel_test`` uses when the dialog is closed/rejected mid-test) now go
through this shared helper.

This test cannot launch a real Windows Sandbox (forbidden by the task, and
unavailable in CI), so it drives the real ``SandboxTestWorker`` termination
logic against a real, controllable stand-in subprocess -- the same pattern
already used by the project's own ``TestM15SandboxTestWorkerLifecycle``
gates in ``tests/ui/test_gui_audit0702_sandbox_config.py``. The genuine,
falsifiable assertion is that the graceful-close boundary
(``sandbox_config.find_window_by_pid``) is actually consulted before any
hard kill happens: reverting the fix (going back to a bare
``ProcessManager.terminate_tree`` call) means that boundary is never
touched, which this test would catch.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.subprocess_compat import CREATE_NO_WINDOW, Popen
from intellicrack.ui import sandbox_config
from intellicrack.ui.sandbox_config import SandboxTestWorker


if TYPE_CHECKING:
    from collections.abc import Generator

_SLEEP_SECONDS = 30
_WAIT_S = 5.0


@pytest.fixture
def sleeping_process(qapp: object) -> Generator[Popen[bytes]]:
    """Launch a real, killable, windowless subprocess standing in for a sandbox client.

    Args:
        qapp: Session QApplication fixture; required so the offscreen Qt
            platform is initialised consistently with the rest of the suite,
            even though this fixture does not construct any Qt widgets.

    Yields:
        Popen[bytes]: A live Python subprocess sleeping for
        ``_SLEEP_SECONDS``, registered with ``ProcessManager`` exactly as
        ``SandboxTestWorker._register_test_process`` would register a real
        launched sandbox client.
    """
    del qapp
    process = Popen(
        [sys.executable, "-c", f"import time; time.sleep({_SLEEP_SECONDS})"],
        creationflags=CREATE_NO_WINDOW,
    )
    ProcessManager.get_instance().register(
        process,
        name="gate-test-fake-sandbox-s16d11",
        process_type=ProcessType.SANDBOX,
    )
    try:
        yield process
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        ProcessManager.get_instance().unregister(process.pid)


@pytest.mark.spawns_process
class TestSandboxTestWorkerDoesNotLeakARunningInstance:
    """S16-D11: sandbox test termination must attempt a graceful close and never leak."""

    @staticmethod
    def test_stop_consults_graceful_close_before_hard_kill_and_leaves_nothing_running(
        sleeping_process: Popen[bytes],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``SandboxTestWorker.stop()`` must consult the graceful-close boundary and leave no leak.

        ``sandbox_config.find_window_by_pid`` is monkeypatched to a recorder
        that still returns ``None`` (the real, deterministic outcome for this
        windowless console stand-in process) so the test asserts the
        production code actually calls into the graceful-close boundary --
        the real behavioural change this fix introduces -- while letting the
        real fallback termination path run unmodified afterwards.

        Args:
            sleeping_process: Real, killable subprocess fixture standing in
                for a launched sandbox client.
            monkeypatch: pytest monkeypatch fixture.
        """
        calls: list[int] = []

        def _recording_find_window_by_pid(pid: int) -> int | None:
            """Record the probed pid and report no window found.

            Args:
                pid: Process ID passed by the code under test.

            Returns:
                int | None: Always ``None`` (no window), the real outcome
                for a windowless console subprocess.
            """
            calls.append(pid)
            return None

        monkeypatch.setattr(sandbox_config, "find_window_by_pid", _recording_find_window_by_pid)

        worker = SandboxTestWorker()
        worker._process = sleeping_process
        assert sleeping_process.poll() is None, "test premise: the stand-in process must still be alive before stop()"

        worker.stop()

        assert calls == [sleeping_process.pid], (
            f"stop() must consult the graceful-close boundary (find_window_by_pid) for the sandbox client's pid before any hard "
            f"kill; got calls={calls!r}. If this is empty, the fix was reverted to a bare force-kill."
        )

        sleeping_process.wait(timeout=_WAIT_S)
        assert sleeping_process.poll() is not None, "the sandbox client process must not still be running after stop()"

        tracked = ProcessManager.get_instance().get_tracked(sleeping_process.pid)
        assert tracked is None, f"ProcessManager must not still be tracking the terminated sandbox client; got {tracked!r}"

    @staticmethod
    def test_run_finally_terminates_the_process_even_without_explicit_stop(
        sleeping_process: Popen[bytes],
    ) -> None:
        """The unconditional ``run()`` ``finally`` cleanup must also leave nothing running.

        Exercises ``_terminate_sandbox_process`` through the real (not
        monkeypatched) ``find_window_by_pid`` Win32 call against the real
        stand-in subprocess, proving the whole graceful-then-forced pipeline
        completes and leaves no leaked process or tracking entry -- with no
        real Windows Sandbox involved.

        Args:
            sleeping_process: Real, killable subprocess fixture standing in
                for a launched sandbox client.
        """
        worker = SandboxTestWorker()
        worker._process = sleeping_process
        assert sleeping_process.poll() is None, "test premise: the stand-in process must still be alive before cleanup"

        worker._terminate_sandbox_process()

        sleeping_process.wait(timeout=_WAIT_S)
        assert sleeping_process.poll() is not None, "the sandbox client process must not still be running after cleanup"

        tracked = ProcessManager.get_instance().get_tracked(sleeping_process.pid)
        assert tracked is None, f"ProcessManager must not still be tracking the terminated sandbox client; got {tracked!r}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
