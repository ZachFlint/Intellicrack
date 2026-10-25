# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the adaptive dispatcher-ready wait in Windows Sandbox create.

The launch sequence can run correctly all the way through
``windows_sandbox_session_bound`` with a real session process alive while the
in-guest dispatcher is slow to signal ready. A fixed 120-second budget would
abort the whole create with a modal failure and give no indication of which
startup stage the guest had actually reached.

:meth:`WindowsSandbox._wait_for_dispatcher_ready` is therefore adaptive: it
starts with a 120-second budget, but every time real evidence of guest
progress appears - the guest logon command actually having run (recorded by
:attr:`WindowsSandbox.DISPATCHER_LOGON_MARKER`, written by the bootstrap
script before it even launches the dispatcher), or any monitor having
produced its first log line - the deadline is pushed out, capped at a
generous ceiling. A guest that never gets anywhere still fails at the
original budget, but one that keeps proving it is alive keeps being given
more time, and the eventual failure names the last stage actually reached.

These gates drive the real, unmodified wait coroutine against a real
temporary directory standing in for the shared folder - the only thing
faked is the passage of time, via monkeypatched module constants, so the
gates run in a few seconds rather than minutes.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from intellicrack.sandbox import windows as windows_module
from intellicrack.sandbox.base import SandboxError
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from pathlib import Path


class _ExposedWindowsSandbox(WindowsSandbox):
    """Exposes the dispatcher-ready internals under test without private access.

    ``basedpyright`` reports ``reportPrivateUsage`` for a test reaching a
    private member directly, so the members under test are forwarded through
    public methods - the same pattern the sibling quiescence gate
    (``tests/sandbox/windows/test_monitor_quiescence_s18d22.py``) uses.
    """

    def use_shared_folder(self, path: Path) -> None:
        """Point the sandbox at a host-side shared folder.

        Args:
            path: Folder standing in for the guest-visible shared mount.
        """
        self._shared_folder = path

    def progress_markers(self) -> tuple[bool, bool]:
        """Forward to :meth:`WindowsSandbox._dispatcher_progress_markers`.

        Returns:
            tuple[bool, bool]: ``(logon_ran, monitor_reported)``.
        """
        return self._dispatcher_progress_markers()

    def failure_stage(self, *, logon_ran: bool, monitor_reported: bool) -> str:
        """Forward to :meth:`WindowsSandbox._dispatcher_wait_failure_stage`.

        Args:
            logon_ran: Whether the guest logon command was observed to run.
            monitor_reported: Whether any monitor produced its first log line.

        Returns:
            str: The stage diagnostic the private implementation produces.
        """
        return self._dispatcher_wait_failure_stage(logon_ran=logon_ran, monitor_reported=monitor_reported)

    async def wait_for_dispatcher_ready(self) -> None:
        """Forward to :meth:`WindowsSandbox._wait_for_dispatcher_ready`."""
        await self._wait_for_dispatcher_ready()


def _make_shared_folder(tmp_path: Path) -> Path:
    """Build the ``flags``/``logs`` layout the dispatcher wait reads from.

    Args:
        tmp_path: Pytest scratch directory for this test.

    Returns:
        Path: The shared-folder root, with empty ``flags`` and ``logs``
        subdirectories already created.
    """
    shared = tmp_path / "shared"
    (shared / "flags").mkdir(parents=True)
    (shared / "logs").mkdir(parents=True)
    return shared


def test_progress_markers_reflect_real_filesystem_state(tmp_path: Path) -> None:
    """The two progress markers must track exactly what is really on disk.

    Args:
        tmp_path: Pytest scratch directory for this test.
    """
    shared = _make_shared_folder(tmp_path)
    sandbox = _ExposedWindowsSandbox()
    sandbox.use_shared_folder(shared)

    assert sandbox.progress_markers() == (False, False), "a freshly created shared folder must show no progress yet"

    (shared / "flags" / WindowsSandbox.DISPATCHER_LOGON_MARKER).write_text("logon_started", encoding="ascii")
    assert sandbox.progress_markers() == (True, False), "the logon marker alone must not also report a monitor log"

    (shared / "logs" / "file_monitor.log").write_text("2026-01-01|created|...\n", encoding="utf-8")
    assert sandbox.progress_markers() == (True, True), "a real log file under logs/ must be detected as monitor progress"


def test_failure_stage_names_the_correct_startup_stage() -> None:
    """Each combination of observed progress must map to a distinct, correct diagnosis."""
    sandbox = _ExposedWindowsSandbox()

    never_started = sandbox.failure_stage(logon_ran=False, monitor_reported=False)
    assert "logon command never ran" in never_started

    logon_only = sandbox.failure_stage(logon_ran=True, monitor_reported=False)
    assert "no monitor produced any output" in logon_only

    both_but_not_ready = sandbox.failure_stage(logon_ran=True, monitor_reported=True)
    assert "dispatcher never signalled ready" in both_but_not_ready

    stages = {never_started, logon_only, both_but_not_ready}
    assert len(stages) == 3, "the three startup stages must produce three distinct diagnostics"


@pytest.mark.asyncio
async def test_wait_returns_immediately_when_the_ready_marker_is_already_present(tmp_path: Path) -> None:
    """A dispatcher that has already signalled ready must not be waited on further.

    Args:
        tmp_path: Pytest scratch directory for this test.
    """
    shared = _make_shared_folder(tmp_path)
    (shared / "flags" / WindowsSandbox.DISPATCHER_READY_MARKER).write_text("ready", encoding="ascii")

    sandbox = _ExposedWindowsSandbox()
    sandbox.use_shared_folder(shared)
    sandbox.process = None

    # A correct implementation returns on its very first poll; a fixed-wait
    # regression would instead block for the whole (real, minutes-long) budget.
    await asyncio.wait_for(sandbox.wait_for_dispatcher_ready(), timeout=5.0)


@pytest.mark.asyncio
async def test_wait_extends_its_deadline_on_real_progress_and_reports_the_reached_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guest progress observed inside the base budget must push the deadline out.

    The ready marker is never written, so the wait must eventually fail - but
    only after running past the shrunken base timeout, because the logon
    marker is already on disk when the wait begins: the wait's first poll
    always runs, before any deadline check can fail, and treats the newly
    seen marker as progress inside the base window. The marker is therefore
    ordered before the wait by construction, not by a delay, so no sub-second
    race with a loaded event loop or disk exists. A non-adaptive
    (fixed-timeout) implementation would instead fail right at the base
    timeout, never seeing the deadline move.

    The extension is far larger than the ceiling, so the end of the wait is
    set by the ceiling cap alone. The elapsed time is therefore bounded below
    by the ceiling (a deadline is never passed early), which is also well past
    the base timeout, while the ten second ``wait_for`` limit is only the
    failure bound for a capless implementation, which would wait out the whole
    extension.

    Args:
        tmp_path: Pytest scratch directory for this test.
        monkeypatch: Pytest fixture used to shrink the real timing constants
            so the gate runs in a few seconds instead of minutes.
    """
    base_timeout = 1.0
    extension = 30.0
    ceiling = 3.0
    monkeypatch.setattr(windows_module, "_DISPATCHER_STARTUP_TIMEOUT", base_timeout)
    monkeypatch.setattr(windows_module, "_DISPATCHER_READY_PROGRESS_EXTENSION_S", extension)
    monkeypatch.setattr(windows_module, "_DISPATCHER_READY_MAX_CEILING_S", ceiling)
    monkeypatch.setattr(windows_module, "_DISPATCHER_POLL_INTERVAL", 0.05)

    shared = _make_shared_folder(tmp_path)
    (shared / "flags" / WindowsSandbox.DISPATCHER_LOGON_MARKER).write_text("logon_started", encoding="ascii")
    sandbox = _ExposedWindowsSandbox()
    sandbox.use_shared_folder(shared)
    sandbox.process = None

    loop = asyncio.get_running_loop()
    started = loop.time()
    with pytest.raises(SandboxError) as exc_info:
        await asyncio.wait_for(sandbox.wait_for_dispatcher_ready(), timeout=10.0)
    elapsed = loop.time() - started

    assert elapsed >= ceiling, (
        f"the wait returned after {elapsed:.2f}s, before the {ceiling}s ceiling and so near the {base_timeout}s base timeout; "
        f"the logon marker was seen inside that window and should have pushed the deadline out to the ceiling"
    )
    assert "no monitor produced any output" in str(exc_info.value), (
        f"the logon marker was observed but no monitor log ever appeared, so the failure must name that exact stage; got: {exc_info.value}"
    )
