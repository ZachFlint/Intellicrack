# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gates for S18-D06: a failed start must not leave a VM or its overlay behind.

``QEMUSandbox.start`` calls ``_cleanup`` when a later step fails, and the launch
itself is not that step - by the time the guest agent is being attached the VM
is up and running. ``_cleanup`` then removed the instance's temporary tree while
QEMU still held ``disk-overlay.qcow2`` open, and passed ``ignore_errors=True``
while doing it, so the removal could neither succeed nor report that it had not.
The one branch that could have ended the VM first reads a ``qemu.pid`` file that
Windows QEMU never writes: it implements neither ``-daemonize`` nor ``-pidfile``
there, so the VM is only ever known by its child process handle.

The forensics on the host that produced this defect say exactly that. Of the 48
abandoned ``%LOCALAPPDATA%\Temp\intellicrack_qemu_*`` directories, the ones
from runs that got as far as launching a VM held precisely one file -
``disk-overlay.qcow2`` - because everything not locked had been removed and the
overlay could not be. Nothing was logged about any of them.

These gates drive the real ``_cleanup`` against a real child process holding a
real file handle, which is the same reason a live QEMU makes its overlay
undeletable on Windows: neither passes ``FILE_SHARE_DELETE``.
"""

from __future__ import annotations

import asyncio
import sys
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig, QEMUSandbox


if TYPE_CHECKING:
    from pathlib import Path


_OVERLAY_NAME: Final[str] = "disk-overlay.qcow2"
_HOLDER_READY: Final[str] = "holding"
# Longer than the reaper's own grace period, so the child never exits of its own
# accord and the gate measures the cleanup ending it rather than it giving up.
_HOLD_UNTIL_KILLED_S: Final[float] = 60.0
# Long enough to outlast the first removal attempt and short enough to be
# released while later attempts are still being made.
_HOLD_PAST_FIRST_ATTEMPT_S: Final[float] = 1.2
_READY_BUDGET_S: Final[float] = 30.0
_CLEANUP_BUDGET_S: Final[float] = 60.0
_IS_WINDOWS: Final[bool] = sys.platform == "win32"

# Opens the overlay and keeps it open, exactly as a running QEMU does. Python's
# open() does not pass FILE_SHARE_DELETE either, so while this process lives the
# file cannot be removed on Windows.
_HOLD_OVERLAY_PROGRAM: Final[str] = f"""
import sys
import time

handle = open(sys.argv[1], "r+b")
handle.write(b"qcow2")
handle.flush()
sys.stdout.write({_HOLDER_READY!r} + "\\n")
sys.stdout.flush()
time.sleep(float(sys.argv[2]))
handle.close()
"""


class _CleanupProbeSandbox(QEMUSandbox):
    """Sandbox whose instance state can be armed the way a failed start leaves it.

    A start that fails while attaching the guest agent has already created the
    temporary directory, launched QEMU and registered its PID. Reaching that
    state through the real start path needs a bootable image and a working
    hypervisor; arming it directly reaches the same state, and the code under
    test - ``_cleanup`` - is entered identically either way. The accessors live
    on a subclass because that is how the protected instance state is reached
    without suppressing a type-checker finding.
    """

    def arm(self, temp_dir: Path, child: asyncio.subprocess.Process) -> None:
        """Put the sandbox in the state a failed start leaves behind.

        Args:
            temp_dir: The instance's temporary directory.
            child: The running process standing in for the launched VM.
        """
        self._temp_dir = temp_dir
        self._qemu_pid = child.pid
        self.process = child

    def instance_dir(self) -> Path | None:
        """Return the temporary directory the sandbox still owns.

        Returns:
            Path | None: The directory, or None once cleanup has released it.
        """
        return self._temp_dir

    async def run_cleanup(self) -> None:
        """Run the production cleanup path a failed start invokes."""
        await self._cleanup()

    @classmethod
    async def remove_tree(cls, temp_dir: Path) -> None:
        """Run the production temporary-tree removal on its own.

        Args:
            temp_dir: The directory to remove.
        """
        await cls._remove_temp_tree(temp_dir)


async def _spawn_overlay_holder(
    tmp_path: Path,
    overlay: Path,
    hold_seconds: float,
) -> asyncio.subprocess.Process:
    """Launch a real process that opens ``overlay`` and holds it open.

    Args:
        tmp_path: Directory the holder's program is written to.
        overlay: The file the holder opens, as QEMU opens its disk overlay.
        hold_seconds: How long the holder keeps the file open.

    Returns:
        asyncio.subprocess.Process: The running holder, already past the point
        of having opened the file. A holder that never reports the file open
        fails the gate here rather than leaving every later assertion to pass
        against a file nothing was holding.
    """
    source = tmp_path / "hold_overlay.py"
    source.write_text(_HOLD_OVERLAY_PROGRAM, encoding="utf-8")
    child = await asyncio.create_subprocess_exec(
        sys.executable,
        str(source),
        str(overlay),
        str(hold_seconds),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout = child.stdout
    assert stdout is not None, "the holder was spawned without the pipe the gate reads its readiness from"
    line = await asyncio.wait_for(stdout.readline(), timeout=_READY_BUDGET_S)
    assert line.decode().strip() == _HOLDER_READY, f"the holder never reported holding the overlay open, so nothing was locked: {line!r}"
    return child


async def _terminate(child: asyncio.subprocess.Process) -> None:
    """Ensure a spawned holder is gone before a test finishes.

    Args:
        child: The holder to end.
    """
    if child.returncode is None:
        child.kill()
    await child.wait()


def _make_instance_dir(tmp_path: Path) -> tuple[Path, Path]:
    """Build an instance directory holding the files a launched VM leaves in it.

    Args:
        tmp_path: Pytest-provided root directory.

    Returns:
        tuple[Path, Path]: The instance directory and its disk overlay.
    """
    temp_dir = tmp_path / "intellicrack_qemu_probe"
    (temp_dir / "shared" / "logs").mkdir(parents=True)
    (temp_dir / "shared" / "logs" / "monitor.log").write_text("collector started\n", encoding="utf-8")
    overlay = temp_dir / _OVERLAY_NAME
    overlay.write_bytes(b"")
    return temp_dir, overlay


def _sandbox() -> _CleanupProbeSandbox:
    """Build a Windows-guest sandbox for the cleanup path.

    Returns:
        _CleanupProbeSandbox: An unstarted sandbox.
    """
    return _CleanupProbeSandbox(SandboxConfig(), QEMUConfig(guest_os=GuestOS.WINDOWS))


@pytest.mark.asyncio
class TestAFailedStartLeavesNothingRunningOrOnDisk:
    """Cleanup owns the VM it is cleaning up after, not just its files."""

    async def test_cleanup_ends_the_vm_still_holding_the_overlay(self, tmp_path: Path) -> None:
        """The instance tree must be gone even though a VM held a file in it.

        This is the leak itself. The process is still running when cleanup
        starts, exactly as it is when a start fails after the launch, and it
        holds the overlay open. Cleanup has to end it before it can remove the
        tree - and on Windows there is no PID file to find it by, so the child
        handle is the only thing that can.

        Args:
            tmp_path: Pytest-provided root directory.
        """
        temp_dir, overlay = _make_instance_dir(tmp_path)
        child = await _spawn_overlay_holder(tmp_path, overlay, _HOLD_UNTIL_KILLED_S)
        sandbox = _sandbox()
        sandbox.arm(temp_dir, child)
        try:
            if _IS_WINDOWS:
                with pytest.raises(PermissionError):
                    overlay.unlink()
            await asyncio.wait_for(sandbox.run_cleanup(), timeout=_CLEANUP_BUDGET_S)
        finally:
            await _terminate(child)

        assert child.returncode is not None, (
            "cleanup returned with the virtual machine still running, so a failed start leaks the VM itself"
        )
        assert not temp_dir.exists(), f"the instance directory survived cleanup: {sorted(p.name for p in temp_dir.iterdir())}"
        assert sandbox.instance_dir() is None, "the sandbox still owns a directory it no longer has"

    async def test_cleanup_stops_tracking_the_pid_it_ended(self, tmp_path: Path) -> None:
        """A PID this cleanup killed must not stay registered for later cleanup.

        ``start`` registers the VM with the process manager before the step that
        fails, so a cleanup that ends the process without unregistering it
        leaves the manager holding a PID that no longer exists - and that a
        later process may be given.

        Args:
            tmp_path: Pytest-provided root directory.
        """
        temp_dir, overlay = _make_instance_dir(tmp_path)
        child = await _spawn_overlay_holder(tmp_path, overlay, _HOLD_UNTIL_KILLED_S)
        manager = ProcessManager.get_instance()
        manager.register_external_pid(child.pid, name="qemu-vm", process_type=ProcessType.SANDBOX)
        sandbox = _sandbox()
        sandbox.arm(temp_dir, child)
        try:
            await asyncio.wait_for(sandbox.run_cleanup(), timeout=_CLEANUP_BUDGET_S)
        finally:
            await _terminate(child)
            still_registered = manager.unregister_external_pid(child.pid)

        assert not still_registered, "the process manager was still tracking the VM's PID after cleanup ended that process"


@pytest.mark.asyncio
class TestRemovalOutlastsAHandleThatIsStillClosing:
    """Windows releases a dead process's handles after the process is gone."""

    async def test_the_tree_is_removed_once_the_handle_is_released(self, tmp_path: Path) -> None:
        """Removal must retry rather than lose a race it can simply wait out.

        A process exiting does not release its file handles synchronously on
        Windows, so the first attempt at removing the tree can still be refused
        while nothing holds the file any more. One attempt turns that into a
        permanent leak; the removal keeps trying, and the file is deleted as
        soon as the handle is actually gone.

        Args:
            tmp_path: Pytest-provided root directory.
        """
        temp_dir, overlay = _make_instance_dir(tmp_path)
        child = await _spawn_overlay_holder(tmp_path, overlay, _HOLD_PAST_FIRST_ATTEMPT_S)
        try:
            if _IS_WINDOWS:
                with pytest.raises(PermissionError):
                    overlay.unlink()
            await asyncio.wait_for(_CleanupProbeSandbox.remove_tree(temp_dir), timeout=_CLEANUP_BUDGET_S)
        finally:
            await _terminate(child)

        assert not temp_dir.exists(), (
            "the tree was abandoned after a single refused attempt, even though the handle was released moments later"
        )
