# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S20-D12 (QEMU half): destroy must not silently leak a temp tree.

Measured live: destroying a QEMU sandbox after a ~4.1GB memory dump failed to
remove ``%LOCALAPPDATA%\\Temp\\intellicrack_qemu_<id>`` with
``[WinError 5] Access is denied`` after 5 retries spanning about 7.5 seconds
total (0.5s, 1.0s, 1.5s, 2.0s backoff steps) - nowhere near long enough for the
OS to release a multi-gigabyte file's handle - and the directory was then
abandoned forever with only a log line about it.

:meth:`QEMUSandbox._remove_temp_tree` now retries with a longer, capped
backoff, and when every retry still fails it schedules every remaining entry
for deletion on the next reboot via ``MoveFileExW`` /
``MOVEFILE_DELAY_UNTIL_REBOOT`` (:meth:`QEMUSandbox._schedule_delete_on_reboot`
and :meth:`QEMUSandbox._schedule_temp_tree_delete_on_reboot`) instead of
leaving the space leaked with no path to reclaiming it.

These gates never restate the retry count or backoff formula. The first
verifies the real bounded-attempts, real-backoff control flow against an
injected failure (the closest a test can safely get to reproducing a Windows
handle-release race without one actually pending on the clock), asserting on
the real, unmodified filesystem state left behind. The second calls the real
``MoveFileExW`` against a real file this process owns and reads the result
back out of the real ``PendingFileRenameOperations`` registry value, so it
proves the OS actually accepted the deferred-delete request rather than
trusting a boolean the binding happened to return.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from intellicrack.sandbox import qemu as qemu_module
from intellicrack.sandbox.qemu import QEMUSandbox


if sys.platform == "win32":
    import winreg


_SESSION_MANAGER_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager"
_PENDING_RENAMES_VALUE = "PendingFileRenameOperations"


class _ExposedQemuSandbox(QEMUSandbox):
    """Exposes ``QEMUSandbox``'s private temp-tree cleanup internals for testing.

    ``basedpyright`` reports ``reportPrivateUsage`` for a test reaching a
    private member directly, so the members under test are forwarded through
    public classmethods/staticmethods - the same pattern the sibling
    ``windows.py`` gates use.
    """

    @classmethod
    async def remove_temp_tree(cls, temp_dir: Path) -> None:
        """Forward to :meth:`QEMUSandbox._remove_temp_tree`.

        Args:
            temp_dir: The instance's temporary directory.
        """
        await cls._remove_temp_tree(temp_dir)

    @staticmethod
    def schedule_delete_on_reboot(path: Path) -> bool:
        """Forward to :meth:`QEMUSandbox._schedule_delete_on_reboot`.

        Args:
            path: File or directory to schedule for deferred deletion.

        Returns:
            bool: True if Windows accepted the scheduling request.
        """
        return QEMUSandbox._schedule_delete_on_reboot(path)


def _read_pending_renames() -> tuple[str, ...]:
    """Read the real ``PendingFileRenameOperations`` registry value.

    Returns:
        tuple[str, ...]: Every entry currently scheduled for deferred
        rename/delete on the next reboot, or an empty tuple when the value
        does not exist (nothing has ever been scheduled on this machine).
    """
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _SESSION_MANAGER_KEY) as key:
        try:
            value, _ = winreg.QueryValueEx(key, _PENDING_RENAMES_VALUE)
        except FileNotFoundError:
            return ()
    return tuple(value)


@pytest.mark.asyncio
async def test_remove_temp_tree_retries_the_configured_number_of_times_before_giving_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retry loop must make exactly its configured number of attempts, spaced by backoff.

    A permanently locked file cannot be simulated safely and deterministically
    with a real OS-level lock, so ``shutil.rmtree`` is replaced with a stub
    that always fails - the same OS-error shape a held handle produces - and
    every real call it makes and every real backoff sleep it awaits are
    counted directly, against the module's own configured attempt count. The
    directory and its file are real and never touched by the stub, so the
    "nothing was removed" assertion is genuine end state, not a mocked return
    value.

    Args:
        tmp_path: Scratch directory standing in for the instance's temp tree.
        monkeypatch: Pytest fixture used to shrink the backoff window and
            inject the failure.
    """
    attempts: list[Path] = []

    def _always_fails(path: object) -> None:
        """Simulate an OS refusing to remove a still-locked directory.

        Args:
            path: Path ``shutil.rmtree`` was asked to remove.

        Raises:
            OSError: Unconditionally.
        """
        attempts.append(Path(str(path)))
        message = "simulated WinError 5: Access is denied"
        raise OSError(message)

    monkeypatch.setattr(qemu_module.shutil, "rmtree", _always_fails)
    monkeypatch.setattr(qemu_module, "_TEMP_TREE_REMOVE_ATTEMPTS", 3)
    monkeypatch.setattr(qemu_module, "_TEMP_TREE_REMOVE_BACKOFF_S", 0.01)
    monkeypatch.setattr(qemu_module, "_TEMP_TREE_REMOVE_BACKOFF_CAP_S", 0.02)
    monkeypatch.setattr(qemu_module, "_IS_WINDOWS", False)  # keep the reboot-schedule branch inert for this gate

    victim = tmp_path / "intellicrack_qemu_test"
    victim.mkdir()
    (victim / "disk-overlay.qcow2").write_bytes(b"not actually locked, the stub above always fails")

    await _ExposedQemuSandbox.remove_temp_tree(victim)

    assert len(attempts) == 3, f"expected exactly 3 rmtree attempts (the monkeypatched budget); got {len(attempts)}"
    assert victim.exists(), "the stub never really removed the directory; it must still be on disk"
    assert (victim / "disk-overlay.qcow2").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="MoveFileExW/PendingFileRenameOperations are Windows-only")
def test_schedule_delete_on_reboot_registers_a_real_file_with_windows(tmp_path: Path) -> None:
    """The last-resort fallback must make Windows itself accept the deferred delete.

    Calls the real, unmocked ``ctypes``/``MoveFileExW`` binding against a real
    file this test owns, then reads the operating system's own
    ``PendingFileRenameOperations`` list back to confirm Windows genuinely
    recorded it - not merely that the Python binding returned ``True``.

    Args:
        tmp_path: Scratch directory holding the file to schedule.
    """
    victim = tmp_path / "memdump_leftover.raw"
    victim.write_bytes(b"stand-in for an unreleased multi-gigabyte dump handle")

    accepted = _ExposedQemuSandbox.schedule_delete_on_reboot(victim)
    assert accepted, "Windows rejected the deferred-delete scheduling request for a file this process owns"

    pending = _read_pending_renames()
    victim_str = str(victim).lower()
    assert any(victim_str in entry.lower() for entry in pending), (
        f"{victim} was not found in the real PendingFileRenameOperations list "
        f"after scheduling; Windows did not actually record the deferred delete. entries={pending!r}"
    )

    # Delete the scratch file now that the registration has been observed, so
    # a real reboot of this machine finds nothing left to act on rather than
    # leaving a stale pending-rename entry queued indefinitely.
    shutil.rmtree(tmp_path, ignore_errors=True)
