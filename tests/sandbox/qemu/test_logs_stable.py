# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit7 F-0031 regression tests for ``QEMUSandbox._wait_for_logs_stable``.

These tests verify that the readiness check correctly waits until the
monitoring log files have stopped growing, replacing the prior hardcoded
``asyncio.sleep(2)`` in ``run_binary``.

The growth being watched here is a file on the host side of the share, which is
where the guest writes its logs on the virtio-9p transport. Since S17-D69 the
FAT transport - every Windows host - exposes that share read-only and the guest
writes to its own disk instead, so the sizes are read out of the guest over the
agent rather than stat'ed here; that path is gated in
``test_readonly_share_transport_s17d69.py``. These tests therefore select the 9p
transport, which is the one whose logs land in the directory they write to.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import TYPE_CHECKING

import pytest

from intellicrack.sandbox import qemu as qemu_module
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig, QEMUSandbox


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def posix_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Select the virtio-9p transport, whose logs land on the host share.

    ``_uses_fat_shared_transport`` reads the module-level platform constant on
    every call, so redirecting it chooses the transport under test without
    altering any behaviour: virtio-9p is compiled out of QEMU's Windows builds,
    which is the only reason a Windows host takes the FAT path at all.

    Args:
        monkeypatch: Fixture used to redirect the platform constant.
    """
    monkeypatch.setattr(qemu_module, "_IS_WINDOWS", False)


class _TestQEMUSandbox(QEMUSandbox):
    """QEMUSandbox subclass that exposes private state and method for tests.

    This is the same pattern used by the audit4 QEMU sandbox tests: a
    subclass adds public accessors for state owned by the parent class so
    that tests can interact with private members without triggering
    ``reportPrivateUsage`` from basedpyright.
    """

    def set_shared_folder(self, path: Path | None) -> None:
        """Set the shared folder path used by the readiness check.

        Args:
            path: Shared folder path that contains the ``logs`` subdirectory.
        """
        self._shared_folder = path

    async def call_wait_for_logs_stable(
        self,
        *,
        poll_delay: float = 0.25,
        stable_polls: int = 4,
        max_wait: float = 30.0,
    ) -> None:
        """Forward to :meth:`QEMUSandbox._wait_for_logs_stable` for tests.

        Args:
            poll_delay: Seconds between successive polls.
            stable_polls: Consecutive equal-size polls required for stability.
            max_wait: Maximum total wait time in seconds.
        """
        await self._wait_for_logs_stable(
            poll_delay=poll_delay,
            stable_polls=stable_polls,
            max_wait=max_wait,
        )


def _build_sandbox(shared_folder: Path) -> _TestQEMUSandbox:
    """Construct a minimally-initialised :class:`_TestQEMUSandbox` for tests.

    Sets the shared folder on the instance so the readiness check has a real
    directory to poll. No QEMU process is started.

    Args:
        shared_folder: Directory used as the sandbox shared folder. The
            caller is responsible for ensuring ``shared_folder / "logs"``
            exists when the test requires it.

    Returns:
        _TestQEMUSandbox: Instance whose shared folder is set to
        ``shared_folder`` and which is otherwise default-initialised.
    """
    sandbox = _TestQEMUSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=GuestOS.LINUX))
    sandbox.set_shared_folder(shared_folder)
    return sandbox


async def _append_until(
    log_path: Path,
    *,
    stop_at_monotonic: float,
    interval: float,
) -> None:
    """Append a small payload to ``log_path`` at fixed intervals until a deadline.

    Args:
        log_path: File to extend. Created if it does not exist.
        stop_at_monotonic: ``time.monotonic`` value at which to stop writing.
        interval: Seconds between writes.
    """
    while time.monotonic() < stop_at_monotonic:
        with log_path.open("ab") as fh:
            fh.write(b"x")
        await asyncio.sleep(interval)


@pytest.mark.asyncio
async def test_returns_after_writer_stops(tmp_path: Path) -> None:
    """``_wait_for_logs_stable`` returns shortly after the writer stops.

    Spawns a background task that appends bytes to one tracked log file every
    ``poll_delay`` seconds for ``write_duration`` seconds, then stops. The
    readiness check is invoked with ``poll_delay=0.1`` and ``stable_polls=3``,
    so it should return within ``write_duration + stable_polls * poll_delay +
    0.5`` seconds (~1.8s). The upper bound of 1.8s specifically rejects a
    naive ``asyncio.sleep(2)`` regression (~2.0s), distinguishing adaptive
    polling from the prior fixed-delay implementation.

    Args:
        tmp_path: Pytest-provided temporary directory used as the shared
            folder.
    """
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()

    sandbox = _build_sandbox(tmp_path)
    target_log = logs_dir / "file_changes.log"
    target_log.touch()

    write_duration = 1.0
    poll_delay = 0.1
    stable_polls = 3
    writer_task = asyncio.create_task(
        _append_until(
            target_log,
            stop_at_monotonic=time.monotonic() + write_duration,
            interval=poll_delay,
        ),
    )

    start = time.monotonic()
    await sandbox.call_wait_for_logs_stable(
        poll_delay=poll_delay,
        stable_polls=stable_polls,
        max_wait=10.0,
    )
    elapsed = time.monotonic() - start

    await writer_task

    upper_bound = write_duration + stable_polls * poll_delay + 0.5
    assert elapsed >= write_duration, f"_wait_for_logs_stable returned at {elapsed:.3f}s before writer stopped at {write_duration:.3f}s"
    assert elapsed <= upper_bound, (
        f"_wait_for_logs_stable took {elapsed:.3f}s; "
        f"expected adaptive stability detection within {upper_bound:.3f}s "
        f"(write_duration={write_duration}s + stable_polls={stable_polls} * poll_delay={poll_delay}s + 0.5s slack). "
        f"A fixed asyncio.sleep(2) implementation would return at ~2.0s, exceeding this bound."
    )


@pytest.mark.asyncio
async def test_returns_quickly_when_no_logs_exist(tmp_path: Path) -> None:
    """``_wait_for_logs_stable`` returns within one stability cycle on an empty logs/ directory.

    With no monitoring log files present, every tracked file is treated as
    size ``0``. After ``stable_polls`` consecutive equal readings the
    readiness check returns. With ``poll_delay=0.1`` and ``stable_polls=3``,
    that should take roughly ``stable_polls * poll_delay`` plus minor
    overhead.

    Args:
        tmp_path: Pytest-provided temporary directory used as the shared
            folder.
    """
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()

    sandbox = _build_sandbox(tmp_path)

    start = time.monotonic()
    await sandbox.call_wait_for_logs_stable(
        poll_delay=0.1,
        stable_polls=3,
        max_wait=10.0,
    )
    elapsed = time.monotonic() - start

    assert elapsed <= 0.5, f"_wait_for_logs_stable took {elapsed:.3f}s on empty logs/; expected <= 0.5s"


@pytest.mark.asyncio
async def test_max_wait_bound_is_respected(tmp_path: Path) -> None:
    """``_wait_for_logs_stable`` returns at ``max_wait`` even if a log keeps growing.

    Spawns a writer that never stops appending and verifies that the readiness
    check returns at approximately ``max_wait`` rather than waiting forever.

    Args:
        tmp_path: Pytest-provided temporary directory used as the shared
            folder.
    """
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()

    sandbox = _build_sandbox(tmp_path)
    target_log = logs_dir / "api_trace.log"
    target_log.touch()

    deadline = time.monotonic() + 5.0
    writer_task = asyncio.create_task(
        _append_until(
            target_log,
            stop_at_monotonic=deadline,
            interval=0.05,
        ),
    )

    start = time.monotonic()
    await sandbox.call_wait_for_logs_stable(
        poll_delay=0.1,
        stable_polls=3,
        max_wait=0.8,
    )
    elapsed = time.monotonic() - start

    writer_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await writer_task

    assert 0.7 <= elapsed <= 1.4, f"_wait_for_logs_stable took {elapsed:.3f}s; expected ~0.8s with max_wait=0.8s"


@pytest.mark.asyncio
async def test_rejects_invalid_arguments(tmp_path: Path) -> None:
    """``_wait_for_logs_stable`` rejects nonsensical poll parameters.

    Args:
        tmp_path: Pytest-provided temporary directory used as the shared
            folder.
    """
    sandbox = _build_sandbox(tmp_path)

    with pytest.raises(ValueError, match="poll_delay"):
        await sandbox.call_wait_for_logs_stable(poll_delay=0.0)
    with pytest.raises(ValueError, match="poll_delay"):
        await sandbox.call_wait_for_logs_stable(poll_delay=-0.1)
    with pytest.raises(ValueError, match="stable_polls"):
        await sandbox.call_wait_for_logs_stable(stable_polls=0)
    with pytest.raises(ValueError, match="max_wait"):
        await sandbox.call_wait_for_logs_stable(max_wait=-1.0)
