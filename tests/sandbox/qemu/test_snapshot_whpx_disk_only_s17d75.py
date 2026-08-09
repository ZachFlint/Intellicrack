# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S17-D75: a snapshot can be taken on the accelerator Windows uses.

``snapshot-save`` serialises CPU and RAM state, and WHPX - the only accelerator
a Windows guest runs under here - registers migration blockers against exactly
that. Measured against a throwaway WHPX machine with no guest running (``-S``,
so nothing executes), the job concludes with ``State blocked due to
non-migratable CPUID feature support, dirty memory tracking support, and
XSAVE/XRSTOR support``, and it stays blocked. The whole Snapshots surface was
therefore dead on Windows; it worked only under TCG or KVM, which is why the
S17-D59 gates never saw it.

A disk-only internal snapshot stores no machine state and is not blocked: on the
same WHPX machine, ``blockdev-snapshot-internal-sync`` on the device returned
success and the tag appeared in ``qemu-img snapshot -l`` on the file.

These gates drive the real :meth:`QEMUSandbox.take_snapshot` against a **real
WHPX QEMU** and judge the disk with ``qemu-img``, an oracle that never touches
the QMP connection the production code uses. The control proves the environment
is genuinely one where the machine-state path fails, so the passing test is not
a tautology: a naive full ``snapshot-save`` on the very same machine is
confirmed blocked. WHPX exists only on Windows and must actually initialise, so
these run in the host-native pass and skip where it cannot.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.types import SandboxError
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import AcceleratorType, GuestOS, QEMUConfig, QEMUSandbox
from tests.sandbox.qemu.live_qemu import (
    ACCEL_WHPX,
    LiveQemu,
    QemuLaunchError,
    start_live_qemu,
    tags_on_disk,
)


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_TAG: Final[str] = "whpx-disk-only-s17d75"
_CONTROL_TAG: Final[str] = "whpx-machine-state-s17d75"
_MACHINE_STATE_FAILURE: Final[str] = "machine-state snapshot"


@pytest.fixture
def whpx_qemu(tmp_path: Path) -> Iterator[LiveQemu]:
    """Start a real WHPX QEMU, or skip where the accelerator is unusable.

    Args:
        tmp_path: Pytest temporary directory.

    Yields:
        LiveQemu: The running WHPX QEMU and the image it holds.
    """
    try:
        yield from start_live_qemu(tmp_path, accel=ACCEL_WHPX)
    except QemuLaunchError as unavailable:
        pytest.skip(f"WHPX is not usable on this host: {unavailable}")


class _WhpxSnapshotSandbox(QEMUSandbox):
    """A ``QEMUSandbox`` attached to an already-running WHPX QEMU.

    Every method under test is the real production implementation. The
    accelerator is pinned to WHPX - the machine really is running under it - so
    :meth:`QEMUSandbox.take_snapshot` takes the branch this gate exists to prove.
    """

    async def attach(self) -> None:
        """Connect the real monitor and pin the accelerator to WHPX."""
        await self._connect_and_verify_qmp()
        self._accelerator = AcceleratorType.WHPX
        self._accelerator_cached = True

    async def detach(self) -> None:
        """Close the monitor connection."""
        if self._qmp is not None:
            await self._qmp.disconnect()

    async def force_machine_state_save(self, name: str) -> None:
        """Drive the production machine-state save path the fix bypasses.

        This is the control's instrument: it runs the real job-based
        ``snapshot-save`` that :meth:`take_snapshot` no longer uses under WHPX,
        so the test can prove that path is genuinely blocked here. The
        :class:`SandboxError` that :meth:`QEMUSandbox._run_snapshot_job` raises
        when WHPX blocks the save propagates to the caller.

        Args:
            name: Snapshot tag to attempt.
        """
        assert self._qmp is not None, "the gate is not attached to a monitor"
        nodes = await self._snapshot_target_nodes()
        job_id = self._new_snapshot_job_id("save")
        monitor = self._qmp
        await self._run_snapshot_job(
            "save",
            _MACHINE_STATE_FAILURE,
            lambda: monitor.snapshot_save(job_id, name, nodes[0], nodes),
            job_id,
        )


def _make_sandbox(running: LiveQemu) -> _WhpxSnapshotSandbox:
    """Build a sandbox wired to the running WHPX QEMU's monitor.

    Args:
        running: The live WHPX QEMU.

    Returns:
        _WhpxSnapshotSandbox: A sandbox ready to attach.
    """
    config = QEMUConfig(
        guest_os=GuestOS.WINDOWS,
        image_path=running.image,
        monitor_port=running.monitor_port,
    )
    return _WhpxSnapshotSandbox(config=SandboxConfig(), qemu_config=config)


class TestASnapshotCanBeTakenUnderWhpx:
    """Under WHPX, ``take_snapshot`` must succeed and reach the disk."""

    @pytest.mark.asyncio
    async def test_take_snapshot_succeeds_and_reaches_the_disk(self, whpx_qemu: LiveQemu) -> None:
        """The Verify: ``take_snapshot`` succeeds under WHPX and the tag is on the file.

        Args:
            whpx_qemu: The running WHPX QEMU.
        """
        sandbox = _make_sandbox(whpx_qemu)
        await sandbox.attach()
        try:
            assert _TAG not in tags_on_disk(whpx_qemu.image), "the gate's premise is broken: the tag already exists"

            returned = await sandbox.take_snapshot(_TAG)

            assert returned == _TAG
            assert _TAG in tags_on_disk(whpx_qemu.image), "take_snapshot reported success but the tag never reached the qcow2"
        finally:
            await sandbox.detach()

    @pytest.mark.asyncio
    async def test_a_machine_state_save_is_genuinely_blocked_here(self, whpx_qemu: LiveQemu) -> None:
        """The control: the naive full save really is blocked on this machine.

        Without this, the test above would pass anywhere a snapshot can be
        taken and would not prove the fix does anything on WHPX. Driving the
        production machine-state path and watching it fail confirms the
        environment is the one the defect is about.

        Args:
            whpx_qemu: The running WHPX QEMU.
        """
        sandbox = _make_sandbox(whpx_qemu)
        await sandbox.attach()
        try:
            with pytest.raises(SandboxError) as raised:
                await sandbox.force_machine_state_save(_CONTROL_TAG)

            assert _MACHINE_STATE_FAILURE in str(raised.value), f"unexpected failure: {raised.value}"
            assert _CONTROL_TAG not in tags_on_disk(whpx_qemu.image), "a blocked machine-state save still wrote a tag"
        finally:
            await sandbox.detach()
