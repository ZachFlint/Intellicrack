# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S17-D74: a failed snapshot must not cost the caller the guest.

QEMU stops the machine to load a snapshot and does not start it again when the
job fails. Measured against QEMU 10.1.0, ``query-status`` after a
``snapshot-load`` of a tag that does not exist is::

    {"status": "restore-vm", "running": false}

and it stays there for the life of the VM. Nothing in ``restore_snapshot``
asked, so a refused restore silently ended the guest: measured live on
2026-08-09 through the GUI's own bridge, the ``execute("hostname")`` that had
answered four times in **0.1 s** timed out after **120.7 s** on the next call,
``anti_evasion`` burned 151.5 s of pure timeout and still reported success, and
``status`` went on reporting ``running``. The QEMU process consumed **0.000
CPU-seconds over 12 s** of wall time while still answering the monitor
instantly - a live main loop with stopped processors.

Note the asymmetry these gates rely on, because it is what makes the defect
specific to restore: a failed ``snapshot-save`` leaves the machine *running*,
so only the load path has anything to repair.

These gates drive the real production methods against a **real QEMU** - a
throwaway TCG machine with a real qcow2 and no accelerator, so no Host Compute
Service is involved - and judge the outcome with the monitor's own
``query-status`` rather than with anything the production code reports about
itself. That needs a real QEMU binary, which the test container does not carry,
so they run in the host-native pass.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, cast

import pytest

from intellicrack.core.types import SandboxError
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig, QEMUSandbox
from tests.sandbox.qemu.live_qemu import LiveQemu, start_live_qemu, tags_on_disk


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_MISSING_TAG: Final[str] = "never-taken-s17d74"
_PRESENT_TAG: Final[str] = "taken-s17d74"
_RESUMED_CLAUSE: Final[str] = "resumed"


@pytest.fixture
def live_qemu(tmp_path: Path) -> Iterator[LiveQemu]:
    """Start a real QEMU on a real qcow2 with an open QMP monitor.

    Args:
        tmp_path: Pytest temporary directory.

    Yields:
        LiveQemu: The running QEMU and the image it holds.
    """
    yield from start_live_qemu(tmp_path)


class _RunStateSandbox(QEMUSandbox):
    """``QEMUSandbox`` attached to an already-running QEMU, able to be asked what it sees.

    Every method under test is the real production implementation. Only the
    connection is made directly, because booting a guest through
    :meth:`QEMUSandbox.start` would need an accelerated VM this gate does not.
    """

    async def attach(self) -> None:
        """Drive the real :meth:`QEMUSandbox._connect_and_verify_qmp`."""
        await self._connect_and_verify_qmp()

    async def detach(self) -> None:
        """Close the monitor connection."""
        if self._qmp is not None:
            await self._qmp.disconnect()

    async def machine_is_running(self) -> bool:
        """Ask the monitor whether the machine's processors are executing.

        This goes to ``query-status`` directly rather than to any state the
        production code keeps, so a sandbox that merely *believes* it is
        running cannot satisfy it.

        Returns:
            bool: True when QEMU reports ``running``.
        """
        assert self._qmp is not None, "the gate is not attached to a monitor"
        reply = await self._qmp.query_status()
        assert reply.success, f"query-status failed: {reply.error}"
        assert isinstance(reply.data, dict), f"query-status returned no record: {reply.data!r}"
        status = cast("dict[str, object]", reply.data)
        return status.get("running") is True


def _make_sandbox(running: LiveQemu) -> _RunStateSandbox:
    """Build a sandbox wired to the running QEMU's monitor.

    Args:
        running: The live QEMU.

    Returns:
        _RunStateSandbox: A sandbox ready to attach.
    """
    config = QEMUConfig(
        guest_os=GuestOS.LINUX,
        image_path=running.image,
        monitor_port=running.monitor_port,
    )
    return _RunStateSandbox(config=SandboxConfig(), qemu_config=config)


class TestAFailedSnapshotLeavesTheMachineRunning:
    """A snapshot operation that fails must hand back the machine it was given."""

    @pytest.mark.asyncio
    async def test_a_refused_restore_leaves_the_machine_executing(self, live_qemu: LiveQemu) -> None:
        """After a restore that QEMU refuses, the processors must still be running.

        This is the defect exactly: the operator asks for a rollback, is told
        it did not happen, and separately - silently - loses the guest.

        Args:
            live_qemu: The running QEMU.
        """
        sandbox = _make_sandbox(live_qemu)
        await sandbox.attach()
        try:
            assert await sandbox.machine_is_running(), "the gate's premise is broken: the machine was not running to begin with"
            assert _MISSING_TAG not in tags_on_disk(live_qemu.image), "the gate's premise is broken: the tag already exists"

            with pytest.raises(SandboxError):
                await sandbox.restore_snapshot(_MISSING_TAG)

            assert await sandbox.machine_is_running(), "the failed restore left the machine stopped and nothing started it again"
        finally:
            await sandbox.detach()

    @pytest.mark.asyncio
    async def test_the_failure_says_the_machine_was_resumed(self, live_qemu: LiveQemu) -> None:
        """The error must report the machine's fate, not only the job's.

        A caller that is told "restore failed" and nothing else cannot know
        whether its guest survived, which is the part of this defect that made
        it invisible for a whole session.

        Args:
            live_qemu: The running QEMU.
        """
        sandbox = _make_sandbox(live_qemu)
        await sandbox.attach()
        try:
            with pytest.raises(SandboxError) as raised:
                await sandbox.restore_snapshot(_MISSING_TAG)

            assert _RESUMED_CLAUSE in str(raised.value), f"the failure does not say what happened to the machine: {raised.value}"
            assert raised.value.vm_state == "running", f"the failure reports the wrong machine state: {raised.value.vm_state!r}"
        finally:
            await sandbox.detach()

    @pytest.mark.asyncio
    async def test_a_successful_restore_still_leaves_the_machine_running(self, live_qemu: LiveQemu) -> None:
        """The repair must not be the only thing keeping the machine alive.

        A restore that succeeds resumes the machine on QEMU's own account. If
        this went red, the fix would be masking a real regression on the happy
        path rather than adding to it.

        Args:
            live_qemu: The running QEMU.
        """
        sandbox = _make_sandbox(live_qemu)
        await sandbox.attach()
        try:
            await sandbox.take_snapshot(_PRESENT_TAG)
            assert _PRESENT_TAG in tags_on_disk(live_qemu.image), "the gate's premise is broken: the snapshot never reached the image"

            await sandbox.restore_snapshot(_PRESENT_TAG)

            assert await sandbox.machine_is_running(), "a snapshot restore that succeeded left the machine stopped"
        finally:
            await sandbox.detach()
