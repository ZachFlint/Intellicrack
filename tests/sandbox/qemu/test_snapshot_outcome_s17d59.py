# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S17-D59: a snapshot operation must report what QEMU actually did.

Every snapshot operation went out as QMP ``human-monitor-command`` and was
judged by ``QMPResponse.success``. That is not a judgement at all: QEMU answers
an HMP request with a *successful* reply whose ``return`` member carries the
monitor's output text, error included. Measured against QEMU 10.1.0:

* ``loadvm nosuch`` -> ``{"return": "Error: Snapshot 'nosuch' does not exist in
  one or more devices\r\n"}``
* a successful ``savevm`` -> ``{"return": ""}``

Same reply shape, so a refused restore and a completed one were indistinguishable
to every caller. Measured live through the GUI path on 2026-08-07:
``snapshot_create`` returned in **0.0 s** on a running 8192 MB guest, which no
real ``savevm`` can do, ``snapshot_list`` then reported ``count: 0``, and
``snapshot_restore`` returned success for a snapshot that had never existed.

A second, separable fault produced that ``count: 0``. ``list_snapshots`` kept
only HMP table rows whose first column ``isdigit()``, and QEMU 10.1 prints
``--`` in that column::

    ID      TAG               VM_SIZE                DATE        VM_CLOCK
    --      probe-ok          889 KiB 2026-08-07 16:14:54  0000:00:01.983

so every row was discarded for a disk that demonstrably held snapshots.

The fix uses the job-based ``snapshot-save``/``snapshot-load``/
``snapshot-delete`` commands, whose real outcome arrives through ``query-jobs``
as a concluded job carrying an ``error`` member only on failure, and reads the
snapshot list as structured data instead of parsing a text table.

These gates drive the production methods against a **real QEMU** - a throwaway
TCG guest with a real qcow2 attached, no accelerator, so no Host Compute
Service is involved - and check ground truth with ``qemu-img`` outside QEMU
entirely. That needs a real QEMU binary, which the test container does not
carry, so they run in the host-native pass.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.types import SandboxError
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig, QEMUSandbox
from tests.sandbox.qemu.live_qemu import LiveQemu, start_live_qemu, tags_on_disk


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_MISSING_TAG: Final[str] = "never-taken"


@pytest.fixture
def live_qemu(tmp_path: Path) -> Iterator[LiveQemu]:
    """Start a real QEMU on a real qcow2 with an open QMP monitor.

    Args:
        tmp_path: Pytest temporary directory.

    Yields:
        LiveQemu: The running QEMU and the image it holds.
    """
    yield from start_live_qemu(tmp_path)


class _SnapshotSandbox(QEMUSandbox):
    """``QEMUSandbox`` subclass that attaches to an already-running QEMU.

    Every method under test is the real production implementation; only the
    connection is established directly, because starting a guest through
    :meth:`QEMUSandbox.start` would boot a full accelerated VM this gate does
    not need.
    """

    async def attach(self) -> None:
        """Drive the real :meth:`QEMUSandbox._connect_and_verify_qmp`."""
        await self._connect_and_verify_qmp()

    async def detach(self) -> None:
        """Close the monitor connection."""
        if self._qmp is not None:
            await self._qmp.disconnect()


def _make_sandbox(running: LiveQemu) -> _SnapshotSandbox:
    """Build a sandbox wired to the running QEMU's monitor.

    Args:
        running: The live QEMU.

    Returns:
        _SnapshotSandbox: A sandbox ready to attach.
    """
    config = QEMUConfig(
        guest_os=GuestOS.LINUX,
        image_path=running.image,
        monitor_port=running.monitor_port,
    )
    return _SnapshotSandbox(config=SandboxConfig(), qemu_config=config)


class TestSnapshotOperationsReportTheRealOutcome:
    """A snapshot call must not claim success QEMU never gave it."""

    @pytest.mark.asyncio
    async def test_restoring_a_snapshot_that_was_never_taken_fails(self, live_qemu: LiveQemu) -> None:
        """Restoring a tag that does not exist must raise, not return.

        This is the defect at its sharpest: QEMU refuses the restore, the
        guest keeps running the state it already had, and the operator is told
        the rollback happened.

        Args:
            live_qemu: The running QEMU.
        """
        sandbox = _make_sandbox(live_qemu)
        await sandbox.attach()
        try:
            assert _MISSING_TAG not in tags_on_disk(live_qemu.image), "the gate's premise is broken: the tag already exists"

            with pytest.raises(SandboxError):
                await sandbox.restore_snapshot(_MISSING_TAG)
        finally:
            await sandbox.detach()

    @pytest.mark.asyncio
    async def test_a_taken_snapshot_is_listed(self, live_qemu: LiveQemu) -> None:
        """A snapshot reported as created must appear in the list.

        Gates the second fault: the HMP table parser dropped every row because
        it required a numeric ID column that QEMU prints as ``--``.

        Args:
            live_qemu: The running QEMU.
        """
        sandbox = _make_sandbox(live_qemu)
        await sandbox.attach()
        try:
            await sandbox.take_snapshot("gate-listed")

            listed = await sandbox.list_snapshots()
            assert "gate-listed" in listed, f"a snapshot that was just taken is not listed: {listed}"
        finally:
            await sandbox.detach()

    @pytest.mark.asyncio
    async def test_a_taken_snapshot_really_reaches_the_image(self, live_qemu: LiveQemu) -> None:
        """The snapshot must exist in the qcow2, judged outside QEMU.

        ``qemu-img`` is the independent oracle here: it reads the file rather
        than asking the same monitor connection the production code used.

        Args:
            live_qemu: The running QEMU.
        """
        sandbox = _make_sandbox(live_qemu)
        await sandbox.attach()
        try:
            await sandbox.take_snapshot("gate-on-disk")
        finally:
            await sandbox.detach()

        live_qemu.stop()

        assert "gate-on-disk" in tags_on_disk(live_qemu.image), "the operation reported a snapshot that never reached the image"

    @pytest.mark.asyncio
    async def test_deleting_one_snapshot_leaves_the_other(self, live_qemu: LiveQemu) -> None:
        """Delete must remove exactly the named snapshot.

        Phrased as "the survivor is still listed" rather than "the deleted one
        is gone", because an implementation whose list is always empty passes
        the second wording for the wrong reason.

        Args:
            live_qemu: The running QEMU.
        """
        sandbox = _make_sandbox(live_qemu)
        await sandbox.attach()
        try:
            await sandbox.take_snapshot("gate-doomed")
            await sandbox.take_snapshot("gate-survivor")

            await sandbox.delete_snapshot("gate-doomed")

            listed = await sandbox.list_snapshots()
            assert "gate-survivor" in listed, f"delete removed the snapshot it was not asked to remove: {listed}"
            assert "gate-doomed" not in listed, f"the deleted snapshot is still listed: {listed}"
        finally:
            await sandbox.detach()
