# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D76: deleting a snapshot that was never taken must not report success.

Measured live on 2026-08-09 through the GUI's own bridge,
``snapshot_delete(instance, "audit-h07")`` returned ``{'success': True}``
immediately after ``snapshot_list`` had returned ``[]`` for that instance.
QEMU's job-based ``snapshot-delete`` is lenient where its siblings are not:
it concludes without error for a tag no disk holds, while ``snapshot-load``
of the same missing tag fails loudly and the block-layer command refuses it
outright (``Snapshot with id 'null' and name 'never-created' does not exist
on device 'virtio0'``). So this was a leniency the app chose to pass on, not
a QEMU limitation it had to accept - the same false-green family as S17-D59,
which fixed create and restore and left delete behind.

These gates drive the real :meth:`QEMUSandbox.delete_snapshot` against a
**real QEMU** - a throwaway TCG machine with a real qcow2 and no accelerator,
so no Host Compute Service is involved - and judge the disk with ``qemu-img``,
which never touches the QMP connection the production code uses and so cannot
agree with a broken implementation by sharing its mistake. That needs a real
QEMU binary, which the test container does not carry, so they run in the
host-native pass.
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


_MISSING_TAG: Final[str] = "never-taken-s17d76"
_PRESENT_TAG: Final[str] = "taken-s17d76"


@pytest.fixture
def live_qemu(tmp_path: Path) -> Iterator[LiveQemu]:
    """Start a real QEMU on a real qcow2 with an open QMP monitor.

    Args:
        tmp_path: Pytest temporary directory.

    Yields:
        LiveQemu: The running QEMU and the image it holds.
    """
    yield from start_live_qemu(tmp_path)


class _DeleteSandbox(QEMUSandbox):
    """``QEMUSandbox`` attached to an already-running QEMU.

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


def _make_sandbox(running: LiveQemu) -> _DeleteSandbox:
    """Build a sandbox wired to the running QEMU's monitor.

    Args:
        running: The live QEMU.

    Returns:
        _DeleteSandbox: A sandbox ready to attach.
    """
    config = QEMUConfig(
        guest_os=GuestOS.LINUX,
        image_path=running.image,
        monitor_port=running.monitor_port,
    )
    return _DeleteSandbox(config=SandboxConfig(), qemu_config=config)


class TestDeletingASnapshotReportsWhatHappened:
    """Deleting a snapshot must succeed only when there was one to delete."""

    @pytest.mark.asyncio
    async def test_deleting_a_tag_that_was_never_taken_raises(self, live_qemu: LiveQemu) -> None:
        """A tag no disk holds must be refused, not reported as deleted.

        Args:
            live_qemu: The running QEMU.
        """
        sandbox = _make_sandbox(live_qemu)
        await sandbox.attach()
        try:
            assert _MISSING_TAG not in tags_on_disk(live_qemu.image), "the gate's premise is broken: the tag already exists"

            with pytest.raises(SandboxError) as raised:
                await sandbox.delete_snapshot(_MISSING_TAG)

            assert _MISSING_TAG in str(raised.value), f"the failure does not name the snapshot: {raised.value}"
        finally:
            await sandbox.detach()

    @pytest.mark.asyncio
    async def test_deleting_the_same_snapshot_twice_raises_the_second_time(self, live_qemu: LiveQemu) -> None:
        """The operator's form of the defect: a repeated delete must not look like a fresh one.

        Args:
            live_qemu: The running QEMU.
        """
        sandbox = _make_sandbox(live_qemu)
        await sandbox.attach()
        try:
            await sandbox.take_snapshot(_PRESENT_TAG)
            assert _PRESENT_TAG in tags_on_disk(live_qemu.image), "the gate's premise is broken: the snapshot never reached the image"

            await sandbox.delete_snapshot(_PRESENT_TAG)

            with pytest.raises(SandboxError):
                await sandbox.delete_snapshot(_PRESENT_TAG)
        finally:
            await sandbox.detach()

    @pytest.mark.asyncio
    async def test_a_snapshot_that_exists_is_still_deleted(self, live_qemu: LiveQemu) -> None:
        """The control: a real tag is removed from the image and no error is raised.

        This is what keeps the refusal honest. A ``delete_snapshot`` that
        raised for everything, or one whose post-check misread the block
        layer and rejected its own successful work, would satisfy the two
        tests above and fail this one.

        Args:
            live_qemu: The running QEMU.
        """
        sandbox = _make_sandbox(live_qemu)
        await sandbox.attach()
        try:
            await sandbox.take_snapshot(_PRESENT_TAG)
            assert _PRESENT_TAG in tags_on_disk(live_qemu.image), "the gate's premise is broken: the snapshot never reached the image"

            await sandbox.delete_snapshot(_PRESENT_TAG)

            assert _PRESENT_TAG not in tags_on_disk(live_qemu.image), "the snapshot was reported deleted but is still on the image"
        finally:
            await sandbox.detach()
