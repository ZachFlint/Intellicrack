# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D61: a guest memory dump must report what really happened.

``QEMUSandbox.dump_memory`` sent ``dump-guest-memory`` synchronously and threw
away whatever QEMU said about it::

    if not result.success:
        raise SandboxError(_ERR_MEMORY_DUMP_FAILED)

Two faults follow from that.

**The real cause was discarded.** QEMU answers a refused dump with a genuine
description - measured against QEMU 10.1.0, aiming a dump at a directory that
does not exist gives ``Could not create '<the dump path>': No such file or
directory`` in two milliseconds - and the operator was shown the bare words
"memory dump failed" instead.

**A dump that succeeds could still be reported as a failure.** A synchronous
``dump-guest-memory`` does not answer until the whole of guest RAM is on disk:
measured at 3.61 s for a 1024 MB guest, so roughly half a minute for the
8192 MB guests this backend runs, far past the 10 s reply budget. The command
also holds the monitor lock for its entire duration, so every other query -
status polling, the VNC port lookup, the guest-agent channel - waits behind it.

The fix issues the dump detached, which is answered in about two milliseconds,
and follows the real progress through ``query-dump`` under a budget sized for a
multi-gigabyte guest.

These gates drive the production method against a **real QEMU** - a throwaway
TCG guest, so no Host Compute Service is involved - and read the dump back off
the filesystem. That needs a real QEMU binary, which the test container does not
carry, so they run in the host-native pass.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.types import SandboxError
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig, QEMUSandbox
from tests.sandbox.qemu.live_qemu import LiveQemu, start_live_qemu


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


DUMP_GUEST_MEMORY_MB: Final[str] = "8192"
ELF_MAGIC: Final[bytes] = b"\x7fELF"
MIN_DUMP_BYTES: Final[int] = 1024 * 1024 * 1024
MONITOR_ANSWER_BUDGET_S: Final[float] = 2.0


@pytest.fixture
def roomy_qemu(tmp_path: Path) -> Iterator[LiveQemu]:
    """Start a real QEMU with the guest memory this backend really configures.

    The size is the whole point. :class:`QEMUConfig` defaults to 8192 MB, and
    measured on this class of host QEMU writes a dump at roughly half a
    gigabyte per second, so a dump of a real guest takes appreciably longer
    than the monitor's 10 s reply budget. At the small size other monitor gates
    use, the dump finishes before either fault can be observed.

    Args:
        tmp_path: Pytest temporary directory.

    Yields:
        LiveQemu: The running QEMU and the image it holds.
    """
    yield from start_live_qemu(tmp_path, memory_mb=DUMP_GUEST_MEMORY_MB)


class _DumpSandbox(QEMUSandbox):
    """``QEMUSandbox`` attached to an already-running QEMU and a real share.

    ``dump_memory`` and its polling are the unmodified production
    implementation; only the connection and the shared folder are established
    directly, because booting a guest through :meth:`QEMUSandbox.start` is not
    what these gates are about.
    """

    async def attach(self, shared_folder: Path) -> None:
        """Connect to the running monitor and bind a real shared folder.

        Args:
            shared_folder: Directory standing in for the guest's share.
        """
        self._shared_folder = shared_folder
        await self._connect_and_verify_qmp()

    async def detach(self) -> None:
        """Close the monitor connection."""
        if self._qmp is not None:
            await self._qmp.disconnect()

    async def monitor_answers_in(self) -> float:
        """Time a plain status query on the same monitor connection.

        Returns:
            float: Seconds the monitor took to answer.
        """
        assert self._qmp is not None, "the gate needs a connected monitor"
        started = time.monotonic()
        reply = await self._qmp.execute_command({"execute": "query-status"})
        elapsed = time.monotonic() - started
        assert reply.success, f"the monitor refused a plain status query: {reply.error}"
        return elapsed


def _make_sandbox(running: LiveQemu) -> _DumpSandbox:
    """Build a sandbox wired to the running QEMU's monitor.

    Args:
        running: The live QEMU.

    Returns:
        _DumpSandbox: A sandbox ready to attach.
    """
    config = QEMUConfig(
        guest_os=GuestOS.LINUX,
        image_path=running.image,
        monitor_port=running.monitor_port,
    )
    return _DumpSandbox(config=SandboxConfig(), qemu_config=config)


class TestAMemoryDumpReportsItsRealOutcome:
    """The dump must land, and a refusal must arrive with QEMU's own words."""

    @pytest.mark.asyncio
    async def test_a_refused_dump_carries_the_reason_qemu_gave(self, roomy_qemu: LiveQemu, tmp_path: Path) -> None:
        """A dump QEMU refuses must name what it refused and why.

        The shared folder deliberately has no ``output`` directory, so QEMU
        cannot create the file. It says so precisely; the operator must be
        shown that, not a generic failure.

        Args:
            roomy_qemu: The running QEMU.
            tmp_path: Pytest temporary directory.
        """
        share = tmp_path / "share-without-output"
        share.mkdir()
        sandbox = _make_sandbox(roomy_qemu)
        await sandbox.attach(share)
        try:
            with pytest.raises(SandboxError) as raised:
                await sandbox.dump_memory()
        finally:
            await sandbox.detach()

        reported = str(raised.value)
        assert str(share / "output") in reported, f"the failure does not say what QEMU could not write: {reported}"
        assert reported.strip() != "memory dump failed", "the real cause was discarded and replaced with a generic message"

    @pytest.mark.asyncio
    async def test_a_dump_of_a_multi_gigabyte_guest_completes(self, roomy_qemu: LiveQemu, tmp_path: Path) -> None:
        """The dump must be reported as done only once it is really on disk.

        The guest is larger than a synchronous dump can deliver inside the
        monitor's reply budget, which is the condition under which the old
        implementation declared a perfectly good dump a failure. The file is
        then read back: its size and its ELF dump header come from the
        filesystem, not from anything the monitor said.

        Args:
            roomy_qemu: The running QEMU.
            tmp_path: Pytest temporary directory.
        """
        share = tmp_path / "share"
        (share / "output").mkdir(parents=True)
        sandbox = _make_sandbox(roomy_qemu)
        await sandbox.attach(share)
        try:
            dump_path = await sandbox.dump_memory()
        finally:
            await sandbox.detach()

        assert dump_path.is_file(), f"the dump was reported as created but {dump_path} does not exist"
        written = dump_path.stat().st_size
        assert written > MIN_DUMP_BYTES, f"a {DUMP_GUEST_MEMORY_MB} MB guest produced only {written} bytes"
        with dump_path.open("rb") as handle:
            assert handle.read(len(ELF_MAGIC)) == ELF_MAGIC, "the file is not the ELF dump QEMU writes"

    @pytest.mark.asyncio
    async def test_the_monitor_still_answers_while_a_dump_runs(self, roomy_qemu: LiveQemu, tmp_path: Path) -> None:
        """A dump in progress must not lock every other caller out of the monitor.

        The monitor connection is serialised by a lock, so a command that only
        answers when the whole of guest RAM has been written stalls status
        polling, the VNC port lookup and the guest-agent channel for as long as
        the dump takes. Here the dump runs while a plain ``query-status`` is
        timed on the same connection.

        Args:
            roomy_qemu: The running QEMU.
            tmp_path: Pytest temporary directory.
        """
        share = tmp_path / "share"
        (share / "output").mkdir(parents=True)
        sandbox = _make_sandbox(roomy_qemu)
        await sandbox.attach(share)
        try:
            dumping = asyncio.ensure_future(sandbox.dump_memory())
            await asyncio.sleep(0.3)
            assert not dumping.done(), "the dump finished too quickly for this gate to mean anything"

            elapsed = await sandbox.monitor_answers_in()
            still_running = not dumping.done()

            dump_path = await dumping
        finally:
            await sandbox.detach()

        assert elapsed < MONITOR_ANSWER_BUDGET_S, f"the monitor was held for {elapsed:.2f}s by the running dump"
        assert still_running, "the dump had already finished, so the query proves nothing about a held monitor"
        assert dump_path.is_file(), "the dump that ran alongside the query never landed"
