# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D63: a QMP reply must be told apart from an asynchronous event.

QMP is not a bare request/response protocol. QEMU pushes events onto the same
socket whenever the machine changes state, and they interleave with replies.
The monitor client read exactly one line after each command and decoded it as
that command's answer, so the first event to arrive was consumed as a reply -
and because an event frame carries no ``error`` member, it decoded as
``QMPResponse(success=True, data=None)``. A successful-looking answer with no
content, for a command that had not been answered at all.

Measured against the bundled QEMU 10.1.0, ``stop`` really does put an event in
front of its reply::

    {"timestamp": {...}, "event": "STOP"}
    {"return": {}, "id": "s1"}

Two consequences, both gated below. The command itself reports a success QEMU
never sent; and the stream stays one frame behind for the life of the
connection, so every later command is handed the previous command's answer.
That is what turned the S17-D59 snapshot work into "QEMU stopped reporting job
... before it finished": ``snapshot-save`` emits ``JOB_STATUS_CHANGE`` ahead of
its reply, and the follow-up ``query-jobs`` then read a frame that listed no
jobs at all.

The fix tags every command with the ``id`` member QMP defines for exactly this
purpose - QEMU echoes it on the reply and never puts it on an event - and reads
frames until the matching one arrives.

These gates drive the production :class:`QMPClient` against a **real QEMU**, so
the event ordering under test is the one QEMU genuinely produces rather than
one the test arranged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.sandbox.qemu import QMPClient
from tests.sandbox.qemu.live_qemu import LiveQemu, start_live_qemu


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_PAUSED = "paused"
_RUNNING = "running"


@pytest.fixture
def live_qemu(tmp_path: Path) -> Iterator[LiveQemu]:
    """Start a real QEMU with an open QMP monitor.

    Args:
        tmp_path: Pytest temporary directory.

    Yields:
        LiveQemu: The running QEMU and the image it holds.
    """
    yield from start_live_qemu(tmp_path)


def _status_of(payload: object) -> str | None:
    """Read the ``status`` member out of a ``query-status`` reply.

    Args:
        payload: The reply's ``return`` member.

    Returns:
        str | None: The reported run state, or None if the payload did not
        carry one.
    """
    if isinstance(payload, dict):
        status = cast("dict[str, object]", payload).get("status")
        if isinstance(status, str):
            return status
    return None


class TestQmpRepliesSurviveAsynchronousEvents:
    """A command must receive its own answer, not the next event on the wire."""

    @pytest.mark.asyncio
    async def test_a_command_that_emits_an_event_still_returns_its_own_reply(self, live_qemu: LiveQemu) -> None:
        """``stop`` emits STOP before answering; the answer is the empty return object.

        Args:
            live_qemu: The running QEMU.
        """
        client = QMPClient(port=live_qemu.monitor_port)
        assert await client.connect(), "the gate needs a real monitor connection"
        try:
            result = await client.stop()

            assert result.success, f"stop was refused: {result.error}"
            assert result.data == {}, f"stop must return QEMU's empty result object, got {result.data!r}"
        finally:
            await client.disconnect()

    @pytest.mark.asyncio
    async def test_the_stream_stays_aligned_across_a_pause_and_resume(self, live_qemu: LiveQemu) -> None:
        """Every command after an event-emitting one must still read its own reply.

        The run state is read back from QEMU after each transition. A client
        one frame behind reports the previous command's answer here, which
        carries no ``status`` at all.

        Args:
            live_qemu: The running QEMU.
        """
        client = QMPClient(port=live_qemu.monitor_port)
        assert await client.connect(), "the gate needs a real monitor connection"
        try:
            before = await client.query_status()
            assert _status_of(before.data) == _RUNNING, f"the machine did not start running: {before.data!r}"

            await client.stop()
            paused = await client.query_status()
            assert _status_of(paused.data) == _PAUSED, (
                f"after stop the monitor reported {_status_of(paused.data)!r}; raw reply {paused.data!r}"
            )

            await client.cont()
            resumed = await client.query_status()
            assert _status_of(resumed.data) == _RUNNING, (
                f"after cont the monitor reported {_status_of(resumed.data)!r}; raw reply {resumed.data!r}"
            )
        finally:
            await client.disconnect()

    @pytest.mark.asyncio
    async def test_a_structured_query_after_an_event_returns_its_own_shape(self, live_qemu: LiveQemu) -> None:
        """A list-returning query issued after an event must return a list.

        ``query-block`` answers with an array. A misaligned client hands back
        whatever the previous command returned - an empty object for ``cont`` -
        which is exactly how the snapshot node selection lost its disk.

        Args:
            live_qemu: The running QEMU.
        """
        client = QMPClient(port=live_qemu.monitor_port)
        assert await client.connect(), "the gate needs a real monitor connection"
        try:
            await client.stop()
            await client.cont()

            devices = await client.query_block()

            assert devices.success, f"query-block was refused: {devices.error}"
            payload: object = devices.data
            assert isinstance(payload, list), f"query-block must answer with an array, got {payload!r}"
            drives: list[object] = []
            for entry in cast("list[object]", payload):
                if isinstance(entry, dict):
                    medium: object = cast("dict[str, object]", entry).get("inserted")
                    if isinstance(medium, dict):
                        drives.append(cast("dict[str, object]", medium))
            assert drives, f"the running machine's real qcow2 is missing from the reply: {payload!r}"
        finally:
            await client.disconnect()
