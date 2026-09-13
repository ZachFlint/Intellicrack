# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S20-D12 (VNC half): the RFB read loop logged idle polling as a stall.

Measured live: while the VNC framebuffer rendered correctly, ``handle_server_message``
logged frequent ``vnc_message_timeout`` warnings. The read loop polls for a new
server message every ``_MESSAGE_READ_TIMEOUT`` (100ms), and on an idle console
that poll times out on essentially every cycle - the previous code logged a
warning on every single one of those, with no way to tell that apart from an
actual protocol stall, because no timeout was ever applied to the body of a
message that had already started.

:meth:`RFBClient._dispatch_server_message` now times the initial poll for a
message-type byte separately from the rest of a message that has already
begun: a poll finding nothing pending raises the internal
``_NoMessagePendingError`` and is never logged, while a timeout partway
through a message that did start is a genuine stall, logged as
``vnc_message_stalled`` and treated as a lost connection (the byte stream is
left unsynced, so nothing downstream can be trusted).

These gates drive the real, unmodified ``RFBClient`` coroutine against a real
``asyncio.StreamReader`` - the only thing swapped in is what bytes (if any)
the stream ever produces - and read the actual outcome from
``structlog.testing.capture_logs``, not from a stubbed logger.
"""

from __future__ import annotations

import asyncio
import struct

import pytest
from structlog.testing import capture_logs

from intellicrack.ui.panels import vnc_widget as vnc_widget_module
from intellicrack.ui.panels.vnc_widget import RFBClient


_SAFETY_TIMEOUT_S = 3.0
_MSG_SERVER_CUT_TEXT = 3


class _ExposedRfbClient(RFBClient):
    """Exposes ``RFBClient``'s private reader slot for testing.

    ``basedpyright`` reports ``reportPrivateUsage`` for a test reaching a
    private member directly, so the reader is installed through a public
    method - the same pattern the sibling ``windows.py``/``qemu.py`` gates use.
    """

    def use_reader(self, reader: asyncio.StreamReader) -> None:
        """Install a stream reader in place of a real socket connection.

        Args:
            reader: Reader standing in for the connected VNC socket.
        """
        self._reader = reader


@pytest.mark.asyncio
async def test_idle_poll_with_nothing_pending_is_not_logged_and_stays_connected() -> None:
    """An idle console (no server message arriving) must not be logged as a stall."""
    client = _ExposedRfbClient()
    client.connected = True
    client.use_reader(asyncio.StreamReader())  # real reader, never fed any bytes

    with capture_logs() as captured:
        handled = await asyncio.wait_for(client.handle_server_message(), timeout=_SAFETY_TIMEOUT_S)

    assert handled is False, "no message was pending, so nothing was handled"
    assert client.connected, "an idle poll timeout must not be treated as a lost connection"
    warnings = [entry for entry in captured if entry.get("log_level") == "warning"]
    assert not warnings, f"an idle poll with nothing pending must not log any warning; got {warnings!r}"


@pytest.mark.asyncio
async def test_a_stall_partway_through_a_message_is_logged_and_disconnects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A message that starts but never finishes must be logged distinctly and drop the connection.

    Args:
        monkeypatch: Pytest fixture used to shrink the body-read timeout so
            the gate runs in a fraction of a second.
    """
    monkeypatch.setattr(vnc_widget_module, "_MESSAGE_BODY_READ_TIMEOUT", 0.15)

    client = _ExposedRfbClient()
    client.connected = True
    reader = asyncio.StreamReader()
    # ServerCutText: type byte, 3 padding bytes, then a 4-byte big-endian
    # length claiming 50 bytes of text that are never actually sent.
    reader.feed_data(bytes([_MSG_SERVER_CUT_TEXT, 0, 0, 0]) + struct.pack("!I", 50))
    client.use_reader(reader)

    with capture_logs() as captured:
        try:
            handled = await asyncio.wait_for(client.handle_server_message(), timeout=_SAFETY_TIMEOUT_S)
        except TimeoutError:
            pytest.fail(
                "handle_server_message hung past the safety timeout; the message body read must be "
                "bounded by its own timeout rather than blocking forever on a stalled connection",
            )

    assert handled is False
    assert not client.connected, "a genuine mid-message stall leaves the byte stream unsynced and must disconnect"
    stall_warnings = [entry for entry in captured if entry.get("event") == "vnc_message_stalled"]
    assert stall_warnings, f"a genuine mid-message stall must be logged as vnc_message_stalled; got {captured!r}"
    assert stall_warnings[0].get("log_level") == "warning"
