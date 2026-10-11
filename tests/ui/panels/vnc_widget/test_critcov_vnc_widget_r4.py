# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Fourth-pass coverage for the framing of an empty SetColourMapEntries message in the VNC viewer client.

The test drives a real ``RFBClient``. Server bytes are written into one end of a genuine loopback ``socket`` pair while the client reads them
through asyncio streams wrapped around the other end. The expected framing comes from RFC 6143 section 7.6.2.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import Final

import pytest

from intellicrack.ui.panels.vnc_widget import RFBClient


pytestmark = pytest.mark.usefixtures("qapp")


_WAIT_S: Final[float] = 5.0
_SENTINEL: Final[bytes] = b"\xaa"
_FIRST_COLOR: Final[int] = 7
_MSG_SET_COLOR_MAP_ENTRIES: Final[int] = 1


async def _scenario() -> tuple[bool, bytes]:
    """Feed an empty color map message and a marker byte, then read the message body and the marker.

    Returns:
        tuple[bool, bytes]: The reader result and the first byte left in the stream after the body.
    """
    peer, mine = socket.socketpair()
    client = RFBClient()
    try:
        reader, writer = await asyncio.open_connection(sock=mine)
        setattr(client, "_reader", reader)
        setattr(client, "_writer", writer)
        header = b"\x00" + struct.pack("!HH", _FIRST_COLOR, 0)
        peer.sendall(header + _SENTINEL)
        body_reader = getattr(client, "_read_message_body")
        result: bool = await asyncio.wait_for(body_reader(reader, _MSG_SET_COLOR_MAP_ENTRIES), _WAIT_S)
        following = await asyncio.wait_for(reader.readexactly(1), _WAIT_S)
    finally:
        await client.disconnect()
        peer.close()
        mine.close()
    return result, following


def test_set_color_map_entries_with_no_colors_consumes_only_its_header() -> None:
    """A SetColourMapEntries message announcing zero colors is its 5-byte header alone, and the next byte belongs to the next message.

    RFC 6143 section 7.6.2: after the type byte come one padding byte, a 2-byte first-color and a 2-byte number-of-colors, then
    ``number-of-colors`` entries of 6 bytes. Here the first color is non-zero and the number of colors is zero, so no entry follows.
    """
    result, following = asyncio.run(_scenario())

    assert result is True
    assert following == _SENTINEL
