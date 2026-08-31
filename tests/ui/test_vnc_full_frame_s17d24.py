# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for S17-D24 and S17-D27: the VM Display never receives a frame.

Two independent protocol defects each kept the sandbox VM Display black, and
either one alone is enough to do it.

S17-D24 - RFC 6143 section 7.5.3 lets a VNC server answer an *incremental*
FramebufferUpdateRequest with nothing at all when no part of the screen changed
since the previous update. Only a *non-incremental* request obliges the server
to transmit the full framebuffer. A client that never sends a non-incremental
request therefore stays black forever in front of a guest sitting at a static
console, which is what the pump did: it asked for ``incremental=True`` on every
iteration including the very first one after the handshake.

S17-D27 - RFC 6143 section 7.5.1 defines SetPixelFormat as the message-type byte
0, three bytes of padding, then the sixteen-byte PIXEL_FORMAT. The client wrote
the bare sixteen-byte format, so a server read its leading bits-per-pixel value
as a client message type and mis-parsed every byte that followed.

These tests drive the real :class:`~intellicrack.ui.panels.vnc_widget.VNCWidget`
and its real ``RFBClient`` against a genuine asyncio TCP server speaking RFB 3.8
(version handshake, security type ``None``, ServerInit with a real pixel format,
raw-encoded FramebufferUpdate). That server models a VNC server in front of a
static screen: it parses the inbound FramebufferUpdateRequest messages and only
answers those whose incremental flag is zero. The assertions read the
incremental flag off the bytes the client actually put on the wire, the framing
of the first message it sends after ServerInit, and the pixels it actually
decoded into its published framebuffer.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, cast

import pytest

from intellicrack.ui.panels import vnc_widget as vnc_widget_module
from intellicrack.ui.panels.vnc_widget import VNCWidget


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from PyQt6.QtGui import QImage

type _PumpFactory = Callable[[], Coroutine[object, object, None]]

_LOOPBACK_HOST: Final[str] = "127.0.0.1"
_FB_WIDTH: Final[int] = 64
_FB_HEIGHT: Final[int] = 48
_PIXEL_BYTES: Final[int] = 4
_RFB_VERSION: Final[bytes] = b"RFB 003.008\n"
_RFB_VERSION_LEN: Final[int] = 12
_SECURITY_NONE: Final[int] = 1
_SECURITY_OK: Final[int] = 0
_MSG_FRAMEBUFFER_UPDATE: Final[int] = 0
_MSG_FRAMEBUFFER_UPDATE_REQUEST: Final[int] = 3
_FB_UPDATE_REQUEST_LEN: Final[int] = 10
_ENCODING_RAW: Final[int] = 0
_NON_INCREMENTAL: Final[int] = 0
_CLIENT_MSG_SET_PIXEL_FORMAT: Final[int] = 0
_PIXEL_FORMAT_OFFSET: Final[int] = 4
_SET_PIXEL_FORMAT_LEN: Final[int] = 20
_CLIENT_PIXEL_FORMAT: Final[bytes] = cast("bytes", getattr(vnc_widget_module, "_PIXEL_FORMAT_32BIT"))
_SERVER_NAME: Final[bytes] = b"intellicrack-s17d24"
_ADDRESS_PORT_FIELDS: Final[int] = 2
_CONNECT_TIMEOUT_S: Final[float] = 5.0
_FRAME_WAIT_S: Final[float] = 4.0
_PUMP_STOP_TIMEOUT_S: Final[float] = 5.0
_SERVER_CLOSE_TIMEOUT_S: Final[float] = 5.0
_PUMP_METHOD_NAME: Final[str] = "_pump_server_loop"
_SAMPLE_POINTS: Final[tuple[tuple[int, int], ...]] = (
    (0, 0),
    (1, 0),
    (17, 9),
    (_FB_WIDTH - 1, _FB_HEIGHT - 1),
)

_SERVER_PIXEL_FORMAT: Final[bytes] = struct.pack(
    "!BBBBHHHBBBxxx",
    32,
    24,
    0,
    1,
    255,
    255,
    255,
    16,
    8,
    0,
)


def _pixel_bgr(px: int, py: int) -> tuple[int, int, int]:
    """Return the blue/green/red triple this test paints at one framebuffer pixel.

    Single source of truth shared by the server (which encodes it into the raw
    rectangle) and the assertions (which read it back out of the decoded
    ``QImage``), so a byte-order or scanline-offset regression in the decoder
    shows up as a mismatch rather than being restated on both sides.

    Args:
        px: Zero-based pixel column.
        py: Zero-based pixel row.

    Returns:
        tuple[int, int, int]: Blue, green and red channel values in range 0-255.
    """
    blue = (px * 7 + 11) & 0xFF
    green = (py * 13 + 29) & 0xFF
    red = (px * 3 + py * 5 + 61) & 0xFF
    return blue, green, red


def _carries_transmitted_pixels(snapshot: QImage | None) -> bool:
    """Report whether a published snapshot holds the pixels the server encodes.

    Used as the poll predicate while the pump runs, so the run stops on the
    decoded server frame rather than on the all-black placeholder framebuffer
    that the handshake publishes before any update has arrived.

    Args:
        snapshot: Frame published by the client, or ``None`` when none exists yet.

    Returns:
        bool: ``True`` when the snapshot has the advertised geometry and every
        sampled pixel equals the colour the server transmitted.
    """
    if snapshot is None or snapshot.width() != _FB_WIDTH or snapshot.height() != _FB_HEIGHT:
        return False
    for px, py in _SAMPLE_POINTS:
        blue, green, red = _pixel_bgr(px, py)
        colour = snapshot.pixelColor(px, py)
        if (colour.red(), colour.green(), colour.blue()) != (red, green, blue):
            return False
    return True


def _raw_frame_bytes(width: int, height: int) -> bytes:
    """Build the BGRX pixel payload of a full-screen raw-encoded rectangle.

    Args:
        width: Framebuffer width in pixels.
        height: Framebuffer height in pixels.

    Returns:
        bytes: ``width * height * 4`` bytes in the little-endian BGRX layout the
        client negotiates in its pixel format.
    """
    payload = bytearray()
    for py in range(height):
        for px in range(width):
            blue, green, red = _pixel_bgr(px, py)
            payload += bytes((blue, green, red, 0))
    return bytes(payload)


class _StaticScreenRFBServer:
    """Real RFB 3.8 server that answers only non-incremental update requests.

    Faithfully models a VNC server exposed by a booted guest that is sitting at
    a static console: an incremental FramebufferUpdateRequest describes a screen
    region the server knows has not changed, so per RFC 6143 the server is
    entitled to send nothing and does send nothing. A non-incremental request
    always yields the complete framebuffer as one raw-encoded rectangle.

    Attributes:
        width: Framebuffer width advertised in ServerInit.
        height: Framebuffer height advertised in ServerInit.
        incremental_flags: Incremental flag byte of every FramebufferUpdateRequest
            received, in arrival order.
        frames_sent: Number of FramebufferUpdate messages transmitted.
        handshake_completed: Whether a client finished the full RFB handshake.
        transport_errors: Textual record of connection errors seen by the handler.
        post_init_bytes: Every client-to-server byte received after ServerInit, in
            arrival order, so the first message the client sends can be checked
            against the wire format the protocol defines for it.
    """

    width: int
    height: int
    incremental_flags: list[int]
    frames_sent: int
    handshake_completed: bool
    transport_errors: list[str]
    post_init_bytes: bytearray

    def __init__(self, width: int, height: int) -> None:
        """Initialise the server state without binding a socket.

        Args:
            width: Framebuffer width to advertise in ServerInit.
            height: Framebuffer height to advertise in ServerInit.
        """
        self.width = width
        self.height = height
        self.incremental_flags = []
        self.frames_sent = 0
        self.handshake_completed = False
        self.transport_errors = []
        self.post_init_bytes = bytearray()
        self._frame: bytes = _raw_frame_bytes(width, height)
        self._server: asyncio.Server | None = None

    async def start(self) -> int:
        """Bind to an ephemeral loopback port and start accepting connections.

        Returns:
            int: TCP port the listening socket was bound to.

        Raises:
            RuntimeError: If the server bound no listening socket at all.
            TypeError: If the bound socket reports an address without an integer port.
        """
        server = await asyncio.start_server(self._handle_client, _LOOPBACK_HOST, 0)
        self._server = server
        sockets = server.sockets
        if not sockets:
            msg = "RFB test server bound no listening socket"
            raise RuntimeError(msg)
        address = cast("tuple[object, ...]", sockets[0].getsockname())
        if len(address) < _ADDRESS_PORT_FIELDS:
            msg = f"RFB test server bound an unexpected address: {address!r}"
            raise TypeError(msg)
        port = address[1]
        if not isinstance(port, int):
            msg = f"RFB test server bound an unexpected port: {port!r}"
            raise TypeError(msg)
        return port

    async def stop(self) -> None:
        """Close the listening socket and wait for the handler to finish."""
        server = self._server
        if server is None:
            return
        self._server = None
        server.close()
        await asyncio.wait_for(server.wait_closed(), timeout=_SERVER_CLOSE_TIMEOUT_S)

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Serve one RFB client connection for its whole lifetime.

        Args:
            reader: Stream reader for the accepted connection.
            writer: Stream writer for the accepted connection.
        """
        try:
            await self._handshake(reader, writer)
            self.handshake_completed = True
            await self._serve_requests(reader, writer)
        except (asyncio.IncompleteReadError, ConnectionError, OSError) as exc:
            self.transport_errors.append(f"{type(exc).__name__}: {exc}")
        finally:
            writer.close()

    async def _handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Run the RFB 3.8 version, security and initialisation handshake.

        Args:
            reader: Stream reader for the accepted connection.
            writer: Stream writer for the accepted connection.

        Raises:
            RuntimeError: If the client selects a security type other than ``None``.
        """
        writer.write(_RFB_VERSION)
        await writer.drain()
        _ = await reader.readexactly(_RFB_VERSION_LEN)

        writer.write(bytes((1, _SECURITY_NONE)))
        await writer.drain()
        selected = await reader.readexactly(1)
        if selected[0] != _SECURITY_NONE:
            msg = f"client selected unsupported security type {selected[0]}"
            raise RuntimeError(msg)
        writer.write(struct.pack("!I", _SECURITY_OK))
        await writer.drain()

        _ = await reader.readexactly(1)
        writer.write(
            struct.pack("!HH", self.width, self.height) + _SERVER_PIXEL_FORMAT + struct.pack("!I", len(_SERVER_NAME)) + _SERVER_NAME,
        )
        await writer.drain()

    async def _serve_requests(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Answer FramebufferUpdateRequest messages until the client goes away.

        The client stream is scanned with a sliding ten-byte window rather than a
        fixed message-length table, so the parser locates every genuine
        FramebufferUpdateRequest (message type 3 whose rectangle matches the
        geometry this server advertised) regardless of what other client-to-server
        traffic precedes it.

        Args:
            reader: Stream reader for the accepted connection.
            writer: Stream writer for the accepted connection.
        """
        window = bytearray()
        while True:
            chunk = await reader.read(1)
            if not chunk:
                return
            self.post_init_bytes += chunk
            window += chunk
            if len(window) > _FB_UPDATE_REQUEST_LEN:
                del window[0]
            if len(window) < _FB_UPDATE_REQUEST_LEN or not self._is_update_request(bytes(window)):
                continue
            incremental = window[1]
            window.clear()
            self.incremental_flags.append(incremental)
            if incremental == _NON_INCREMENTAL:
                writer.write(self._encode_full_update())
                await writer.drain()
                self.frames_sent += 1

    def _is_update_request(self, candidate: bytes) -> bool:
        """Report whether ten buffered bytes form a FramebufferUpdateRequest.

        Args:
            candidate: Exactly ten bytes taken from the client-to-server stream.

        Returns:
            bool: ``True`` when the bytes are a well-formed full-screen
            FramebufferUpdateRequest for this server's geometry.
        """
        if candidate[0] != _MSG_FRAMEBUFFER_UPDATE_REQUEST or candidate[1] > 1:
            return False
        x, y, width, height = struct.unpack("!HHHH", candidate[2:])
        return x == 0 and y == 0 and width == self.width and height == self.height

    def _encode_full_update(self) -> bytes:
        """Encode a FramebufferUpdate carrying the whole screen as one raw rectangle.

        Returns:
            bytes: Complete server-to-client FramebufferUpdate message.
        """
        return (
            struct.pack("!BBH", _MSG_FRAMEBUFFER_UPDATE, 0, 1)
            + struct.pack("!HHHHi", 0, 0, self.width, self.height, _ENCODING_RAW)
            + self._frame
        )


@dataclass(frozen=True)
class _DriveResult:
    """Everything observed while driving the widget against the static-screen server.

    Attributes:
        connected: Whether ``RFBClient.connect`` reported a successful handshake.
        handshake_completed: Whether the server saw the handshake through to ServerInit.
        incremental_flags: Incremental flag of every FramebufferUpdateRequest the
            client put on the wire, in order.
        frames_sent: Number of FramebufferUpdate messages the server transmitted.
        frame_signalled: Whether the widget signalled a published frame carrying the
            transmitted pixels before the wait expired.
        snapshot: Frame the widget published, or ``None`` when it never decoded one.
        transport_errors: Connection errors recorded by the server handler.
        post_init_bytes: Client-to-server bytes received after ServerInit, in order.
    """

    connected: bool
    handshake_completed: bool
    incremental_flags: tuple[int, ...]
    frames_sent: int
    frame_signalled: bool
    snapshot: QImage | None
    transport_errors: tuple[str, ...]
    post_init_bytes: bytes


async def _await_event(event: asyncio.Event, limit_s: float) -> bool:
    """Wait for an event, reporting whether it was set before the limit elapsed.

    Args:
        event: Event signalled by the framebuffer-updated slot.
        limit_s: Maximum seconds to wait.

    Returns:
        bool: ``True`` when the event was set in time, ``False`` on expiry.
    """
    try:
        await asyncio.wait_for(event.wait(), timeout=limit_s)
    except TimeoutError:
        return False
    return True


async def _pump_until_frame(widget: VNCWidget) -> bool:
    """Run the widget's real frame pump until it shows the server frame or time runs out.

    The wait is driven by the widget's own ``framebuffer_updated`` signal, which
    the production pump emits after every publish, so no polling is involved.

    Args:
        widget: Connected widget whose production pump coroutine is exercised.

    Returns:
        bool: ``True`` when the widget published the server's transmitted frame.
    """
    frame_ready = asyncio.Event()

    def _on_framebuffer_updated() -> None:
        """Signal the waiter once a published frame carries the server's pixels."""
        if _carries_transmitted_pixels(widget.client.snapshot_frame()):
            frame_ready.set()

    _ = widget.framebuffer_updated.connect(_on_framebuffer_updated)
    pump = cast("_PumpFactory", getattr(widget, _PUMP_METHOD_NAME))
    task = asyncio.create_task(pump())
    try:
        return await _await_event(frame_ready, _FRAME_WAIT_S)
    finally:
        widget.client.connected = False
        await asyncio.wait_for(task, timeout=_PUMP_STOP_TIMEOUT_S)
        _ = widget.framebuffer_updated.disconnect(_on_framebuffer_updated)


async def _drive_widget_against_static_screen() -> _DriveResult:
    """Connect the real widget to the static-screen RFB server and record the outcome.

    Returns:
        _DriveResult: Wire-level and framebuffer-level observations of the run.
    """
    server = _StaticScreenRFBServer(_FB_WIDTH, _FB_HEIGHT)
    port = await server.start()
    widget = VNCWidget()
    connected = False
    signalled = False
    snapshot: QImage | None = None
    try:
        connected = await widget.client.connect(_LOOPBACK_HOST, port, timeout=_CONNECT_TIMEOUT_S)
        if connected:
            signalled = await _pump_until_frame(widget)
            snapshot = widget.client.snapshot_frame()
    finally:
        await widget.client.disconnect()
        await server.stop()
        widget.close()
    return _DriveResult(
        connected=connected,
        handshake_completed=server.handshake_completed,
        incremental_flags=tuple(server.incremental_flags),
        frames_sent=server.frames_sent,
        frame_signalled=signalled,
        snapshot=snapshot,
        transport_errors=tuple(server.transport_errors),
        post_init_bytes=bytes(server.post_init_bytes),
    )


@pytest.fixture(scope="module")
def static_screen_run(qapp: object) -> _DriveResult:
    """Drive the widget once against the static-screen RFB server for this module.

    Args:
        qapp: Session ``QApplication`` fixture; ``VNCWidget`` requires one.

    Returns:
        _DriveResult: Observations shared by every test in this module.
    """
    _ = qapp
    return asyncio.run(_drive_widget_against_static_screen())


class TestFirstUpdateRequestIsNonIncremental:
    """S17-D24: the first FramebufferUpdateRequest after connecting must be full."""

    @staticmethod
    def test_first_request_on_the_wire_is_non_incremental(static_screen_run: _DriveResult) -> None:
        """The incremental byte of the client's first update request must be zero.

        Args:
            static_screen_run: Observations from the single driven session.
        """
        assert static_screen_run.connected, "the RFB handshake did not succeed"
        assert static_screen_run.handshake_completed, "the server never completed ServerInit"
        assert static_screen_run.incremental_flags, "the client sent no FramebufferUpdateRequest at all"
        assert static_screen_run.incremental_flags[0] == _NON_INCREMENTAL, (
            "the first FramebufferUpdateRequest after connecting was incremental "
            f"(flags on the wire: {static_screen_run.incremental_flags[:8]}); a server showing a static "
            "screen is entitled to answer that with nothing, so the display never receives a frame"
        )


class TestStaticScreenServerDeliversAFrame:
    """S17-D24: a server that only answers full requests must still fill the display."""

    @staticmethod
    def test_server_transmits_a_framebuffer_update(static_screen_run: _DriveResult) -> None:
        """The static-screen server must have been asked in a way it can answer.

        Args:
            static_screen_run: Observations from the single driven session.
        """
        assert static_screen_run.frames_sent >= 1, (
            "the server sent no FramebufferUpdate because it never received a non-incremental "
            f"request (flags: {static_screen_run.incremental_flags[:8]}, "
            f"transport errors: {static_screen_run.transport_errors})"
        )

    @staticmethod
    def test_widget_displays_the_transmitted_frame(static_screen_run: _DriveResult) -> None:
        """The published snapshot must be the decoded server frame, not the black placeholder.

        The handshake pre-fills the framebuffer with black and marks it dirty, so
        a snapshot merely existing proves nothing. Every sampled pixel is compared
        against the colour the server actually put on the wire.

        Args:
            static_screen_run: Observations from the single driven session.
        """
        snapshot = static_screen_run.snapshot
        assert snapshot is not None, (
            "the widget never published a frame; the VM Display would stay black "
            f"(requests sent: {len(static_screen_run.incremental_flags)}, frames served: {static_screen_run.frames_sent})"
        )
        assert static_screen_run.frame_signalled, (
            "the widget never emitted framebuffer_updated for a frame carrying the server's pixels; "
            f"the VM Display would stay black (requests sent: {len(static_screen_run.incremental_flags)}, "
            f"frames served: {static_screen_run.frames_sent})"
        )
        assert snapshot.width() == _FB_WIDTH
        assert snapshot.height() == _FB_HEIGHT
        for px, py in _SAMPLE_POINTS:
            expected_blue, expected_green, expected_red = _pixel_bgr(px, py)
            colour = snapshot.pixelColor(px, py)
            assert (colour.red(), colour.green(), colour.blue()) == (
                expected_red,
                expected_green,
                expected_blue,
            ), f"pixel ({px},{py}) decoded as {(colour.red(), colour.green(), colour.blue())}"


class TestSetPixelFormatIsAWellFormedMessage:
    """S17-D27: the pixel format must be sent as a SetPixelFormat message, not raw."""

    @staticmethod
    def test_first_client_message_after_server_init_is_set_pixel_format(
        static_screen_run: _DriveResult,
    ) -> None:
        """The bytes after ServerInit must be a framed SetPixelFormat, not a bare format.

        RFC 6143 7.5.1 defines SetPixelFormat as the message-type byte 0, three
        bytes of padding, then the sixteen-byte PIXEL_FORMAT. Writing only the
        sixteen-byte format leaves the first byte as the bits-per-pixel value,
        which a server reads as a client message type; every byte the client
        sends afterwards is then interpreted at the wrong offset, so no
        FramebufferUpdateRequest is ever recognised however many are sent.

        Args:
            static_screen_run: Observations from the single driven session.
        """
        stream = static_screen_run.post_init_bytes
        assert len(stream) >= _SET_PIXEL_FORMAT_LEN, (
            f"the client sent only {len(stream)} bytes after ServerInit, too few to carry a SetPixelFormat message"
        )
        message_type = stream[0]
        assert message_type == _CLIENT_MSG_SET_PIXEL_FORMAT, (
            f"the first byte the client sent after ServerInit was {message_type}, not the SetPixelFormat "
            f"message type {_CLIENT_MSG_SET_PIXEL_FORMAT}; a server parses that byte as the message type and "
            f"desynchronises from the client stream (first bytes: {stream[:_SET_PIXEL_FORMAT_LEN].hex(' ')})"
        )
        assert stream[_PIXEL_FORMAT_OFFSET:_SET_PIXEL_FORMAT_LEN] == _CLIENT_PIXEL_FORMAT, (
            "the SetPixelFormat body is not the pixel format the client's decoder expects "
            f"(sent: {stream[_PIXEL_FORMAT_OFFSET:_SET_PIXEL_FORMAT_LEN].hex(' ')})"
        )
