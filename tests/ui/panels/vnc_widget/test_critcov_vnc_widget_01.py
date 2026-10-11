# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the RFB handshake, message framing and rectangle decoders of the VNC viewer client.

Every test drives a real ``RFBClient``. Server bytes are written into one end of a genuine loopback ``socket`` pair while the client reads
them through asyncio streams wrapped around the other end, so the client frames, consumes and answers real bytes; the bytes the client
sends back are read from the peer socket. The expected values come from the RFB protocol definition (RFC 6143 and the Tight encoding
description), from published DES known-answer vectors, from a decrypt with a hand-written key, from ``zlib`` and from plain pixel
arithmetic written out in each test, never from re-running the code under test.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import zlib
from contextlib import asynccontextmanager, contextmanager
from typing import TYPE_CHECKING, Any, Final, NamedTuple

import pytest
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher
from PyQt6.QtGui import QColor, QImage

import intellicrack.ui.panels.vnc_widget as vnc_widget_mod
from intellicrack.ui.panels.vnc_widget import RFBClient


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable, Coroutine, Generator


type _Rgb = tuple[int, int, int]

pytestmark = pytest.mark.usefixtures("qapp")


_Dynamic = Any

_LOOPBACK: Final[str] = "127.0.0.1"
_WAIT_S: Final[float] = 5.0
_RFB_VERSION: Final[bytes] = b"RFB 003.008\n"
_SENTINEL: Final[bytes] = b"\xaa"
_BLACK: Final[_Rgb] = (0, 0, 0)
_AUTH_CHALLENGE: Final[bytes] = bytes(16)
_AUTH_PASSWORD: Final[str] = "\x01"
_AUTH_RESPONSE: Final[bytes] = struct.pack("!II", 0x95A8D728, 0x13DAA94D) * 2
_ENCODING_COPY_RECT: Final[int] = 1
_ENCODING_RRE: Final[int] = 2
_ENCODING_HEXTILE: Final[int] = 5
_ENCODING_TIGHT: Final[int] = 7
_ENCODING_ZRLE: Final[int] = 16
_DES_KNOWN_ANSWERS: Final[list[tuple[int, int, int]]] = [
    (0x01, 0x95A8D728, 0x13DAA94D),
    (0x02, 0x0EEC1487, 0xDD8C26D5),
    (0x04, 0x7AD16FFB, 0x79C45926),
]


class _Rig(NamedTuple):
    """A client wired to one end of a loopback socket pair.

    Attributes:
        client: Real client whose reader and writer wrap one end of the pair.
        peer: The other end of the pair, standing in for the server side of the connection.
        reader: The stream reader installed on the client.
    """

    client: RFBClient
    peer: socket.socket
    reader: asyncio.StreamReader


def _priv(obj: object, name: str) -> _Dynamic:
    """Read a private attribute or method of a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.

    Returns:
        _Dynamic: The attribute value.
    """
    return getattr(obj, name)


def _set_priv(obj: object, name: str, value: object) -> None:
    """Assign a private data attribute on a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.
        value: Value to store.
    """
    setattr(obj, name, value)


@contextmanager
def _tight_flag(*, value: bool) -> Generator[None]:
    """Temporarily set the module's Pillow-availability flag and restore it afterwards.

    Args:
        value: Availability to report while the context is active.

    Yields:
        None: Control while the flag holds ``value``.
    """
    original = _priv(vnc_widget_mod, "_TIGHT_AVAILABLE")
    _set_priv(vnc_widget_mod, "_TIGHT_AVAILABLE", value)
    try:
        yield
    finally:
        _set_priv(vnc_widget_mod, "_TIGHT_AVAILABLE", original)


def _bgrx(red: int, green: int, blue: int) -> bytes:
    """Encode one pixel in the 32-bit little-endian layout the client negotiates.

    Args:
        red: Red channel.
        green: Green channel.
        blue: Blue channel.

    Returns:
        bytes: Four bytes, blue first, with an unused fourth byte of zero.
    """
    return bytes((blue, green, red, 0))


def _compact_length(value: int) -> bytes:
    """Encode a length in the Tight compact representation.

    Args:
        value: Length to encode, below 4194304.

    Returns:
        bytes: One byte below 128, two bytes below 16384, otherwise three bytes whose last byte carries all eight bits.
    """
    if value < 0x80:
        return bytes((value,))
    if value < 0x4000:
        return bytes(((value & 0x7F) | 0x80, value >> 7))
    return bytes(((value & 0x7F) | 0x80, ((value >> 7) & 0x7F) | 0x80, value >> 14))


def _make_framebuffer(width: int, height: int, fill: _Rgb = _BLACK) -> QImage:
    """Create a framebuffer image filled with one color.

    Args:
        width: Image width in pixels.
        height: Image height in pixels.
        fill: Red, green and blue fill color.

    Returns:
        QImage: A ``Format_RGB32`` image.
    """
    image = QImage(width, height, QImage.Format.Format_RGB32)
    image.fill(QColor(*fill))
    return image


def _client_with_framebuffer(width: int, height: int, fill: _Rgb = _BLACK) -> RFBClient:
    """Create a client that owns a framebuffer but no connection.

    Args:
        width: Framebuffer width in pixels.
        height: Framebuffer height in pixels.
        fill: Red, green and blue fill color.

    Returns:
        RFBClient: Client whose ``framebuffer`` is a filled image.
    """
    client = RFBClient()
    client.framebuffer = _make_framebuffer(width, height, fill)
    return client


def _rgb_at(client: RFBClient, x: int, y: int) -> _Rgb:
    """Read one framebuffer pixel as red, green and blue.

    Args:
        client: Client that owns the framebuffer.
        x: Pixel column.
        y: Pixel row.

    Returns:
        _Rgb: Red, green and blue channels of the pixel.
    """
    framebuffer = client.framebuffer
    assert framebuffer is not None
    colour = framebuffer.pixelColor(x, y)
    return (colour.red(), colour.green(), colour.blue())


def _pixels(client: RFBClient) -> list[_Rgb]:
    """Read every framebuffer pixel in row-major order.

    Args:
        client: Client that owns the framebuffer.

    Returns:
        list[_Rgb]: One red, green and blue triple per pixel.
    """
    framebuffer = client.framebuffer
    assert framebuffer is not None
    return [_rgb_at(client, x, y) for y in range(framebuffer.height()) for x in range(framebuffer.width())]


def _seed_rgb(x: int, y: int) -> _Rgb:
    """Compute the distinct color the seeding helper paints at one pixel.

    Args:
        x: Pixel column.
        y: Pixel row.

    Returns:
        _Rgb: Red, green and blue channels, all below 256 for coordinates up to 15.
    """
    return (30 + 7 * x, 40 + 5 * y, 50 + x + y)


def _seed(client: RFBClient) -> None:
    """Paint every framebuffer pixel with its distinct seed color.

    Args:
        client: Client that owns the framebuffer.
    """
    framebuffer = client.framebuffer
    assert framebuffer is not None
    for y in range(framebuffer.height()):
        for x in range(framebuffer.width()):
            red, green, blue = _seed_rgb(x, y)
            framebuffer.setPixelColor(x, y, QColor(red, green, blue))


@asynccontextmanager
async def _rig(width: int = 0, height: int = 0, *, connected: bool = False) -> AsyncGenerator[_Rig]:
    """Wire a fresh client to one end of a loopback socket pair and clean everything up afterwards.

    Args:
        width: Framebuffer width, or zero for a client without a framebuffer.
        height: Framebuffer height.
        connected: Whether to mark the client as connected.

    Yields:
        _Rig: The client, the server-side socket and the client's stream reader.
    """
    peer, mine = socket.socketpair()
    client = RFBClient()
    try:
        reader, writer = await asyncio.open_connection(sock=mine)
        _set_priv(client, "_reader", reader)
        _set_priv(client, "_writer", writer)
        if width:
            client.framebuffer = _make_framebuffer(width, height)
        client.connected = connected
        yield _Rig(client, peer, reader)
    finally:
        await client.disconnect()
        peer.close()
        mine.close()


def _drive[T](
    scenario: Callable[[_Rig], Coroutine[object, object, T]],
    *,
    width: int = 0,
    height: int = 0,
    connected: bool = False,
) -> T:
    """Run a scenario against a wired client on a fresh event loop.

    Args:
        scenario: Coroutine function that receives the rig.
        width: Framebuffer width, or zero for a client without a framebuffer.
        height: Framebuffer height.
        connected: Whether to mark the client as connected.

    Returns:
        T: Whatever the scenario returned.
    """

    async def runner() -> T:
        """Wire the client and await the scenario.

        Returns:
            T: Whatever the scenario returned.
        """
        async with _rig(width, height, connected=connected) as rig:
            return await scenario(rig)

    return asyncio.run(runner())


async def _next_byte(rig: _Rig) -> bytes:
    """Read the next byte the client has not consumed yet.

    Args:
        rig: Rig whose reader is read.

    Returns:
        bytes: The next unread byte of the server stream.
    """
    return await asyncio.wait_for(rig.reader.readexactly(1), _WAIT_S)


async def _written_by_client(rig: _Rig) -> bytes:
    """Close the client and collect everything it sent to the server side.

    Every byte the server side sent must already have been consumed, otherwise closing would reset the connection and lose the data.

    Args:
        rig: Rig whose client is disconnected.

    Returns:
        bytes: All bytes the client wrote, up to end of stream.
    """
    await rig.client.disconnect()
    rig.peer.settimeout(_WAIT_S)
    received = bytearray()
    while True:
        piece = rig.peer.recv(4096)
        if not piece:
            return bytes(received)
        received += piece


async def _negotiate_security_against(server_bytes: bytes, password: str | None) -> tuple[bool, bytes]:
    """Run the client's security negotiation against pre-written server bytes.

    Args:
        server_bytes: Everything the server sends from the security-type list onward.
        password: Password handed to the negotiation.

    Returns:
        tuple[bool, bytes]: The negotiation result and the bytes the client wrote.
    """
    async with _rig() as rig:
        rig.peer.sendall(server_bytes)
        accepted = await _priv(rig.client, "_negotiate_security")(password)
        written = await _written_by_client(rig)
    return accepted, written


@pytest.mark.parametrize(
    ("method", "args"),
    [("decompress", (None, b"payload")), ("flush", (None, 16))],
    ids=["decompress", "flush"],
)
def test_zlib_protocol_default_bodies_produce_no_output(method: str, args: tuple[object, ...]) -> None:
    """The protocol's own method bodies return empty bytes when called directly.

    Args:
        method: Protocol method name.
        args: Arguments including the unbound ``self``.
    """
    protocol = _priv(vnc_widget_mod, "_ZlibDecompressor")
    assert _priv(protocol, method)(*args) == b""


def test_rfb_protocol_mode_is_electronic_codebook() -> None:
    """The protocol cipher mode is an ECB instance, as RFC 6143 requires for the DES challenge."""
    mode = _priv(vnc_widget_mod, "_rfb_protocol_mode")()
    assert type(mode).__name__ == "ECB"
    assert type(mode).__module__ == "cryptography.hazmat.primitives.ciphers.modes"
    assert mode.name == "ECB"


def test_reverse_bits_matches_binary_string_reversal_for_every_byte() -> None:
    """Every byte value maps to the byte whose eight-digit binary form is the original read backwards."""
    reverse = _priv(vnc_widget_mod, "_reverse_bits")
    for value in range(256):
        assert reverse(value) == int(format(value, "08b")[::-1], 2)
    assert reverse(0x01) == 0x80
    assert reverse(0x06) == 0x60
    assert reverse(0xFF) == 0xFF


@pytest.mark.parametrize(("password_byte", "high", "low"), _DES_KNOWN_ANSWERS)
def test_vnc_auth_encrypt_matches_des_variable_key_known_answers(password_byte: int, high: int, low: int) -> None:
    """A zero challenge encrypts to the published DES variable-key answer for the bit-reversed password key.

    The password byte ``0x01`` reverses to the key byte ``0x80`` and so on; DES ignores the low parity bit of each key byte, so these keys
    are the published single-bit variable-key vectors. Every 8-byte block of a zero challenge encrypts independently in ECB mode.

    Args:
        password_byte: Single password character code.
        high: First four bytes of the expected ciphertext block.
        low: Last four bytes of the expected ciphertext block.
    """
    response = _priv(vnc_widget_mod, "_vnc_auth_encrypt")(bytes(16), chr(password_byte))
    assert response == struct.pack("!II", high, low) * 2


def test_vnc_auth_encrypt_is_des_under_the_bit_reversed_password() -> None:
    """Decrypting the response with the hand-reversed key of the password recovers the challenge.

    The password ``A`` is ``0x41`` (binary 01000001), whose bit-reversed byte is ``0x82`` (binary 10000010).
    """
    challenge = bytes(range(16, 32))
    response = _priv(vnc_widget_mod, "_vnc_auth_encrypt")(challenge, "A")
    key = bytes((0x82,)) + bytes(7)
    decryptor = Cipher(TripleDES(key * 3), _priv(vnc_widget_mod, "_rfb_protocol_mode")()).decryptor()
    assert len(response) == len(challenge)
    assert decryptor.update(response) + decryptor.finalize() == challenge


def test_vnc_auth_encrypt_uses_only_the_first_eight_password_bytes() -> None:
    """Characters after the eighth do not change the response, while the eighth does."""
    encrypt = _priv(vnc_widget_mod, "_vnc_auth_encrypt")
    challenge = bytes(range(16))
    assert encrypt(challenge, "abcdefgh") == encrypt(challenge, "abcdefghIJKLMN")
    assert encrypt(challenge, "abcdefgh") != encrypt(challenge, "abcdefgi")


def test_vnc_auth_encrypt_null_pads_a_short_password() -> None:
    """A short password behaves exactly like the same password padded with zero bytes to eight."""
    encrypt = _priv(vnc_widget_mod, "_vnc_auth_encrypt")
    challenge = bytes(range(16))
    assert encrypt(challenge, "ab") == encrypt(challenge, "ab\x00\x00\x00\x00\x00\x00")
    assert encrypt(challenge, "ab") != encrypt(challenge, "abc")


def test_publish_frame_without_a_framebuffer_publishes_nothing() -> None:
    """Publishing with no framebuffer leaves no snapshot, and a later publish stores an independent copy."""
    client = RFBClient()
    client.publish_frame()
    assert client.snapshot_frame() is None
    client.framebuffer = _make_framebuffer(2, 2, (9, 8, 7))
    client.publish_frame()
    snapshot = client.snapshot_frame()
    assert snapshot is not None
    assert snapshot is not client.framebuffer
    assert snapshot.pixelColor(1, 1).red() == 9


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("_negotiate_version", ()),
        ("_negotiate_security", (None,)),
        ("_perform_vnc_auth", ("secret",)),
        ("_client_init", ()),
    ],
)
def test_handshake_steps_refuse_to_run_without_a_connection(method: str, args: tuple[object, ...]) -> None:
    """Each handshake step raises ``ConnectionError`` when the client has no reader and writer.

    Args:
        method: Name of the handshake step.
        args: Arguments passed to the step.
    """
    client = RFBClient()

    async def scenario() -> None:
        """Run the handshake step on the unconnected client."""
        await _priv(client, method)(*args)

    with pytest.raises(ConnectionError, match="Not connected"):
        asyncio.run(scenario())


def test_security_failure_reason_is_consumed_and_negotiation_fails() -> None:
    """A server that offers zero security types sends a reason string that the client reads in full."""
    reason = b"too many connections"

    async def scenario(rig: _Rig) -> tuple[bool, bytes, bytes]:
        """Negotiate against a failure reply followed by a marker byte.

        Args:
            rig: Wired client.

        Returns:
            tuple[bool, bytes, bytes]: Negotiation result, the byte after the reason, and what the client wrote.
        """
        rig.peer.sendall(b"\x00" + struct.pack("!I", len(reason)) + reason + _SENTINEL)
        accepted = await _priv(rig.client, "_negotiate_security")(None)
        following = await _next_byte(rig)
        written = await _written_by_client(rig)
        return accepted, following, written

    accepted, following, written = _drive(scenario)
    assert accepted is False
    assert following == _SENTINEL
    assert written == b""


def test_vnc_authentication_sends_its_type_then_the_des_response() -> None:
    """With only VNC authentication offered the client selects type 2 and answers the challenge with the DES response."""
    server = bytes((1, 2)) + _AUTH_CHALLENGE + struct.pack("!I", 0)
    accepted, written = asyncio.run(_negotiate_security_against(server, _AUTH_PASSWORD))
    assert accepted is True
    assert written == bytes((2,)) + _AUTH_RESPONSE


def test_vnc_authentication_reports_a_rejected_response() -> None:
    """A non-zero security result after the challenge response makes the negotiation fail."""
    server = bytes((1, 2)) + _AUTH_CHALLENGE + struct.pack("!I", 1)
    accepted, written = asyncio.run(_negotiate_security_against(server, _AUTH_PASSWORD))
    assert accepted is False
    assert written == bytes((2,)) + _AUTH_RESPONSE


def test_vnc_authentication_without_a_password_sends_nothing() -> None:
    """When the server demands VNC authentication and no password is given, the client fails without writing anything."""
    accepted, written = asyncio.run(_negotiate_security_against(bytes((1, 2)), None))
    assert accepted is False
    assert written == b""


def test_security_types_the_client_cannot_use_fail_without_sending() -> None:
    """A server offering only types other than None and VNC authentication is refused without a reply."""
    accepted, written = asyncio.run(_negotiate_security_against(bytes((2, 5, 19)), "secret"))
    assert accepted is False
    assert written == b""


def test_connect_returns_false_when_vnc_authentication_is_rejected() -> None:
    """A full ``connect`` over TCP reports failure when the server rejects the DES response, and sends the expected bytes."""

    async def scenario() -> tuple[bool, bool, bool, bytes]:
        """Connect to a loopback listener that rejects the password.

        Returns:
            tuple[bool, bool, bool, bytes]: The connect result, the client's connected flag, whether no framebuffer was
            allocated, and the bytes the client sent.
        """
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client = RFBClient()
        accepted_socket: socket.socket | None = None
        try:
            listener.bind((_LOOPBACK, 0))
            listener.listen(1)
            listener.settimeout(0.0)
            port: int = listener.getsockname()[1]
            loop = asyncio.get_running_loop()
            attempt = asyncio.ensure_future(client.connect(_LOOPBACK, port, timeout=_WAIT_S, password=_AUTH_PASSWORD))
            accepted_socket, _ = await asyncio.wait_for(loop.sock_accept(listener), _WAIT_S)
            await loop.sock_sendall(
                accepted_socket,
                _RFB_VERSION + bytes((1, 2)) + _AUTH_CHALLENGE + struct.pack("!I", 1),
            )
            connected = await asyncio.wait_for(attempt, _WAIT_S)
            await client.disconnect()
            received = bytearray()
            while True:
                piece = await asyncio.wait_for(loop.sock_recv(accepted_socket, 4096), _WAIT_S)
                if not piece:
                    break
                received += piece
            return connected, client.connected, client.framebuffer is None, bytes(received)
        finally:
            if accepted_socket is not None:
                accepted_socket.close()
            listener.close()
            await client.disconnect()

    connected, still_connected, no_framebuffer, received = asyncio.run(scenario())
    assert connected is False
    assert still_connected is False
    assert no_framebuffer
    assert received == _RFB_VERSION + bytes((2,)) + _AUTH_RESPONSE


@pytest.mark.parametrize(
    ("msg_type", "body", "handled"),
    [
        pytest.param(2, b"", True, id="bell"),
        pytest.param(3, b"\x00\x00\x00" + struct.pack("!I", 0), True, id="cut-text-empty"),
        pytest.param(3, b"\x00\x00\x00" + struct.pack("!I", 3) + b"abc", True, id="cut-text-with-text"),
        pytest.param(9, b"", False, id="unknown-type"),
    ],
)
def test_message_bodies_are_consumed_exactly_and_unknown_types_are_reported(msg_type: int, body: bytes, *, handled: bool) -> None:
    """Bell and cut-text messages are handled and consume exactly their body, and an unknown type is reported unhandled.

    Args:
        msg_type: Server message type byte.
        body: Bytes that follow the type byte.
        handled: Expected result of the body reader.
    """

    async def scenario(rig: _Rig) -> tuple[bool, bytes]:
        """Read one message body followed by a marker byte.

        Args:
            rig: Wired client.

        Returns:
            tuple[bool, bytes]: The reader result and the next unread byte.
        """
        rig.peer.sendall(body + _SENTINEL)
        result = await _priv(rig.client, "_read_message_body")(rig.reader, msg_type)
        return result, await _next_byte(rig)

    result, following = _drive(scenario)
    assert result is handled
    assert following == _SENTINEL


def test_set_colour_map_entries_message_is_consumed_exactly() -> None:
    """A SetColourMapEntries message is its 5-byte header followed by six bytes per colour, and nothing more is consumed.

    RFC 6143 section 7.6.2: after the type byte come one padding byte, a 2-byte first-colour, a 2-byte number-of-colours and then
    ``number-of-colours`` entries of 6 bytes. The next byte after those is the next message.
    """
    header = b"\x00" + struct.pack("!HH", 0, 1)
    entry = struct.pack("!HHH", 0, 0x1111, 0x2222)

    async def scenario(rig: _Rig) -> tuple[bool, bytes]:
        """Read one SetColourMapEntries body followed by a marker byte.

        Args:
            rig: Wired client.

        Returns:
            tuple[bool, bytes]: The reader result and the next unread byte.
        """
        rig.peer.sendall(header + entry + _SENTINEL)
        result = await _priv(rig.client, "_read_message_body")(rig.reader, 1)
        return result, await _next_byte(rig)

    result, following = _drive(scenario)
    assert result is True
    assert following == _SENTINEL


def test_handle_server_message_marks_the_client_disconnected_when_the_server_closes() -> None:
    """End of stream in front of a message type byte clears the connected flag and reports no message."""

    async def scenario(rig: _Rig) -> tuple[bool, bool]:
        """Close the server side and let the client poll for a message.

        Args:
            rig: Wired, connected client.

        Returns:
            tuple[bool, bool]: The poll result and the client's connected flag afterwards.
        """
        rig.peer.close()
        assert await asyncio.wait_for(rig.reader.read(1), _WAIT_S) == b""
        handled = await rig.client.handle_server_message()
        return handled, rig.client.connected

    handled, still_connected = _drive(scenario, connected=True)
    assert handled is False
    assert still_connected is False


def test_handle_server_message_marks_the_client_disconnected_when_the_connection_is_reset() -> None:
    """A connection reset by the server clears the connected flag and reports no message."""

    async def scenario(rig: _Rig) -> tuple[bool, bool, bool]:
        """Abort the server side with a reset and let the client poll for a message.

        Args:
            rig: Wired, connected client.

        Returns:
            tuple[bool, bool, bool]: Whether the reset reached the reader, the poll result and the connected flag afterwards.
        """
        rig.peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("HH", 1, 0))
        rig.peer.close()
        reset_seen = False
        try:
            await asyncio.wait_for(rig.reader.read(1), _WAIT_S)
        except ConnectionError:
            reset_seen = True
        handled = await rig.client.handle_server_message()
        return reset_seen, handled, rig.client.connected

    reset_seen, handled, still_connected = _drive(scenario, connected=True)
    assert reset_seen
    assert handled is False
    assert still_connected is False


def test_framebuffer_update_without_a_framebuffer_consumes_nothing() -> None:
    """A FramebufferUpdate arriving before any framebuffer exists is left unread."""

    async def scenario(rig: _Rig) -> bytes:
        """Offer an update header to a client that has no framebuffer.

        Args:
            rig: Wired client without a framebuffer.

        Returns:
            bytes: The three bytes still unread afterwards.
        """
        rig.peer.sendall(b"\x00\x00\x01")
        await _priv(rig.client, "_handle_framebuffer_update")()
        return await asyncio.wait_for(rig.reader.readexactly(3), _WAIT_S)

    assert _drive(scenario) == b"\x00\x00\x01"


@pytest.mark.parametrize(
    ("method", "args", "expected"),
    [
        pytest.param("_handle_framebuffer_update", (), None, id="framebuffer-update"),
        pytest.param("_handle_copy_rect", (0, 0, 1, 1), None, id="copy-rect"),
        pytest.param("_handle_rre_rect", (0, 0, 1, 1), None, id="rre"),
        pytest.param("_handle_hextile_rect", (0, 0, 1, 1), None, id="hextile"),
        pytest.param("_decode_hextile_tile", (0, 0, 1, 1, b"back", b"fore"), (b"back", b"fore"), id="hextile-tile"),
        pytest.param("_handle_zrle_rect", (0, 0, 1, 1), None, id="zrle"),
        pytest.param("_handle_tight_rect", (0, 0, 1, 1), None, id="tight"),
        pytest.param("_handle_tight_basic", (0, 0, 0, 1, 1), None, id="tight-basic"),
        pytest.param("_read_tight_compact_length", (), 0, id="tight-length"),
        pytest.param("_read_raw_pixels", (4,), None, id="raw-pixels"),
    ],
)
def test_decoders_do_nothing_without_a_connection(method: str, args: tuple[object, ...], expected: object) -> None:
    """Every decoder returns quietly when the client has no reader, leaving state untouched.

    Args:
        method: Name of the decoder method.
        args: Arguments passed to it.
        expected: Expected return value.
    """
    client = RFBClient()

    async def scenario() -> object:
        """Run the decoder on the unconnected client.

        Returns:
            object: The decoder's return value.
        """
        return await _priv(client, method)(*args)

    assert asyncio.run(scenario()) == expected
    assert client.framebuffer is None
    assert not client.take_dirty_flag()


def test_raw_rectangle_cut_short_by_the_server_paints_nothing() -> None:
    """A raw rectangle whose pixel data ends early is dropped whole instead of being half applied."""

    async def scenario(rig: _Rig) -> tuple[list[_Rgb], list[_Rgb], bool]:
        """Send half of a 2x2 raw rectangle and close the connection.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            tuple[list[_Rgb], list[_Rgb], bool]: Pixels before, pixels after and the dirty flag.
        """
        _seed(rig.client)
        before = _pixels(rig.client)
        rig.peer.sendall(bytes(8))
        rig.peer.close()
        await _priv(rig.client, "_handle_raw_rect")(0, 0, 2, 2)
        return before, _pixels(rig.client), rig.client.take_dirty_flag()

    before, after, dirty = _drive(scenario, width=4, height=4)
    assert after == before
    assert dirty is False


@pytest.mark.parametrize("encoding", [-239, 99], ids=["cursor-pseudo-encoding", "unassigned"])
def test_unsupported_encoding_leaves_the_framebuffer_untouched(encoding: int) -> None:
    """A rectangle in an encoding the client does not decode paints nothing and marks nothing dirty.

    Args:
        encoding: Encoding identifier the client does not implement.
    """

    async def scenario(rig: _Rig) -> tuple[list[_Rgb], list[_Rgb], bool]:
        """Dispatch a rectangle in the unsupported encoding.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            tuple[list[_Rgb], list[_Rgb], bool]: Pixels before, pixels after and the dirty flag.
        """
        _seed(rig.client)
        before = _pixels(rig.client)
        await _priv(rig.client, "_dispatch_rect_encoding")(encoding, 0, 0, 2, 2)
        return before, _pixels(rig.client), rig.client.take_dirty_flag()

    before, after, dirty = _drive(scenario, width=4, height=4)
    assert after == before
    assert dirty is False


def test_apply_raw_rect_clips_rectangles_that_leave_the_framebuffer() -> None:
    """Rows above, below and columns right of the framebuffer are skipped while the visible part lands in the right place."""

    def source_pixel(row: int, col: int) -> bytes:
        """Build the source pixel for one row and column of the rectangle.

        Args:
            row: Source row.
            col: Source column.

        Returns:
            bytes: The pixel in blue, green, red, pad order.
        """
        return _bgrx(20 + 10 * row + col, 100 + 10 * row + col, 150 + 10 * row + col)

    data = b"".join(source_pixel(row, col) for row in range(3) for col in range(2))
    client = _client_with_framebuffer(4, 4)
    client.apply_raw_rect(3, -1, 2, 3, data)
    assert _rgb_at(client, 3, 0) == (30, 110, 160)
    assert _rgb_at(client, 3, 1) == (40, 120, 170)
    assert _rgb_at(client, 3, 2) == _BLACK
    assert _rgb_at(client, 2, 0) == _BLACK

    low = _client_with_framebuffer(4, 4)
    low.apply_raw_rect(0, 3, 2, 3, data)
    assert _rgb_at(low, 0, 3) == (20, 100, 150)
    assert _rgb_at(low, 1, 3) == (21, 101, 151)
    assert _rgb_at(low, 0, 2) == _BLACK

    off_right = _client_with_framebuffer(4, 4)
    off_right.apply_raw_rect(4, 0, 2, 3, data)
    empty = _client_with_framebuffer(4, 4)
    empty.apply_raw_rect(0, 0, 0, 3, data)
    assert _pixels(off_right) == [_BLACK] * 16
    assert _pixels(empty) == [_BLACK] * 16


def test_fill_rect_paints_exactly_the_rectangle_and_pads_a_short_pixel() -> None:
    """A fill covers only its rectangle, and a three-byte pixel is padded with a zero fourth byte."""
    client = _client_with_framebuffer(6, 4)
    client.fill_rect(1, 1, 3, 2, _bgrx(200, 100, 50))
    inside = [_rgb_at(client, x, y) for x in range(1, 4) for y in range(1, 3)]
    assert inside == [(200, 100, 50)] * 6
    assert _rgb_at(client, 0, 1) == _BLACK
    assert _rgb_at(client, 4, 1) == _BLACK
    assert _rgb_at(client, 1, 3) == _BLACK

    client.fill_rect(0, 0, 2, 1, bytes((1, 2, 3)))
    assert _rgb_at(client, 0, 0) == (3, 2, 1)
    assert _rgb_at(client, 1, 0) == (3, 2, 1)

    bare = RFBClient()
    bare.fill_rect(0, 0, 2, 2, _bgrx(1, 2, 3))
    assert bare.framebuffer is None
    before = _pixels(client)
    client.fill_rect(0, 0, 0, 2, _bgrx(9, 9, 9))
    client.fill_rect(0, 0, 2, 0, _bgrx(9, 9, 9))
    assert _pixels(client) == before


def test_apply_copy_rect_copies_a_disjoint_block() -> None:
    """A block is copied to its destination and the pixels around the destination keep their values."""
    client = _client_with_framebuffer(8, 4)
    _seed(client)
    client.apply_copy_rect(1, 2, 5, 0, 2, 2)
    for col in range(2):
        for row in range(2):
            assert _rgb_at(client, 5 + col, row) == _seed_rgb(1 + col, 2 + row)
    assert _rgb_at(client, 4, 0) == _seed_rgb(4, 0)
    assert _rgb_at(client, 7, 1) == _seed_rgb(7, 1)
    assert _rgb_at(client, 5, 2) == _seed_rgb(5, 2)


def test_apply_copy_rect_reads_the_whole_source_before_writing_when_blocks_overlap() -> None:
    """Overlapping source and destination give the same result as copying through a separate buffer."""
    client = _client_with_framebuffer(8, 8)
    _seed(client)
    client.apply_copy_rect(0, 0, 1, 1, 3, 3)
    for col in range(3):
        for row in range(3):
            assert _rgb_at(client, 1 + col, 1 + row) == _seed_rgb(col, row)
    assert _rgb_at(client, 0, 0) == _seed_rgb(0, 0)
    assert _rgb_at(client, 4, 4) == _seed_rgb(4, 4)


def test_apply_copy_rect_clips_sources_beyond_the_framebuffer() -> None:
    """The in-bounds part of a source that hangs off the edge is copied and nothing outside the destination changes."""
    client = _client_with_framebuffer(8, 4)
    _seed(client)
    client.apply_copy_rect(6, 3, 0, 0, 2, 2)
    assert _rgb_at(client, 0, 0) == _seed_rgb(6, 3)
    assert _rgb_at(client, 1, 0) == _seed_rgb(7, 3)
    outside_destination = [(x, y) for y in range(4) for x in range(8) if not (x < 2 and y < 2)]
    assert all(_rgb_at(client, x, y) == _seed_rgb(x, y) for x, y in outside_destination)

    far = _client_with_framebuffer(8, 4)
    _seed(far)
    far.apply_copy_rect(20, 0, 0, 0, 2, 2)
    assert all(_rgb_at(far, x, y) == _seed_rgb(x, y) for x, y in outside_destination)


def test_apply_copy_rect_ignores_missing_framebuffer_and_empty_blocks() -> None:
    """Copying with no framebuffer does nothing, and empty blocks leave the framebuffer unchanged."""
    bare = RFBClient()
    bare.apply_copy_rect(0, 0, 1, 1, 2, 2)
    assert bare.framebuffer is None
    client = _client_with_framebuffer(4, 4)
    _seed(client)
    before = _pixels(client)
    client.apply_copy_rect(0, 0, 1, 1, 0, 2)
    client.apply_copy_rect(0, 0, 1, 1, 2, 0)
    assert _pixels(client) == before


def test_copy_rect_encoding_reads_the_source_position_and_marks_the_frame_dirty() -> None:
    """A CopyRect rectangle carries a source x and y; the client copies that block and flags the frame as changed."""

    async def scenario(rig: _Rig) -> tuple[list[_Rgb], bool, bytes]:
        """Dispatch a CopyRect rectangle for a 2x2 block.

        Args:
            rig: Wired client with a seeded framebuffer.

        Returns:
            tuple[list[_Rgb], bool, bytes]: The destination pixels, the dirty flag and the next unread byte.
        """
        _seed(rig.client)
        rig.peer.sendall(struct.pack("!HH", 1, 2) + _SENTINEL)
        await _priv(rig.client, "_dispatch_rect_encoding")(_ENCODING_COPY_RECT, 5, 1, 2, 2)
        destination = [_rgb_at(rig.client, 5 + col, 1 + row) for col in range(2) for row in range(2)]
        return destination, rig.client.take_dirty_flag(), await _next_byte(rig)

    destination, dirty, following = _drive(scenario, width=8, height=4)
    assert destination == [_seed_rgb(1 + col, 2 + row) for col in range(2) for row in range(2)]
    assert dirty
    assert following == _SENTINEL


def test_rre_encoding_paints_background_then_each_subrectangle() -> None:
    """An RRE rectangle fills the background and paints each colored subrectangle at its offset inside the rectangle."""
    background = _bgrx(30, 20, 10)
    first = _bgrx(50, 100, 200) + struct.pack("!HHHH", 1, 1, 2, 2)
    second = _bgrx(3, 2, 1) + struct.pack("!HHHH", 5, 3, 1, 1)
    stream = struct.pack("!I", 2) + background + first + second + _SENTINEL

    async def scenario(rig: _Rig) -> tuple[list[_Rgb], bool, bytes]:
        """Dispatch an RRE rectangle with two subrectangles.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            tuple[list[_Rgb], bool, bytes]: Sampled pixels, the dirty flag and the next unread byte.
        """
        rig.peer.sendall(stream)
        await _priv(rig.client, "_dispatch_rect_encoding")(_ENCODING_RRE, 2, 1, 6, 4)
        samples = [(2, 1), (3, 2), (4, 3), (5, 3), (7, 4), (8, 1), (2, 5)]
        return [_rgb_at(rig.client, x, y) for x, y in samples], rig.client.take_dirty_flag(), await _next_byte(rig)

    pixels, dirty, following = _drive(scenario, width=10, height=8)
    assert pixels == [(30, 20, 10), (50, 100, 200), (50, 100, 200), (30, 20, 10), (3, 2, 1), _BLACK, _BLACK]
    assert dirty
    assert following == _SENTINEL


def test_rre_encoding_without_subrectangles_fills_the_background_only() -> None:
    """An RRE rectangle with zero subrectangles is just a background fill of the whole rectangle."""

    async def scenario(rig: _Rig) -> tuple[list[_Rgb], bytes]:
        """Dispatch an RRE rectangle with an empty subrectangle list.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            tuple[list[_Rgb], bytes]: Sampled pixels and the next unread byte.
        """
        rig.peer.sendall(struct.pack("!I", 0) + _bgrx(9, 8, 7) + _SENTINEL)
        await _priv(rig.client, "_dispatch_rect_encoding")(_ENCODING_RRE, 1, 1, 3, 2)
        samples = [(1, 1), (3, 2), (0, 1), (4, 1)]
        return [_rgb_at(rig.client, x, y) for x, y in samples], await _next_byte(rig)

    pixels, following = _drive(scenario, width=6, height=4)
    assert pixels == [(9, 8, 7), (9, 8, 7), _BLACK, _BLACK]
    assert following == _SENTINEL


def test_apply_rre_rect_stops_at_a_truncated_subrectangle_list() -> None:
    """When the data holds fewer subrectangles than announced the complete ones are drawn and the rest is ignored."""
    client = _client_with_framebuffer(8, 8)
    complete = _bgrx(200, 150, 100) + struct.pack("!HHHH", 1, 1, 1, 1)
    announced_but_missing = 2
    client.apply_rre_rect(0, 0, 4, 4, _bgrx(1, 2, 3), announced_but_missing, complete)
    assert _rgb_at(client, 0, 0) == (1, 2, 3)
    assert _rgb_at(client, 1, 1) == (200, 150, 100)
    assert _rgb_at(client, 2, 2) == (1, 2, 3)
    assert _rgb_at(client, 4, 4) == _BLACK


def test_hextile_encoding_carries_colors_across_tiles_and_applies_every_tile_kind() -> None:
    """A rectangle of four tiles exercises background and foreground carry-over, plain, colored and raw tiles."""
    background = _bgrx(30, 20, 10)
    foreground = _bgrx(50, 100, 200)
    tile_one = bytes((0x0E,)) + background + foreground + bytes((2,)) + bytes((0x00, 0x11, 0xF0, 0x03))
    tile_two = bytes((0x08, 1, 0x11, 0x00))
    tile_three = bytes((0x18, 1)) + _bgrx(9, 8, 7) + bytes((0x00, 0x00))
    tile_four = bytes((0x01,)) + _bgrx(60, 61, 62) + _bgrx(63, 64, 65)
    stream = tile_one + tile_two + tile_three + tile_four + _SENTINEL

    async def scenario(rig: _Rig) -> tuple[dict[tuple[int, int], _Rgb], bool, bytes]:
        """Dispatch a Hextile rectangle covering four tiles.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            tuple[dict[tuple[int, int], _Rgb], bool, bytes]: Sampled pixels by position, the dirty flag and the next unread byte.
        """
        rig.peer.sendall(stream)
        await _priv(rig.client, "_dispatch_rect_encoding")(_ENCODING_HEXTILE, 2, 1, 18, 17)
        points = [
            (2, 1),
            (3, 2),
            (4, 1),
            (17, 1),
            (17, 4),
            (17, 5),
            (18, 1),
            (19, 2),
            (18, 2),
            (2, 17),
            (3, 17),
            (18, 17),
            (19, 17),
            (1, 1),
        ]
        return {point: _rgb_at(rig.client, *point) for point in points}, rig.client.take_dirty_flag(), await _next_byte(rig)

    sampled, dirty, following = _drive(scenario, width=24, height=20)
    assert sampled == {
        (2, 1): (50, 100, 200),
        (3, 2): (50, 100, 200),
        (4, 1): (30, 20, 10),
        (17, 1): (50, 100, 200),
        (17, 4): (50, 100, 200),
        (17, 5): (30, 20, 10),
        (18, 1): (30, 20, 10),
        (19, 2): (50, 100, 200),
        (18, 2): (30, 20, 10),
        (2, 17): (9, 8, 7),
        (3, 17): (30, 20, 10),
        (18, 17): (60, 61, 62),
        (19, 17): (63, 64, 65),
        (1, 1): _BLACK,
    }
    assert dirty
    assert following == _SENTINEL


def test_hextile_encoding_reuses_the_background_for_plain_and_empty_subrectangle_tiles() -> None:
    """Tiles that specify no color use the carried background, including tiles with a zero subrectangle count."""
    stream = bytes((0x02,)) + _bgrx(5, 6, 7) + bytes((0x00,)) + bytes((0x08, 0x00)) + _SENTINEL

    async def scenario(rig: _Rig) -> tuple[list[_Rgb], bytes]:
        """Dispatch a one-row Hextile rectangle of three tiles.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            tuple[list[_Rgb], bytes]: Sampled pixels and the next unread byte.
        """
        rig.peer.sendall(stream)
        await _priv(rig.client, "_dispatch_rect_encoding")(_ENCODING_HEXTILE, 0, 0, 48, 1)
        samples = [(0, 0), (15, 0), (16, 0), (31, 0), (32, 0), (47, 0), (0, 1)]
        return [_rgb_at(rig.client, x, y) for x, y in samples], await _next_byte(rig)

    pixels, following = _drive(scenario, width=48, height=2)
    assert pixels == [(5, 6, 7)] * 6 + [_BLACK]
    assert following == _SENTINEL


def test_hextile_background_only_tile_marks_the_framebuffer_dirty() -> None:
    """A rectangle made only of background-filled tiles changes the framebuffer, so the frame must be flagged for publishing."""

    async def scenario(rig: _Rig) -> tuple[_Rgb, _Rgb, bool]:
        """Dispatch a single background-only Hextile tile.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            tuple[_Rgb, _Rgb, bool]: The first pixel, the last pixel and the dirty flag.
        """
        rig.peer.sendall(bytes((0x02,)) + _bgrx(5, 6, 7))
        await _priv(rig.client, "_handle_hextile_rect")(0, 0, 16, 16)
        return _rgb_at(rig.client, 0, 0), _rgb_at(rig.client, 15, 15), rig.client.take_dirty_flag()

    first, last, dirty = _drive(scenario, width=16, height=16)
    assert first == (5, 6, 7)
    assert last == (5, 6, 7)
    assert dirty


def test_apply_hextile_subrects_stops_at_truncated_data_and_decodes_colored_entries() -> None:
    """Plain entries use the foreground, colored entries carry their own color, and missing entries are ignored."""
    client = _client_with_framebuffer(12, 8)
    foreground = _bgrx(200, 100, 50)
    plain = bytes((0x00, 0x00, 0x11, 0x11))
    client.apply_hextile_subrects(4, 2, 3, plain, foreground, coloured=False)
    assert _rgb_at(client, 4, 2) == (200, 100, 50)
    assert [_rgb_at(client, x, y) for x in (5, 6) for y in (3, 4)] == [(200, 100, 50)] * 4
    assert _rgb_at(client, 7, 2) == _BLACK

    coloured_client = _client_with_framebuffer(12, 8)
    coloured = _bgrx(1, 2, 3) + bytes((0x21, 0x10))
    coloured_client.apply_hextile_subrects(0, 0, 2, coloured, foreground, coloured=True)
    assert [_rgb_at(coloured_client, x, 1) for x in (2, 3)] == [(1, 2, 3)] * 2
    assert _rgb_at(coloured_client, 2, 2) == _BLACK


def test_zrle_encoding_decompresses_and_paints_every_64_pixel_tile() -> None:
    """A rectangle larger than one tile is cut into 64x64 tiles taken in row-major order from the decompressed payload."""
    grays = (0x10, 0x30, 0x50, 0x70)
    payload = b"".join(bytes((1, gray, gray, gray)) for gray in grays)
    compressed = zlib.compress(payload)
    stream = struct.pack("!I", len(compressed)) + compressed + _SENTINEL

    async def scenario(rig: _Rig) -> tuple[list[_Rgb], bool, bytes]:
        """Dispatch a 70x65 ZRLE rectangle made of four solid tiles.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            tuple[list[_Rgb], bool, bytes]: Sampled pixels, the dirty flag and the next unread byte.
        """
        rig.peer.sendall(stream)
        await _priv(rig.client, "_dispatch_rect_encoding")(_ENCODING_ZRLE, 5, 3, 70, 65)
        samples = [(5, 3), (68, 66), (69, 3), (74, 66), (5, 67), (68, 67), (69, 67), (74, 67), (4, 3), (75, 3), (5, 68)]
        return [_rgb_at(rig.client, x, y) for x, y in samples], rig.client.take_dirty_flag(), await _next_byte(rig)

    pixels, dirty, following = _drive(scenario, width=80, height=70)
    expected_gray = [0x10, 0x10, 0x30, 0x30, 0x50, 0x50, 0x70, 0x70]
    assert pixels == [(gray, gray, gray) for gray in expected_gray] + [_BLACK] * 3
    assert dirty
    assert following == _SENTINEL


def test_zrle_decompressor_state_carries_over_between_rectangles() -> None:
    """Both rectangles belong to one zlib stream, so the second only decodes with the decompressor kept from the first."""
    compressor = zlib.compressobj()
    chunk_one = compressor.compress(bytes((1, 0x22, 0x22, 0x22))) + compressor.flush(zlib.Z_SYNC_FLUSH)
    chunk_two = compressor.compress(bytes((1, 0x44, 0x44, 0x44))) + compressor.flush(zlib.Z_SYNC_FLUSH)
    stream = struct.pack("!I", len(chunk_one)) + chunk_one + struct.pack("!I", len(chunk_two)) + chunk_two

    async def scenario(rig: _Rig) -> tuple[_Rgb, _Rgb]:
        """Dispatch two one-pixel ZRLE rectangles from the same compressed stream.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            tuple[_Rgb, _Rgb]: The two decoded pixels.
        """
        rig.peer.sendall(stream)
        dispatch = _priv(rig.client, "_dispatch_rect_encoding")
        await dispatch(_ENCODING_ZRLE, 0, 0, 1, 1)
        await dispatch(_ENCODING_ZRLE, 1, 0, 1, 1)
        return _rgb_at(rig.client, 0, 0), _rgb_at(rig.client, 1, 0)

    first, second = _drive(scenario, width=4, height=2)
    assert first == (0x22, 0x22, 0x22)
    assert second == (0x44, 0x44, 0x44)


def test_zrle_rectangle_with_corrupt_compressed_data_paints_nothing() -> None:
    """Compressed data that is not a zlib stream is consumed and dropped without painting or marking the frame dirty."""
    garbage = b"not zlib"

    async def scenario(rig: _Rig) -> tuple[list[_Rgb], list[_Rgb], bool, bytes]:
        """Dispatch a ZRLE rectangle whose payload is garbage.

        Args:
            rig: Wired client with a seeded framebuffer.

        Returns:
            tuple[list[_Rgb], list[_Rgb], bool, bytes]: Pixels before, pixels after, the dirty flag and the next unread byte.
        """
        _seed(rig.client)
        before = _pixels(rig.client)
        rig.peer.sendall(struct.pack("!I", len(garbage)) + garbage + _SENTINEL)
        await _priv(rig.client, "_dispatch_rect_encoding")(_ENCODING_ZRLE, 0, 0, 2, 2)
        return before, _pixels(rig.client), rig.client.take_dirty_flag(), await _next_byte(rig)

    before, after, dirty, following = _drive(scenario, width=4, height=4)
    assert after == before
    assert dirty is False
    assert following == _SENTINEL


def test_apply_zrle_rect_stops_when_the_payload_runs_out_of_tiles() -> None:
    """A payload holding fewer tiles than the rectangle needs paints the tiles it has and then stops."""
    client = _client_with_framebuffer(70, 2, (9, 9, 9))
    client.apply_zrle_rect(0, 0, 70, 1, bytes((1, 1, 1, 1)))
    assert _rgb_at(client, 0, 0) == (1, 1, 1)
    assert _rgb_at(client, 63, 0) == (1, 1, 1)
    assert _rgb_at(client, 64, 0) == (9, 9, 9)
    assert _rgb_at(client, 69, 0) == (9, 9, 9)


def test_tight_fill_paints_one_color_and_resets_the_flagged_streams() -> None:
    """A Tight fill rectangle paints its red, green, blue color, and the low four control bits reset the matching zlib streams."""

    async def scenario(rig: _Rig) -> tuple[list[_Rgb], bool, list[bool], bytes]:
        """Handle a fill rectangle whose control byte resets streams 0 and 2.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            tuple[list[_Rgb], bool, list[bool], bytes]: Sampled pixels, the dirty flag, which streams survive and the next unread byte.
        """
        _set_priv(rig.client, "_tight_zlib_streams", [zlib.decompressobj() for _ in range(4)])
        rig.peer.sendall(bytes((0x85, 200, 100, 50)) + _SENTINEL)
        await _priv(rig.client, "_handle_tight_rect")(2, 1, 3, 2)
        samples = [(2, 1), (4, 2), (1, 1), (5, 1), (2, 3)]
        survivors = [stream is not None for stream in _priv(rig.client, "_tight_zlib_streams")]
        return [_rgb_at(rig.client, x, y) for x, y in samples], rig.client.take_dirty_flag(), survivors, await _next_byte(rig)

    pixels, dirty, survivors, following = _drive(scenario, width=8, height=6)
    assert pixels == [(200, 100, 50), (200, 100, 50), _BLACK, _BLACK, _BLACK]
    assert dirty
    assert survivors == [False, True, False, True]
    assert following == _SENTINEL


def test_tight_encoding_dispatches_to_the_decoder_when_available() -> None:
    """With Tight support available the dispatcher hands a Tight rectangle to its decoder."""

    async def scenario(rig: _Rig) -> list[_Rgb]:
        """Dispatch a Tight fill rectangle with the availability flag set.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            list[_Rgb]: Sampled pixels.
        """
        rig.peer.sendall(bytes((0x80, 200, 100, 50)))
        with _tight_flag(value=True):
            await _priv(rig.client, "_dispatch_rect_encoding")(_ENCODING_TIGHT, 1, 1, 2, 2)
        return [_rgb_at(rig.client, x, y) for x, y in [(1, 1), (2, 2), (3, 3)]]

    assert _drive(scenario, width=4, height=4) == [(200, 100, 50), (200, 100, 50), _BLACK]


def test_tight_encoding_paints_nothing_when_unavailable() -> None:
    """With Tight support unavailable the dispatcher skips Tight rectangles without painting or flagging the frame."""

    async def scenario(rig: _Rig) -> tuple[list[_Rgb], list[_Rgb], bool]:
        """Dispatch a Tight rectangle with the availability flag cleared.

        Args:
            rig: Wired client with a seeded framebuffer.

        Returns:
            tuple[list[_Rgb], list[_Rgb], bool]: Pixels before, pixels after and the dirty flag.
        """
        _seed(rig.client)
        before = _pixels(rig.client)
        with _tight_flag(value=False):
            await _priv(rig.client, "_dispatch_rect_encoding")(_ENCODING_TIGHT, 0, 0, 2, 2)
        return before, _pixels(rig.client), rig.client.take_dirty_flag()

    before, after, dirty = _drive(scenario, width=4, height=4)
    assert after == before
    assert dirty is False


@pytest.mark.parametrize(
    ("available", "jpeg"),
    [pytest.param(False, b"abcde", id="unavailable-with-data"), pytest.param(True, b"", id="available-without-data")],
)
def test_tight_jpeg_rectangle_keeps_the_stream_in_sync_when_nothing_can_be_decoded(jpeg: bytes, *, available: bool) -> None:
    """A Tight JPEG rectangle without usable data is read to its end and paints nothing.

    Args:
        jpeg: JPEG payload carried by the rectangle.
        available: Value of the Pillow-availability flag.
    """

    async def scenario(rig: _Rig) -> tuple[list[_Rgb], list[_Rgb], bool, bytes]:
        """Handle a JPEG rectangle followed by a marker byte.

        Args:
            rig: Wired client with a seeded framebuffer.

        Returns:
            tuple[list[_Rgb], list[_Rgb], bool, bytes]: Pixels before, pixels after, the dirty flag and the next unread byte.
        """
        _seed(rig.client)
        before = _pixels(rig.client)
        rig.peer.sendall(bytes((0x90,)) + _compact_length(len(jpeg)) + jpeg + _SENTINEL)
        with _tight_flag(value=available):
            await _priv(rig.client, "_handle_tight_rect")(0, 0, 2, 2)
        return before, _pixels(rig.client), rig.client.take_dirty_flag(), await _next_byte(rig)

    before, after, dirty, following = _drive(scenario, width=4, height=4)
    assert after == before
    assert dirty is False
    assert following == _SENTINEL


def test_tight_copy_filter_reads_small_rectangles_uncompressed() -> None:
    """A rectangle below twelve bytes of pixel data is sent raw as red, green, blue triples."""

    async def scenario(rig: _Rig) -> tuple[_Rgb, _Rgb, _Rgb, bool, bytes]:
        """Handle a 2x1 basic rectangle with the copy filter.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            tuple[_Rgb, _Rgb, _Rgb, bool, bytes]: Two painted pixels, one untouched pixel, the dirty flag and the next unread byte.
        """
        rig.peer.sendall(bytes((0x00, 200, 100, 50, 10, 20, 30)) + _SENTINEL)
        await _priv(rig.client, "_handle_tight_rect")(1, 1, 2, 1)
        return (
            _rgb_at(rig.client, 1, 1),
            _rgb_at(rig.client, 2, 1),
            _rgb_at(rig.client, 3, 1),
            rig.client.take_dirty_flag(),
            await _next_byte(rig),
        )

    first, second, beyond, dirty, following = _drive(scenario, width=4, height=2)
    assert first == (200, 100, 50)
    assert second == (10, 20, 30)
    assert beyond == _BLACK
    assert dirty
    assert following == _SENTINEL


def _tight_row(row: int) -> bytes:
    """Build four red, green, blue pixels for one row of the compressed Tight test.

    Args:
        row: Row number, 0 to 2.

    Returns:
        bytes: Twelve bytes of pixel data.
    """
    pixels = bytearray()
    for column in range(4):
        base = 40 * row + 10 * column
        pixels += bytes((base + 5, base + 6, base + 7))
    return bytes(pixels)


def test_tight_zlib_stream_persists_between_rectangles_until_reset() -> None:
    """The second rectangle only decodes with the decompressor kept from the first, and a reset bit starts a fresh stream."""
    shared = zlib.compressobj()
    chunk_zero = shared.compress(_tight_row(0)) + shared.flush(zlib.Z_SYNC_FLUSH)
    chunk_one = shared.compress(_tight_row(1)) + shared.flush(zlib.Z_SYNC_FLUSH)
    chunk_two = zlib.compress(_tight_row(2))
    stream = (
        bytes((0x10,))
        + _compact_length(len(chunk_zero))
        + chunk_zero
        + bytes((0x10,))
        + _compact_length(len(chunk_one))
        + chunk_one
        + bytes((0x12,))
        + _compact_length(len(chunk_two))
        + chunk_two
        + _SENTINEL
    )

    async def scenario(rig: _Rig) -> tuple[list[bool], list[list[_Rgb]], bytes]:
        """Handle three rectangles that use zlib stream 1.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            tuple[list[bool], list[list[_Rgb]], bytes]: Which streams exist after the first rectangle, the decoded rows and the next
            unread byte.
        """
        rig.peer.sendall(stream)
        handler = _priv(rig.client, "_handle_tight_rect")
        await handler(0, 0, 4, 1)
        existing = [stream_state is not None for stream_state in _priv(rig.client, "_tight_zlib_streams")]
        await handler(0, 1, 4, 1)
        await handler(0, 2, 4, 1)
        rows = [[_rgb_at(rig.client, column, row) for column in range(4)] for row in range(3)]
        return existing, rows, await _next_byte(rig)

    existing, rows, following = _drive(scenario, width=4, height=3)
    assert existing == [False, True, False, False]
    assert rows == [
        [(40 * row + 10 * column + 5, 40 * row + 10 * column + 6, 40 * row + 10 * column + 7) for column in range(4)] for row in range(3)
    ]
    assert following == _SENTINEL


def test_tight_corrupt_zlib_data_paints_nothing() -> None:
    """Compressed pixel data that is not a zlib stream is consumed and dropped without painting or flagging the frame."""
    garbage = b"notzl"

    async def scenario(rig: _Rig) -> tuple[list[_Rgb], list[_Rgb], bool, bytes]:
        """Handle a compressed rectangle whose data is garbage.

        Args:
            rig: Wired client with a seeded framebuffer.

        Returns:
            tuple[list[_Rgb], list[_Rgb], bool, bytes]: Pixels before, pixels after, the dirty flag and the next unread byte.
        """
        _seed(rig.client)
        before = _pixels(rig.client)
        rig.peer.sendall(bytes((0x00,)) + _compact_length(len(garbage)) + garbage + _SENTINEL)
        await _priv(rig.client, "_handle_tight_rect")(0, 0, 4, 1)
        return before, _pixels(rig.client), rig.client.take_dirty_flag(), await _next_byte(rig)

    before, after, dirty, following = _drive(scenario, width=4, height=2)
    assert after == before
    assert dirty is False
    assert following == _SENTINEL


def test_tight_two_color_palette_uses_a_most_significant_bit_first_bitmap() -> None:
    """With a two-entry palette each pixel is one bit, eight to a byte, most significant bit first."""
    palette = bytes((200, 100, 50, 10, 20, 30))
    bitmap = bytes((0xA0, 0x50))

    async def scenario(rig: _Rig) -> tuple[list[list[_Rgb]], bytes]:
        """Handle a 4x2 palette rectangle with two colors.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            tuple[list[list[_Rgb]], bytes]: The decoded rows and the next unread byte.
        """
        rig.peer.sendall(bytes((0x40, 0x01, 0x01)) + palette + bitmap + _SENTINEL)
        await _priv(rig.client, "_handle_tight_rect")(1, 0, 4, 2)
        rows = [[_rgb_at(rig.client, x, y) for x in range(1, 5)] for y in range(2)]
        return rows, await _next_byte(rig)

    rows, following = _drive(scenario, width=6, height=2)
    zero, one = (200, 100, 50), (10, 20, 30)
    assert rows == [[one, zero, one, zero], [zero, one, zero, one]]
    assert following == _SENTINEL


def test_tight_larger_palette_uses_one_compressed_index_byte_per_pixel() -> None:
    """With more than two palette entries each pixel is an index byte, and the index data is zlib compressed."""
    palette = bytes((200, 100, 50, 10, 20, 30, 1, 2, 3))
    indices = bytes((0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2))
    compressed = zlib.compress(indices)

    async def scenario(rig: _Rig) -> tuple[list[_Rgb], bytes]:
        """Handle a 4x3 palette rectangle with three colors on stream 2.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            tuple[list[_Rgb], bytes]: All twelve decoded pixels and the next unread byte.
        """
        rig.peer.sendall(bytes((0x60, 0x01, 0x02)) + palette + _compact_length(len(compressed)) + compressed + _SENTINEL)
        await _priv(rig.client, "_handle_tight_rect")(0, 0, 4, 3)
        return [_rgb_at(rig.client, x, y) for y in range(3) for x in range(4)], await _next_byte(rig)

    pixels, following = _drive(scenario, width=4, height=3)
    colors = [(200, 100, 50), (10, 20, 30), (1, 2, 3)]
    assert pixels == [colors[index] for index in indices]
    assert following == _SENTINEL


@pytest.mark.parametrize("filter_id", [0, 2], ids=["copy", "gradient"])
def test_tight_explicit_filter_without_a_palette_decodes_a_single_pixel(filter_id: int) -> None:
    """An explicit copy or gradient filter byte is read and no palette follows; a gradient's first pixel is stored unchanged.

    Args:
        filter_id: Tight filter identifier sent after the control byte.
    """

    async def scenario(rig: _Rig) -> tuple[_Rgb, bytes]:
        """Handle a 1x1 basic rectangle with an explicit filter byte.

        Args:
            rig: Wired client with a framebuffer.

        Returns:
            tuple[_Rgb, bytes]: The decoded pixel and the next unread byte.
        """
        rig.peer.sendall(bytes((0x40, filter_id, 200, 100, 50)) + _SENTINEL)
        await _priv(rig.client, "_handle_tight_rect")(1, 1, 1, 1)
        return _rgb_at(rig.client, 1, 1), await _next_byte(rig)

    pixel, following = _drive(scenario, width=3, height=3)
    assert pixel == (200, 100, 50)
    assert following == _SENTINEL


@pytest.mark.parametrize("value", [0, 1, 127, 128, 300, 16383, 16384, 65535])
def test_tight_compact_length_decodes_one_two_and_three_byte_forms(value: int) -> None:
    """A compact length is read byte by byte until a byte without the continuation bit, and no further.

    Args:
        value: Length to encode and decode.
    """

    async def scenario(rig: _Rig) -> tuple[int, bytes]:
        """Read one compact length followed by a marker byte.

        Args:
            rig: Wired client.

        Returns:
            tuple[int, bytes]: The decoded length and the next unread byte.
        """
        rig.peer.sendall(_compact_length(value) + _SENTINEL)
        length = await _priv(rig.client, "_read_tight_compact_length")()
        return length, await _next_byte(rig)

    length, following = _drive(scenario)
    assert length == value
    assert following == _SENTINEL


@pytest.mark.parametrize("value", [2097152, 4194303])
def test_tight_compact_length_third_byte_carries_all_eight_bits(value: int) -> None:
    """The third byte of a compact length contributes all eight of its bits, so lengths up to 4194303 decode.

    Args:
        value: Length of two mebibytes or more.
    """

    async def scenario(rig: _Rig) -> int:
        """Read one three-byte compact length.

        Args:
            rig: Wired client.

        Returns:
            int: The decoded length.
        """
        rig.peer.sendall(_compact_length(value))
        return await _priv(rig.client, "_read_tight_compact_length")()

    assert _drive(scenario) == value
