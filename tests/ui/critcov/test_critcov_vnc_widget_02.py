# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the ZRLE and Tight decoders, the pump lifecycle, pop-out and the input forwarding of the VNC widget.

The decoders are fed payloads built here from the RFB definitions (RFC 6143 section 7.7.6 for ZRLE, the Tight filter definitions for
Tight) and the decoded framebuffer is compared with colors worked out by hand. Input forwarding and the server pump run against a real
loopback TCP connection whose peer end is a plain ``socket`` this file owns: the handshake bytes are written to it up front, and the bytes
the widget sends back are parsed with the message lengths the RFB specification defines. A connection that the peer resets with a hard
close is used for the transport error paths.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import time
from itertools import starmap
from typing import TYPE_CHECKING, Any, NamedTuple

import pytest
from PyQt6.QtCore import QEvent, QPointF, Qt
from PyQt6.QtGui import QImage, QKeyEvent, QMouseEvent

from intellicrack.ui.panels import async_bridge as async_bridge_module
from intellicrack.ui.panels.async_bridge import drain_bridge_workers, ensure_loop
from intellicrack.ui.panels.vnc_widget import RFBClient, VNCWidget
from intellicrack.ui.resources.theme_manager import ThemeManager
from tests._helpers.polling import wait_until
from tests.ui.conftest import SignalRecorder


if TYPE_CHECKING:
    from collections.abc import Generator

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_Dynamic = Any

_LOOPBACK: str = "127.0.0.1"
_SOCKET_TIMEOUT_S: float = 10.0
_CONNECT_TIMEOUT_S: float = 5.0
_RECV_SLICE_S: float = 0.1
_RECV_CHUNK: int = 4096
_GATHER_BUDGET_S: float = 10.0
_WAIT_MS: int = 20_000
_PUMP_STOP_TIMEOUT_S: float = 10.0
_RESET_BUDGET_S: float = 10.0
_POLL_INTERVAL_S: float = 0.01

_FB_W: int = 160
_FB_H: int = 120
_WIDGET_W: int = 640
_WIDGET_H: int = 240
_SERVER_NAME: bytes = b"critcov-vnc"
_SERVER_PIXEL_FORMAT: bytes = bytes((32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0))

_HANDSHAKE_PREFIX_LEN: int = 14
_CLIENT_MESSAGE_LENGTHS: dict[int, int] = {0: 20, 3: 10, 4: 8, 5: 6}
_MSG_KEY_EVENT: int = 4
_MSG_POINTER_EVENT: int = 5

_BLACK: tuple[int, int, int] = (0, 0, 0)
_WHITE: tuple[int, int, int] = (255, 255, 255)

_ZRLE_RAW: int = 0
_ZRLE_SOLID: int = 1
_ZRLE_PLAIN_RLE: int = 128
_ZRLE_PALETTE_RLE_BASE: int = 128
_ZRLE_RUN_CONTINUES: int = 255
_ZRLE_TILE: int = 64

_TIGHT_COPY: int = 0
_TIGHT_PALETTE: int = 1
_TIGHT_GRADIENT: int = 2


class _Session(NamedTuple):
    """A connected widget together with the peer end of its TCP connection.

    Attributes:
        widget: Widget that completed the RFB handshake against the peer.
        peer: Socket accepted from the widget's connection, used to read what the widget sends.
        recorder: Recorder of every ``connection_status_changed`` emission of the widget.
        stream: Every byte received from the widget so far, handshake included.
    """

    widget: VNCWidget
    peer: socket.socket
    recorder: SignalRecorder
    stream: bytearray


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


def _make_client(width: int, height: int) -> RFBClient:
    """Build a client that owns a black framebuffer of the given size.

    Args:
        width: Framebuffer width in pixels.
        height: Framebuffer height in pixels.

    Returns:
        RFBClient: Client with an all-black ``Format_RGB32`` framebuffer.
    """
    client = RFBClient()
    framebuffer = QImage(width, height, QImage.Format.Format_RGB32)
    framebuffer.fill(0xFF000000)
    client.framebuffer = framebuffer
    client.width = width
    client.height = height
    return client


def _rgb_at(client: RFBClient, x: int, y: int) -> tuple[int, int, int]:
    """Read one framebuffer pixel as red, green and blue components.

    Args:
        client: Client whose framebuffer is read.
        x: Pixel column.
        y: Pixel row.

    Returns:
        tuple[int, int, int]: Red, green and blue components of the pixel.
    """
    framebuffer = client.framebuffer
    assert framebuffer is not None
    color = framebuffer.pixelColor(x, y)
    return (color.red(), color.green(), color.blue())


def _paint_white(client: RFBClient) -> None:
    """Fill the whole framebuffer of a client with white.

    Args:
        client: Client whose framebuffer is filled.
    """
    client.fill_rect(0, 0, client.width, client.height, bytes((255, 255, 255, 0)))


def _cp(level: int, green: int) -> bytes:
    """Build a 3-byte CPIXEL whose first and last bytes are equal.

    Args:
        level: Value of the first and the last byte.
        green: Value of the middle byte.

    Returns:
        bytes: The three CPIXEL bytes.
    """
    return bytes((level, green, level))


def _sym(level: int, green: int) -> tuple[int, int, int]:
    """Build the color a CPIXEL made by ``_cp`` stands for.

    Args:
        level: Value of the red and the blue component.
        green: Value of the green component.

    Returns:
        tuple[int, int, int]: Red, green and blue components.
    """
    return (level, green, level)


def _pack_rows(rows: list[list[int]], bits: int) -> bytes:
    """Pack palette indices most significant bit first, padding every row to a whole byte.

    Args:
        rows: Palette index of every pixel, one list per row.
        bits: Bits per index: 1, 2 or 4.

    Returns:
        bytes: The packed bit stream.
    """
    out = bytearray()
    for row in rows:
        acc = 0
        used = 0
        for index in row:
            acc = (acc << bits) | index
            used += bits
        pad = (-used) % 8
        acc <<= pad
        out += acc.to_bytes((used + pad) // 8, "big")
    return bytes(out)


def _assert_grid(client: RFBClient, x0: int, y0: int, grid: list[list[tuple[int, int, int]]]) -> None:
    """Assert that a block of the framebuffer holds the expected colors.

    Args:
        client: Client whose framebuffer is read.
        x0: Column of the block's left edge.
        y0: Row of the block's top edge.
        grid: Expected color of every pixel of the block, one list per row.
    """
    for dy, row in enumerate(grid):
        for dx, expected in enumerate(row):
            assert _rgb_at(client, x0 + dx, y0 + dy) == expected, f"pixel ({x0 + dx},{y0 + dy})"


def test_zrle_stops_at_the_first_tile_the_payload_does_not_cover() -> None:
    """A payload that ends after the first tile leaves the second tile untouched."""
    client = _make_client(2 * _ZRLE_TILE, 1)
    payload = bytes([_ZRLE_SOLID]) + _cp(0x40, 0x80)
    client.apply_zrle_rect(0, 0, 2 * _ZRLE_TILE, 1, payload)
    assert _rgb_at(client, 0, 0) == _sym(0x40, 0x80)
    assert _rgb_at(client, _ZRLE_TILE - 1, 0) == _sym(0x40, 0x80)
    assert _rgb_at(client, _ZRLE_TILE, 0) == _BLACK
    assert _rgb_at(client, 2 * _ZRLE_TILE - 1, 0) == _BLACK
    assert _priv(client, "_apply_zrle_tile")(b"", 0, 0, 0, 2, 2) == -1


def test_zrle_raw_tile_places_every_cpixel_at_its_offset() -> None:
    """A raw tile writes its CPIXELs row by row at the rectangle's offset."""
    client = _make_client(5, 4)
    cpixels = [_cp(10 * (i + 1), 20 + 5 * i) for i in range(6)]
    client.apply_zrle_rect(1, 1, 3, 2, bytes([_ZRLE_RAW]) + b"".join(cpixels))
    grid = [[_sym(10 * (r * 3 + c + 1), 20 + 5 * (r * 3 + c)) for c in range(3)] for r in range(2)]
    _assert_grid(client, 1, 1, grid)
    assert _rgb_at(client, 0, 0) == _BLACK
    assert _rgb_at(client, 4, 3) == _BLACK
    assert _rgb_at(client, 0, 1) == _BLACK


def test_zrle_raw_tile_with_a_short_payload_leaves_the_missing_pixels_black() -> None:
    """A raw tile whose payload ends inside a CPIXEL paints only the complete CPIXELs."""
    client = _make_client(2, 2)
    payload = bytes([_ZRLE_RAW]) + _cp(0x21, 0x31) + _cp(0x22, 0x32) + b"\x07"
    client.apply_zrle_rect(0, 0, 2, 2, payload)
    assert _rgb_at(client, 0, 0) == _sym(0x21, 0x31)
    assert _rgb_at(client, 1, 0) == _sym(0x22, 0x32)
    assert _rgb_at(client, 0, 1) == _BLACK
    assert _rgb_at(client, 1, 1) == _BLACK


def test_zrle_solid_tile_fills_exactly_its_rectangle() -> None:
    """A solid tile paints the rectangle it covers and nothing around it."""
    client = _make_client(8, 8)
    client.apply_zrle_rect(2, 3, 4, 2, bytes([_ZRLE_SOLID]) + _cp(0x33, 0x99))
    for y in range(8):
        for x in range(8):
            inside = 2 <= x < 6 and 3 <= y < 5
            assert _rgb_at(client, x, y) == (_sym(0x33, 0x99) if inside else _BLACK), f"pixel ({x},{y})"


def test_zrle_solid_tile_with_a_short_cpixel_paints_black() -> None:
    """A solid tile whose CPIXEL is cut short paints black rather than stale content."""
    client = _make_client(4, 2)
    _paint_white(client)
    client.apply_zrle_rect(0, 0, 4, 2, bytes([_ZRLE_SOLID, 0xAA]))
    for y in range(2):
        for x in range(4):
            assert _rgb_at(client, x, y) == _BLACK


@pytest.mark.parametrize(
    ("size", "width", "height", "rows"),
    [
        (2, 5, 2, [[0, 1, 1, 0, 1], [1, 0, 0, 1, 0]]),
        (3, 5, 2, [[0, 1, 2, 2, 1], [2, 2, 0, 1, 0]]),
        (4, 5, 2, [[3, 2, 1, 0, 3], [0, 1, 2, 3, 0]]),
        (5, 3, 2, [[4, 3, 2], [1, 0, 4]]),
        (16, 3, 2, [[15, 0, 7], [8, 1, 14]]),
    ],
    ids=["two-colors-1bit", "three-colors-2bit", "four-colors-2bit", "five-colors-4bit", "sixteen-colors-4bit"],
)
def test_zrle_packed_palette_tile_unpacks_indices_most_significant_bit_first(
    size: int,
    width: int,
    height: int,
    rows: list[list[int]],
) -> None:
    """A packed-palette tile resolves every index through the palette, with each row padded to a byte.

    Args:
        size: Number of palette entries, which is also the subencoding byte.
        width: Tile width in pixels.
        height: Tile height in pixels.
        rows: Palette index of every pixel.
    """
    entries = [(10 + 7 * i, 200 - 9 * i) for i in range(size)]
    bits = 1 if size == 2 else 2 if size <= 4 else 4
    payload = bytes([size]) + b"".join(starmap(_cp, entries)) + _pack_rows(rows, bits)
    client = _make_client(width + 2, height + 1)
    client.apply_zrle_rect(1, 1, width, height, payload)
    grid = [[_sym(*entries[index]) for index in row] for row in rows]
    _assert_grid(client, 1, 1, grid)
    assert _rgb_at(client, 0, 0) == _BLACK
    assert _rgb_at(client, width + 1, height) == _BLACK


@pytest.mark.parametrize("subencoding", [17, 129], ids=["palette-above-16", "rle-with-one-color"])
def test_zrle_unused_subencodings_consume_only_the_subencoding_byte(subencoding: int) -> None:
    """A subencoding the format does not define draws nothing and leaves the cursor after its byte.

    Args:
        subencoding: Subencoding byte that no decoder handles.
    """
    client = _make_client(4, 2)
    _paint_white(client)
    cursor = _priv(client, "_apply_zrle_tile")(bytes([subencoding]) + b"extra", 0, 0, 0, 4, 2)
    assert cursor == 1
    for y in range(2):
        for x in range(4):
            assert _rgb_at(client, x, y) == _WHITE


def test_zrle_plain_rle_expands_runs_and_clamps_the_last_one() -> None:
    """Plain RLE runs are one plus the sum of their length bytes, continued by 255, and stop at the tile end."""
    client = _make_client(4, 2)
    first = _cp(0x20, 0x60)
    second = _cp(0x50, 0x90)
    payload = bytes([_ZRLE_PLAIN_RLE]) + first + bytes([2]) + second + bytes([_ZRLE_RUN_CONTINUES, 1])
    client.apply_zrle_rect(0, 0, 4, 2, payload)
    for index in range(8):
        expected = _sym(0x20, 0x60) if index < 3 else _sym(0x50, 0x90)
        assert _rgb_at(client, index % 4, index // 4) == expected, f"pixel {index}"


def test_zrle_plain_rle_with_a_short_payload_stops_painting() -> None:
    """Plain RLE treats a missing length byte as a run of one and leaves the pixels after the payload black."""
    client = _make_client(4, 1)
    first = _cp(0x20, 0x60)
    second = _cp(0x50, 0x90)
    client.apply_zrle_rect(0, 0, 4, 1, bytes([_ZRLE_PLAIN_RLE]) + first + bytes([0]) + second)
    assert _rgb_at(client, 0, 0) == _sym(0x20, 0x60)
    assert _rgb_at(client, 1, 0) == _sym(0x50, 0x90)
    assert _rgb_at(client, 2, 0) == _BLACK
    assert _rgb_at(client, 3, 0) == _BLACK


def test_zrle_palette_rle_expands_indices_and_runs() -> None:
    """Palette RLE entries are a palette index, with the high bit announcing a run length that follows."""
    client = _make_client(5, 2)
    first = _cp(0x30, 0x70)
    second = _cp(0x60, 0xA0)
    stream = bytes([0x00, 0x81, 3, 0x80, _ZRLE_RUN_CONTINUES, _ZRLE_RUN_CONTINUES, 0])
    payload = bytes([_ZRLE_PALETTE_RLE_BASE + 2]) + first + second + stream
    client.apply_zrle_rect(0, 0, 5, 2, payload)
    expected = [_sym(0x30, 0x70)] + [_sym(0x60, 0xA0)] * 4 + [_sym(0x30, 0x70)] * 5
    for index, color in enumerate(expected):
        assert _rgb_at(client, index % 5, index // 5) == color, f"pixel {index}"


def test_zrle_palette_rle_with_a_short_payload_stops_painting() -> None:
    """A palette RLE run with no length byte is a run of one, and pixels after the payload stay black."""
    client = _make_client(4, 1)
    first = _cp(0x30, 0x70)
    second = _cp(0x60, 0xA0)
    client.apply_zrle_rect(0, 0, 4, 1, bytes([_ZRLE_PALETTE_RLE_BASE + 2]) + first + second + bytes([0x81]))
    assert _rgb_at(client, 0, 0) == _sym(0x60, 0xA0)
    assert _rgb_at(client, 1, 0) == _BLACK
    assert _rgb_at(client, 2, 0) == _BLACK
    assert _rgb_at(client, 3, 0) == _BLACK


def test_zrle_tiles_of_every_subencoding_follow_each_other_through_the_payload() -> None:
    """Five consecutive tiles of different subencodings each start where the previous one ended."""
    width = 5 * _ZRLE_TILE
    client = _make_client(width, 1)
    raw = bytes([_ZRLE_RAW]) + b"".join(_cp(i + 1, 200 - i) for i in range(_ZRLE_TILE))
    packed_palette = [_cp(0x90, 0x10), _cp(0xA0, 0x20)]
    packed = bytes([2]) + b"".join(packed_palette) + _pack_rows([[i % 2 for i in range(_ZRLE_TILE)]], 1)
    plain = bytes([_ZRLE_PLAIN_RLE]) + _cp(0x11, 0x22) + bytes([_ZRLE_TILE - 1])
    palette_entries = [_cp(0x01, 0x02), _cp(0x03, 0x04), _cp(0x05, 0x06)]
    palette_rle = bytes([_ZRLE_PALETTE_RLE_BASE + 3]) + b"".join(palette_entries) + bytes([0x82, _ZRLE_TILE - 1])
    solid = bytes([_ZRLE_SOLID]) + _cp(0x44, 0x55)
    client.apply_zrle_rect(0, 0, width, 1, raw + packed + plain + palette_rle + solid)
    expected: list[tuple[int, int, int]] = []
    expected += [_sym(i + 1, 200 - i) for i in range(_ZRLE_TILE)]
    expected += [_sym(0x90, 0x10) if i % 2 == 0 else _sym(0xA0, 0x20) for i in range(_ZRLE_TILE)]
    expected += [_sym(0x11, 0x22)] * _ZRLE_TILE
    expected += [_sym(0x05, 0x06)] * _ZRLE_TILE
    expected += [_sym(0x44, 0x55)] * _ZRLE_TILE
    assert [_rgb_at(client, x, 0) for x in range(width)] == expected


@pytest.mark.parametrize(("subencoding", "label"), [(_ZRLE_SOLID, "solid"), (_ZRLE_RAW, "raw")], ids=["solid", "raw"])
def test_zrle_cpixel_bytes_arrive_in_the_order_of_the_negotiated_little_endian_format(subencoding: int, label: str) -> None:
    """A CPIXEL is the three least significant bytes of the pixel, so a little-endian 16/8/0 format sends blue first.

    The client asks for 32 bits per pixel, depth 24, big-endian flag 0, red shift 16, green shift 8 and blue shift 0. RFC 6143 section
    7.7.6 defines the CPIXEL of such a format as the three least significant bytes of the pixel, in the byte order of the format. The
    pixel 0x00RRGGBB therefore goes out as blue, green, red.

    Args:
        subencoding: Subencoding byte of the one-pixel tile: solid or raw.
        label: Name of the subencoding, shown in the failure message.
    """
    client = _make_client(1, 1)
    red, green, blue = 0x11, 0x22, 0x33
    client.apply_zrle_rect(0, 0, 1, 1, bytes([subencoding, blue, green, red]))
    assert _rgb_at(client, 0, 0) == (red, green, blue), f"{label} tile decoded with red and blue exchanged"


@pytest.mark.parametrize("filter_id", [_TIGHT_COPY, _TIGHT_PALETTE, _TIGHT_GRADIENT], ids=["copy", "palette", "gradient"])
@pytest.mark.parametrize(("width", "height"), [(0, 2), (3, -1)], ids=["zero-width", "negative-height"])
def test_tight_basic_ignores_an_empty_rectangle(filter_id: int, width: int, height: int) -> None:
    """A rectangle without area changes nothing and raises nothing, whichever filter it names.

    Args:
        filter_id: Tight filter identifier.
        width: Rectangle width.
        height: Rectangle height.
    """
    client = _make_client(4, 4)
    _paint_white(client)
    client.apply_tight_basic(0, 0, width, height, bytes(range(1, 13)), filter_id, bytes(6), 2)
    for y in range(4):
        for x in range(4):
            assert _rgb_at(client, x, y) == _WHITE


def test_tight_copy_filter_reads_rgb_triplets() -> None:
    """The copy filter paints one red, green, blue triplet per pixel at the rectangle's offset."""
    client = _make_client(5, 4)
    triplets = [(10 + i, 50 + 2 * i, 90 + 3 * i) for i in range(6)]
    data = b"".join(bytes(t) for t in triplets)
    client.apply_tight_basic(1, 2, 3, 2, data, _TIGHT_COPY, b"", 0)
    _assert_grid(client, 1, 2, [triplets[0:3], triplets[3:6]])
    assert _rgb_at(client, 0, 2) == _BLACK
    assert _rgb_at(client, 4, 3) == _BLACK
    assert _rgb_at(client, 1, 1) == _BLACK


def test_tight_copy_filter_with_short_data_leaves_the_missing_pixels_black() -> None:
    """The copy filter paints only the complete triplets when the data is short."""
    client = _make_client(3, 2)
    triplets = [(10 + i, 50 + 2 * i, 90 + 3 * i) for i in range(4)]
    data = b"".join(bytes(t) for t in triplets) + b"\x01\x02"
    client.apply_tight_basic(0, 0, 3, 2, data, _TIGHT_COPY, b"", 0)
    _assert_grid(client, 0, 0, [triplets[0:3], [triplets[3], _BLACK, _BLACK]])


def test_tight_palette_filter_unpacks_two_color_bitmaps_most_significant_bit_first() -> None:
    """With two palette entries every pixel is one bit, most significant first, and each row is padded to a byte."""
    client = _make_client(12, 4)
    color0 = (0x10, 0x20, 0x30)
    color1 = (0xA0, 0xB0, 0xC0)
    rows = [[0, 1, 1, 0, 0, 1, 0, 1, 1, 0], [1, 0, 0, 1, 1, 0, 1, 0, 0, 1]]
    client.apply_tight_basic(1, 1, 10, 2, _pack_rows(rows, 1), _TIGHT_PALETTE, bytes(color0) + bytes(color1), 2)
    _assert_grid(client, 1, 1, [[(color0, color1)[index] for index in row] for row in rows])
    assert _rgb_at(client, 0, 1) == _BLACK
    assert _rgb_at(client, 11, 2) == _BLACK
    assert _rgb_at(client, 1, 3) == _BLACK


def test_tight_palette_filter_with_short_bitmap_data_leaves_later_rows_black() -> None:
    """A two-color bitmap that ends after the first row leaves the second row black."""
    client = _make_client(10, 2)
    color0 = (0x10, 0x20, 0x30)
    color1 = (0xA0, 0xB0, 0xC0)
    rows = [[0, 1, 1, 0, 0, 1, 0, 1, 1, 0]]
    client.apply_tight_basic(0, 0, 10, 2, _pack_rows(rows, 1), _TIGHT_PALETTE, bytes(color0) + bytes(color1), 2)
    _assert_grid(client, 0, 0, [[(color0, color1)[index] for index in rows[0]], [_BLACK] * 10])


def test_tight_palette_filter_paints_black_for_an_entry_missing_from_the_palette() -> None:
    """A two-color bitmap whose palette bytes hold only one entry paints black where the missing entry is chosen."""
    client = _make_client(4, 1)
    color0 = (0x10, 0x20, 0x30)
    client.apply_tight_basic(0, 0, 4, 1, _pack_rows([[0, 1, 0, 1]], 1), _TIGHT_PALETTE, bytes(color0), 2)
    _assert_grid(client, 0, 0, [[color0, _BLACK, color0, _BLACK]])


def test_tight_palette_filter_with_more_colors_reads_one_index_byte_per_pixel() -> None:
    """With more than two palette entries every pixel is one index byte."""
    client = _make_client(3, 2)
    colors = [(1, 2, 3), (40, 50, 60), (70, 80, 90), (110, 120, 130)]
    palette = b"".join(bytes(color) for color in colors)
    client.apply_tight_basic(0, 0, 3, 2, bytes([0, 1, 2, 3, 2, 1]), _TIGHT_PALETTE, palette, 4)
    _assert_grid(client, 0, 0, [[colors[0], colors[1], colors[2]], [colors[3], colors[2], colors[1]]])


def test_tight_palette_filter_skips_unknown_indices_and_missing_data() -> None:
    """An index past the palette and pixels past the end of the data stay black."""
    client = _make_client(4, 1)
    colors = [(1, 2, 3), (40, 50, 60), (70, 80, 90)]
    palette = b"".join(bytes(color) for color in colors)
    client.apply_tight_basic(0, 0, 4, 1, bytes([1, 9, 0]), _TIGHT_PALETTE, palette, 3)
    _assert_grid(client, 0, 0, [[colors[1], _BLACK, colors[0], _BLACK]])


def test_tight_gradient_filter_adds_the_left_plus_upper_minus_upper_left_prediction() -> None:
    """Each gradient pixel is its filtered value plus the prediction left + upper - upper-left, modulo 256.

    Worked by hand for a 2x2 rectangle: the first row predicts from the left neighbor only, the first column from the upper neighbor
    only, and the last pixel from all three neighbors.
    """
    client = _make_client(2, 2)
    filtered = [(10, 20, 30), (1, 2, 3), (4, 5, 6), (100, 100, 100)]
    client.apply_tight_basic(0, 0, 2, 2, b"".join(bytes(p) for p in filtered), _TIGHT_GRADIENT, b"", 0)
    _assert_grid(client, 0, 0, [[(10, 20, 30), (11, 22, 33)], [(14, 25, 36), (115, 127, 139)]])


def test_tight_gradient_filter_clamps_a_negative_prediction_to_zero() -> None:
    """A prediction below zero is clamped to zero before the filtered value is added."""
    client = _make_client(2, 2)
    filtered = [(200, 100, 50), (56, 156, 206), (56, 156, 206), (7, 8, 9)]
    client.apply_tight_basic(0, 0, 2, 2, b"".join(bytes(p) for p in filtered), _TIGHT_GRADIENT, b"", 0)
    _assert_grid(client, 0, 0, [[(200, 100, 50), _BLACK], [_BLACK, (7, 8, 9)]])


def test_tight_gradient_filter_clamps_a_prediction_above_255() -> None:
    """A prediction above 255 is clamped to 255 before the filtered value is added."""
    client = _make_client(2, 2)
    filtered = [(0, 0, 0), (200, 200, 200), (200, 200, 200), (1, 2, 3)]
    client.apply_tight_basic(0, 0, 2, 2, b"".join(bytes(p) for p in filtered), _TIGHT_GRADIENT, b"", 0)
    _assert_grid(client, 0, 0, [[_BLACK, (200, 200, 200)], [(200, 200, 200), (0, 1, 2)]])


def test_tight_gradient_filter_with_short_data_paints_black_for_the_missing_pixels() -> None:
    """A gradient row whose data ends early gets black pixels for the missing ones."""
    client = _make_client(2, 1)
    client.apply_tight_basic(0, 0, 2, 1, bytes((10, 20, 30, 1)), _TIGHT_GRADIENT, b"", 0)
    _assert_grid(client, 0, 0, [[(10, 20, 30), _BLACK]])


def test_disconnect_swallows_a_transport_error_raised_while_closing() -> None:
    """Closing a connection the peer reset still completes and clears the client's streams."""

    async def scenario() -> tuple[bool, object, object]:
        """Reset a client's connection from the peer side and disconnect it.

        Returns:
            tuple[bool, object, object]: The connected flag, the reader and the writer after the disconnect.
        """
        client = RFBClient()
        try:
            await _attach_reset(client)
            await asyncio.wait_for(client.disconnect(), timeout=_PUMP_STOP_TIMEOUT_S)
        finally:
            await client.disconnect()
        return client.connected, _priv(client, "_reader"), _priv(client, "_writer")

    connected, reader, writer = asyncio.run(scenario())
    assert connected is False
    assert reader is None
    assert writer is None


async def _noop() -> None:
    """Complete immediately."""


async def _finished_task() -> asyncio.Task[None]:
    """Create a task and wait until it is done.

    Returns:
        asyncio.Task[None]: The finished task.
    """
    task = asyncio.ensure_future(_noop())
    await task
    return task


async def _attach_loopback(client: RFBClient) -> socket.socket:
    """Connect a client to a fresh loopback listener without any RFB handshake.

    The client's streams are set straight to the new connection and it is marked connected with a ``_FB_W`` by ``_FB_H`` geometry, so
    its message loop can run against the returned peer socket.

    Args:
        client: Client to attach.

    Returns:
        socket.socket: The accepted peer end of the connection.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.settimeout(_SOCKET_TIMEOUT_S)
        listener.bind((_LOOPBACK, 0))
        listener.listen(1)
        port: int = listener.getsockname()[1]
        reader, writer = await asyncio.open_connection(_LOOPBACK, port)
        _set_priv(client, "_reader", reader)
        _set_priv(client, "_writer", writer)
        client.connected = True
        client.width = _FB_W
        client.height = _FB_H
        peer, _address = listener.accept()
    finally:
        listener.close()
    return peer


async def _attach_reset(client: RFBClient) -> None:
    """Attach a client to a loopback connection that the peer then resets with a hard close.

    Returns once the client's reader holds the connection error the reset produced.

    Args:
        client: Client to attach.
    """
    peer = await _attach_loopback(client)
    try:
        peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("HH", 1, 0))
    finally:
        peer.close()
    reader: asyncio.StreamReader = _priv(client, "_reader")
    _ = await wait_until(lambda: reader.exception() is not None, budget=_RESET_BUDGET_S, interval=_POLL_INTERVAL_S)
    assert isinstance(reader.exception(), OSError)


@pytest.mark.asyncio
async def test_pump_ends_when_the_transport_fails(qtbot: QtBot) -> None:
    """The pump loop returns instead of retrying when sending its request raises a transport error.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
    """
    widget = VNCWidget()
    qtbot.addWidget(widget)
    try:
        await _attach_reset(widget.client)
        await asyncio.wait_for(_priv(widget, "_pump_server_loop")(), timeout=_PUMP_STOP_TIMEOUT_S)
    finally:
        await widget.client.disconnect()


@pytest.mark.asyncio
async def test_pump_that_ends_on_a_transport_error_leaves_the_client_disconnected(qtbot: QtBot) -> None:
    """When the pump stops because the transport failed, the client reports itself disconnected.

    The widget learns of a lost connection only through ``client.connected`` (``_on_update_tick`` stops its timer and emits
    ``connection_status_changed(False)`` when that is false), and its documentation says the tick exists to notice when the pump has
    exited. A pump that ends on a transport error while the client still claims to be connected leaves the display frozen and reported as
    live for good.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
    """
    widget = VNCWidget()
    qtbot.addWidget(widget)
    try:
        await _attach_reset(widget.client)
        await asyncio.wait_for(_priv(widget, "_pump_server_loop")(), timeout=_PUMP_STOP_TIMEOUT_S)
        connected = widget.client.connected
    finally:
        await widget.client.disconnect()
    assert connected is False


@pytest.mark.asyncio
async def test_pump_cancelled_during_its_idle_sleep_ends_cleanly(qtbot: QtBot) -> None:
    """Cancelling the pump while it sleeps between idle polls ends the loop without an error.

    The first pass finds nothing to read and a dirty framebuffer, so the pump emits ``framebuffer_updated`` and then goes to sleep. The
    slot connected here cancels the pump task from inside that emission, so the cancellation reaches the sleep itself.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
    """
    widget = VNCWidget()
    qtbot.addWidget(widget)
    peer: socket.socket | None = None
    try:
        peer = await _attach_loopback(widget.client)
        _set_priv(widget.client, "_fb_dirty", value=True)
        task = asyncio.ensure_future(_priv(widget, "_pump_server_loop")())

        def cancel_pump() -> None:
            """Cancel the pump task while the pump is emitting."""
            _ = task.cancel()

        _ = widget.framebuffer_updated.connect(cancel_pump)
        await asyncio.wait_for(task, timeout=_PUMP_STOP_TIMEOUT_S)
        assert task.done()
        assert not task.cancelled()
        assert widget.client.connected is True
    finally:
        await widget.client.disconnect()
        if peer is not None:
            peer.close()


@pytest.mark.asyncio
async def test_pump_cancelled_while_waiting_for_a_server_message_ends_cleanly(qtbot: QtBot) -> None:
    """Cancelling the pump while it waits for the server's reply ends the loop without an error.

    The test waits until the pump's first update request has reached the peer, so the pump is waiting for a message the peer never sends.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
    """
    widget = VNCWidget()
    qtbot.addWidget(widget)
    peer: socket.socket | None = None
    try:
        peer = await _attach_loopback(widget.client)
        peer.settimeout(0.0)
        task = asyncio.ensure_future(_priv(widget, "_pump_server_loop")())
        request = await asyncio.wait_for(asyncio.get_running_loop().sock_recv(peer, 10), timeout=_PUMP_STOP_TIMEOUT_S)
        assert len(request) == 10
        assert request[0] == 3
        _ = task.cancel()
        await asyncio.wait_for(task, timeout=_PUMP_STOP_TIMEOUT_S)
        assert task.done()
        assert not task.cancelled()
        assert widget.client.connected is True
    finally:
        await widget.client.disconnect()
        if peer is not None:
            peer.close()


def _handshake_bytes() -> bytes:
    """Build everything an RFB 3.8 server sends before the first framebuffer update.

    The sequence is the protocol version, one security type (None) with its accepted result, and ServerInit with a 32-bit true-color
    pixel format and the server name. None of it depends on what the client writes, so it can be queued on the socket in advance.

    Returns:
        bytes: The server's handshake bytes.
    """
    server_init = (
        _FB_W.to_bytes(2, "big") + _FB_H.to_bytes(2, "big") + _SERVER_PIXEL_FORMAT + len(_SERVER_NAME).to_bytes(4, "big") + _SERVER_NAME
    )
    return b"RFB 003.008\n" + bytes((1, 1)) + (0).to_bytes(4, "big") + server_init


def _client_messages(stream: bytes) -> list[tuple[int, bytes]]:
    """Split the bytes a client sent after the handshake into RFB client messages.

    The first fourteen bytes are the version string, the chosen security type and ClientInit. Every later message is framed by its type
    byte: SetPixelFormat is 20 bytes, FramebufferUpdateRequest 10, KeyEvent 8 and PointerEvent 6.

    Args:
        stream: Every byte received from the client so far.

    Returns:
        list[tuple[int, bytes]]: Type and full bytes of each complete message.
    """
    messages: list[tuple[int, bytes]] = []
    offset = _HANDSHAKE_PREFIX_LEN
    while offset < len(stream):
        length = _CLIENT_MESSAGE_LENGTHS.get(stream[offset])
        if length is None or offset + length > len(stream):
            break
        messages.append((stream[offset], stream[offset : offset + length]))
        offset += length
    return messages


def _collect(session: _Session, msg_type: int, count: int) -> list[bytes]:
    """Read from the peer until enough messages of one type have arrived or the budget is spent.

    Args:
        session: Session whose peer socket is read.
        msg_type: Message type byte to wait for.
        count: Number of messages of that type to wait for.

    Returns:
        list[bytes]: Every message of that type received so far, in arrival order.
    """
    deadline = time.monotonic() + _GATHER_BUDGET_S
    while True:
        found = [message for kind, message in _client_messages(bytes(session.stream)) if kind == msg_type]
        if len(found) >= count or time.monotonic() >= deadline:
            return found
        try:
            chunk = session.peer.recv(_RECV_CHUNK)
        except TimeoutError:
            continue
        if not chunk:
            return found
        session.stream.extend(chunk)


@pytest.fixture
def session(qtbot: QtBot) -> Generator[_Session]:
    """Connect a widget to a loopback peer, complete the RFB handshake and wait for the pump to start.

    Args:
        qtbot: pytest-qt fixture that owns the widget and spins the event loop.

    Yields:
        _Session: The connected widget, its peer socket and the recorder of its status signals.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.settimeout(_SOCKET_TIMEOUT_S)
    listener.bind((_LOOPBACK, 0))
    listener.listen(1)
    port: int = listener.getsockname()[1]
    widget = VNCWidget()
    qtbot.addWidget(widget)
    recorder = SignalRecorder()
    _ = widget.connection_status_changed.connect(recorder)
    peer: socket.socket | None = None
    try:
        widget.connect_to_server(_LOOPBACK, port, timeout=_CONNECT_TIMEOUT_S)
        peer, _address = listener.accept()
        peer.sendall(_handshake_bytes())
        qtbot.waitUntil(lambda: bool(recorder.calls), timeout=_WAIT_MS)
        assert recorder.calls == [(True,)]
        qtbot.waitUntil(lambda: _priv(widget, "_pump_task_ref") is not None, timeout=_WAIT_MS)
        peer.settimeout(_RECV_SLICE_S)
        yield _Session(widget, peer, recorder, bytearray())
    finally:
        widget.disconnect_from_server()
        drain_bridge_workers()
        if peer is not None:
            peer.close()
        listener.close()


def _mouse_event(kind: QEvent.Type, x: float, y: float, button: Qt.MouseButton, buttons: Qt.MouseButton) -> QMouseEvent:
    """Build a real mouse event at a widget position.

    Args:
        kind: Event type.
        x: Horizontal position in widget coordinates.
        y: Vertical position in widget coordinates.
        button: Button that caused the event.
        buttons: Buttons held while the event is delivered.

    Returns:
        QMouseEvent: The event.
    """
    position = QPointF(x, y)
    return QMouseEvent(kind, position, position, button, buttons, Qt.KeyboardModifier.NoModifier)


def _key_event(kind: QEvent.Type, key: Qt.Key, text: str) -> QKeyEvent:
    """Build a real key event without modifiers.

    Args:
        kind: Event type.
        key: Qt key code.
        text: Text the key produces.

    Returns:
        QKeyEvent: The event.
    """
    return QKeyEvent(kind, key, Qt.KeyboardModifier.NoModifier, text)


def _worker_set() -> set[object]:
    """Snapshot the bridge workers currently retained by the async bridge.

    Returns:
        set[object]: The retained worker objects.
    """
    registry = _priv(async_bridge_module, "_WorkerRegistry")
    with registry.lock:
        return set(registry.workers)


def _deliver_all_input(widget: VNCWidget) -> None:
    """Deliver one real event to each of the widget's five input handlers.

    Args:
        widget: Widget whose handlers receive the events.
    """
    button = Qt.MouseButton.LeftButton
    widget.mouseMoveEvent(_mouse_event(QEvent.Type.MouseMove, 5, 5, Qt.MouseButton.NoButton, button))
    widget.mousePressEvent(_mouse_event(QEvent.Type.MouseButtonPress, 5, 5, button, button))
    widget.mouseReleaseEvent(_mouse_event(QEvent.Type.MouseButtonRelease, 5, 5, button, Qt.MouseButton.NoButton))
    widget.keyPressEvent(_key_event(QEvent.Type.KeyPress, Qt.Key.Key_Return, ""))
    widget.keyReleaseEvent(_key_event(QEvent.Type.KeyRelease, Qt.Key.Key_Return, ""))


def test_input_is_not_forwarded_while_disconnected(qtbot: QtBot) -> None:
    """With no connection the five input handlers dispatch nothing to the bridge.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
    """
    widget = VNCWidget()
    qtbot.addWidget(widget)
    before = _worker_set()
    _deliver_all_input(widget)
    assert _worker_set() - before == set()


def test_missing_input_events_are_ignored_while_connected(qtbot: QtBot) -> None:
    """A handler given no event returns without raising or dispatching, even on a connected client.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
    """
    widget = VNCWidget()
    qtbot.addWidget(widget)
    widget.client.connected = True
    before = _worker_set()
    widget.mouseMoveEvent(None)
    widget.mousePressEvent(None)
    widget.mouseReleaseEvent(None)
    widget.keyPressEvent(None)
    widget.keyReleaseEvent(None)
    assert _worker_set() - before == set()


def test_scale_coords_is_the_origin_without_a_framebuffer(qtbot: QtBot) -> None:
    """Until a framebuffer exists every mouse position maps to the origin.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
    """
    widget = VNCWidget()
    qtbot.addWidget(widget)
    event = _mouse_event(QEvent.Type.MouseMove, 50, 60, Qt.MouseButton.NoButton, Qt.MouseButton.NoButton)
    assert _priv(widget, "_scale_coords")(event) == (0, 0)


def test_scale_coords_is_the_origin_while_the_framebuffer_has_no_width(qtbot: QtBot) -> None:
    """A framebuffer that reports width zero maps every mouse position to the origin.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
    """
    widget = VNCWidget()
    qtbot.addWidget(widget)
    widget.client.framebuffer = QImage(_FB_W, _FB_H, QImage.Format.Format_RGB32)
    widget.client.width = 0
    widget.client.height = 100
    event = _mouse_event(QEvent.Type.MouseMove, 50, 50, Qt.MouseButton.NoButton, Qt.MouseButton.NoButton)
    assert _priv(widget, "_scale_coords")(event) == (0, 0)


def test_scale_coords_maps_widget_pixels_onto_the_framebuffer(qtbot: QtBot) -> None:
    """Widget positions scale by the framebuffer-to-widget size ratio on each axis and are truncated.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
    """
    widget = VNCWidget()
    qtbot.addWidget(widget)
    widget.resize(_WIDGET_W, _WIDGET_H)
    assert (widget.width(), widget.height()) == (_WIDGET_W, _WIDGET_H)
    widget.client.framebuffer = QImage(_FB_W, _FB_H, QImage.Format.Format_RGB32)
    widget.client.width = _FB_W
    widget.client.height = _FB_H
    scale = _priv(widget, "_scale_coords")
    inner = _mouse_event(QEvent.Type.MouseMove, 203, 101, Qt.MouseButton.NoButton, Qt.MouseButton.NoButton)
    corner = _mouse_event(QEvent.Type.MouseMove, 639, 239, Qt.MouseButton.NoButton, Qt.MouseButton.NoButton)
    assert scale(inner) == (50, 50)
    assert scale(corner) == (159, 119)


def test_mouse_move_forwards_a_scaled_pointer_event_with_the_held_buttons(session: _Session) -> None:
    """A mouse move sends a PointerEvent at the framebuffer position with the held buttons as the mask.

    Args:
        session: Connected widget and its peer.
    """
    session.widget.resize(_WIDGET_W, _WIDGET_H)
    event = _mouse_event(QEvent.Type.MouseMove, 203, 101, Qt.MouseButton.NoButton, Qt.MouseButton.LeftButton)
    session.widget.mouseMoveEvent(event)
    sent = _collect(session, _MSG_POINTER_EVENT, 1)
    assert sent == [bytes((5, 1)) + (50).to_bytes(2, "big") + (50).to_bytes(2, "big")]


def test_mouse_press_and_release_forward_the_pressed_mask_then_zero(session: _Session) -> None:
    """A press sends the held buttons as the mask, and a release sends mask zero at the release position.

    Args:
        session: Connected widget and its peer.
    """
    session.widget.resize(_WIDGET_W, _WIDGET_H)
    held = Qt.MouseButton.LeftButton | Qt.MouseButton.RightButton
    session.widget.mousePressEvent(_mouse_event(QEvent.Type.MouseButtonPress, 203, 101, Qt.MouseButton.LeftButton, held))
    pressed = _collect(session, _MSG_POINTER_EVENT, 1)
    assert pressed == [bytes((5, 5)) + (50).to_bytes(2, "big") + (50).to_bytes(2, "big")]
    session.widget.mouseReleaseEvent(_mouse_event(QEvent.Type.MouseButtonRelease, 639, 239, Qt.MouseButton.LeftButton, held))
    both = _collect(session, _MSG_POINTER_EVENT, 2)
    assert both[1] == bytes((5, 0)) + (159).to_bytes(2, "big") + (119).to_bytes(2, "big")


@pytest.mark.parametrize(
    ("key", "text", "down", "keysym"),
    [
        (Qt.Key.Key_Return, "", True, 0xFF0D),
        (Qt.Key.Key_Escape, "", False, 0xFF1B),
        (Qt.Key.Key_A, "a", True, 0x61),
        (Qt.Key.Key_A, "A", False, 0x41),
    ],
    ids=["return-press", "escape-release", "lowercase-press", "uppercase-release"],
)
def test_key_events_forward_the_x11_keysym_and_the_down_flag(session: _Session, key: Qt.Key, text: str, keysym: int, *, down: bool) -> None:
    """A key press or release sends a KeyEvent carrying the X11 keysym and the matching down flag.

    Args:
        session: Connected widget and its peer.
        key: Qt key code of the event.
        text: Text the key produces.
        keysym: X11 keysym the message must carry.
        down: Whether the key is pressed rather than released.
    """
    if down:
        session.widget.keyPressEvent(_key_event(QEvent.Type.KeyPress, key, text))
    else:
        session.widget.keyReleaseEvent(_key_event(QEvent.Type.KeyRelease, key, text))
    sent = _collect(session, _MSG_KEY_EVENT, 1)
    assert sent == [bytes((4, 1 if down else 0, 0, 0)) + keysym.to_bytes(4, "big")]


def test_cancel_pump_task_ends_a_live_pump_without_disconnecting(session: _Session, qtbot: QtBot) -> None:
    """Cancelling the pump task stops the pump even though the connection stays up.

    Args:
        session: Connected widget and its peer.
        qtbot: pytest-qt fixture that spins the event loop while waiting.
    """
    widget = session.widget
    task = _priv(widget, "_pump_task_ref")
    assert task is not None
    _priv(widget, "_cancel_pump_task")()
    assert _priv(widget, "_pump_task_ref") is None
    assert _priv(widget, "_pump_loop") is None
    qtbot.waitUntil(task.done, timeout=_WAIT_MS)
    assert not task.cancelled()
    assert widget.client.connected is True


def test_cancel_pump_task_with_a_finished_task_only_clears_its_references(qtbot: QtBot) -> None:
    """A pump task that already finished is left alone and the widget forgets it.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
    """
    widget = VNCWidget()
    qtbot.addWidget(widget)
    loop = ensure_loop()
    finished = asyncio.run_coroutine_threadsafe(_finished_task(), loop).result(timeout=_PUMP_STOP_TIMEOUT_S)
    _set_priv(widget, "_pump_loop", loop)
    _set_priv(widget, "_pump_task_ref", finished)
    _priv(widget, "_cancel_pump_task")()
    _ = asyncio.run_coroutine_threadsafe(_noop(), loop).result(timeout=_PUMP_STOP_TIMEOUT_S)
    assert _priv(widget, "_pump_task_ref") is None
    assert _priv(widget, "_pump_loop") is None
    assert finished.done()
    assert not finished.cancelled()
    assert finished.exception() is None


def test_peer_closing_the_connection_surfaces_a_disconnect(session: _Session, qtbot: QtBot) -> None:
    """When the server closes its end, the repaint tick stops itself and reports the disconnect.

    Args:
        session: Connected widget and its peer.
        qtbot: pytest-qt fixture that spins the event loop while waiting.
    """
    widget = session.widget
    session.peer.shutdown(socket.SHUT_WR)
    qtbot.waitUntil(lambda: len(session.recorder.calls) >= 2, timeout=_WAIT_MS)
    assert session.recorder.calls[-1] == (False,)
    assert not widget.update_timer.isActive()
    assert widget.client.connected is False
    assert _priv(widget, "_pump_task_ref") is None


def test_update_tick_reports_a_lost_connection_once_and_stops_the_timer(qtbot: QtBot) -> None:
    """With the client disconnected the tick stops the timer, forgets the pump and emits False.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
    """
    widget = VNCWidget()
    qtbot.addWidget(widget)
    recorder = SignalRecorder()
    _ = widget.connection_status_changed.connect(recorder)
    widget.update_timer.start(_WAIT_MS)
    try:
        assert widget.update_timer.isActive()
        _priv(widget, "_on_update_tick")()
        assert not widget.update_timer.isActive()
        assert recorder.calls == [(False,)]
    finally:
        widget.update_timer.stop()


def test_update_tick_keeps_a_connected_widget_running(qtbot: QtBot) -> None:
    """With the client connected the tick leaves the timer running and emits nothing.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
    """
    widget = VNCWidget()
    qtbot.addWidget(widget)
    recorder = SignalRecorder()
    _ = widget.connection_status_changed.connect(recorder)
    widget.client.connected = True
    widget.update_timer.start(_WAIT_MS)
    try:
        _priv(widget, "_on_update_tick")()
        assert widget.update_timer.isActive()
        assert recorder.calls == []
    finally:
        widget.update_timer.stop()


def _render(widget: VNCWidget) -> QImage:
    """Render a widget into an image through its real paint handler.

    Args:
        widget: Widget to render.

    Returns:
        QImage: The rendered widget.
    """
    widget.resize(320, 240)
    image = QImage(widget.width(), widget.height(), QImage.Format.Format_RGB32)
    image.fill(0xFFFF00FF)
    widget.render(image)
    return image


def test_idle_display_is_painted_with_the_theme_background(qtbot: QtBot) -> None:
    """A widget with no frame fills itself with the active theme's analysis background color.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
    """
    widget = VNCWidget()
    qtbot.addWidget(widget)
    image = _render(widget)
    background = ThemeManager.get_instance().get_analysis_colors()["background"]
    for x, y in ((4, 235), (160, 235), (4, 120)):
        color = image.pixelColor(x, y)
        assert (color.red(), color.green(), color.blue()) == (background.red(), background.green(), background.blue()), f"pixel ({x},{y})"


def test_idle_display_draws_its_caption(qtbot: QtBot) -> None:
    """The idle display draws its caption in the middle of the widget, over the background color.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
    """
    widget = VNCWidget()
    qtbot.addWidget(widget)
    image = _render(widget)
    background = ThemeManager.get_instance().get_analysis_colors()["background"]
    expected = (background.red(), background.green(), background.blue())
    inked = any(
        (image.pixelColor(x, y).red(), image.pixelColor(x, y).green(), image.pixelColor(x, y).blue()) != expected
        for y in range(100, 140)
        for x in range(100, 220)
    )
    assert inked


def test_popout_without_a_dock_host_redocks_as_a_top_level_widget(qtbot: QtBot) -> None:
    """With no dock host configured, re-docking turns the widget into a visible top-level widget again.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
    """
    widget = VNCWidget()
    qtbot.addWidget(widget)
    try:
        widget.popout()
        window = _priv(widget, "_popout_window")
        assert window is not None
        assert widget.parent() is window
        widget.redock()
        assert _priv(widget, "_popout_window") is None
        assert widget.parent() is None
        assert widget.isVisible()
        assert _priv(widget, "_popout_btn").text() == "Pop Out"
    finally:
        widget.redock()
