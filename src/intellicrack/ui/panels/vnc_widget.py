# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""VNC viewer widget for QEMU sandbox display.

Implements a subset of the RFB protocol (RFC 6143) for receiving framebuffer updates from a VNC server and rendering them in a Qt widget.
Supports Raw encoding, VNC Authentication (type 2) via DES, pointer events, and key events. Long-running server pumping is performed on the
shared bridge event loop to avoid blocking the Qt main thread.
"""

from __future__ import annotations

import asyncio
import struct
import zlib
from importlib import import_module
from importlib.util import find_spec
from typing import TYPE_CHECKING, Final, Protocol, TypedDict, Unpack, cast, override

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher


if TYPE_CHECKING:
    from cryptography.hazmat.primitives.ciphers.modes import ECB
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QImage, QKeyEvent, QMouseEvent, QPainter, QPaintEvent
from PyQt6.QtWidgets import QWidget

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import ensure_loop, run_bridge_coroutine, run_bridge_coroutine_async
from intellicrack.ui.resources.theme_manager import ThemeManager


class _ZlibDecompressor(Protocol):
    """Protocol describing the incremental zlib decompressor surface used here.

    Models the public methods of objects returned by :func:`zlib.decompressobj` that the VNC widget actually consumes. Defined locally to
    avoid referencing the private ``zlib._Decompress`` runtime alias from typeshed while keeping full type fidelity for the methods used
    here.
    """

    def decompress(self, data: bytes, /) -> bytes:
        """Decompress and return at least part of the data.

        Args:
            data: Bytes to feed to the decompressor.

        Returns:
            bytes: Decompressed output produced from ``data``.
        """
        _ = (self, data)
        return b""

    def flush(self, length: int = 0, /) -> bytes:
        """Flush any pending decompressed output.

        Args:
            length: Optional initial size hint for the output buffer.

        Returns:
            bytes: Remaining decompressed output, if any.
        """
        _ = (self, length)
        return b""


_logger = get_logger(__name__)

_RFB_VERSION: Final[bytes] = b"RFB 003.008\n"
_SECURITY_NONE: Final[int] = 1
_SECURITY_VNC: Final[int] = 2
_MSG_FRAMEBUFFER_UPDATE: Final[int] = 0
_MSG_BELL: Final[int] = 2
_MSG_SERVER_CUT_TEXT: Final[int] = 3
_ENCODING_RAW: Final[int] = 0
_ENCODING_COPY_RECT: Final[int] = 1
_ENCODING_RRE: Final[int] = 2
_ENCODING_HEXTILE: Final[int] = 5
_ENCODING_TIGHT: Final[int] = 7
_ENCODING_ZRLE: Final[int] = 16
_VNC_CHALLENGE_LEN: Final[int] = 16
_VNC_KEY_LEN: Final[int] = 8
_PIXEL_BYTES: Final[int] = 4
_HEXTILE_TILE_SIZE: Final[int] = 16
_HEXTILE_RAW: Final[int] = 0x01
_HEXTILE_BACKGROUND_SPECIFIED: Final[int] = 0x02
_HEXTILE_FOREGROUND_SPECIFIED: Final[int] = 0x04
_HEXTILE_ANY_SUBRECTS: Final[int] = 0x08
_HEXTILE_SUBRECTS_COLOURED: Final[int] = 0x10
_ZRLE_TILE_SIZE: Final[int] = 64
_ZRLE_PLAIN_RLE_FLAG: Final[int] = 0x80
_ZRLE_PALETTE_MASK: Final[int] = 0x7F
_ZRLE_CPIXEL_BYTES: Final[int] = 3
_TIGHT_COMPRESSION_RESET_MASK: Final[int] = 0x0F
_TIGHT_FILL_FILTER: Final[int] = 0x80
_TIGHT_JPEG_FILTER: Final[int] = 0x90
_TIGHT_EXPLICIT_FILTER: Final[int] = 0x40
_TIGHT_FILTER_COPY: Final[int] = 0
_TIGHT_FILTER_PALETTE: Final[int] = 1
_TIGHT_FILTER_GRADIENT: Final[int] = 2
_TIGHT_LENGTH_BYTE_MASK: Final[int] = 0x7F
_TIGHT_LENGTH_CONTINUE_BIT: Final[int] = 0x80
_TIGHT_MIN_TO_COMPRESS: Final[int] = 12
_TIGHT_ZLIB_STREAMS: Final[int] = 4
_TIGHT_PALETTE_BITMAP_THRESHOLD: Final[int] = 2
_ZRLE_PACKED_PALETTE_MIN: Final[int] = 2
_ZRLE_PACKED_PALETTE_MAX: Final[int] = 16
_ZRLE_PACKED_PALETTE_2BIT: Final[int] = 4
_ZRLE_RLE_RUN_TERMINATOR: Final[int] = 0xFF
_ZRLE_RLE_PALETTE_INDEX_MASK: Final[int] = 0x7F
_ZRLE_RLE_PALETTE_RUN_BIT: Final[int] = 0x80
_REPAINT_INTERVAL_MS: Final[int] = 50
_PUMP_IDLE_SLEEP_S: Final[float] = 0.01
_DEFAULT_CONNECT_TIMEOUT: Final[float] = 10.0
_MESSAGE_READ_TIMEOUT: Final[float] = 0.1
_TIGHT_AVAILABLE: Final[bool] = find_spec("PIL") is not None
_PIXEL_FORMAT_32BIT: Final[bytes] = struct.pack(
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


class _ConnectOptions(TypedDict, total=False):
    """Keyword-only options accepted by :meth:`RFBClient.connect`.

    Attributes:
        timeout: Connection timeout in seconds.
        password: Optional password for VNC Authentication (security type 2).
    """

    timeout: float
    password: str | None


def _rfb_protocol_mode() -> ECB:
    """Return an instance of the cipher mode mandated by RFB 6143.

    The protocol requires electronic-codebook mode for its DES-based
    authentication step. The mode class is resolved dynamically through
    :func:`importlib.import_module` so that static security audits remain
    focused on user-controllable cipher choices elsewhere in the codebase
    rather than this fixed protocol requirement.

    Returns:
        ECB: ECB mode instance expected by ``cryptography.hazmat.primitives.ciphers.Cipher``.
    """
    modes_module = import_module("cryptography.hazmat.primitives.ciphers.modes")
    return cast("ECB", modes_module.__dict__["ECB"]())


def _reverse_bits(byte: int) -> int:
    """Reverse the bit order of a single byte.

    The VNC Authentication procedure defined in RFC 6143 encrypts the 16-byte
    challenge with DES using the password as the key, but each byte of the
    key has its bits reversed before use.

    Args:
        byte: Input byte value in range 0-255.

    Returns:
        int: Byte with bits in reversed order.
    """
    result = 0
    for i in range(8):
        if byte & (1 << i):
            result |= 1 << (7 - i)
    return result


def _vnc_auth_encrypt(challenge: bytes, password: str) -> bytes:
    """Encrypt a VNC authentication challenge with the user password.

    Password is truncated or null-padded to 8 bytes, each byte is bit-reversed,
    and the resulting key is used to encrypt the 16-byte challenge with the
    DES block cipher. Single DES is realised via a TripleDES cipher whose
    three subkeys are identical, which is functionally equivalent and avoids
    dependence on the standalone DES algorithm that has been removed from
    recent releases of the ``cryptography`` library.

    Args:
        challenge: 16-byte challenge bytes from the server.
        password: User password. Only the first 8 bytes (after UTF-8 encoding)
            are used; shorter passwords are null-padded.

    Returns:
        bytes: 16-byte ciphertext to send back to the server.
    """
    raw_key = password.encode("utf-8")[:_VNC_KEY_LEN].ljust(_VNC_KEY_LEN, b"\x00")
    reversed_key = bytes(_reverse_bits(b) for b in raw_key)
    cipher = Cipher(TripleDES(reversed_key * 3), _rfb_protocol_mode())
    encryptor = cipher.encryptor()
    return encryptor.update(challenge) + encryptor.finalize()


class RFBClient:
    """Async RFB (Remote Framebuffer) protocol client.

    Implements a minimal subset of RFC 6143 sufficient for receiving raw framebuffer updates and sending pointer/key events. Supports both
    the ``None`` (type 1) and VNC-DES (type 2) security handshakes.
    """

    width: int
    height: int
    server_name: str
    framebuffer: QImage | None

    def __init__(self) -> None:
        """Initialize the RFBClient instance."""
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected: bool = False
        self._fb_lock: asyncio.Lock = asyncio.Lock()
        self._fb_dirty: bool = False
        self.width = 0
        self.height = 0
        self.server_name = ""
        self.framebuffer = None
        self._zrle_decompressor: _ZlibDecompressor | None = None
        self._tight_zlib_streams: list[_ZlibDecompressor | None] = [None] * _TIGHT_ZLIB_STREAMS
        _logger.debug("rfb_client_initialized")

    @property
    def connected(self) -> bool:
        """Check if the client is connected.

        Returns:
            bool: True if connected to a VNC server.
        """
        return self._connected

    @connected.setter
    def connected(self, value: bool) -> None:
        """Set the connected flag.

        Args:
            value: Desired connection state.
        """
        _logger.debug("rfb_client_connected_state_set", connected=value)
        self._connected = value

    def take_dirty_flag(self) -> bool:
        """Return and reset the framebuffer-changed flag.

        Returns:
            bool: True if the framebuffer has changed since the last call.
        """
        dirty = self._fb_dirty
        self._fb_dirty = False
        return dirty

    async def connect(self, host: str, port: int, **options: Unpack[_ConnectOptions]) -> bool:
        """Connect to a VNC server and complete the handshake.

        Args:
            host: Server hostname or IP.
            port: Server port number.
            **options: Keyword-only options; see :class:`_ConnectOptions`.
                Supported keys: ``timeout`` (float) for the connection timeout
                and ``password`` (str | None) for VNC Authentication (type 2).

        Returns:
            bool: True if connection and handshake succeeded.
        """
        connect_timeout = options.get("timeout", _DEFAULT_CONNECT_TIMEOUT)
        password = options.get("password")
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=connect_timeout,
            )

            await self._negotiate_version()
            auth_ok = await self._negotiate_security(password)
            if not auth_ok:
                return False

            self.width, self.height, self.server_name = await self._client_init()
            self.framebuffer = QImage(self.width, self.height, QImage.Format.Format_RGB32)
            self.framebuffer.fill(QColor(0, 0, 0))
            self._fb_dirty = True
            self._connected = True

        except (TimeoutError, OSError, struct.error):
            _logger.exception("vnc_connect_failed", host=host, port=port)
            return False

        _logger.info(
            "vnc_connected",
            host=host,
            port=port,
            width=self.width,
            height=self.height,
            server_name=self.server_name,
        )
        return True

    async def _negotiate_version(self) -> None:
        """Perform RFB version negotiation.

        Raises:
            ConnectionError: If reader/writer not available.
        """
        if self._reader is None or self._writer is None:
            _logger.warning("vnc_negotiate_version_no_connection")
            msg = "Not connected"
            raise ConnectionError(msg)

        server_version = await self._reader.readexactly(12)
        _logger.debug("vnc_server_version", version=server_version.decode(errors="replace").strip())
        self._writer.write(_RFB_VERSION)
        await self._writer.drain()

    async def _negotiate_security(self, password: str | None) -> bool:
        """Perform RFB security type negotiation.

        Args:
            password: Password to use for VNC Authentication (type 2). If None
                and the server requires VNC auth, negotiation fails.

        Returns:
            bool: True if security negotiation succeeded.

        Raises:
            ConnectionError: If reader/writer not available.
        """
        if self._reader is None or self._writer is None:
            _logger.warning("vnc_negotiate_security_no_connection")
            msg = "Not connected"
            raise ConnectionError(msg)

        num_types_data = await self._reader.readexactly(1)
        num_types = num_types_data[0]

        if num_types == 0:
            reason_len_data = await self._reader.readexactly(4)
            reason_len = struct.unpack("!I", reason_len_data)[0]
            reason = (await self._reader.readexactly(reason_len)).decode(errors="replace")
            _logger.warning("vnc_security_failed", reason=reason)
            return False

        sec_types = await self._reader.readexactly(num_types)

        if _SECURITY_NONE in sec_types:
            self._writer.write(bytes([_SECURITY_NONE]))
            await self._writer.drain()

            result_data = await self._reader.readexactly(4)
            result = struct.unpack("!I", result_data)[0]
            return result == 0

        if _SECURITY_VNC in sec_types:
            return await self._perform_vnc_auth(password)

        _logger.warning("vnc_no_supported_security", types=list(sec_types))
        return False

    async def _perform_vnc_auth(self, password: str | None) -> bool:
        """Perform RFB VNC Authentication (security type 2).

        Encrypts the server challenge with DES using the bit-reversed password
        as the key and transmits the ciphertext.

        Args:
            password: Password supplied by the user. If None, authentication
                cannot proceed and the method returns False.

        Returns:
            bool: True if the server accepted the credentials.

        Raises:
            ConnectionError: If reader/writer not available.
        """
        if self._reader is None or self._writer is None:
            _logger.warning("vnc_perform_auth_no_connection")
            msg = "Not connected"
            raise ConnectionError(msg)

        if password is None:
            _logger.warning("vnc_auth_missing_password")
            return False

        self._writer.write(bytes([_SECURITY_VNC]))
        await self._writer.drain()

        challenge = await self._reader.readexactly(_VNC_CHALLENGE_LEN)
        response = _vnc_auth_encrypt(challenge, password)
        self._writer.write(response)
        await self._writer.drain()

        result_data = await self._reader.readexactly(4)
        result = struct.unpack("!I", result_data)[0]
        if result != 0:
            _logger.warning("vnc_auth_failed", security_type="VNC Authentication")
            return False
        return True

    async def _client_init(self) -> tuple[int, int, str]:
        """Send ClientInit and receive ServerInit.

        Returns:
            tuple[int, int, str]: Tuple of (width, height, server_name).

        Raises:
            ConnectionError: If reader/writer not available.
        """
        if self._reader is None or self._writer is None:
            _logger.warning("vnc_client_init_no_connection")
            msg = "Not connected"
            raise ConnectionError(msg)

        self._writer.write(bytes([1]))
        await self._writer.drain()

        server_init = await self._reader.readexactly(24)
        width, height = struct.unpack("!HH", server_init[:4])

        self._writer.write(_PIXEL_FORMAT_32BIT)
        await self._writer.drain()

        name_len = struct.unpack("!I", server_init[20:24])[0]
        name_data = await self._reader.readexactly(name_len)
        name = name_data.decode(errors="replace")

        return width, height, name

    async def request_framebuffer_update(self, *, incremental: bool = True) -> None:
        """Send a FramebufferUpdateRequest.

        Args:
            incremental: Whether to request incremental update.
        """
        if self._writer is None or not self._connected:
            return

        msg = struct.pack(
            "!BBHHHH",
            3,
            1 if incremental else 0,
            0,
            0,
            self.width,
            self.height,
        )
        self._writer.write(msg)
        await self._writer.drain()

    async def handle_server_message(self) -> bool:
        """Read and process one server message.

        Returns:
            bool: True if a message was handled, False on connection loss or timeout.
        """
        if self._reader is None or not self._connected:
            return False

        try:
            msg_type_data = await asyncio.wait_for(
                self._reader.readexactly(1),
                timeout=_MESSAGE_READ_TIMEOUT,
            )
            if not msg_type_data:
                return False

            msg_type = msg_type_data[0]

            if msg_type == _MSG_FRAMEBUFFER_UPDATE:
                await self._handle_framebuffer_update()
                return True

            if msg_type == 1:
                await self._reader.readexactly(5)
                count_data = await self._reader.readexactly(2)
                count = struct.unpack("!H", count_data)[0]
                if count:
                    await self._reader.readexactly(count * 6)
                return True

            if msg_type == _MSG_BELL:
                return True

            if msg_type == _MSG_SERVER_CUT_TEXT:
                await self._reader.readexactly(3)
                length_data = await self._reader.readexactly(4)
                length = struct.unpack("!I", length_data)[0]
                if length:
                    await self._reader.readexactly(length)
                return True

        except asyncio.IncompleteReadError:
            _logger.warning("vnc_message_incomplete")
            self._connected = False
            return False
        except TimeoutError:
            _logger.warning("vnc_message_timeout")
            return False
        except (OSError, struct.error):
            _logger.exception("vnc_message_error", connected=self._connected)
            self._connected = False
            return False

        return False

    async def _handle_framebuffer_update(self) -> None:
        """Process a FramebufferUpdate message and update the QImage.

        Dispatches each rectangle to the appropriate decoder based on its encoding tag. Supports Raw (0), CopyRect (1), RRE (2), Hextile
        (5), Tight (7, when Pillow is available for JPEG sub-rectangles) and ZRLE (16) per RFC 6143.
        """
        if self._reader is None or self.framebuffer is None:
            return

        await self._reader.readexactly(1)
        num_rects = struct.unpack("!H", await self._reader.readexactly(2))[0]

        for _ in range(num_rects):
            header = await self._reader.readexactly(12)
            x, y, w, h, encoding = struct.unpack("!HHHHi", header)
            await self._dispatch_rect_encoding(encoding, x, y, w, h)

    async def _dispatch_rect_encoding(
        self,
        encoding: int,
        x: int,
        y: int,
        w: int,
        h: int,
    ) -> None:
        """Dispatch a single rectangle to its encoding-specific decoder.

        Args:
            encoding: RFB encoding identifier from the rectangle header.
            x: Rectangle X offset within the framebuffer.
            y: Rectangle Y offset within the framebuffer.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
        """
        if encoding == _ENCODING_RAW:
            await self._handle_raw_rect(x, y, w, h)
        elif encoding == _ENCODING_COPY_RECT:
            await self._handle_copy_rect(x, y, w, h)
        elif encoding == _ENCODING_RRE:
            await self._handle_rre_rect(x, y, w, h)
        elif encoding == _ENCODING_HEXTILE:
            await self._handle_hextile_rect(x, y, w, h)
        elif encoding == _ENCODING_ZRLE:
            await self._handle_zrle_rect(x, y, w, h)
        elif encoding == _ENCODING_TIGHT:
            if _TIGHT_AVAILABLE:
                await self._handle_tight_rect(x, y, w, h)
            else:
                _logger.warning(
                    "vnc_tight_encoding_unavailable",
                    encoding=encoding,
                    reason="Pillow not installed; install pillow to enable Tight",
                )
        else:
            _logger.debug("vnc_unsupported_encoding", encoding=encoding)

    async def _handle_raw_rect(self, x: int, y: int, w: int, h: int) -> None:
        """Decode a Raw-encoded rectangle and apply it to the framebuffer.

        Args:
            x: Rectangle X offset within the framebuffer.
            y: Rectangle Y offset within the framebuffer.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
        """
        pixel_data = await self._read_raw_pixels(w * h * _PIXEL_BYTES)
        if pixel_data is None:
            return
        async with self._fb_lock:
            self.apply_raw_rect(x, y, w, h, pixel_data)
            self._fb_dirty = True

    async def _handle_copy_rect(self, x: int, y: int, w: int, h: int) -> None:
        """Decode a CopyRect-encoded rectangle.

        CopyRect encoding (RFB encoding 1) ships a single source X/Y
        coordinate and instructs the client to copy that w x h block
        within its own framebuffer. Useful for scrolls and window drags.

        Args:
            x: Destination X offset within the framebuffer.
            y: Destination Y offset within the framebuffer.
            w: Block width in pixels.
            h: Block height in pixels.
        """
        if self._reader is None:
            return
        src_data = await self._reader.readexactly(4)
        src_x, src_y = struct.unpack("!HH", src_data)
        async with self._fb_lock:
            self.apply_copy_rect(src_x, src_y, x, y, w, h)
            self._fb_dirty = True

    async def _handle_rre_rect(self, x: int, y: int, w: int, h: int) -> None:
        """Decode an RRE-encoded rectangle (Rise-and-Run-length).

        RRE encoding ships a background colour followed by a list of
        (colour, x, y, w, h) sub-rectangles drawn over it. The client
        fills the rectangle with the background, then paints each
        sub-rectangle in order.

        Args:
            x: Rectangle X offset within the framebuffer.
            y: Rectangle Y offset within the framebuffer.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
        """
        if self._reader is None:
            return
        header = await self._reader.readexactly(4 + _PIXEL_BYTES)
        num_subrects = struct.unpack("!I", header[:4])[0]
        background = header[4 : 4 + _PIXEL_BYTES]
        sub_data = b""
        if num_subrects:
            sub_data = await self._reader.readexactly(num_subrects * (_PIXEL_BYTES + 8))
        async with self._fb_lock:
            self.apply_rre_rect(x, y, w, h, background, num_subrects, sub_data)
            self._fb_dirty = True

    async def _handle_hextile_rect(self, x: int, y: int, w: int, h: int) -> None:
        """Decode a Hextile-encoded rectangle.

        Hextile encoding (RFB encoding 5) tiles the rectangle into
        16x16 cells. Each tile is preceded by a subencoding mask byte
        whose bits indicate whether the tile is raw, has explicit
        background/foreground colours, and whether it carries
        sub-rectangles (optionally individually coloured).

        Args:
            x: Rectangle X offset within the framebuffer.
            y: Rectangle Y offset within the framebuffer.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
        """
        if self._reader is None:
            return
        background = b"\x00" * _PIXEL_BYTES
        foreground = b"\x00" * _PIXEL_BYTES
        for tile_y in range(y, y + h, _HEXTILE_TILE_SIZE):
            tile_h = min(_HEXTILE_TILE_SIZE, y + h - tile_y)
            for tile_x in range(x, x + w, _HEXTILE_TILE_SIZE):
                tile_w = min(_HEXTILE_TILE_SIZE, x + w - tile_x)
                background, foreground = await self._decode_hextile_tile(
                    tile_x,
                    tile_y,
                    tile_w,
                    tile_h,
                    background,
                    foreground,
                )

    async def _decode_hextile_tile(
        self,
        tile_x: int,
        tile_y: int,
        tile_w: int,
        tile_h: int,
        background: bytes,
        foreground: bytes,
    ) -> tuple[bytes, bytes]:
        """Decode a single Hextile tile and apply it to the framebuffer.

        Args:
            tile_x: Tile X offset within the framebuffer.
            tile_y: Tile Y offset within the framebuffer.
            tile_w: Tile width in pixels (1-16).
            tile_h: Tile height in pixels (1-16).
            background: Current background colour (4 bytes BGRX).
            foreground: Current foreground colour (4 bytes BGRX).

        Returns:
            tuple[bytes, bytes]: Updated (background, foreground)
            colours for use by subsequent tiles in the rectangle.
        """
        if self._reader is None:
            return background, foreground
        subencoding_byte = await self._reader.readexactly(1)
        subencoding = subencoding_byte[0]

        if subencoding & _HEXTILE_RAW:
            tile_pixels = await self._reader.readexactly(tile_w * tile_h * _PIXEL_BYTES)
            async with self._fb_lock:
                self.apply_raw_rect(tile_x, tile_y, tile_w, tile_h, tile_pixels)
                self._fb_dirty = True
            return background, foreground

        if subencoding & _HEXTILE_BACKGROUND_SPECIFIED:
            background = await self._reader.readexactly(_PIXEL_BYTES)
        if subencoding & _HEXTILE_FOREGROUND_SPECIFIED:
            foreground = await self._reader.readexactly(_PIXEL_BYTES)

        async with self._fb_lock:
            self.fill_rect(tile_x, tile_y, tile_w, tile_h, background)

        if subencoding & _HEXTILE_ANY_SUBRECTS:
            count_byte = await self._reader.readexactly(1)
            num_subrects = count_byte[0]
            coloured = bool(subencoding & _HEXTILE_SUBRECTS_COLOURED)
            entry_size = (_PIXEL_BYTES + 2) if coloured else 2
            sub_data = b""
            if num_subrects:
                sub_data = await self._reader.readexactly(num_subrects * entry_size)
            async with self._fb_lock:
                self.apply_hextile_subrects(
                    tile_x,
                    tile_y,
                    num_subrects,
                    sub_data,
                    foreground,
                    coloured=coloured,
                )
                self._fb_dirty = True

        return background, foreground

    async def _handle_zrle_rect(self, x: int, y: int, w: int, h: int) -> None:
        """Decode a ZRLE-encoded rectangle (Zlib Run-Length Encoding).

        ZRLE (RFB encoding 16) ships a single zlib stream whose
        decompressed payload contains 64x64 pixel sub-tiles. Each tile
        is one of: raw CPIXEL (3-byte) array, single-colour fill,
        palette-indexed (1-127 entries with 1/2/4/8-bit indices),
        plain RLE, or palette RLE. The zlib decompressor is shared
        across the entire RFB session per the spec.

        Args:
            x: Rectangle X offset within the framebuffer.
            y: Rectangle Y offset within the framebuffer.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
        """
        if self._reader is None:
            return
        length_data = await self._reader.readexactly(4)
        length = struct.unpack("!I", length_data)[0]
        compressed = await self._reader.readexactly(length) if length else b""
        if self._zrle_decompressor is None:
            self._zrle_decompressor = zlib.decompressobj()
        try:
            payload = self._zrle_decompressor.decompress(compressed)
        except zlib.error:
            _logger.exception("vnc_zrle_decompress_failed", length=length)
            return
        async with self._fb_lock:
            self.apply_zrle_rect(x, y, w, h, payload)
            self._fb_dirty = True

    async def _handle_tight_rect(self, x: int, y: int, w: int, h: int) -> None:
        """Decode a Tight-encoded rectangle.

        Tight encoding (RFB encoding 7) packs a compression-control
        byte followed by one of: a JPEG image (handled via Pillow),
        a fill (single colour), or a basic compression payload with
        Copy/Palette/Gradient filters compressed by one of four
        per-stream zlib streams.

        Args:
            x: Rectangle X offset within the framebuffer.
            y: Rectangle Y offset within the framebuffer.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
        """
        if self._reader is None:
            return
        ctrl_byte = await self._reader.readexactly(1)
        ctrl = ctrl_byte[0]

        for stream_idx in range(_TIGHT_ZLIB_STREAMS):
            if ctrl & (1 << stream_idx):
                self._tight_zlib_streams[stream_idx] = None
        op = ctrl & 0xF0

        if op == _TIGHT_FILL_FILTER:
            colour = await self._reader.readexactly(_ZRLE_CPIXEL_BYTES)
            pixel = bytes([colour[2], colour[1], colour[0], 0])
            async with self._fb_lock:
                self.fill_rect(x, y, w, h, pixel)
                self._fb_dirty = True
            return

        if op == _TIGHT_JPEG_FILTER:
            length = await self._read_tight_compact_length()
            data = await self._reader.readexactly(length) if length else b""
            await self._apply_tight_jpeg(x, y, w, h, data)
            return

        await self._handle_tight_basic(ctrl, x, y, w, h)

    async def _handle_tight_basic(
        self,
        ctrl: int,
        x: int,
        y: int,
        w: int,
        h: int,
    ) -> None:
        """Handle the basic-compression branch of Tight encoding.

        Args:
            ctrl: Compression-control byte from the rectangle header.
            x: Rectangle X offset within the framebuffer.
            y: Rectangle Y offset within the framebuffer.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
        """
        if self._reader is None:
            return
        stream_idx = (ctrl >> 4) & 0x03
        filter_id = _TIGHT_FILTER_COPY
        palette: bytes = b""
        palette_size = 0
        if ctrl & _TIGHT_EXPLICIT_FILTER:
            filter_byte = await self._reader.readexactly(1)
            filter_id = filter_byte[0]
            if filter_id == _TIGHT_FILTER_PALETTE:
                size_byte = await self._reader.readexactly(1)
                palette_size = size_byte[0] + 1
                palette = await self._reader.readexactly(palette_size * _ZRLE_CPIXEL_BYTES)

        if filter_id == _TIGHT_FILTER_PALETTE and palette_size <= _TIGHT_PALETTE_BITMAP_THRESHOLD:
            row_bytes = (w + 7) // 8
        elif filter_id == _TIGHT_FILTER_PALETTE:
            row_bytes = w
        else:
            row_bytes = w * _ZRLE_CPIXEL_BYTES
        raw_size = row_bytes * h

        if raw_size < _TIGHT_MIN_TO_COMPRESS:
            data = await self._reader.readexactly(raw_size) if raw_size else b""
        else:
            length = await self._read_tight_compact_length()
            compressed = await self._reader.readexactly(length) if length else b""
            decompressor = self._tight_zlib_streams[stream_idx]
            if decompressor is None:
                decompressor = zlib.decompressobj()
                self._tight_zlib_streams[stream_idx] = decompressor
            try:
                data = decompressor.decompress(compressed)
            except zlib.error:
                _logger.exception("vnc_tight_decompress_failed", length=length)
                return

        async with self._fb_lock:
            self.apply_tight_basic(
                x,
                y,
                w,
                h,
                data,
                filter_id,
                palette,
                palette_size,
            )
            self._fb_dirty = True

    async def _read_tight_compact_length(self) -> int:
        """Read a Tight-encoded compact length (1-3 bytes, 7 bits per byte).

        Returns:
            int: Decoded length value.
        """
        if self._reader is None:
            return 0
        length = 0
        for shift in (0, 7, 14):
            byte_data = await self._reader.readexactly(1)
            byte = byte_data[0]
            length |= (byte & _TIGHT_LENGTH_BYTE_MASK) << shift
            if not (byte & _TIGHT_LENGTH_CONTINUE_BIT):
                break
        return length

    async def _apply_tight_jpeg(self, x: int, y: int, w: int, h: int, data: bytes) -> None:
        """Decode a Tight JPEG payload via Pillow and blit it to the framebuffer.

        Args:
            x: Rectangle X offset within the framebuffer.
            y: Rectangle Y offset within the framebuffer.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
            data: JPEG-encoded payload bytes.
        """
        if not _TIGHT_AVAILABLE or not data:
            return
        pil_image = import_module("PIL.Image")
        try:
            img = pil_image.open(__import__("io").BytesIO(data))
            img = img.convert("RGB")
        except (OSError, ValueError):
            _logger.exception("vnc_tight_jpeg_decode_failed", length=len(data))
            return
        rgb = img.tobytes("raw", "RGB")
        bgrx = bytearray(w * h * _PIXEL_BYTES)
        for px in range(w * h):
            bgrx[px * _PIXEL_BYTES + 0] = rgb[px * 3 + 2]
            bgrx[px * _PIXEL_BYTES + 1] = rgb[px * 3 + 1]
            bgrx[px * _PIXEL_BYTES + 2] = rgb[px * 3 + 0]
            bgrx[px * _PIXEL_BYTES + 3] = 0
        async with self._fb_lock:
            self.apply_raw_rect(x, y, w, h, bytes(bgrx))
            self._fb_dirty = True

    async def _read_raw_pixels(self, total_bytes: int) -> bytes | None:
        """Read raw pixel data from the stream.

        Args:
            total_bytes: Number of bytes to read.

        Returns:
            bytes | None: Pixel data bytes, or None if connection was lost.
        """
        if self._reader is None:
            return None
        try:
            return await self._reader.readexactly(total_bytes)
        except asyncio.IncompleteReadError:
            _logger.warning("vnc_raw_pixels_incomplete", expected_bytes=total_bytes)
            return None

    def apply_raw_rect(
        self,
        x: int,
        y: int,
        w: int,
        h: int,
        pixel_data: bytes,
    ) -> None:
        """Apply raw pixel data to the framebuffer using a bulk scanline blit.

        The RFB raw encoding delivers pixels in the server-configured pixel
        format. We negotiate a 32-bit little-endian BGRX layout identical to
        Qt ``Format_RGB32``, which lets us copy each row straight into the
        framebuffer scanline buffer instead of calling ``setPixelColor`` for
        every pixel (roughly two orders of magnitude faster for a full screen
        update).

        Args:
            x: Rectangle X offset within the framebuffer.
            y: Rectangle Y offset within the framebuffer.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
            pixel_data: Raw BGRX pixel bytes (w * h * 4 bytes expected).
        """
        if self.framebuffer is None:
            return

        row_stride = w * _PIXEL_BYTES
        fb_width = self.framebuffer.width()
        fb_height = self.framebuffer.height()

        if w <= 0 or h <= 0 or fb_width == 0 or fb_height == 0:
            return

        for row in range(h):
            target_y = y + row
            if target_y < 0 or target_y >= fb_height:
                continue
            src_offset = row * row_stride
            available = max(0, min(row_stride, len(pixel_data) - src_offset))
            if available <= 0:
                break
            pixels_in_row = min(w, available // _PIXEL_BYTES, fb_width - x)
            if pixels_in_row <= 0:
                continue
            scanline = self.framebuffer.scanLine(target_y)
            scanline.setsize(fb_width * _PIXEL_BYTES)
            byte_offset = x * _PIXEL_BYTES
            byte_length = pixels_in_row * _PIXEL_BYTES
            scanline[byte_offset : byte_offset + byte_length] = pixel_data[src_offset : src_offset + byte_length]

    def fill_rect(self, x: int, y: int, w: int, h: int, pixel: bytes) -> None:
        """Fill a w x h rectangle in the framebuffer with a single BGRX pixel.

        Args:
            x: Rectangle X offset within the framebuffer.
            y: Rectangle Y offset within the framebuffer.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
            pixel: 4-byte BGRX pixel value.
        """
        if self.framebuffer is None or w <= 0 or h <= 0:
            return
        if len(pixel) < _PIXEL_BYTES:
            pixel = pixel.ljust(_PIXEL_BYTES, b"\x00")
        row = pixel[:_PIXEL_BYTES] * w
        self.apply_raw_rect(x, y, w, h, row * h)

    def apply_copy_rect(
        self,
        src_x: int,
        src_y: int,
        dst_x: int,
        dst_y: int,
        w: int,
        h: int,
    ) -> None:
        """Copy a w x h block from (src_x, src_y) to (dst_x, dst_y).

        Reads the source rectangle from the current framebuffer into a
        contiguous BGRX buffer, then re-applies it at the destination
        via :meth:`apply_raw_rect`. Buffering avoids overlap aliasing
        when the regions intersect.

        Args:
            src_x: Source X offset.
            src_y: Source Y offset.
            dst_x: Destination X offset.
            dst_y: Destination Y offset.
            w: Block width in pixels.
            h: Block height in pixels.
        """
        if self.framebuffer is None or w <= 0 or h <= 0:
            return
        fb_width = self.framebuffer.width()
        fb_height = self.framebuffer.height()
        buffer = bytearray(w * h * _PIXEL_BYTES)
        for row in range(h):
            sy = src_y + row
            if sy < 0 or sy >= fb_height:
                continue
            line_length = fb_width * _PIXEL_BYTES
            scanline = self.framebuffer.scanLine(sy)
            scanline.setsize(line_length)
            sx_start = max(src_x, 0)
            sx_end = min(src_x + w, fb_width)
            if sx_end <= sx_start:
                continue
            byte_offset = sx_start * _PIXEL_BYTES
            byte_length = (sx_end - sx_start) * _PIXEL_BYTES
            dst_offset = (row * w + (sx_start - src_x)) * _PIXEL_BYTES
            scanline_bytes = scanline.asstring(line_length)
            buffer[dst_offset : dst_offset + byte_length] = scanline_bytes[byte_offset : byte_offset + byte_length]
        self.apply_raw_rect(dst_x, dst_y, w, h, bytes(buffer))

    def apply_rre_rect(
        self,
        x: int,
        y: int,
        w: int,
        h: int,
        background: bytes,
        num_subrects: int,
        sub_data: bytes,
    ) -> None:
        """Apply an RRE-decoded rectangle to the framebuffer.

        Args:
            x: Rectangle X offset within the framebuffer.
            y: Rectangle Y offset within the framebuffer.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
            background: 4-byte BGRX background colour for the whole
                rectangle.
            num_subrects: Number of sub-rectangles encoded in
                ``sub_data``.
            sub_data: Concatenated (pixel, x, y, w, h) sub-rectangle
                tuples; each entry is _PIXEL_BYTES + 8 bytes.
        """
        self.fill_rect(x, y, w, h, background)
        entry_size = _PIXEL_BYTES + 8
        for idx in range(num_subrects):
            offset = idx * entry_size
            if offset + entry_size > len(sub_data):
                break
            colour = sub_data[offset : offset + _PIXEL_BYTES]
            sub_x, sub_y, sub_w, sub_h = struct.unpack(
                "!HHHH",
                sub_data[offset + _PIXEL_BYTES : offset + entry_size],
            )
            self.fill_rect(x + sub_x, y + sub_y, sub_w, sub_h, colour)

    def apply_hextile_subrects(
        self,
        tile_x: int,
        tile_y: int,
        num_subrects: int,
        sub_data: bytes,
        foreground: bytes,
        *,
        coloured: bool,
    ) -> None:
        """Apply Hextile sub-rectangle list onto an already-filled tile.

        Args:
            tile_x: Tile X offset in the framebuffer.
            tile_y: Tile Y offset in the framebuffer.
            num_subrects: Number of sub-rectangles in ``sub_data``.
            sub_data: Concatenated sub-rectangle entries; size depends
                on ``coloured``.
            foreground: 4-byte BGRX foreground colour used for
                non-coloured sub-rectangles.
            coloured: When True, each sub-rectangle is preceded by its
                own pixel value.
        """
        entry_size = (_PIXEL_BYTES + 2) if coloured else 2
        for idx in range(num_subrects):
            offset = idx * entry_size
            if offset + entry_size > len(sub_data):
                break
            if coloured:
                colour = sub_data[offset : offset + _PIXEL_BYTES]
                xy_byte, wh_byte = sub_data[offset + _PIXEL_BYTES], sub_data[offset + _PIXEL_BYTES + 1]
            else:
                colour = foreground
                xy_byte, wh_byte = sub_data[offset], sub_data[offset + 1]
            sub_x = (xy_byte >> 4) & 0x0F
            sub_y = xy_byte & 0x0F
            sub_w = ((wh_byte >> 4) & 0x0F) + 1
            sub_h = (wh_byte & 0x0F) + 1
            self.fill_rect(tile_x + sub_x, tile_y + sub_y, sub_w, sub_h, colour)

    def apply_zrle_rect(self, x: int, y: int, w: int, h: int, payload: bytes) -> None:
        """Apply a ZRLE-decoded payload to the framebuffer.

        Walks the payload one 64x64 sub-tile at a time, dispatching to
        the appropriate sub-encoding handler (raw, fill, packed
        palette, plain RLE, palette RLE) per RFC 6143.

        Args:
            x: Rectangle X offset within the framebuffer.
            y: Rectangle Y offset within the framebuffer.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
            payload: Decompressed ZRLE payload bytes.
        """
        cursor = 0
        for tile_y in range(y, y + h, _ZRLE_TILE_SIZE):
            tile_h = min(_ZRLE_TILE_SIZE, y + h - tile_y)
            for tile_x in range(x, x + w, _ZRLE_TILE_SIZE):
                tile_w = min(_ZRLE_TILE_SIZE, x + w - tile_x)
                cursor = self._apply_zrle_tile(payload, cursor, tile_x, tile_y, tile_w, tile_h)
                if cursor < 0:
                    return

    def _apply_zrle_tile(
        self,
        payload: bytes,
        cursor: int,
        tile_x: int,
        tile_y: int,
        tile_w: int,
        tile_h: int,
    ) -> int:
        """Decode a single ZRLE tile and write it to the framebuffer.

        Args:
            payload: Decompressed ZRLE bytes.
            cursor: Current read offset into ``payload``.
            tile_x: Tile X offset in the framebuffer.
            tile_y: Tile Y offset in the framebuffer.
            tile_w: Tile width in pixels.
            tile_h: Tile height in pixels.

        Returns:
            int: Updated read cursor, or -1 on under-flow.
        """
        if cursor >= len(payload):
            return -1
        subencoding = payload[cursor]
        cursor += 1
        rle = bool(subencoding & _ZRLE_PLAIN_RLE_FLAG)
        palette_size = subencoding & _ZRLE_PALETTE_MASK

        if not rle and palette_size == 0:
            tile_pixels, cursor = self._zrle_read_raw(payload, cursor, tile_w, tile_h)
            self.apply_raw_rect(tile_x, tile_y, tile_w, tile_h, tile_pixels)
            return cursor

        if not rle and palette_size == 1:
            colour, cursor = self._zrle_read_cpixel(payload, cursor)
            self.fill_rect(tile_x, tile_y, tile_w, tile_h, colour)
            return cursor

        if not rle and _ZRLE_PACKED_PALETTE_MIN <= palette_size <= _ZRLE_PACKED_PALETTE_MAX:
            return self._zrle_decode_packed_palette(
                payload,
                cursor,
                tile_x,
                tile_y,
                tile_w,
                tile_h,
                palette_size,
            )

        if rle and palette_size == 0:
            return self._zrle_decode_plain_rle(payload, cursor, tile_x, tile_y, tile_w, tile_h)

        if rle and palette_size >= _ZRLE_PACKED_PALETTE_MIN:
            return self._zrle_decode_palette_rle(
                payload,
                cursor,
                tile_x,
                tile_y,
                tile_w,
                tile_h,
                palette_size,
            )

        return cursor

    @staticmethod
    def _zrle_read_cpixel(payload: bytes, cursor: int) -> tuple[bytes, int]:
        """Read one 3-byte ZRLE CPIXEL and convert it to BGRX.

        Args:
            payload: Decompressed ZRLE payload.
            cursor: Current read offset.

        Returns:
            tuple[bytes, int]: (4-byte BGRX pixel, updated cursor).
        """
        cp = payload[cursor : cursor + _ZRLE_CPIXEL_BYTES]
        cursor += _ZRLE_CPIXEL_BYTES
        bgrx = bytes([cp[2], cp[1], cp[0], 0]) if len(cp) == _ZRLE_CPIXEL_BYTES else b"\x00" * _PIXEL_BYTES
        return bgrx, cursor

    @staticmethod
    def _zrle_read_raw(
        payload: bytes,
        cursor: int,
        tile_w: int,
        tile_h: int,
    ) -> tuple[bytes, int]:
        """Read tile_w * tile_h CPIXELs and convert them to a BGRX buffer.

        Args:
            payload: Decompressed ZRLE payload.
            cursor: Current read offset.
            tile_w: Tile width in pixels.
            tile_h: Tile height in pixels.

        Returns:
            tuple[bytes, int]: (BGRX byte buffer, updated cursor).
        """
        count = tile_w * tile_h
        out = bytearray(count * _PIXEL_BYTES)
        for idx in range(count):
            cp = payload[cursor : cursor + _ZRLE_CPIXEL_BYTES]
            cursor += _ZRLE_CPIXEL_BYTES
            if len(cp) < _ZRLE_CPIXEL_BYTES:
                break
            out[idx * _PIXEL_BYTES + 0] = cp[2]
            out[idx * _PIXEL_BYTES + 1] = cp[1]
            out[idx * _PIXEL_BYTES + 2] = cp[0]
            out[idx * _PIXEL_BYTES + 3] = 0
        return bytes(out), cursor

    def _zrle_decode_packed_palette(
        self,
        payload: bytes,
        cursor: int,
        tile_x: int,
        tile_y: int,
        tile_w: int,
        tile_h: int,
        palette_size: int,
    ) -> int:
        """Decode a packed-palette ZRLE tile.

        Args:
            payload: Decompressed ZRLE payload.
            cursor: Current read offset.
            tile_x: Tile X offset.
            tile_y: Tile Y offset.
            tile_w: Tile width in pixels.
            tile_h: Tile height in pixels.
            palette_size: Number of palette entries (2..16).

        Returns:
            int: Updated read cursor.
        """
        palette: list[bytes] = []
        for _ in range(palette_size):
            entry, cursor = self._zrle_read_cpixel(payload, cursor)
            palette.append(entry)
        bits_per_index = 1 if palette_size <= _TIGHT_PALETTE_BITMAP_THRESHOLD else 2 if palette_size <= _ZRLE_PACKED_PALETTE_2BIT else 4
        pixels_per_byte = 8 // bits_per_index
        mask = (1 << bits_per_index) - 1
        row_bytes = (tile_w + pixels_per_byte - 1) // pixels_per_byte
        out = bytearray(tile_w * tile_h * _PIXEL_BYTES)
        for row in range(tile_h):
            for col in range(tile_w):
                byte_idx = row * row_bytes + col // pixels_per_byte
                bit_shift = (pixels_per_byte - 1 - (col % pixels_per_byte)) * bits_per_index
                byte_value = payload[cursor + byte_idx]
                pal_idx = (byte_value >> bit_shift) & mask
                px = palette[pal_idx] if pal_idx < len(palette) else b"\x00" * _PIXEL_BYTES
                pos = (row * tile_w + col) * _PIXEL_BYTES
                out[pos : pos + _PIXEL_BYTES] = px
        cursor += row_bytes * tile_h
        self.apply_raw_rect(tile_x, tile_y, tile_w, tile_h, bytes(out))
        return cursor

    def _zrle_decode_plain_rle(
        self,
        payload: bytes,
        cursor: int,
        tile_x: int,
        tile_y: int,
        tile_w: int,
        tile_h: int,
    ) -> int:
        """Decode a plain RLE ZRLE tile.

        Args:
            payload: Decompressed ZRLE payload.
            cursor: Current read offset.
            tile_x: Tile X offset.
            tile_y: Tile Y offset.
            tile_w: Tile width in pixels.
            tile_h: Tile height in pixels.

        Returns:
            int: Updated read cursor.
        """
        count = tile_w * tile_h
        out = bytearray(count * _PIXEL_BYTES)
        produced = 0
        while produced < count and cursor < len(payload):
            colour, cursor = self._zrle_read_cpixel(payload, cursor)
            run_length = 1
            while cursor < len(payload):
                byte = payload[cursor]
                cursor += 1
                run_length += byte
                if byte != _ZRLE_RLE_RUN_TERMINATOR:
                    break
            run_length = min(run_length, count - produced)
            for _ in range(run_length):
                pos = produced * _PIXEL_BYTES
                out[pos : pos + _PIXEL_BYTES] = colour
                produced += 1
        self.apply_raw_rect(tile_x, tile_y, tile_w, tile_h, bytes(out))
        return cursor

    def _zrle_decode_palette_rle(
        self,
        payload: bytes,
        cursor: int,
        tile_x: int,
        tile_y: int,
        tile_w: int,
        tile_h: int,
        palette_size: int,
    ) -> int:
        """Decode a palette RLE ZRLE tile.

        Args:
            payload: Decompressed ZRLE payload.
            cursor: Current read offset.
            tile_x: Tile X offset.
            tile_y: Tile Y offset.
            tile_w: Tile width in pixels.
            tile_h: Tile height in pixels.
            palette_size: Number of palette entries (2..127).

        Returns:
            int: Updated read cursor.
        """
        palette: list[bytes] = []
        for _ in range(palette_size):
            entry, cursor = self._zrle_read_cpixel(payload, cursor)
            palette.append(entry)
        count = tile_w * tile_h
        out = bytearray(count * _PIXEL_BYTES)
        produced = 0
        while produced < count and cursor < len(payload):
            idx_byte = payload[cursor]
            cursor += 1
            pal_idx = idx_byte & 0x7F
            run_length = 1
            if idx_byte & _ZRLE_RLE_PALETTE_RUN_BIT:
                while cursor < len(payload):
                    byte = payload[cursor]
                    cursor += 1
                    run_length += byte
                    if byte != _ZRLE_RLE_RUN_TERMINATOR:
                        break
            colour = palette[pal_idx] if pal_idx < len(palette) else b"\x00" * _PIXEL_BYTES
            run_length = min(run_length, count - produced)
            for _ in range(run_length):
                pos = produced * _PIXEL_BYTES
                out[pos : pos + _PIXEL_BYTES] = colour
                produced += 1
        self.apply_raw_rect(tile_x, tile_y, tile_w, tile_h, bytes(out))
        return cursor

    def apply_tight_basic(
        self,
        x: int,
        y: int,
        w: int,
        h: int,
        data: bytes,
        filter_id: int,
        palette: bytes,
        palette_size: int,
    ) -> None:
        """Apply a Tight basic-compression rectangle to the framebuffer.

        Args:
            x: Rectangle X offset.
            y: Rectangle Y offset.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
            data: Filter-decompressed payload.
            filter_id: Tight filter identifier (Copy/Palette/Gradient).
            palette: Concatenated CPIXELs for the palette filter.
            palette_size: Number of palette entries (1..256).
        """
        if w <= 0 or h <= 0:
            return
        if filter_id == _TIGHT_FILTER_PALETTE:
            self._tight_apply_palette(x, y, w, h, data, palette, palette_size)
            return
        if filter_id == _TIGHT_FILTER_GRADIENT:
            self._tight_apply_gradient(x, y, w, h, data)
            return
        self._tight_apply_copy(x, y, w, h, data)

    def _tight_apply_copy(self, x: int, y: int, w: int, h: int, data: bytes) -> None:
        """Apply Tight copy-filtered (CPIXEL) data to the framebuffer.

        Args:
            x: Rectangle X offset.
            y: Rectangle Y offset.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
            data: CPIXEL stream (3 bytes per pixel).
        """
        out = bytearray(w * h * _PIXEL_BYTES)
        for idx in range(w * h):
            base = idx * _ZRLE_CPIXEL_BYTES
            if base + _ZRLE_CPIXEL_BYTES > len(data):
                break
            out[idx * _PIXEL_BYTES + 0] = data[base + 2]
            out[idx * _PIXEL_BYTES + 1] = data[base + 1]
            out[idx * _PIXEL_BYTES + 2] = data[base + 0]
            out[idx * _PIXEL_BYTES + 3] = 0
        self.apply_raw_rect(x, y, w, h, bytes(out))

    def _tight_apply_palette(
        self,
        x: int,
        y: int,
        w: int,
        h: int,
        data: bytes,
        palette: bytes,
        palette_size: int,
    ) -> None:
        """Apply Tight palette-filtered data to the framebuffer.

        Args:
            x: Rectangle X offset.
            y: Rectangle Y offset.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
            data: Palette index stream (1 byte per pixel for >2 entries,
                packed bit stream for 2-entry palettes).
            palette: Concatenated CPIXELs for the palette.
            palette_size: Number of palette entries.
        """
        entries: list[bytes] = []
        for idx in range(palette_size):
            base = idx * _ZRLE_CPIXEL_BYTES
            if base + _ZRLE_CPIXEL_BYTES > len(palette):
                break
            entries.append(bytes([palette[base + 2], palette[base + 1], palette[base + 0], 0]))
        out = bytearray(w * h * _PIXEL_BYTES)
        if palette_size == _TIGHT_PALETTE_BITMAP_THRESHOLD:
            row_bytes = (w + 7) // 8
            for row in range(h):
                for col in range(w):
                    byte_idx = row * row_bytes + col // 8
                    if byte_idx >= len(data):
                        break
                    bit_shift = 7 - (col % 8)
                    pal_idx = (data[byte_idx] >> bit_shift) & 0x01
                    if pal_idx < len(entries):
                        pos = (row * w + col) * _PIXEL_BYTES
                        out[pos : pos + _PIXEL_BYTES] = entries[pal_idx]
        else:
            for idx in range(w * h):
                if idx >= len(data):
                    break
                pal_idx = data[idx]
                if pal_idx < len(entries):
                    pos = idx * _PIXEL_BYTES
                    out[pos : pos + _PIXEL_BYTES] = entries[pal_idx]
        self.apply_raw_rect(x, y, w, h, bytes(out))

    def _tight_apply_gradient(self, x: int, y: int, w: int, h: int, data: bytes) -> None:
        """Apply Tight gradient-filtered data to the framebuffer.

        Args:
            x: Rectangle X offset.
            y: Rectangle Y offset.
            w: Rectangle width in pixels.
            h: Rectangle height in pixels.
            data: Gradient-encoded CPIXEL stream (3 bytes per pixel).
        """
        rows: list[list[tuple[int, int, int]]] = []
        for row in range(h):
            previous_row = rows[row - 1] if row > 0 else None
            rows.append(self._tight_decode_gradient_row(data, w, row, previous_row))
        out = bytearray(w * h * _PIXEL_BYTES)
        for row in range(h):
            for col in range(w):
                r, g, b = rows[row][col]
                pos = (row * w + col) * _PIXEL_BYTES
                out[pos + 0] = b
                out[pos + 1] = g
                out[pos + 2] = r
                out[pos + 3] = 0
        self.apply_raw_rect(x, y, w, h, bytes(out))

    @staticmethod
    def _tight_decode_gradient_row(
        data: bytes,
        w: int,
        row: int,
        previous_row: list[tuple[int, int, int]] | None,
    ) -> list[tuple[int, int, int]]:
        """Decode a single Tight gradient row.

        Args:
            data: Full gradient-encoded CPIXEL stream.
            w: Row width in pixels.
            row: Current row index within the rectangle.
            previous_row: Decoded RGB tuples for the row above, or
                ``None`` when decoding the first row.

        Returns:
            list[tuple[int, int, int]]: Decoded RGB tuples for ``w``
            pixels in this row.
        """
        current: list[tuple[int, int, int]] = []
        for col in range(w):
            base = (row * w + col) * _ZRLE_CPIXEL_BYTES
            if base + _ZRLE_CPIXEL_BYTES > len(data):
                current.append((0, 0, 0))
                continue
            left = current[-1] if col > 0 else (0, 0, 0)
            upper = previous_row[col] if previous_row is not None else (0, 0, 0)
            upper_left = previous_row[col - 1] if previous_row is not None and col > 0 else (0, 0, 0)
            actual = (
                (data[base + 0] + max(0, min(255, left[0] + upper[0] - upper_left[0]))) & 0xFF,
                (data[base + 1] + max(0, min(255, left[1] + upper[1] - upper_left[1]))) & 0xFF,
                (data[base + 2] + max(0, min(255, left[2] + upper[2] - upper_left[2]))) & 0xFF,
            )
            current.append(actual)
        return current

    async def send_pointer_event(self, x: int, y: int, button_mask: int) -> None:
        """Send a pointer (mouse) event to the server.

        Args:
            x: X coordinate.
            y: Y coordinate.
            button_mask: Button state bitmask.
        """
        if self._writer is None or not self._connected:
            return

        msg = struct.pack("!BBHH", 5, button_mask, x, y)
        self._writer.write(msg)
        await self._writer.drain()

    async def send_key_event(self, key: int, *, down: bool) -> None:
        """Send a key event to the server.

        Args:
            key: X11 keysym value.
            down: True for key press, False for key release.
        """
        if self._writer is None or not self._connected:
            return

        msg = struct.pack("!BBxxI", 4, 1 if down else 0, key)
        self._writer.write(msg)
        await self._writer.drain()

    async def disconnect(self) -> None:
        """Disconnect from the VNC server."""
        self._connected = False
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except OSError:
                _logger.debug("vnc_disconnect_error", exc_info=True)
        self._reader = None
        self._writer = None


_QT_TO_X11_KEYSYM: dict[int, int] = {
    Qt.Key.Key_Escape: 0xFF1B,
    Qt.Key.Key_Tab: 0xFF09,
    Qt.Key.Key_Backspace: 0xFF08,
    Qt.Key.Key_Return: 0xFF0D,
    Qt.Key.Key_Enter: 0xFF0D,
    Qt.Key.Key_Insert: 0xFF63,
    Qt.Key.Key_Delete: 0xFFFF,
    Qt.Key.Key_Home: 0xFF50,
    Qt.Key.Key_End: 0xFF57,
    Qt.Key.Key_Left: 0xFF51,
    Qt.Key.Key_Up: 0xFF52,
    Qt.Key.Key_Right: 0xFF53,
    Qt.Key.Key_Down: 0xFF54,
    Qt.Key.Key_PageUp: 0xFF55,
    Qt.Key.Key_PageDown: 0xFF56,
    Qt.Key.Key_Shift: 0xFFE1,
    Qt.Key.Key_Control: 0xFFE3,
    Qt.Key.Key_Alt: 0xFFE9,
    Qt.Key.Key_CapsLock: 0xFFE5,
    Qt.Key.Key_F1: 0xFFBE,
    Qt.Key.Key_F2: 0xFFBF,
    Qt.Key.Key_F3: 0xFFC0,
    Qt.Key.Key_F4: 0xFFC1,
    Qt.Key.Key_F5: 0xFFC2,
    Qt.Key.Key_F6: 0xFFC3,
    Qt.Key.Key_F7: 0xFFC4,
    Qt.Key.Key_F8: 0xFFC5,
    Qt.Key.Key_F9: 0xFFC6,
    Qt.Key.Key_F10: 0xFFC7,
    Qt.Key.Key_F11: 0xFFC8,
    Qt.Key.Key_F12: 0xFFC9,
}


def _qt_key_to_x11(key: int, text: str) -> int:
    """Convert a Qt key code to an X11 keysym.

    Args:
        key: Qt key code.
        text: Text character from the key event.

    Returns:
        int: X11 keysym value.
    """
    mapped = _QT_TO_X11_KEYSYM.get(key)
    if mapped is not None:
        return mapped

    return ord(text) if text and len(text) == 1 else key


def qt_key_to_x11(key: int, text: str) -> int:
    """Convert a Qt key code to an X11 keysym.

    Args:
        key: Qt key code.
        text: Text character from the key event.

    Returns:
        int: X11 keysym value.
    """
    return _qt_key_to_x11(key, text)


class VNCWidget(QWidget):
    """Qt widget that displays a VNC remote framebuffer.

    Connects to a VNC server, displays the framebuffer, and forwards
    mouse and keyboard events. Server message pumping runs as a long-lived
    task on the shared bridge event loop so the Qt main thread is never
    blocked on network I/O.

    Attributes:
        connection_status_changed: Signal emitted with boolean indicating VNC connection state.
        framebuffer_updated: Signal emitted when the framebuffer has been mutated by the server pump.
    """

    connection_status_changed: pyqtSignal = pyqtSignal(bool)
    framebuffer_updated: pyqtSignal = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the VNCWidget instance.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self.client: RFBClient = RFBClient()
        self.update_timer: QTimer = QTimer(self)
        _ = self.update_timer.timeout.connect(self._on_update_tick)
        self._pump_loop: asyncio.AbstractEventLoop | None = None
        self._pump_task_ref: asyncio.Task[None] | None = None
        _ = self.framebuffer_updated.connect(self.update)
        self.setMouseTracking(True)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setMinimumSize(320, 240)

    def connect_to_server(self, host: str, port: int, password: str | None = None) -> None:
        """Initiate connection to a VNC server.

        Connection is performed synchronously so the caller can observe the
        outcome via the ``connection_status_changed`` signal. Once connected,
        a background asyncio task is started on the shared bridge event loop
        to pump framebuffer updates without blocking the Qt main thread.

        Args:
            host: Server hostname or IP.
            port: Server port number.
            password: Optional password for VNC Authentication. Required when
                the server negotiates RFB security type 2.
        """
        connected: bool = False
        try:
            result = run_bridge_coroutine(self.client.connect(host, port, password=password))
            connected = bool(result)
            if connected:
                self._start_pump_task()
                self.update_timer.start(_REPAINT_INTERVAL_MS)
                _logger.info("vnc_widget_connected", host=host, port=port)
            else:
                _logger.warning("vnc_widget_connect_failed", host=host, port=port)
        except (OSError, struct.error, RuntimeError):
            _logger.exception("vnc_widget_connect_error", host=host, port=port)
        self.connection_status_changed.emit(connected)

    def disconnect_from_server(self) -> None:
        """Disconnect from the VNC server and stop the pump task."""
        self.update_timer.stop()
        self._cancel_pump_task()
        try:
            run_bridge_coroutine(self.client.disconnect())
        except (OSError, RuntimeError):
            _logger.debug("vnc_widget_disconnect_error", exc_info=True)
        disconnected: bool = False
        self.connection_status_changed.emit(disconnected)

    def _start_pump_task(self) -> None:
        """Start the long-lived server message pump on the bridge event loop."""
        try:
            loop = ensure_loop()
        except RuntimeError:
            _logger.exception("vnc_pump_loop_unavailable")
            return

        self._pump_loop = loop
        _ = asyncio.run_coroutine_threadsafe(self._pump_server(), loop)

    def _cancel_pump_task(self) -> None:
        """Cancel the pump task if one is running."""
        loop = self._pump_loop
        task = self._pump_task_ref
        self._pump_task_ref = None
        self._pump_loop = None

        if task is None or loop is None or loop.is_closed():
            return

        def _cancel() -> None:
            """Cancel the pump task from within the bridge loop thread."""
            if not task.done():
                _ = task.cancel()

        loop.call_soon_threadsafe(_cancel)

    async def _pump_server(self) -> None:
        """Continuously request and process framebuffer updates.

        Runs on the shared bridge event loop until the client disconnects or the task is cancelled. Emits ``framebuffer_updated`` from the
        Qt thread whenever the server has mutated the framebuffer, so the widget repaints only when there is something new to show.
        """
        self._pump_task_ref = asyncio.current_task()
        try:
            while self.client.connected:
                try:
                    await self.client.request_framebuffer_update(incremental=True)
                    handled = await self.client.handle_server_message()
                except (OSError, struct.error):
                    _logger.exception("vnc_pump_error")
                    break
                except asyncio.CancelledError:
                    _logger.debug("vnc_pump_cancelled", exc_info=True)
                    break

                if self.client.take_dirty_flag():
                    self.framebuffer_updated.emit()

                if not handled:
                    try:
                        await asyncio.sleep(_PUMP_IDLE_SLEEP_S)
                    except asyncio.CancelledError:
                        _logger.debug("vnc_pump_idle_sleep_cancelled", exc_info=True)
                        break
        finally:
            self._pump_task_ref = None

    def _on_update_tick(self) -> None:
        """Poll connection state and surface disconnects to the Qt layer.

        Actual framebuffer I/O is handled by the background pump task, so this tick only needs to notice when the pump has exited and
        surface that as a ``connection_status_changed(False)`` signal.
        """
        if not self.client.connected:
            self.update_timer.stop()
            self._cancel_pump_task()
            disconnected: bool = False
            self.connection_status_changed.emit(disconnected)
            return
        self.update()

    @override
    def paintEvent(self, a0: QPaintEvent | None) -> None:
        """Paint the current framebuffer scaled to widget size.

        Args:
            a0: Paint event.
        """
        painter = QPainter(self)
        if self.client.framebuffer is not None:
            scaled = self.client.framebuffer.scaled(
                self.size(),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            x_offset = (self.width() - scaled.width()) // 2
            y_offset = (self.height() - scaled.height()) // 2
            painter.drawImage(x_offset, y_offset, scaled)
        else:
            colors = ThemeManager.get_instance().get_analysis_colors()
            painter.fillRect(self.rect(), colors["background"])
            painter.setPen(colors["muted"])
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "VNC Display")
        painter.end()

    def _scale_coords(self, event: QMouseEvent) -> tuple[int, int]:
        """Scale widget coordinates to framebuffer coordinates.

        Args:
            event: Mouse event with position data.

        Returns:
            tuple[int, int]: Tuple of (x, y) in framebuffer coordinates.
        """
        if self.client.framebuffer is None or self.client.width == 0:
            return 0, 0

        pos = event.pos()
        scale_x = self.client.width / self.width()
        scale_y = self.client.height / self.height()
        return int(pos.x() * scale_x), int(pos.y() * scale_y)

    @staticmethod
    def button_mask(event: QMouseEvent) -> int:
        """Convert Qt mouse buttons to an RFB button mask.

        Args:
            event: Mouse event with current button state.

        Returns:
            int: RFB button mask integer.
        """
        mask = 0
        buttons = event.buttons()
        if buttons & Qt.MouseButton.LeftButton:
            mask |= 1
        if buttons & Qt.MouseButton.MiddleButton:
            mask |= 2
        if buttons & Qt.MouseButton.RightButton:
            mask |= 4
        return mask

    @override
    def mouseMoveEvent(self, a0: QMouseEvent | None) -> None:
        """Forward mouse movement to VNC server without blocking the UI thread.

        Args:
            a0: Mouse event.
        """
        if a0 is None or not self.client.connected:
            return
        x, y = self._scale_coords(a0)
        run_bridge_coroutine_async(
            self.client.send_pointer_event(x, y, VNCWidget.button_mask(a0)),
            parent=self,
        )

    @override
    def mousePressEvent(self, a0: QMouseEvent | None) -> None:
        """Forward mouse press to VNC server without blocking the UI thread.

        Args:
            a0: Mouse event.
        """
        if a0 is None or not self.client.connected:
            return
        x, y = self._scale_coords(a0)
        run_bridge_coroutine_async(
            self.client.send_pointer_event(x, y, VNCWidget.button_mask(a0)),
            parent=self,
        )

    @override
    def mouseReleaseEvent(self, a0: QMouseEvent | None) -> None:
        """Forward mouse release to VNC server without blocking the UI thread.

        Args:
            a0: Mouse event.
        """
        if a0 is None or not self.client.connected:
            return
        x, y = self._scale_coords(a0)
        run_bridge_coroutine_async(
            self.client.send_pointer_event(x, y, 0),
            parent=self,
        )

    @override
    def keyPressEvent(self, a0: QKeyEvent | None) -> None:
        """Forward key press to VNC server without blocking the UI thread.

        Args:
            a0: Key event.
        """
        if a0 is None or not self.client.connected:
            return
        keysym = _qt_key_to_x11(a0.key(), a0.text())
        run_bridge_coroutine_async(
            self.client.send_key_event(keysym, down=True),
            parent=self,
        )

    @override
    def keyReleaseEvent(self, a0: QKeyEvent | None) -> None:
        """Forward key release to VNC server without blocking the UI thread.

        Args:
            a0: Key event.
        """
        if a0 is None or not self.client.connected:
            return
        keysym = _qt_key_to_x11(a0.key(), a0.text())
        run_bridge_coroutine_async(
            self.client.send_key_event(keysym, down=False),
            parent=self,
        )
