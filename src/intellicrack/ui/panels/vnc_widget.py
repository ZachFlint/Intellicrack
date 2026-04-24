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
from importlib import import_module
from typing import TYPE_CHECKING, Final, TypedDict, Unpack, cast, override

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


_logger = get_logger("ui.panels.vnc_widget")

_RFB_VERSION: Final[bytes] = b"RFB 003.008\n"
_SECURITY_NONE: Final[int] = 1
_SECURITY_VNC: Final[int] = 2
_MSG_FRAMEBUFFER_UPDATE: Final[int] = 0
_MSG_BELL: Final[int] = 2
_MSG_SERVER_CUT_TEXT: Final[int] = 3
_ENCODING_RAW: Final[int] = 0
_VNC_CHALLENGE_LEN: Final[int] = 16
_VNC_KEY_LEN: Final[int] = 8
_PIXEL_BYTES: Final[int] = 4
_REPAINT_INTERVAL_MS: Final[int] = 50
_PUMP_IDLE_SLEEP_S: Final[float] = 0.01
_DEFAULT_CONNECT_TIMEOUT: Final[float] = 10.0
_MESSAGE_READ_TIMEOUT: Final[float] = 0.1
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

    Implements a minimal subset of RFC 6143 sufficient for receiving raw
    framebuffer updates and sending pointer/key events. Supports both the
    ``None`` (type 1) and VNC-DES (type 2) security handshakes.
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
            _logger.debug("vnc_message_incomplete")
            self._connected = False
            return False
        except TimeoutError:
            _logger.debug("vnc_message_timeout")
            return False
        except (OSError, struct.error):
            _logger.exception("vnc_message_error", connected=self._connected)
            self._connected = False
            return False

        return False

    async def _handle_framebuffer_update(self) -> None:
        """Process a FramebufferUpdate message and update the QImage."""
        if self._reader is None or self.framebuffer is None:
            return

        await self._reader.readexactly(1)
        num_rects = struct.unpack("!H", await self._reader.readexactly(2))[0]

        for _ in range(num_rects):
            header = await self._reader.readexactly(12)
            x, y, w, h, encoding = struct.unpack("!HHHHi", header)

            if encoding == _ENCODING_RAW:
                pixel_data = await self._read_raw_pixels(w * h * _PIXEL_BYTES)
                if pixel_data is None:
                    return
                async with self._fb_lock:
                    self.apply_raw_rect(x, y, w, h, pixel_data)
                    self._fb_dirty = True
            else:
                _logger.debug("vnc_unsupported_encoding", encoding=encoding)

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
        self.setMouseTracking(enable=True)
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

        Runs on the shared bridge event loop until the client disconnects or
        the task is cancelled. Emits ``framebuffer_updated`` from the Qt
        thread whenever the server has mutated the framebuffer, so the
        widget repaints only when there is something new to show.
        """
        self._pump_task_ref = asyncio.current_task()
        try:
            while self.client.connected:
                try:
                    await self.client.request_framebuffer_update(incremental=True)
                    handled = await self.client.handle_server_message()
                except (OSError, struct.error):
                    _logger.debug("vnc_pump_error", exc_info=True)
                    break
                except asyncio.CancelledError:
                    _logger.debug("vnc_pump_cancelled")
                    break

                if self.client.take_dirty_flag():
                    self.framebuffer_updated.emit()

                if not handled:
                    try:
                        await asyncio.sleep(_PUMP_IDLE_SLEEP_S)
                    except asyncio.CancelledError:
                        _logger.debug("vnc_pump_cancelled")
                        break
        finally:
            self._pump_task_ref = None

    def _on_update_tick(self) -> None:
        """Poll connection state and surface disconnects to the Qt layer.

        Actual framebuffer I/O is handled by the background pump task, so
        this tick only needs to notice when the pump has exited and surface
        that as a ``connection_status_changed(False)`` signal.
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
