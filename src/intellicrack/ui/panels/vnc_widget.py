# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""VNC viewer widget for QEMU sandbox display.

Implements a subset of the RFB protocol (RFC 6143) for receiving framebuffer updates from a VNC server and rendering them in a Qt widget.
Supports Raw encoding, pointer events, and key events.
"""

from __future__ import annotations

import asyncio
import struct
from typing import Final, override

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QImage, QKeyEvent, QMouseEvent, QPainter, QPaintEvent
from PyQt6.QtWidgets import QWidget

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from intellicrack.ui.resources.theme_manager import ThemeManager


_logger = get_logger("ui.panels.vnc_widget")

_RFB_VERSION: Final[bytes] = b"RFB 003.008\n"
_SECURITY_NONE: Final[int] = 1
_SECURITY_VNC: Final[int] = 2
_MSG_FRAMEBUFFER_UPDATE: Final[int] = 0
_MSG_BELL: Final[int] = 2
_MSG_SERVER_CUT_TEXT: Final[int] = 3
_ENCODING_RAW: Final[int] = 0
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
_FB_UPDATE_INTERVAL_MS: Final[int] = 50


class RFBClient:
    """Async RFB (Remote Framebuffer) protocol client.

    Implements a minimal subset of RFC 6143 sufficient for receiving raw framebuffer updates and sending pointer/key events.
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

    async def connect(self, host: str, port: int, connect_timeout: float = 10.0) -> bool:
        """Connect to a VNC server and complete the handshake.

        Args:
            host: Server hostname or IP.
            port: Server port number.
            connect_timeout: Connection timeout in seconds.

        Returns:
            bool: True if connection and handshake succeeded.
        """
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=connect_timeout,
            )

            await self._negotiate_version()
            auth_ok = await self._negotiate_security()
            if not auth_ok:
                return False

            self.width, self.height, self.server_name = await self._client_init()
            self.framebuffer = QImage(self.width, self.height, QImage.Format.Format_RGB32)
            self.framebuffer.fill(QColor(0, 0, 0))
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

        server_version = await self._reader.read(12)
        _logger.debug("vnc_server_version", version=server_version.decode(errors="replace").strip())
        self._writer.write(_RFB_VERSION)
        await self._writer.drain()

    async def _negotiate_security(self) -> bool:
        """Perform RFB security type negotiation.

        Returns:
            bool: True if security negotiation succeeded.

        Raises:
            ConnectionError: If reader/writer not available.
        """
        if self._reader is None or self._writer is None:
            msg = "Not connected"
            raise ConnectionError(msg)

        num_types_data = await self._reader.read(1)
        num_types = num_types_data[0]

        if num_types == 0:
            reason_len_data = await self._reader.read(4)
            reason_len = struct.unpack("!I", reason_len_data)[0]
            reason = (await self._reader.read(reason_len)).decode(errors="replace")
            _logger.warning("vnc_security_failed", reason=reason)
            return False

        sec_types = await self._reader.read(num_types)

        if _SECURITY_NONE in sec_types:
            self._writer.write(bytes([_SECURITY_NONE]))
            await self._writer.drain()

            result_data = await self._reader.read(4)
            result = struct.unpack("!I", result_data)[0]
            return result == 0

        if _SECURITY_VNC in sec_types:
            self._writer.write(bytes([_SECURITY_VNC]))
            await self._writer.drain()

            challenge = await self._reader.read(16)
            response = challenge
            self._writer.write(response)
            await self._writer.drain()

            result_data = await self._reader.read(4)
            result = struct.unpack("!I", result_data)[0]
            if result != 0:
                _logger.warning("vnc_auth_failed", security_type="VNC Authentication")
                return False
            return True

        _logger.warning("vnc_no_supported_security", types=list(sec_types))
        return False

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

        server_init = await self._reader.read(24)
        width, height = struct.unpack("!HH", server_init[:4])

        self._writer.write(struct.pack("!BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0))
        await self._writer.drain()

        name_len = struct.unpack("!I", server_init[20:24])[0]
        name_data = await self._reader.read(name_len)
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
            bool: True if a message was handled, False on connection loss.
        """
        if self._reader is None or not self._connected:
            return False

        try:
            msg_type_data = await asyncio.wait_for(
                self._reader.read(1),
                timeout=0.1,
            )
            if not msg_type_data:
                return False

            msg_type = msg_type_data[0]

            if msg_type == _MSG_FRAMEBUFFER_UPDATE:
                await self._handle_framebuffer_update()
                return True

            if msg_type == 1:
                await self._reader.read(5)
                count_data = await self._reader.read(2)
                count = struct.unpack("!H", count_data)[0]
                await self._reader.read(count * 6)
                return True

            if msg_type == _MSG_BELL:
                return True

            if msg_type == _MSG_SERVER_CUT_TEXT:
                await self._reader.read(3)
                length_data = await self._reader.read(4)
                length = struct.unpack("!I", length_data)[0]
                await self._reader.read(length)
                return True

        except TimeoutError:
            _logger.warning("vnc_message_timeout")
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

        await self._reader.read(1)
        num_rects = struct.unpack("!H", await self._reader.read(2))[0]

        for _ in range(num_rects):
            x, y, w, h, encoding = struct.unpack("!HHHHi", await self._reader.read(12))

            if encoding == _ENCODING_RAW:
                pixel_data = await self._read_raw_pixels(w * h * 4)
                if pixel_data is None:
                    return
                self._apply_raw_rect(x, y, w, h, pixel_data)
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
        data = b""
        remaining = total_bytes
        while remaining > 0:
            chunk = await self._reader.read(min(remaining, 65536))
            if not chunk:
                return None
            data += chunk
            remaining -= len(chunk)
        return data

    def _apply_raw_rect(
        self,
        x: int,
        y: int,
        w: int,
        h: int,
        pixel_data: bytes,
    ) -> None:
        """Apply raw pixel data to the framebuffer.

        Args:
            x: Rectangle X offset.
            y: Rectangle Y offset.
            w: Rectangle width.
            h: Rectangle height.
            pixel_data: Raw BGRA pixel bytes.
        """
        if self.framebuffer is None:
            return
        for row in range(h):
            for col in range(w):
                px_offset = (row * w + col) * 4
                if px_offset + 3 >= len(pixel_data):
                    break
                self.framebuffer.setPixelColor(
                    x + col,
                    y + row,
                    QColor(
                        pixel_data[px_offset + 2],
                        pixel_data[px_offset + 1],
                        pixel_data[px_offset],
                    ),
                )

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
    mouse and keyboard events.

    Args:
        parent: Parent widget.

    Attributes:
        connection_status_changed: Signal emitted with boolean indicating VNC connection state.
    """

    connection_status_changed: pyqtSignal = pyqtSignal(bool)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the VNCWidget instance.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self.client = RFBClient()
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._on_update_tick)
        self.setMouseTracking(enable=True)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setMinimumSize(320, 240)

    def connect_to_server(self, host: str, port: int) -> None:
        """Initiate connection to a VNC server.

        Args:
            host: Server hostname or IP.
            port: Server port number.
        """
        connected: bool = False
        try:
            result = run_bridge_coroutine(self.client.connect(host, port))
            connected = bool(result)
            if connected:
                self.update_timer.start(_FB_UPDATE_INTERVAL_MS)
                _logger.info("vnc_widget_connected", host=host, port=port)
            else:
                _logger.warning("vnc_widget_connect_failed", host=host, port=port)
        except (OSError, struct.error, RuntimeError):
            _logger.exception("vnc_widget_connect_error", host=host, port=port)
        self.connection_status_changed.emit(connected)

    def disconnect_from_server(self) -> None:
        """Disconnect from the VNC server."""
        self.update_timer.stop()
        try:
            run_bridge_coroutine(self.client.disconnect())
        except (OSError, RuntimeError):
            _logger.debug("vnc_widget_disconnect_error", exc_info=True)
        disconnected: bool = False
        self.connection_status_changed.emit(disconnected)

    def _on_update_tick(self) -> None:
        """Timer callback to request framebuffer updates and repaint."""
        if not self.client.connected:
            self.update_timer.stop()
            disconnected: bool = False
            self.connection_status_changed.emit(disconnected)
            return

        try:
            run_bridge_coroutine(self.client.request_framebuffer_update(incremental=True))
            run_bridge_coroutine(self.client.handle_server_message())
        except (OSError, struct.error, RuntimeError):
            _logger.debug("vnc_update_tick_error", exc_info=True)

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
    def _button_mask(event: QMouseEvent) -> int:
        """Convert Qt mouse buttons to RFB button mask.

        Args:
            event: Mouse event.

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
        """Forward mouse movement to VNC server.

        Args:
            a0: Mouse event.
        """
        if a0 is None or not self.client.connected:
            return
        x, y = self._scale_coords(a0)
        try:
            run_bridge_coroutine(self.client.send_pointer_event(x, y, self._button_mask(a0)))
        except (OSError, RuntimeError):
            _logger.debug("vnc_pointer_error", exc_info=True)

    @override
    def mousePressEvent(self, a0: QMouseEvent | None) -> None:
        """Forward mouse press to VNC server.

        Args:
            a0: Mouse event.
        """
        if a0 is None or not self.client.connected:
            return
        x, y = self._scale_coords(a0)
        try:
            run_bridge_coroutine(self.client.send_pointer_event(x, y, self._button_mask(a0)))
        except (OSError, RuntimeError):
            _logger.debug("vnc_pointer_error", exc_info=True)

    @override
    def mouseReleaseEvent(self, a0: QMouseEvent | None) -> None:
        """Forward mouse release to VNC server.

        Args:
            a0: Mouse event.
        """
        if a0 is None or not self.client.connected:
            return
        x, y = self._scale_coords(a0)
        try:
            run_bridge_coroutine(self.client.send_pointer_event(x, y, 0))
        except (OSError, RuntimeError):
            _logger.debug("vnc_pointer_error", exc_info=True)

    @override
    def keyPressEvent(self, a0: QKeyEvent | None) -> None:
        """Forward key press to VNC server.

        Args:
            a0: Key event.
        """
        if a0 is None or not self.client.connected:
            return
        keysym = _qt_key_to_x11(a0.key(), a0.text())
        try:
            run_bridge_coroutine(self.client.send_key_event(keysym, down=True))
        except (OSError, RuntimeError):
            _logger.debug("vnc_key_error", exc_info=True)

    @override
    def keyReleaseEvent(self, a0: QKeyEvent | None) -> None:
        """Forward key release to VNC server.

        Args:
            a0: Key event.
        """
        if a0 is None or not self.client.connected:
            return
        keysym = _qt_key_to_x11(a0.key(), a0.text())
        try:
            run_bridge_coroutine(self.client.send_key_event(keysym, down=False))
        except (OSError, RuntimeError):
            _logger.debug("vnc_key_error", exc_info=True)
