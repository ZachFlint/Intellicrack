# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for VNC viewer widget and RFB client.

Validates RFBClient protocol state management, VNCWidget lifecycle,
keysym conversion, framebuffer pixel application, and protocol
message construction using real RFB data structures.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtCore import QEvent, QPointF, Qt
from PyQt6.QtGui import QColor, QImage, QMouseEvent

import intellicrack.ui.panels.vnc_widget as vnc_widget_mod
from intellicrack.ui.panels.vnc_widget import (
    RFBClient,
    VNCWidget,
)


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication

FRAMEBUFFER_WIDTH = 640
FRAMEBUFFER_HEIGHT = 480
SMALL_FB_WIDTH = 4
SMALL_FB_HEIGHT = 4
VNC_PORT_UNREACHABLE = 59999

POINTER_EVENT_MSG_TYPE = 5
KEY_EVENT_MSG_TYPE = 4
FB_UPDATE_REQ_MSG_TYPE = 3
POINTER_EVENT_LEN = 6
KEY_EVENT_LEN = 8
FB_UPDATE_REQ_LEN = 10

KEYSYM_ESCAPE = 0xFF1B
KEYSYM_RETURN = 0xFF0D
KEYSYM_TAB = 0xFF09
KEYSYM_LEFT = 0xFF51
KEYSYM_UP = 0xFF52
KEYSYM_RIGHT = 0xFF53
KEYSYM_DOWN = 0xFF54
KEYSYM_F1 = 0xFFBE
KEYSYM_F12 = 0xFFC9
KEYSYM_SHIFT = 0xFFE1
KEYSYM_CONTROL = 0xFFE3
KEYSYM_ALT = 0xFFE9

MIN_VNC_WIDTH = 320
MIN_VNC_HEIGHT = 240

CONNECT_WAIT_SEC = 2.0
CONNECT_POLL_SEC = 0.01

ARBITRARY_UNMAPPED_KEY = 0x01FFFFFF

PIXEL_BYTES_PER_PIXEL = 4
PIXEL_BLUE_OFFSET = 0
PIXEL_GREEN_OFFSET = 1
PIXEL_RED_OFFSET = 2

POINTER_TEST_X = 100
POINTER_TEST_Y = 200
COLOR_FULL = 255

POINTER_BUTTON_MASK = 1
KEY_DOWN_FLAG = 1
FB_REQ_INCREMENTAL = 1

RFB_BUTTON_LEFT = 1
RFB_BUTTON_MIDDLE = 2
RFB_BUTTON_RIGHT = 4

PARTIAL_PIXEL_COUNT = 2
PARTIAL_BLUE = 128
PARTIAL_GREEN = 64
PARTIAL_RED = 32


class _RecordingWriter:
    """In-memory stand-in for :class:`asyncio.StreamWriter`.

    Captures every byte the production RFB encoders push onto the wire so the
    exact on-wire payload can be compared against an independent RFB-spec
    oracle. Only the surface the client actually uses (``write`` and an awaitable
    ``drain``) is implemented; this is the external transport boundary, not the
    unit under test.
    """

    def __init__(self) -> None:
        """Initialize the recorder with an empty byte buffer."""
        self.buffer = bytearray()

    def write(self, data: bytes) -> None:
        """Record bytes the client writes to the transport.

        Args:
            data: Bytes the client would send to the VNC server.
        """
        self.buffer.extend(data)

    async def drain(self) -> None:
        """Satisfy the awaited ``drain`` call without doing real I/O."""
        return


def _make_mouse_event(buttons: Qt.MouseButton) -> QMouseEvent:
    """Build a real ``QMouseEvent`` carrying the given pressed-button state.

    Args:
        buttons: Combined Qt mouse-button flags reported by ``event.buttons()``.

    Returns:
        QMouseEvent: A move event whose button state is ``buttons``.
    """
    origin = QPointF(0.0, 0.0)
    return QMouseEvent(
        QEvent.Type.MouseMove,
        origin,
        origin,
        Qt.MouseButton.NoButton,
        buttons,
        Qt.KeyboardModifier.NoModifier,
    )


class TestRFBClientState:
    """Tests for RFBClient initialization and state tracking."""

    @staticmethod
    def test_initial_state() -> None:
        """Verify client initializes as disconnected with zero dimensions."""
        client = RFBClient()
        assert not client.connected
        assert client.width == 0
        assert client.height == 0
        assert not client.server_name
        assert client.framebuffer is None

    @staticmethod
    def test_connected_property_reflects_internal_state() -> None:
        """Verify connected property tracks _connected flag."""
        client = RFBClient()
        assert not client.connected
        client.connected = True
        assert client.connected
        client.connected = False
        assert not client.connected

    @staticmethod
    def test_connect_to_unreachable_returns_false() -> None:
        """Verify connect returns False for unreachable server."""
        client = RFBClient()
        result = asyncio.run(client.connect("127.0.0.1", VNC_PORT_UNREACHABLE, timeout=0.5))
        assert result is False
        assert not client.connected

    @staticmethod
    def test_disconnect_idempotent() -> None:
        """Verify disconnect can be called multiple times safely."""
        client = RFBClient()
        asyncio.run(client.disconnect())
        asyncio.run(client.disconnect())
        assert not client.connected

    @staticmethod
    def test_request_framebuffer_update_when_disconnected() -> None:
        """Verify request_framebuffer_update writes nothing while disconnected."""
        client = RFBClient()
        recorder = _RecordingWriter()
        client._writer = cast("asyncio.StreamWriter", recorder)
        assert not client.connected
        asyncio.run(client.request_framebuffer_update())
        assert bytes(recorder.buffer) == b""

    @staticmethod
    def test_handle_server_message_when_disconnected() -> None:
        """Verify handle_server_message returns False when disconnected."""
        client = RFBClient()
        result = asyncio.run(client.handle_server_message())
        assert result is False


class TestRFBClientProtocolStructures:
    """Tests for RFB protocol message construction."""

    @staticmethod
    def test_pointer_event_format() -> None:
        """Verify the real send_pointer_event emits RFB-spec PointerEvent bytes."""
        client = RFBClient()
        recorder = _RecordingWriter()
        client._writer = cast("asyncio.StreamWriter", recorder)
        client.connected = True

        asyncio.run(client.send_pointer_event(POINTER_TEST_X, POINTER_TEST_Y, POINTER_BUTTON_MASK))

        wire = bytes(recorder.buffer)
        expected = (
            bytes([POINTER_EVENT_MSG_TYPE, POINTER_BUTTON_MASK]) + POINTER_TEST_X.to_bytes(2, "big") + POINTER_TEST_Y.to_bytes(2, "big")
        )
        assert len(expected) == POINTER_EVENT_LEN
        assert wire == expected

    @staticmethod
    def test_key_event_format() -> None:
        """Verify the real send_key_event emits RFB-spec KeyEvent bytes."""
        client = RFBClient()
        recorder = _RecordingWriter()
        client._writer = cast("asyncio.StreamWriter", recorder)
        client.connected = True

        asyncio.run(client.send_key_event(KEYSYM_RETURN, down=True))

        wire = bytes(recorder.buffer)
        expected = bytes([KEY_EVENT_MSG_TYPE, KEY_DOWN_FLAG, 0, 0]) + KEYSYM_RETURN.to_bytes(4, "big")
        assert len(expected) == KEY_EVENT_LEN
        assert wire == expected

    @staticmethod
    def test_key_event_release_clears_down_flag() -> None:
        """Verify a key release sets the down flag byte to zero per RFB spec."""
        client = RFBClient()
        recorder = _RecordingWriter()
        client._writer = cast("asyncio.StreamWriter", recorder)
        client.connected = True

        asyncio.run(client.send_key_event(KEYSYM_ESCAPE, down=False))

        wire = bytes(recorder.buffer)
        expected = bytes([KEY_EVENT_MSG_TYPE, 0, 0, 0]) + KEYSYM_ESCAPE.to_bytes(4, "big")
        assert wire == expected

    @staticmethod
    def test_framebuffer_update_request_format() -> None:
        """Verify request_framebuffer_update emits RFB-spec request bytes."""
        client = RFBClient()
        recorder = _RecordingWriter()
        client._writer = cast("asyncio.StreamWriter", recorder)
        client.connected = True
        client.width = FRAMEBUFFER_WIDTH
        client.height = FRAMEBUFFER_HEIGHT

        asyncio.run(client.request_framebuffer_update(incremental=True))

        wire = bytes(recorder.buffer)
        expected = (
            bytes([FB_UPDATE_REQ_MSG_TYPE, FB_REQ_INCREMENTAL])
            + (0).to_bytes(2, "big")
            + (0).to_bytes(2, "big")
            + FRAMEBUFFER_WIDTH.to_bytes(2, "big")
            + FRAMEBUFFER_HEIGHT.to_bytes(2, "big")
        )
        assert len(expected) == FB_UPDATE_REQ_LEN
        assert wire == expected

    @staticmethod
    def test_send_pointer_when_disconnected() -> None:
        """Verify send_pointer_event writes nothing while disconnected."""
        client = RFBClient()
        recorder = _RecordingWriter()
        client._writer = cast("asyncio.StreamWriter", recorder)
        assert not client.connected
        asyncio.run(client.send_pointer_event(POINTER_TEST_X, POINTER_TEST_Y, POINTER_BUTTON_MASK))
        assert bytes(recorder.buffer) == b""

    @staticmethod
    def test_send_key_when_disconnected() -> None:
        """Verify send_key_event writes nothing while disconnected."""
        client = RFBClient()
        recorder = _RecordingWriter()
        client._writer = cast("asyncio.StreamWriter", recorder)
        assert not client.connected
        asyncio.run(client.send_key_event(KEYSYM_RETURN, down=True))
        assert bytes(recorder.buffer) == b""


class TestRFBClientFramebuffer:
    """Tests for framebuffer pixel manipulation."""

    @staticmethod
    def test_apply_raw_rect_sets_pixels() -> None:
        """Verify _apply_raw_rect writes correct pixel colors."""
        client = RFBClient()
        client.framebuffer = QImage(SMALL_FB_WIDTH, SMALL_FB_HEIGHT, QImage.Format.Format_RGB32)
        client.framebuffer.fill(QColor(0, 0, 0))

        pixel_data = bytes([255, 0, 0, 0]) * (SMALL_FB_WIDTH * SMALL_FB_HEIGHT)
        client.apply_raw_rect(0, 0, SMALL_FB_WIDTH, SMALL_FB_HEIGHT, pixel_data)

        color = client.framebuffer.pixelColor(0, 0)
        assert color.red() == 0
        assert color.green() == 0
        assert color.blue() == COLOR_FULL

    @staticmethod
    def test_apply_raw_rect_partial_data() -> None:
        """Verify apply_raw_rect writes only the pixels covered by truncated data.

        Eight bytes of BGRX data describe exactly two pixels. With a row stride
        of ``SMALL_FB_WIDTH * 4`` bytes the production scanline blit can only
        fill the first two pixels of row 0; the remaining pixels of row 0 and
        every later row must retain the original fill colour.
        """
        client = RFBClient()
        client.framebuffer = QImage(SMALL_FB_WIDTH, SMALL_FB_HEIGHT, QImage.Format.Format_RGB32)
        client.framebuffer.fill(QColor(0, 0, 0))

        pixel_data = bytes([PARTIAL_BLUE, PARTIAL_GREEN, PARTIAL_RED, 0]) * PARTIAL_PIXEL_COUNT
        client.apply_raw_rect(0, 0, SMALL_FB_WIDTH, SMALL_FB_HEIGHT, pixel_data)

        for col in range(PARTIAL_PIXEL_COUNT):
            written = client.framebuffer.pixelColor(col, 0)
            assert written.red() == PARTIAL_RED
            assert written.green() == PARTIAL_GREEN
            assert written.blue() == PARTIAL_BLUE

        remainder_of_first_row = client.framebuffer.pixelColor(PARTIAL_PIXEL_COUNT, 0)
        assert remainder_of_first_row.red() == 0
        assert remainder_of_first_row.green() == 0
        assert remainder_of_first_row.blue() == 0

        untouched_row = client.framebuffer.pixelColor(0, 1)
        assert untouched_row.red() == 0
        assert untouched_row.green() == 0
        assert untouched_row.blue() == 0

    @staticmethod
    def test_apply_raw_rect_no_framebuffer() -> None:
        """Verify apply_raw_rect allocates no framebuffer when none exists."""
        client = RFBClient()
        assert client.framebuffer is None
        client.apply_raw_rect(0, 0, 1, 1, bytes(PIXEL_BYTES_PER_PIXEL))
        assert client.framebuffer is None

    @staticmethod
    def test_apply_raw_rect_at_offset() -> None:
        """Verify _apply_raw_rect applies data at correct x,y offset."""
        client = RFBClient()
        client.framebuffer = QImage(SMALL_FB_WIDTH, SMALL_FB_HEIGHT, QImage.Format.Format_RGB32)
        client.framebuffer.fill(QColor(0, 0, 0))

        pixel_data = bytes([0, 255, 0, 0])
        client.apply_raw_rect(2, 2, 1, 1, pixel_data)

        color_at = client.framebuffer.pixelColor(2, 2)
        assert color_at.green() == COLOR_FULL
        color_origin = client.framebuffer.pixelColor(0, 0)
        assert color_origin.red() == 0
        assert color_origin.green() == 0
        assert color_origin.blue() == 0


class TestQtKeyToX11:
    """Tests for Qt key to X11 keysym conversion."""

    @staticmethod
    def test_escape_key() -> None:
        """Verify Escape maps to correct X11 keysym."""
        assert vnc_widget_mod.qt_key_to_x11(Qt.Key.Key_Escape, "") == KEYSYM_ESCAPE

    @staticmethod
    def test_return_key() -> None:
        """Verify Return maps to correct X11 keysym."""
        assert vnc_widget_mod.qt_key_to_x11(Qt.Key.Key_Return, "") == KEYSYM_RETURN

    @staticmethod
    def test_tab_key() -> None:
        """Verify Tab maps to correct X11 keysym."""
        assert vnc_widget_mod.qt_key_to_x11(Qt.Key.Key_Tab, "") == KEYSYM_TAB

    @staticmethod
    def test_arrow_keys() -> None:
        """Verify arrow keys map to correct X11 keysyms."""
        assert vnc_widget_mod.qt_key_to_x11(Qt.Key.Key_Left, "") == KEYSYM_LEFT
        assert vnc_widget_mod.qt_key_to_x11(Qt.Key.Key_Up, "") == KEYSYM_UP
        assert vnc_widget_mod.qt_key_to_x11(Qt.Key.Key_Right, "") == KEYSYM_RIGHT
        assert vnc_widget_mod.qt_key_to_x11(Qt.Key.Key_Down, "") == KEYSYM_DOWN

    @staticmethod
    def test_function_keys() -> None:
        """Verify F1 and F12 map to correct keysyms."""
        assert vnc_widget_mod.qt_key_to_x11(Qt.Key.Key_F1, "") == KEYSYM_F1
        assert vnc_widget_mod.qt_key_to_x11(Qt.Key.Key_F12, "") == KEYSYM_F12

    @staticmethod
    def test_printable_char_uses_text() -> None:
        """Verify printable characters use ord(text)."""
        assert vnc_widget_mod.qt_key_to_x11(Qt.Key.Key_A, "a") == ord("a")
        assert vnc_widget_mod.qt_key_to_x11(Qt.Key.Key_A, "A") == ord("A")

    @staticmethod
    def test_unknown_key_returns_key_value() -> None:
        """Verify unmapped key with no text returns the key code."""
        assert vnc_widget_mod.qt_key_to_x11(ARBITRARY_UNMAPPED_KEY, "") == ARBITRARY_UNMAPPED_KEY

    @staticmethod
    def test_modifier_keys() -> None:
        """Verify modifier keys map to correct keysyms."""
        assert vnc_widget_mod.qt_key_to_x11(Qt.Key.Key_Shift, "") == KEYSYM_SHIFT
        assert vnc_widget_mod.qt_key_to_x11(Qt.Key.Key_Control, "") == KEYSYM_CONTROL
        assert vnc_widget_mod.qt_key_to_x11(Qt.Key.Key_Alt, "") == KEYSYM_ALT


@pytest.mark.usefixtures("qapp")
class TestVNCWidget:
    """Tests for VNCWidget Qt widget lifecycle."""

    @staticmethod
    def test_construction() -> None:
        """Verify VNCWidget constructs with its minimum size and a wired RFB client."""
        widget = VNCWidget()
        assert widget.minimumWidth() >= MIN_VNC_WIDTH
        assert widget.minimumHeight() >= MIN_VNC_HEIGHT
        assert isinstance(widget.client, RFBClient)
        assert not widget.client.connected
        assert widget.client.framebuffer is None

    @staticmethod
    def test_initial_client_disconnected() -> None:
        """Verify internal RFB client starts disconnected."""
        widget = VNCWidget()
        assert not widget.client.connected

    @staticmethod
    def test_disconnect_from_server_idempotent() -> None:
        """Verify disconnect_from_server can be called without prior connect."""
        widget = VNCWidget()
        widget.disconnect_from_server()
        assert not widget.client.connected

    @staticmethod
    def test_connect_to_unreachable_emits_false(qapp: QApplication) -> None:
        """Verify failed connection emits connection_status_changed(False).

        Args:
            qapp: Qt application fixture used to pump pending events.
        """
        widget = VNCWidget()
        statuses: list[bool] = []
        widget.connection_status_changed.connect(statuses.append)

        widget.connect_to_server("127.0.0.1", VNC_PORT_UNREACHABLE)

        deadline = time.monotonic() + CONNECT_WAIT_SEC
        while not statuses and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(CONNECT_POLL_SEC)

        assert statuses
        assert statuses[-1] is False

    @staticmethod
    def test_mouse_tracking_enabled() -> None:
        """Verify mouse tracking is enabled for cursor forwarding."""
        widget = VNCWidget()
        assert widget.hasMouseTracking()

    @staticmethod
    def test_focus_policy_strong() -> None:
        """Verify focus policy accepts keyboard input."""
        widget = VNCWidget()
        assert widget.focusPolicy() == Qt.FocusPolicy.StrongFocus

    @staticmethod
    def test_update_timer_not_running_initially() -> None:
        """Verify the framebuffer update timer is not running at start."""
        widget = VNCWidget()
        assert not widget.update_timer.isActive()

    @staticmethod
    def test_button_mask_maps_qt_buttons_to_rfb_bits() -> None:
        """Verify button_mask maps Qt mouse buttons to exact RFB bitmask values.

        Per RFB the pointer button mask uses bit 0 for the left button, bit 1
        for the middle button and bit 2 for the right button, OR-combined when
        several buttons are held.
        """
        left = _make_mouse_event(Qt.MouseButton.LeftButton)
        middle = _make_mouse_event(Qt.MouseButton.MiddleButton)
        right = _make_mouse_event(Qt.MouseButton.RightButton)
        none = _make_mouse_event(Qt.MouseButton.NoButton)
        left_and_right = _make_mouse_event(Qt.MouseButton.LeftButton | Qt.MouseButton.RightButton)

        assert VNCWidget.button_mask(left) == RFB_BUTTON_LEFT
        assert VNCWidget.button_mask(middle) == RFB_BUTTON_MIDDLE
        assert VNCWidget.button_mask(right) == RFB_BUTTON_RIGHT
        assert VNCWidget.button_mask(none) == 0
        assert VNCWidget.button_mask(left_and_right) == RFB_BUTTON_LEFT | RFB_BUTTON_RIGHT
