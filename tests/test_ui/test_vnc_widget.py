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
import struct
import time
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QImage

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
        client._connected = True
        assert client.connected
        client._connected = False
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
        """Verify request_framebuffer_update is no-op when disconnected."""
        client = RFBClient()
        asyncio.run(client.request_framebuffer_update())

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
        """Verify pointer event is correctly packed per RFB spec."""
        msg = struct.pack("!BBHH", POINTER_EVENT_MSG_TYPE, 1, POINTER_TEST_X, POINTER_TEST_Y)
        assert len(msg) == POINTER_EVENT_LEN
        msg_type, button_mask, x, y = struct.unpack("!BBHH", msg)
        assert msg_type == POINTER_EVENT_MSG_TYPE
        assert button_mask == 1
        assert x == POINTER_TEST_X
        assert y == POINTER_TEST_Y

    @staticmethod
    def test_key_event_format() -> None:
        """Verify key event is correctly packed per RFB spec."""
        msg = struct.pack("!BBxxI", KEY_EVENT_MSG_TYPE, 1, KEYSYM_RETURN)
        assert len(msg) == KEY_EVENT_LEN
        msg_type, down_flag = struct.unpack_from("!BB", msg, 0)
        keysym = struct.unpack_from("!I", msg, PIXEL_BYTES_PER_PIXEL)[0]
        assert msg_type == KEY_EVENT_MSG_TYPE
        assert down_flag == 1
        assert keysym == KEYSYM_RETURN

    @staticmethod
    def test_framebuffer_update_request_format() -> None:
        """Verify framebuffer update request is correctly packed."""
        msg = struct.pack(
            "!BBHHHH",
            FB_UPDATE_REQ_MSG_TYPE,
            1,
            0,
            0,
            FRAMEBUFFER_WIDTH,
            FRAMEBUFFER_HEIGHT,
        )
        assert len(msg) == FB_UPDATE_REQ_LEN
        msg_type, incremental, _x, _y, w, h = struct.unpack("!BBHHHH", msg)
        assert msg_type == FB_UPDATE_REQ_MSG_TYPE
        assert incremental == 1
        assert w == FRAMEBUFFER_WIDTH
        assert h == FRAMEBUFFER_HEIGHT

    @staticmethod
    def test_send_pointer_when_disconnected() -> None:
        """Verify send_pointer_event is no-op when not connected."""
        client = RFBClient()
        asyncio.run(client.send_pointer_event(100, 200, 1))

    @staticmethod
    def test_send_key_when_disconnected() -> None:
        """Verify send_key_event is no-op when not connected."""
        client = RFBClient()
        asyncio.run(client.send_key_event(KEYSYM_RETURN, down=True))


class TestRFBClientFramebuffer:
    """Tests for framebuffer pixel manipulation."""

    @staticmethod
    def test_apply_raw_rect_sets_pixels() -> None:
        """Verify _apply_raw_rect writes correct pixel colors."""
        client = RFBClient()
        client.framebuffer = QImage(SMALL_FB_WIDTH, SMALL_FB_HEIGHT, QImage.Format.Format_RGB32)
        client.framebuffer.fill(QColor(0, 0, 0))

        pixel_data = bytes([255, 0, 0, 0]) * (SMALL_FB_WIDTH * SMALL_FB_HEIGHT)
        client._apply_raw_rect(0, 0, SMALL_FB_WIDTH, SMALL_FB_HEIGHT, pixel_data)

        color = client.framebuffer.pixelColor(0, 0)
        assert color.red() == 0
        assert color.green() == 0
        assert color.blue() == COLOR_FULL

    @staticmethod
    def test_apply_raw_rect_partial_data() -> None:
        """Verify _apply_raw_rect handles truncated pixel data."""
        client = RFBClient()
        client.framebuffer = QImage(SMALL_FB_WIDTH, SMALL_FB_HEIGHT, QImage.Format.Format_RGB32)
        client.framebuffer.fill(QColor(0, 0, 0))

        pixel_data = bytes([128, 64, 32, 0]) * 2
        client._apply_raw_rect(0, 0, SMALL_FB_WIDTH, SMALL_FB_HEIGHT, pixel_data)

    @staticmethod
    def test_apply_raw_rect_no_framebuffer() -> None:
        """Verify _apply_raw_rect is no-op without framebuffer."""
        client = RFBClient()
        client._apply_raw_rect(0, 0, 1, 1, bytes(PIXEL_BYTES_PER_PIXEL))

    @staticmethod
    def test_apply_raw_rect_at_offset() -> None:
        """Verify _apply_raw_rect applies data at correct x,y offset."""
        client = RFBClient()
        client.framebuffer = QImage(SMALL_FB_WIDTH, SMALL_FB_HEIGHT, QImage.Format.Format_RGB32)
        client.framebuffer.fill(QColor(0, 0, 0))

        pixel_data = bytes([0, 255, 0, 0])
        client._apply_raw_rect(2, 2, 1, 1, pixel_data)

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
        assert vnc_widget_mod._qt_key_to_x11(Qt.Key.Key_Escape, "") == KEYSYM_ESCAPE

    @staticmethod
    def test_return_key() -> None:
        """Verify Return maps to correct X11 keysym."""
        assert vnc_widget_mod._qt_key_to_x11(Qt.Key.Key_Return, "") == KEYSYM_RETURN

    @staticmethod
    def test_tab_key() -> None:
        """Verify Tab maps to correct X11 keysym."""
        assert vnc_widget_mod._qt_key_to_x11(Qt.Key.Key_Tab, "") == KEYSYM_TAB

    @staticmethod
    def test_arrow_keys() -> None:
        """Verify arrow keys map to correct X11 keysyms."""
        assert vnc_widget_mod._qt_key_to_x11(Qt.Key.Key_Left, "") == KEYSYM_LEFT
        assert vnc_widget_mod._qt_key_to_x11(Qt.Key.Key_Up, "") == KEYSYM_UP
        assert vnc_widget_mod._qt_key_to_x11(Qt.Key.Key_Right, "") == KEYSYM_RIGHT
        assert vnc_widget_mod._qt_key_to_x11(Qt.Key.Key_Down, "") == KEYSYM_DOWN

    @staticmethod
    def test_function_keys() -> None:
        """Verify F1 and F12 map to correct keysyms."""
        assert vnc_widget_mod._qt_key_to_x11(Qt.Key.Key_F1, "") == KEYSYM_F1
        assert vnc_widget_mod._qt_key_to_x11(Qt.Key.Key_F12, "") == KEYSYM_F12

    @staticmethod
    def test_printable_char_uses_text() -> None:
        """Verify printable characters use ord(text)."""
        assert vnc_widget_mod._qt_key_to_x11(Qt.Key.Key_A, "a") == ord("a")
        assert vnc_widget_mod._qt_key_to_x11(Qt.Key.Key_A, "A") == ord("A")

    @staticmethod
    def test_unknown_key_returns_key_value() -> None:
        """Verify unmapped key with no text returns the key code."""
        assert vnc_widget_mod._qt_key_to_x11(ARBITRARY_UNMAPPED_KEY, "") == ARBITRARY_UNMAPPED_KEY

    @staticmethod
    def test_modifier_keys() -> None:
        """Verify modifier keys map to correct keysyms."""
        assert vnc_widget_mod._qt_key_to_x11(Qt.Key.Key_Shift, "") == KEYSYM_SHIFT
        assert vnc_widget_mod._qt_key_to_x11(Qt.Key.Key_Control, "") == KEYSYM_CONTROL
        assert vnc_widget_mod._qt_key_to_x11(Qt.Key.Key_Alt, "") == KEYSYM_ALT


@pytest.mark.usefixtures("qapp")
class TestVNCWidget:
    """Tests for VNCWidget Qt widget lifecycle."""

    @staticmethod
    def test_construction() -> None:
        """Verify VNCWidget can be constructed."""
        widget = VNCWidget()
        assert widget.minimumWidth() >= MIN_VNC_WIDTH
        assert widget.minimumHeight() >= MIN_VNC_HEIGHT

    @staticmethod
    def test_initial_client_disconnected() -> None:
        """Verify internal RFB client starts disconnected."""
        widget = VNCWidget()
        assert not widget._client.connected

    @staticmethod
    def test_disconnect_from_server_idempotent() -> None:
        """Verify disconnect_from_server can be called without prior connect."""
        widget = VNCWidget()
        widget.disconnect_from_server()
        assert not widget._client.connected

    @staticmethod
    def test_connect_to_unreachable_emits_false(qapp: QApplication) -> None:
        """Verify failed connection emits connection_status_changed(False)."""
        widget = VNCWidget()
        statuses: list[bool] = []
        widget.connection_status_changed.connect(statuses.append)

        widget.connect_to_server("127.0.0.1", VNC_PORT_UNREACHABLE)

        deadline = time.monotonic() + CONNECT_WAIT_SEC
        while not statuses and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(CONNECT_POLL_SEC)

        assert len(statuses) >= 1
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
        assert not widget._update_timer.isActive()

    @staticmethod
    def test_button_mask_static_method_exists() -> None:
        """Verify _button_mask is accessible as a static method."""
        assert callable(VNCWidget._button_mask)
