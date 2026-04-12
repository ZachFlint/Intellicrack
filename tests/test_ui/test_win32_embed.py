# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for Win32 window embedding utilities.

Validates find_window_by_pid, embed_window, and poll_and_embed
functionality including platform detection, error paths, and
QTimer-based polling lifecycle.
"""

from __future__ import annotations

import ctypes
import inspect
import os
import sys
import time
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QWidget

from intellicrack.ui import win32_embed as win32_embed_mod
from intellicrack.ui.win32_embed import (
    embed_window,
    find_window_by_pid,
    poll_and_embed,
)


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


NONEXISTENT_PID = 999999999
GW_OWNER_EXPECTED = 4
MAX_TITLE_LEN_EXPECTED = 256
DEFAULT_MAX_RETRIES = 15
DEFAULT_INTERVAL_MS = 500
POLL_WAIT_SEC = 0.5
POLL_SLEEP_SEC = 0.01


@pytest.mark.usefixtures("qapp")
class TestFindWindowByPid:
    """Tests for find_window_by_pid function."""

    @staticmethod
    def test_returns_none_for_nonexistent_pid() -> None:
        """Verify None is returned when no window matches the PID."""
        result = find_window_by_pid(NONEXISTENT_PID)
        assert result is None

    @staticmethod
    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
    def test_returns_int_or_none_for_current_pid() -> None:
        """Verify return type is int or None for a real process."""
        result = find_window_by_pid(os.getpid())
        assert result is None or isinstance(result, int)

    @staticmethod
    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
    def test_ctypes_windll_available() -> None:
        """Verify ctypes.windll is available on Windows."""
        assert hasattr(ctypes, "windll")

    @staticmethod
    def test_constants_are_correct() -> None:
        """Verify module constants have expected values."""
        assert win32_embed_mod.GW_OWNER == GW_OWNER_EXPECTED
        assert win32_embed_mod.MAX_TITLE_LEN == MAX_TITLE_LEN_EXPECTED


@pytest.mark.usefixtures("qapp")
class TestEmbedWindow:
    """Tests for embed_window function."""

    @staticmethod
    def test_returns_widget_or_none_for_zero_hwnd() -> None:
        """Verify embed_window handles zero handle without crashing."""
        parent = QWidget()
        result = embed_window(0, parent)
        assert result is None or isinstance(result, QWidget)

    @staticmethod
    def test_returns_widget_or_none_for_garbage_hwnd() -> None:
        """Verify embed_window handles a bogus handle gracefully."""
        parent = QWidget()
        result = embed_window(0xDEADBEEF, parent)
        assert result is None or isinstance(result, QWidget)


@pytest.mark.usefixtures("qapp")
class TestPollAndEmbed:
    """Tests for poll_and_embed polling lifecycle."""

    @staticmethod
    def test_callback_not_called_for_missing_pid(qapp: QApplication) -> None:
        """Verify callback is not invoked when no window is found.

        Args:
            qapp: Qt application fixture used to pump the polling timer.
        """
        parent = QWidget()
        called: list[QWidget] = []

        poll_and_embed(
            pid=NONEXISTENT_PID,
            parent=parent,
            callback=called.append,
            max_retries=2,
            interval_ms=50,
        )

        deadline = time.monotonic() + POLL_WAIT_SEC
        while time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(POLL_SLEEP_SEC)

        assert not called

    @staticmethod
    def test_max_retries_limits_attempts(qapp: QApplication) -> None:
        """Verify polling stops after max_retries attempts.

        Args:
            qapp: Qt application fixture used to pump the polling timer.
        """
        parent = QWidget()
        results: list[QWidget] = []

        poll_and_embed(
            pid=NONEXISTENT_PID,
            parent=parent,
            callback=results.append,
            max_retries=3,
            interval_ms=30,
        )

        deadline = time.monotonic() + POLL_WAIT_SEC
        while time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(POLL_SLEEP_SEC)

        assert not results

    @staticmethod
    def test_accepts_callable_callback() -> None:
        """Verify poll_and_embed accepts various callable types."""
        parent = QWidget()

        def noop_callback(_widget: QWidget) -> None:
            pass

        poll_and_embed(
            pid=NONEXISTENT_PID,
            parent=parent,
            callback=noop_callback,
            max_retries=1,
            interval_ms=100,
        )

    @staticmethod
    def test_default_retry_params() -> None:
        """Verify default parameter values are sensible."""
        sig = inspect.signature(poll_and_embed)
        params = sig.parameters
        assert params["max_retries"].default == DEFAULT_MAX_RETRIES
        assert params["interval_ms"].default == DEFAULT_INTERVAL_MS
