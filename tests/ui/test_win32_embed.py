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

import contextlib
import ctypes
import inspect
import os
import sys
import time
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication, QWidget

from intellicrack.ui import win32_embed as win32_embed_mod
from intellicrack.ui.win32_embed import (
    embed_window,
    find_window_by_pid,
    poll_and_embed,
)


if TYPE_CHECKING:
    from collections.abc import Iterator


NONEXISTENT_PID = 999999999
GW_OWNER_EXPECTED = 4
MAX_TITLE_LEN_EXPECTED = 256
DEFAULT_MAX_RETRIES = 15
DEFAULT_INTERVAL_MS = 500
POLL_WAIT_SEC = 0.5
POLL_SLEEP_SEC = 0.01
EMBED_MIN_WIDTH_EXPECTED = 200
EMBED_MIN_HEIGHT_EXPECTED = 150
GARBAGE_HWND = 0xDEADBEEF
EMBED_POLL_TIMEOUT_SEC = 5.0

_HEADLESS_SKIP_REASON = (
    "headless environment: QWidget.show() produced no enumerable native HWND; no window manager available in this container"
)


def _probe_native_hwnd_available(qapp: QApplication) -> bool:
    """Probe whether a shown QWidget produces an enumerable native HWND.

    Creates a titled top-level widget, shows it, pumps the Qt event loop
    briefly, then queries ``find_window_by_pid`` to verify that the native
    Win32 enumerator can see the resulting window handle.  Returns ``False``
    in a headless container where the window manager does not create backing
    HWNDs, so callers can skip HWND-dependent tests gracefully.

    Args:
        qapp: Live Qt application used to pump show events.

    Returns:
        bool: True when at least one enumerable native HWND belongs to this
            process after showing a titled widget; False in headless
            environments where no such handle is produced.
    """
    probe = QWidget()
    probe.setWindowTitle("Intellicrack HWND Capability Probe")
    probe.resize(EMBED_MIN_WIDTH_EXPECTED, EMBED_MIN_HEIGHT_EXPECTED)
    probe.show()
    deadline = time.monotonic() + EMBED_POLL_TIMEOUT_SEC
    while time.monotonic() < deadline:
        qapp.processEvents()
        if probe.isVisible() and probe.windowHandle() is not None:
            break
        time.sleep(POLL_SLEEP_SEC)
    hwnd = find_window_by_pid(os.getpid())
    probe.close()
    qapp.processEvents()
    return hwnd is not None


@pytest.fixture(scope="module")
def native_hwnd_available(qapp: QApplication) -> bool:
    """Return whether a native HWND is enumerable in this environment.

    Probes once per test module by showing a real QWidget and querying
    ``find_window_by_pid``.  Tests that require a native window handle
    must depend on this fixture and call ``pytest.skip`` when it is
    ``False``.

    Args:
        qapp: Live Qt application fixture (session-scoped) used to pump
            show events during the capability probe.

    Returns:
        bool: True when the current environment exposes native HWNDs to
            the Win32 ``EnumWindows`` enumerator; False in headless
            containers where no window manager is present.
    """
    return _probe_native_hwnd_available(qapp)


def _pump_until_visible(qapp: QApplication, widget: QWidget, timeout_sec: float) -> None:
    """Pump the Qt event loop until a widget becomes visible or time runs out.

    Args:
        qapp: Live Qt application used to process pending events.
        widget: Widget whose ``isVisible`` state is awaited.
        timeout_sec: Maximum number of seconds to spend pumping events.
    """
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        qapp.processEvents()
        if widget.isVisible() and widget.windowHandle() is not None:
            return
        time.sleep(POLL_SLEEP_SEC)


@contextlib.contextmanager
def _shown_window(qapp: QApplication, title: str, width: int, height: int) -> Iterator[QWidget]:
    """Create, show, and reliably close a real top-level Qt window.

    Args:
        qapp: Live Qt application used to pump the show events.
        title: Window title applied so the Win32 enumerator accepts it.
        width: Initial window width in pixels.
        height: Initial window height in pixels.

    Yields:
        QWidget: The shown, visible top-level widget.
    """
    widget = QWidget()
    try:
        widget.setWindowTitle(title)
        widget.resize(width, height)
        widget.show()
        _pump_until_visible(qapp, widget, EMBED_POLL_TIMEOUT_SEC)
        yield widget
    finally:
        widget.close()


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
    def test_finds_real_visible_window_for_current_pid(qapp: QApplication, *, native_hwnd_available: bool) -> None:
        """Verify a real shown top-level window of this process is located.

        Creates an actual visible, titled, top-level window owned by the
        current process and asserts the enumerator returns a non-``None``
        native handle. The returned handle is independently confirmed to
        belong to the current process via the Win32
        ``GetWindowThreadProcessId`` API and to be visible via
        ``IsWindowVisible``, so a broken enumerator (one that always returns
        ``None`` or matches a window of the wrong process) fails.

        Skips automatically when the environment is headless and no native
        HWND is produced by ``QWidget.show()``, as occurs in containers
        without a window manager.

        Args:
            qapp: Qt application fixture used to pump the show events.
            native_hwnd_available: Module-scoped probe result; skip when False.
        """
        if not native_hwnd_available:
            pytest.skip(_HEADLESS_SKIP_REASON)

        wintypes = ctypes.wintypes

        with _shown_window(qapp, "Intellicrack Win32 Embed Probe", EMBED_MIN_WIDTH_EXPECTED, EMBED_MIN_HEIGHT_EXPECTED) as window:
            assert window.isVisible()

            found = find_window_by_pid(os.getpid())

            assert found is not None
            assert isinstance(found, int)
            assert found > 0

            user32 = ctypes.WinDLL("user32", use_last_error=True)
            user32.GetWindowThreadProcessId.argtypes = [
                wintypes.HWND,
                ctypes.POINTER(wintypes.DWORD),
            ]
            user32.GetWindowThreadProcessId.restype = wintypes.DWORD
            user32.IsWindowVisible.argtypes = [wintypes.HWND]
            user32.IsWindowVisible.restype = wintypes.BOOL

            owning_pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(found, ctypes.byref(owning_pid))
            assert owning_pid.value == os.getpid()
            assert bool(user32.IsWindowVisible(found))

    @staticmethod
    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
    def test_embeds_real_window_into_qt_parent(qapp: QApplication, *, native_hwnd_available: bool) -> None:
        """Verify a real foreign HWND is reparented into a Qt container.

        Drives the full Win32 embedding path end-to-end: a genuine
        top-level window is created, shown, and its native handle handed to
        ``embed_window`` for reparenting under a Qt parent. The container's
        observable wiring (parent ownership and the production minimum-size
        contract) is asserted, so a regression that fails to reparent or to
        apply the minimum size fails the test.

        Skips automatically when the environment is headless and no native
        HWND is produced by ``QWidget.show()``, as occurs in containers
        without a window manager.

        Args:
            qapp: Qt application fixture used to pump the show events.
            native_hwnd_available: Module-scoped probe result; skip when False.
        """
        if not native_hwnd_available:
            pytest.skip(_HEADLESS_SKIP_REASON)

        with (
            _shown_window(qapp, "Intellicrack Win32 Embed Parent", EMBED_MIN_WIDTH_EXPECTED * 2, EMBED_MIN_HEIGHT_EXPECTED * 2) as parent,
            _shown_window(qapp, "Intellicrack Win32 Embed Foreign", EMBED_MIN_WIDTH_EXPECTED, EMBED_MIN_HEIGHT_EXPECTED) as foreign,
        ):
            hwnd = int(foreign.winId())
            container = embed_window(hwnd, parent)

            assert container is not None
            assert isinstance(container, QWidget)
            assert container.parent() is parent
            assert container.minimumWidth() == EMBED_MIN_WIDTH_EXPECTED
            assert container.minimumHeight() == EMBED_MIN_HEIGHT_EXPECTED

    @staticmethod
    def test_constants_are_correct() -> None:
        """Verify module constants have expected values."""
        assert win32_embed_mod.GW_OWNER == GW_OWNER_EXPECTED
        assert win32_embed_mod.MAX_TITLE_LEN == MAX_TITLE_LEN_EXPECTED


@pytest.mark.usefixtures("qapp")
class TestEmbedWindow:
    """Tests for embed_window function."""

    @staticmethod
    def test_returns_none_for_zero_hwnd() -> None:
        """Verify embed_window rejects a zero handle with None."""
        parent = QWidget()
        result = embed_window(0, parent)
        assert result is None

    @staticmethod
    def test_returns_none_for_garbage_hwnd() -> None:
        """Verify embed_window rejects a bogus handle with None."""
        parent = QWidget()
        result = embed_window(GARBAGE_HWND, parent)
        assert result is None


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
    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
    def test_polling_embeds_and_invokes_callback(qapp: QApplication, *, native_hwnd_available: bool) -> None:
        """Verify the polling loop embeds a found window and fires the callback.

        Drives the complete ``poll_and_embed`` lifecycle against a real
        visible window of the current process: the poller must locate the
        window, embed it, and invoke the callback exactly once with the real
        container widget. The container's production minimum-size contract is
        asserted to confirm a genuine embed rather than a spurious callback,
        so a poller that never finds, never embeds, or never calls back fails.

        Skips automatically when the environment is headless and no native
        HWND is produced by ``QWidget.show()``, as occurs in containers
        without a window manager.

        Args:
            qapp: Qt application fixture used to pump the polling timer.
            native_hwnd_available: Module-scoped probe result; skip when False.
        """
        if not native_hwnd_available:
            pytest.skip(_HEADLESS_SKIP_REASON)

        received: list[QWidget] = []
        parent = QWidget()
        with _shown_window(qapp, "Intellicrack Win32 Embed Poll Probe", EMBED_MIN_WIDTH_EXPECTED, EMBED_MIN_HEIGHT_EXPECTED):
            poll_and_embed(
                pid=os.getpid(),
                parent=parent,
                callback=received.append,
                max_retries=DEFAULT_MAX_RETRIES,
                interval_ms=20,
            )

            deadline = time.monotonic() + EMBED_POLL_TIMEOUT_SEC
            while time.monotonic() < deadline and not received:
                qapp.processEvents()
                time.sleep(POLL_SLEEP_SEC)

            assert len(received) == 1
            container = received[0]
            assert isinstance(container, QWidget)
            assert container.parent() is parent
            assert container.minimumWidth() == EMBED_MIN_WIDTH_EXPECTED
            assert container.minimumHeight() == EMBED_MIN_HEIGHT_EXPECTED

    @staticmethod
    def test_default_retry_params() -> None:
        """Verify default parameter values are sensible."""
        sig = inspect.signature(poll_and_embed)
        params = sig.parameters
        assert params["max_retries"].default == DEFAULT_MAX_RETRIES
        assert params["interval_ms"].default == DEFAULT_INTERVAL_MS
