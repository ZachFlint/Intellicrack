# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for GUI audit finding M3 (VNC framebuffer thread safety).

Finding M3: ``apply_raw_rect`` writes to the framebuffer on the shared bridge
event loop while ``paintEvent`` read ``client.framebuffer.scaled(...)`` on the
Qt GUI thread. The ``asyncio.Lock`` only serialised bridge-loop coroutines and
never guarded ``paintEvent``, so the GUI thread could read a partially written
QImage (torn frame or freed-buffer crash).

These tests assert the fix: the bridge loop builds into a back buffer and
atomically publishes a completed copy under a ``threading.Lock`` that
``paintEvent`` also holds when reading, so a consumer never observes an
intermediate buffer.
"""

from __future__ import annotations

import asyncio
import threading
from typing import TYPE_CHECKING

from PyQt6.QtGui import QColor, QImage

from intellicrack.ui.panels.vnc_widget import RFBClient, VNCWidget


if TYPE_CHECKING:
    from types import TracebackType

    import pytest


FB_SIZE = 32
COLOR_A = (200, 10, 10)
COLOR_B = (10, 20, 210)
CONCURRENCY_ITERATIONS = 300


def _make_framebuffer(width: int, height: int, rgb: tuple[int, int, int]) -> QImage:
    """Create a solid-colour RGB32 framebuffer.

    Args:
        width: Framebuffer width in pixels.
        height: Framebuffer height in pixels.
        rgb: Fill colour as an ``(r, g, b)`` triple.

    Returns:
        QImage: A freshly filled ``Format_RGB32`` image.
    """
    image = QImage(width, height, QImage.Format.Format_RGB32)
    image.fill(QColor(rgb[0], rgb[1], rgb[2]))
    return image


def _solid_bgrx(width: int, height: int, rgb: tuple[int, int, int]) -> bytes:
    """Build a solid-colour BGRX pixel buffer for ``apply_raw_rect``.

    Args:
        width: Rectangle width in pixels.
        height: Rectangle height in pixels.
        rgb: Colour as an ``(r, g, b)`` triple.

    Returns:
        bytes: ``width * height * 4`` BGRX bytes.
    """
    pixel = bytes([rgb[2], rgb[1], rgb[0], 0])
    return pixel * (width * height)


def _is_uniform(image: QImage) -> bool:
    """Return whether every pixel of ``image`` is identical.

    Args:
        image: Image to inspect.

    Returns:
        bool: ``True`` when all sampled pixels share one colour.
    """
    reference = image.pixel(0, 0)
    return all(image.pixel(x, y) == reference for y in range(image.height()) for x in range(image.width()))


class _RecordingLock:
    """A context-manager lock wrapper that counts how often it is entered."""

    def __init__(self) -> None:
        """Initialise the recording lock over a real ``threading.Lock``."""
        self._lock: threading.Lock = threading.Lock()
        self.enter_count: int = 0

    def __enter__(self) -> bool:
        """Acquire the underlying lock and record the entry.

        Returns:
            bool: The result of acquiring the wrapped lock.
        """
        self.enter_count += 1
        return self._lock.__enter__()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Release the underlying lock.

        Args:
            exc_type: Exception type raised in the guarded block, if any.
            exc: Exception instance raised in the guarded block, if any.
            tb: Active traceback, if any.
        """
        self._lock.__exit__(exc_type, exc, tb)


class TestFramebufferDoubleBuffering:
    """M3: publish/consume must double-buffer under a threading lock."""

    @staticmethod
    def test_publish_frame_creates_independent_copy() -> None:
        """publish_frame must snapshot a copy distinct from the live back buffer.

        A shared reference would let the GUI thread read a buffer the bridge
        loop is still mutating; the fix publishes an independent copy.
        """
        client = RFBClient()
        client.framebuffer = _make_framebuffer(FB_SIZE, FB_SIZE, COLOR_A)
        client.publish_frame()

        snapshot = client.snapshot_frame()
        assert snapshot is not None
        assert snapshot is not client.framebuffer

    @staticmethod
    def test_snapshot_is_stable_across_backbuffer_mutation() -> None:
        """A published snapshot must not change when the back buffer is mutated.

        This is the core double-buffering guarantee: once published, the frame
        the GUI thread reads is immutable until the next publish.
        """
        client = RFBClient()
        client.framebuffer = _make_framebuffer(FB_SIZE, FB_SIZE, COLOR_A)
        client.publish_frame()
        first = client.snapshot_frame()
        assert first is not None
        first_pixel = first.pixel(0, 0)

        client.apply_raw_rect(0, 0, FB_SIZE, FB_SIZE, _solid_bgrx(FB_SIZE, FB_SIZE, COLOR_B))
        still_first = client.snapshot_frame()
        assert still_first is not None
        assert still_first.pixel(0, 0) == first_pixel

        client.publish_frame()
        updated = client.snapshot_frame()
        assert updated is not None
        assert updated.pixel(0, 0) != first_pixel

    @staticmethod
    def test_publish_and_snapshot_acquire_same_lock() -> None:
        """Both publish and consume must hold the shared threading lock.

        A writer that swaps without the lock, or a reader that reads without it,
        reintroduces the torn-frame race.
        """
        client = RFBClient()
        recording = _RecordingLock()
        setattr(client, "_publish_lock", recording)
        client.framebuffer = _make_framebuffer(FB_SIZE, FB_SIZE, COLOR_A)

        client.publish_frame()
        assert recording.enter_count == 1
        assert client.snapshot_frame() is not None
        assert recording.enter_count == 2

    @staticmethod
    def test_publish_lock_is_threading_not_asyncio() -> None:
        """The publish lock must be a threading lock, distinct from the asyncio lock.

        Only a threading lock can guard the GUI thread's paintEvent; the
        asyncio lock still serialises the bridge-loop decoders.
        """
        client = RFBClient()
        publish_lock = getattr(client, "_publish_lock")
        fb_lock = getattr(client, "_fb_lock")
        assert not isinstance(publish_lock, asyncio.Lock)
        assert isinstance(fb_lock, asyncio.Lock)
        with publish_lock:
            pass

    @staticmethod
    def test_concurrent_publish_never_exposes_partial_frame() -> None:
        """A reader must never observe a half-written frame under concurrency.

        A writer thread builds alternating solid frames via row-level blits and
        publishes each completed frame, while the reader repeatedly snapshots.
        Because publish installs a completed copy, every snapshot is a single
        solid colour; a torn read would surface a mixed (non-uniform) image.
        """
        client = RFBClient()
        client.framebuffer = _make_framebuffer(FB_SIZE, FB_SIZE, COLOR_A)
        client.publish_frame()

        stop = threading.Event()
        failures: list[str] = []

        def _writer() -> None:
            """Alternate the back buffer between two solid colours and publish."""
            data_a = _solid_bgrx(FB_SIZE, FB_SIZE, COLOR_A)
            data_b = _solid_bgrx(FB_SIZE, FB_SIZE, COLOR_B)
            for i in range(CONCURRENCY_ITERATIONS):
                payload = data_a if i % 2 == 0 else data_b
                client.apply_raw_rect(0, 0, FB_SIZE, FB_SIZE, payload)
                client.publish_frame()
            stop.set()

        writer = threading.Thread(target=_writer, name="m3-writer")
        writer.start()
        try:
            while not stop.is_set():
                snapshot = client.snapshot_frame()
                if snapshot is not None and not _is_uniform(snapshot):
                    failures.append("partial frame observed")
                    break
        finally:
            stop.set()
            writer.join(timeout=10.0)

        assert not writer.is_alive()
        assert not failures


class TestPaintEventUsesSnapshot:
    """M3: paintEvent must read the published snapshot, not the live buffer."""

    @staticmethod
    def test_paint_event_reads_snapshot(qapp: object, monkeypatch: pytest.MonkeyPatch) -> None:
        """The paint path must obtain its image via snapshot_frame.

        Args:
            qapp: Session QApplication fixture (unused directly, ensures a Qt app).
            monkeypatch: Fixture used to spy on ``snapshot_frame``.
        """
        _ = qapp
        widget = VNCWidget()
        widget.client.framebuffer = _make_framebuffer(FB_SIZE, FB_SIZE, COLOR_A)
        widget.client.publish_frame()
        widget.resize(120, 120)

        calls: list[bool] = []
        original = widget.client.snapshot_frame

        def _spy() -> QImage | None:
            """Record the call and defer to the real snapshot.

            Returns:
                QImage | None: The real published snapshot.
            """
            calls.append(True)
            return original()

        monkeypatch.setattr(widget.client, "snapshot_frame", _spy)
        _ = widget.grab()

        assert calls
