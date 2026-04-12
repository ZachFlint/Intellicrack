# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for hex editor async search workers.

Verifies SearchWorker and NumericSearchWorker construction,
hex/text search execution, error signal emission, and numeric
fallback scanning against real byte data.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, NoReturn

import pytest

from intellicrack.ui.panels.hex_editor import NumericSearchWorker, SearchWorker

from .conftest import SignalRecorder


if TYPE_CHECKING:
    from pytestqt.qtbot import QtBot


class SimpleDocument:
    """Real document with search methods operating on actual byte data.

    Args:
        data: Raw byte content to search within.
    """

    def __init__(self, data: bytes) -> None:
        self._data: bytes = data

    def search_hex(self, query: str, max_results: int) -> list[tuple[int, int]]:
        """Search for hex byte pattern in the document.

        Args:
            query: Hex string without spaces (e.g. "DEADBEEF").
            max_results: Maximum number of matches to return.

        Returns:
            list[tuple[int, int]]: List of (offset, length) tuples.
        """
        needle = bytes.fromhex(query)
        results: list[tuple[int, int]] = []
        start = 0
        while len(results) < max_results:
            idx = self._data.find(needle, start)
            if idx == -1:
                break
            results.append((idx, len(needle)))
            start = idx + 1
        return results

    def search_text(
        self,
        query: str,
        encoding: str,
        *,
        case_sensitive: bool,
        max_results: int,
    ) -> list[tuple[int, int]]:
        """Search for text string in the document using the given encoding.

        Args:
            query: Text string to search for.
            encoding: Character encoding name.
            case_sensitive: Whether matching is case-sensitive.
            max_results: Maximum number of matches to return.

        Returns:
            list[tuple[int, int]]: List of (offset, length) tuples.
        """
        needle = query.encode(encoding)
        haystack = self._data
        if not case_sensitive:
            needle = needle.lower()
            haystack = haystack.lower()
        results: list[tuple[int, int]] = []
        start = 0
        while len(results) < max_results:
            idx = haystack.find(needle, start)
            if idx == -1:
                break
            results.append((idx, len(needle)))
            start = idx + 1
        return results

    def length(self) -> int:
        """Return the total length of the document data.

        Returns:
            int: Number of bytes in the document.
        """
        return len(self._data)

    def read(self, offset: int, length: int) -> bytes:
        """Read a slice of bytes from the document.

        Args:
            offset: Start offset in bytes.
            length: Number of bytes to read.

        Returns:
            bytes: The requested byte slice.
        """
        return self._data[offset : offset + length]


class ErrorDocument:
    """Document that raises ValueError on any search call.

    Used to test error signal emission from search workers.
    """

    def search_hex(self, _query: str, _max_results: int) -> NoReturn:
        """Raise ValueError unconditionally.

        Args:
            _query: Ignored query pattern placeholder.
            _max_results: Ignored maximum-results placeholder.

        Raises:
            ValueError: Always raised for testing.
        """
        msg = "intentional test error"
        raise ValueError(msg)


@pytest.mark.usefixtures("qapp")
class TestSearchWorkerConstruction:
    """Tests for SearchWorker attribute assignment."""

    @staticmethod
    def test_search_worker_construction() -> None:
        """Verify worker stores document, mode, query, encoding, and max_results."""
        data = b"\x00" * 16
        doc = SimpleDocument(data)
        worker = SearchWorker(doc, "Hex", "00", "utf-8", 50)

        assert worker.document is doc
        assert worker.mode == "Hex"
        assert worker.query == "00"
        assert worker.encoding == "utf-8"
        assert worker.max_results == 50


@pytest.mark.usefixtures("qapp")
class TestSearchWorkerExecution:
    """Tests for SearchWorker hex and text search execution."""

    @staticmethod
    def test_search_worker_hex_search(qtbot: QtBot) -> None:
        """Verify hex search finds expected offsets in repeated pattern.

        Args:
            qtbot: pytest-qt bot fixture used to wait on Qt signals.
        """
        pattern = b"\xde\xad\xbe\xef"
        data = pattern * 4
        doc = SimpleDocument(data)
        worker = SearchWorker(doc, "Hex", "DEAD", "utf-8", 100)

        recorder = SignalRecorder()
        worker.search_finished.connect(recorder)

        with qtbot.waitSignal(worker.search_finished, timeout=5000):
            worker.start()

        assert recorder.times_called == 1
        results: list[tuple[int, int]] = recorder.calls[0][0]
        offsets = [r[0] for r in results]
        assert 0 in offsets
        assert 4 in offsets
        assert 8 in offsets
        assert 12 in offsets

    @staticmethod
    def test_search_worker_text_search(qtbot: QtBot) -> None:
        """Verify text search locates ASCII string in document.

        Args:
            qtbot: pytest-qt bot fixture used to wait on Qt signals.
        """
        data = b"prefix_hello_suffix_hello_end"
        doc = SimpleDocument(data)
        worker = SearchWorker(doc, "Text", "hello", "utf-8", 100)

        recorder = SignalRecorder()
        worker.search_finished.connect(recorder)

        with qtbot.waitSignal(worker.search_finished, timeout=5000):
            worker.start()

        assert recorder.times_called == 1
        results: list[tuple[int, int]] = recorder.calls[0][0]
        offsets = [r[0] for r in results]
        assert 7 in offsets
        assert 20 in offsets
        assert all(length == 5 for _, length in results)


@pytest.mark.usefixtures("qapp")
class TestSearchWorkerError:
    """Tests for SearchWorker error signal emission."""

    @staticmethod
    def test_search_worker_error(qtbot: QtBot) -> None:
        """Verify search_error is emitted when document raises ValueError.

        Args:
            qtbot: pytest-qt bot fixture used to wait on Qt signals.
        """
        doc = ErrorDocument()
        worker = SearchWorker(doc, "Hex", "DEAD", "utf-8", 100)

        recorder = SignalRecorder()
        worker.search_error.connect(recorder)

        with qtbot.waitSignal(worker.search_error, timeout=5000):
            worker.start()

        assert recorder.times_called == 1
        exc = recorder.calls[0][0]
        assert isinstance(exc, ValueError)
        assert "intentional test error" in str(exc)


@pytest.mark.usefixtures("qapp")
class TestNumericSearchWorker:
    """Tests for NumericSearchWorker fallback scanning."""

    @staticmethod
    def test_numeric_search_worker_fallback(qtbot: QtBot) -> None:
        """Verify fallback scan finds known 32-bit value in byte data.

        Args:
            qtbot: pytest-qt bot fixture used to wait on Qt signals.
        """
        target_value: int = 42
        packed = struct.pack("<I", target_value)
        data = b"\x00" * 8 + packed + b"\x00" * 8 + packed + b"\x00" * 4
        doc = SimpleDocument(data)

        worker = NumericSearchWorker(
            doc,
            min_val=42.0,
            max_val=42.0,
            fmt="<I",
            byte_width=4,
            alignment=1,
            max_results=100,
            use_native=False,
        )

        recorder = SignalRecorder()
        worker.search_finished.connect(recorder)

        with qtbot.waitSignal(worker.search_finished, timeout=5000):
            worker.start()

        assert recorder.times_called == 1
        results: list[tuple[int, int]] = recorder.calls[0][0]
        offsets = [r[0] for r in results]
        assert 8 in offsets
        assert 20 in offsets
        assert all(bw == 4 for _, bw in results)
