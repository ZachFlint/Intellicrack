# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for hex editor async search helpers and the generic worker.

Verifies that ``execute_text_search`` and ``execute_numeric_search``
return the expected matches against real byte data, and that
``GenericCallableWorker`` correctly emits ``call_finished`` and
``call_error`` signals from a background QThread.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, NoReturn

import pytest

from intellicrack.ui.panels.async_bridge import GenericCallableWorker
from intellicrack.ui.panels.hex_editor import execute_numeric_search, execute_text_search

from .conftest import SignalRecorder


if TYPE_CHECKING:
    from pytestqt.qtbot import QtBot


class SimpleDocument:
    """Real document with search methods operating on actual byte data."""

    def __init__(self, data: bytes) -> None:
        """Store the byte content used to back search operations.

        Args:
            data: Raw byte content to search within.
        """
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

    Used to test error signal emission from the generic worker.
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


class TestExecuteTextSearch:
    """Tests for ``execute_text_search`` against real byte data."""

    @staticmethod
    def test_hex_search_finds_repeated_pattern() -> None:
        """Verify hex search finds expected offsets in repeated pattern."""
        pattern = b"\xde\xad\xbe\xef"
        data = pattern * 4
        doc = SimpleDocument(data)
        results = execute_text_search(doc, "Hex", "DEAD", "utf-8", 100)
        offsets = [r[0] for r in results]
        assert 0 in offsets
        assert 4 in offsets
        assert 8 in offsets
        assert 12 in offsets

    @staticmethod
    def test_text_search_finds_ascii_string() -> None:
        """Verify text search locates ASCII string in document."""
        data = b"prefix_hello_suffix_hello_end"
        doc = SimpleDocument(data)
        results = execute_text_search(doc, "Text", "hello", "utf-8", 100)
        offsets = [r[0] for r in results]
        assert 7 in offsets
        assert 20 in offsets
        assert all(length == 5 for _, length in results)

    @staticmethod
    def test_unknown_mode_returns_empty() -> None:
        """Unknown mode strings yield an empty result list."""
        doc = SimpleDocument(b"\x00")
        assert execute_text_search(doc, "Unsupported", "x", "utf-8", 10) == []


class TestExecuteNumericSearchFallback:
    """Tests for the Python fallback path of ``execute_numeric_search``."""

    @staticmethod
    def test_numeric_search_fallback_locates_value() -> None:
        """Verify fallback scan finds known 32-bit value in byte data."""
        target_value: int = 42
        packed = struct.pack("<I", target_value)
        data = b"\x00" * 8 + packed + b"\x00" * 8 + packed + b"\x00" * 4
        doc = SimpleDocument(data)
        results = execute_numeric_search(
            doc,
            min_val=42.0,
            max_val=42.0,
            fmt="<I",
            byte_width=4,
            alignment=1,
            max_results=100,
            use_native=False,
            size=4,
            signed=False,
            big_endian=False,
            is_range=False,
        )
        offsets = [r[0] for r in results]
        assert 8 in offsets
        assert 20 in offsets
        assert all(bw == 4 for _, bw in results)


@pytest.mark.usefixtures("qapp")
class TestGenericCallableWorker:
    """Tests for ``GenericCallableWorker`` driving search helpers on a thread."""

    @staticmethod
    def test_worker_emits_finished_for_text_search(qtbot: QtBot) -> None:
        """The worker emits ``call_finished`` with the helper's result.

        Args:
            qtbot: pytest-qt bot fixture used to wait on Qt signals.
        """
        pattern = b"\xde\xad\xbe\xef"
        data = pattern * 2
        doc = SimpleDocument(data)
        worker = GenericCallableWorker(execute_text_search, doc, "Hex", "DEAD", "utf-8", 50)

        recorder = SignalRecorder()
        _: object = worker.call_finished.connect(recorder)

        with qtbot.waitSignal(worker.call_finished, timeout=5000):
            worker.start()

        assert recorder.times_called == 1
        results = recorder.calls[0][0]
        assert isinstance(results, list)
        offsets = [r[0] for r in results]
        assert 0 in offsets
        assert 4 in offsets

    @staticmethod
    def test_worker_emits_error_on_failure(qtbot: QtBot) -> None:
        """The worker emits ``call_error`` when the callable raises.

        Args:
            qtbot: pytest-qt bot fixture used to wait on Qt signals.
        """
        doc = ErrorDocument()
        worker = GenericCallableWorker(execute_text_search, doc, "Hex", "DEAD", "utf-8", 50)

        recorder = SignalRecorder()
        _: object = worker.call_error.connect(recorder)

        with qtbot.waitSignal(worker.call_error, timeout=5000):
            worker.start()

        assert recorder.times_called == 1
        exc = recorder.calls[0][0]
        assert isinstance(exc, ValueError)
        assert "intentional test error" in str(exc)
