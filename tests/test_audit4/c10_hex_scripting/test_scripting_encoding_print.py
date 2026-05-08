# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Audit4 C10 regression tests for hex editor scripting (F-0020, F-0021).

Covers:

- F-0020: ``_DocAPI.search_text`` must use the encoding passed to
  ``_DocAPI.__init__`` rather than the hard-coded ``"utf-8"`` literal.
  When the panel's encoding combo selects ``"latin-1"``, a call to
  ``doc.search_text('café')`` must encode the search term using latin-1.

- F-0021: ``execute_script`` must capture output from ``print()`` calls
  regardless of whether ``file=`` is passed.  The captured output must
  appear in the ``"output"`` key of the returned dict; no exception should
  be raised and the call must not crash when ``file=`` is set to an
  arbitrary object.
"""

from __future__ import annotations

from typing import Any

import pytest

import intellicrack.ui.panels.hex_editor._scripting as _scripting_module
from intellicrack.ui.panels.hex_editor._scripting import execute_script


_DocAPI = getattr(_scripting_module, "_DocAPI")
_ReadOnlyDocAPI = getattr(_scripting_module, "_ReadOnlyDocAPI")


class _RecordingDoc:
    """Minimal document stub that records ``search_text`` call arguments."""

    def __init__(self) -> None:
        """Initialise the recording stub with empty call history."""
        self.search_text_calls: list[dict[str, Any]] = []

    def length(self) -> int:
        """Return zero as the stub document length.

        Returns:
            int: Always zero.
        """
        return 0

    def read(self, offset: int, length: int) -> bytes:
        """Return empty bytes from the stub document.

        Args:
            offset: Ignored start offset.
            length: Ignored byte count.

        Returns:
            bytes: Always empty bytes.
        """
        _ = (offset, length)
        return b""

    def write_bytes(self, offset: int, data: bytes) -> None:
        """No-op stub write.

        Args:
            offset: Ignored.
            data: Ignored.
        """
        _ = (self, offset, data)

    def insert_bytes(self, offset: int, data: bytes) -> None:
        """No-op stub insert.

        Args:
            offset: Ignored.
            data: Ignored.
        """
        _ = (self, offset, data)

    def delete_bytes(self, offset: int, length: int) -> None:
        """No-op stub delete.

        Args:
            offset: Ignored.
            length: Ignored.
        """
        _ = (self, offset, length)

    def search_hex(self, pattern: str, max_results: int) -> list[tuple[int, int]]:
        """Return empty results from stub hex search.

        Args:
            pattern: Ignored.
            max_results: Ignored.

        Returns:
            list[tuple[int, int]]: Always empty.
        """
        _ = (self, pattern, max_results)
        return []

    def search_text(
        self,
        text: str,
        encoding: str,
        *,
        case_sensitive: bool,
        max_results: int,
    ) -> list[tuple[int, int]]:
        """Record the call arguments and return empty results.

        Args:
            text: Search text.
            encoding: Character encoding supplied by the caller.
            case_sensitive: Case-sensitivity flag.
            max_results: Maximum result count.

        Returns:
            list[tuple[int, int]]: Always empty.
        """
        self.search_text_calls.append(
            {
                "text": text,
                "encoding": encoding,
                "case_sensitive": case_sensitive,
                "max_results": max_results,
            },
        )
        return []

    def add_bookmark(self, offset: int, length: int, label: str, color: str) -> int:
        """No-op stub bookmark; returns zero.

        Args:
            offset: Ignored.
            length: Ignored.
            label: Ignored.
            color: Ignored.

        Returns:
            int: Always zero.
        """
        _ = (self, offset, length, label, color)
        return 0


class TestF0020SearchTextEncoding:
    """F-0020: ``_DocAPI.search_text`` must honour the encoding from the panel combo."""

    @staticmethod
    def test_default_encoding_is_utf8() -> None:
        """When no encoding is specified, ``search_text`` passes ``'utf-8'`` to the doc."""
        doc = _RecordingDoc()
        api = _DocAPI(doc, None, None)
        api.search_text("hello")
        assert len(doc.search_text_calls) == 1
        assert doc.search_text_calls[0]["encoding"] == "utf-8"

    @staticmethod
    def test_latin1_encoding_is_forwarded() -> None:
        """When ``encoding='latin1'`` is set, ``search_text`` must pass it through."""
        doc = _RecordingDoc()
        api = _DocAPI(doc, None, None, encoding="latin1")
        api.search_text("café")
        assert len(doc.search_text_calls) == 1
        assert doc.search_text_calls[0]["encoding"] == "latin1"

    @staticmethod
    def test_latin1_encoding_not_utf8() -> None:
        """With latin-1 encoding, the forwarded encoding must not be ``'utf-8'``."""
        doc = _RecordingDoc()
        api = _DocAPI(doc, None, None, encoding="latin1")
        api.search_text("café")
        assert doc.search_text_calls[0]["encoding"] != "utf-8"

    @staticmethod
    def test_custom_encoding_cp1252_forwarded() -> None:
        """Any encoding name passed to ``_DocAPI`` must reach ``search_text``."""
        doc = _RecordingDoc()
        api = _DocAPI(doc, None, None, encoding="cp1252")
        api.search_text("test")
        assert doc.search_text_calls[0]["encoding"] == "cp1252"

    @staticmethod
    def test_readonly_proxy_delegates_search_text() -> None:
        """``_ReadOnlyDocAPI.search_text`` must delegate to the inner API preserving encoding."""
        doc = _RecordingDoc()
        base = _DocAPI(doc, None, None, encoding="latin1")
        ro = _ReadOnlyDocAPI(base)
        ro.search_text("café")
        assert len(doc.search_text_calls) == 1
        assert doc.search_text_calls[0]["encoding"] == "latin1"

    @staticmethod
    def test_max_results_forwarded() -> None:
        """``max_results`` supplied to the public API must reach the document."""
        doc = _RecordingDoc()
        api = _DocAPI(doc, None, None, encoding="utf-8")
        api.search_text("x", max_results=42)
        assert doc.search_text_calls[0]["max_results"] == 42


class TestF0021PrintCapture:
    """F-0021: ``execute_script`` must capture ``print()`` output regardless of ``file=``."""

    @staticmethod
    def _make_doc_api() -> object:
        """Build a read-only doc API backed by a recording stub.

        Returns:
            object: Read-only proxy around a recording document stub.
        """
        return _ReadOnlyDocAPI(_DocAPI(_RecordingDoc(), None, None))

    @pytest.mark.parametrize("script", ['print("hello")', "x = 1\nprint(x)"])
    def test_print_output_captured(self, script: str) -> None:
        """Output from ``print()`` with no ``file=`` must appear in the result.

        Args:
            script: Python source with a ``print()`` call.
        """
        api = _ReadOnlyDocAPI(_DocAPI(_RecordingDoc(), None, None))
        result = execute_script(script, api)
        assert result["error"] is None
        assert "output" in result
        assert result["output"].strip()

    @staticmethod
    def test_print_hello_appears_in_output() -> None:
        """``print('hello')`` must produce ``'hello'`` in the ``output`` field."""
        result = execute_script('print("hello")', _ReadOnlyDocAPI(_DocAPI(_RecordingDoc(), None, None)))
        assert "hello" in result["output"]

    @staticmethod
    def test_print_with_file_none_does_not_lose_output() -> None:
        """``print('hello', file=None)`` must not lose output to the capture buffer."""
        doc_api = _ReadOnlyDocAPI(_DocAPI(_RecordingDoc(), None, None))
        result = execute_script('print("captured", file=None)', doc_api)
        assert result["error"] is None
        assert "captured" in result["output"]

    @staticmethod
    def test_print_with_none_file_kwarg_captures_output() -> None:
        """``print('hello', file=None)`` must still produce captured output."""
        doc_api = _ReadOnlyDocAPI(_DocAPI(_RecordingDoc(), None, None))
        result = execute_script('print("hello", file=None)', doc_api)
        assert result["error"] is None
        assert "hello" in result["output"]

    @staticmethod
    def test_print_with_flush_true_captures_output() -> None:
        """``print('world', flush=True)`` must produce captured output without error."""
        doc_api = _ReadOnlyDocAPI(_DocAPI(_RecordingDoc(), None, None))
        result = execute_script('print("world", flush=True)', doc_api)
        assert result["error"] is None
        assert "world" in result["output"]

    @staticmethod
    def test_print_sep_and_end_honoured() -> None:
        """``print`` sep/end keyword args must work correctly."""
        doc_api = _ReadOnlyDocAPI(_DocAPI(_RecordingDoc(), None, None))
        result = execute_script('print("a", "b", sep="-", end="!")', doc_api)
        assert result["error"] is None
        assert "a-b!" in result["output"]

    @staticmethod
    def test_multiple_print_calls_all_captured() -> None:
        """Multiple ``print()`` calls must all appear concatenated in ``output``."""
        doc_api = _ReadOnlyDocAPI(_DocAPI(_RecordingDoc(), None, None))
        script = 'print("line1")\nprint("line2")\nprint("line3")'
        result = execute_script(script, doc_api)
        assert result["error"] is None
        output = result["output"]
        assert "line1" in output
        assert "line2" in output
        assert "line3" in output
