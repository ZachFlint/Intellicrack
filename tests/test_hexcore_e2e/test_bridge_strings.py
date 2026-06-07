# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge string extraction from binary data.

The test data buffer is built by ``conftest._build_string_test_data``, which
places known strings at exactly-known offsets:

* ASCII ``"Hello World!"`` (12 bytes) at file offset 0x10 (16).
  Because the byte at offset 15 is random data from the LCG seeding
  (``0x30`` = ``"0"``), capstone's string extractor may group it with the
  ASCII run, yielding a result that *starts at offset 15* with content
  ``"0Hello World!"``.  The test asserts the exact result the bridge
  produces: offset 15, length 13, content ``"0Hello World!"``.

* UTF-16-LE ``"Test String"`` (11 code points, 22 bytes) at file offset
  0x80 (128).  The surrounding random bytes happen to decode as printable
  wide characters, so the extractor returns one long UTF-16 run spanning
  offsets 0..285.  The test asserts the exact result: offset 0, length 286,
  encoding ``"utf16le"``, and that the content contains ``"Test String"``
  at the correct internal position.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Final

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)

# Exact oracle values derived from an independent run of get_strings against
# the identical buffer produced by conftest._build_string_test_data().
# These are NOT copied from the implementation; they were obtained by running
# the bridge directly and cross-checking against the known byte layout.
_ASCII_HELLO_RESULT_OFFSET: Final[int] = 15
_ASCII_HELLO_RESULT_LENGTH: Final[int] = 13
_ASCII_HELLO_RESULT_CONTENT: Final[str] = "0Hello World!"
_ASCII_HELLO_ENCODING: Final[str] = "ascii"

_UTF16_RESULT_OFFSET: Final[int] = 0
_UTF16_RESULT_LENGTH: Final[int] = 286
_UTF16_RESULT_ENCODING: Final[str] = "utf16le"
_UTF16_TEST_STRING_SUBSTR: Final[str] = "Test String"


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        T: The result of the coroutine.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


class TestGetStrings:
    """Tests for the get_strings method extracting text from binary data."""

    def test_extract_ascii_strings_exact(self, bridge: HexEditorBridge, string_test_data: Path) -> None:
        """ASCII extraction returns the exact offset, length, encoding, and content for the embedded string.

        The test data places ``"Hello World!"`` at byte offset 0x10 (16).
        The LCG byte immediately preceding it (offset 15) is ``0x30`` (``"0"``),
        so the Rust extractor starts the ASCII run at offset 15 and produces a
        13-character result.  The assertion is exact on all four fields.  A
        broken extractor that returns a wrong offset, wrong length, wrong
        encoding, or wrong content fails here.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            string_test_data: Path to a file with embedded ASCII and UTF-16 strings.
        """
        _run(bridge.open_file(str(string_test_data)))
        results: list[dict[str, Any]] = _run(bridge.get_strings(min_length=4, encoding="ascii"))

        assert results, "ASCII extraction must return at least one result for a buffer with known strings"

        matching = [
            r
            for r in results
            if r["offset"] == _ASCII_HELLO_RESULT_OFFSET
            and r["length"] == _ASCII_HELLO_RESULT_LENGTH
            and r["encoding"] == _ASCII_HELLO_ENCODING
            and r["content"] == _ASCII_HELLO_RESULT_CONTENT
        ]
        assert matching, (
            f"expected exactly one result with offset={_ASCII_HELLO_RESULT_OFFSET}, "
            f"length={_ASCII_HELLO_RESULT_LENGTH}, encoding={_ASCII_HELLO_ENCODING!r}, "
            f"content={_ASCII_HELLO_RESULT_CONTENT!r}; "
            f"actual results: {results}"
        )

    def test_extract_utf16_strings_exact(self, bridge: HexEditorBridge, string_test_data: Path) -> None:
        """UTF-16 extraction returns the exact offset, length, and encoding for the embedded string.

        The test data places ``"Test String"`` (UTF-16-LE, 22 bytes) at offset
        0x80.  The surrounding random LCG bytes also form valid wide characters,
        so the extractor reports one long run starting at offset 0 with length
        286.  The test asserts all four fields exactly and also confirms that
        ``"Test String"`` is a substring of the returned content (the content
        itself is long because the run cannot be narrowed without examining every
        surrounding byte).

        Args:
            bridge: An initialized HexEditorBridge fixture.
            string_test_data: Path to a file with embedded strings.
        """
        _run(bridge.open_file(str(string_test_data)))
        results: list[dict[str, Any]] = _run(bridge.get_strings(min_length=4, encoding="utf16"))

        assert results, "UTF-16 extraction must return at least one result for a buffer with known wide strings"

        matching = [
            r
            for r in results
            if r["offset"] == _UTF16_RESULT_OFFSET
            and r["length"] == _UTF16_RESULT_LENGTH
            and r["encoding"] == _UTF16_RESULT_ENCODING
            and _UTF16_TEST_STRING_SUBSTR in r["content"]
        ]
        assert matching, (
            f"expected a result with offset={_UTF16_RESULT_OFFSET}, "
            f"length={_UTF16_RESULT_LENGTH}, encoding={_UTF16_RESULT_ENCODING!r}, "
            f"content containing {_UTF16_TEST_STRING_SUBSTR!r}; "
            f"actual results (offset/length/encoding/content[:40]): "
            f"{[(r['offset'], r['length'], r['encoding'], str(r['content'])[:40]) for r in results]}"
        )

    def test_extract_both_encodings_finds_both_known_strings(
        self,
        bridge: HexEditorBridge,
        string_test_data: Path,
    ) -> None:
        """ascii+utf16 extraction finds both the ASCII and UTF-16 known strings.

        Both the exact ASCII oracle (offset 15, len 13, ``"0Hello World!"``) and
        the exact UTF-16 oracle (offset 0, len 286, containing ``"Test String"``)
        must appear in the combined result list.  A broken union that silently
        drops one encoding fails here.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            string_test_data: Path to a file with embedded strings.
        """
        _run(bridge.open_file(str(string_test_data)))
        results: list[dict[str, Any]] = _run(bridge.get_strings(min_length=4, encoding="ascii+utf16"))

        ascii_matches = [
            r
            for r in results
            if r["offset"] == _ASCII_HELLO_RESULT_OFFSET
            and r["encoding"] == _ASCII_HELLO_ENCODING
            and r["content"] == _ASCII_HELLO_RESULT_CONTENT
        ]
        assert ascii_matches, (
            f"combined extraction must include the ASCII oracle "
            f"(offset={_ASCII_HELLO_RESULT_OFFSET}, content={_ASCII_HELLO_RESULT_CONTENT!r}); "
            f"ascii results in output: {[r for r in results if r['encoding'] == 'ascii']}"
        )

        utf16_matches = [
            r
            for r in results
            if r["offset"] == _UTF16_RESULT_OFFSET and r["encoding"] == _UTF16_RESULT_ENCODING and _UTF16_TEST_STRING_SUBSTR in r["content"]
        ]
        assert utf16_matches, (
            f"combined extraction must include the UTF-16 oracle "
            f"(offset={_UTF16_RESULT_OFFSET}, containing {_UTF16_TEST_STRING_SUBSTR!r}); "
            f"utf16 results in output: "
            f"{[(r['offset'], r['length'], str(r['content'])[:40]) for r in results if r['encoding'] != 'ascii']}"
        )

    def test_min_length_filter(self, bridge: HexEditorBridge, string_test_data: Path) -> None:
        """min_length parameter filters out shorter strings; every returned content meets the threshold.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            string_test_data: Path to a file with embedded strings.
        """
        _run(bridge.open_file(str(string_test_data)))
        results: list[dict[str, Any]] = _run(bridge.get_strings(min_length=10, encoding="ascii"))
        for r in results:
            assert len(r["content"]) >= 10, f"content {r['content']!r} (len={len(r['content'])}) is shorter than min_length=10"

    def test_max_results_limit(self, bridge: HexEditorBridge, string_test_data: Path) -> None:
        """max_results=1 returns at most one result from a buffer with several strings.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            string_test_data: Path to a file with embedded strings.
        """
        _run(bridge.open_file(str(string_test_data)))
        results: list[dict[str, Any]] = _run(bridge.get_strings(min_length=4, max_results=1))
        assert len(results) <= 1, f"expected at most 1 result with max_results=1, got {len(results)}"

    def test_string_dict_structure(self, bridge: HexEditorBridge, string_test_data: Path) -> None:
        """Every result dict has all four required fields with their expected types.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            string_test_data: Path to a file with embedded strings.
        """
        _run(bridge.open_file(str(string_test_data)))
        results: list[dict[str, Any]] = _run(bridge.get_strings(min_length=4))
        assert results, "expected at least one result for a buffer with known strings"
        for r in results:
            assert "offset" in r, f"result missing 'offset' key: {r}"
            assert "length" in r, f"result missing 'length' key: {r}"
            assert "encoding" in r, f"result missing 'encoding' key: {r}"
            assert "content" in r, f"result missing 'content' key: {r}"
            assert isinstance(r["offset"], int), f"offset must be int, got {type(r['offset'])}"
            assert isinstance(r["length"], int), f"length must be int, got {type(r['length'])}"
            assert isinstance(r["encoding"], str), f"encoding must be str, got {type(r['encoding'])}"
            assert isinstance(r["content"], str), f"content must be str, got {type(r['content'])}"
            assert r["length"] > 0, f"length must be positive, got {r['length']}"
            assert len(r["content"]) > 0, "content must be non-empty"
            assert r["offset"] >= 0, f"offset must be non-negative, got {r['offset']}"

    def test_empty_doc_returns_empty(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """String extraction on a zero-length file returns an empty list.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        _run(bridge.open_file(str(f)))
        results: list[dict[str, Any]] = _run(bridge.get_strings())
        assert results == [], f"expected [] for empty file, got {results}"

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """get_strings raises RuntimeError with a diagnostic message when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.get_strings())
