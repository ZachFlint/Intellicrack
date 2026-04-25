# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge search operations."""

from __future__ import annotations

import asyncio
import struct
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


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


class TestBridgeSearchHex:
    """Tests covering hex-pattern search with exact bytes and wildcards."""

    def test_search_hex_returns_list(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that search_hex returns a list.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, int]] = _run(loaded_bridge.search_hex("4D 5A"))
        assert isinstance(results, list)

    def test_search_hex_result_items_have_offset_and_length(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that each search_hex result dict has offset and length keys.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, int]] = _run(loaded_bridge.search_hex("4D 5A"))
        assert results
        for item in results:
            assert "offset" in item
            assert "length" in item

    def test_search_hex_finds_mz_signature_at_offset_zero(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that searching for the MZ magic bytes finds offset 0 in a PE file.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, int]] = _run(loaded_bridge.search_hex("4D 5A"))
        offsets = [r["offset"] for r in results]
        assert 0 in offsets

    def test_search_hex_result_length_matches_pattern_byte_count(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that match length equals the number of bytes in the search pattern.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, int]] = _run(loaded_bridge.search_hex("4D 5A"))
        assert results[0]["length"] == 2

    def test_search_hex_wildcard_finds_mz_with_second_byte_wild(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that a wildcard pattern matches where the wildcard byte varies.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data = b"MZ\x90\x00" + bytes(60)
        f = tmp_path / "wild.bin"
        f.write_bytes(data)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, int]] = _run(bridge.search_hex("4D ?? 90"))
        assert any(r["offset"] == 0 for r in results)

    def test_search_hex_no_match_returns_empty_list(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that a pattern with no matches returns an empty list.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, int]] = _run(loaded_bridge.search_hex("DE AD BE EF CA FE BA BE 00 11 22 33 44 55 66 77"))
        assert not results

    def test_search_hex_max_results_respected(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that max_results caps the number of returned matches.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data = b"\xaa\xbb" * 200
        f = tmp_path / "repeated.bin"
        f.write_bytes(data)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, int]] = _run(bridge.search_hex("AA BB", max_results=5))
        assert len(results) <= 5


class TestBridgeSearchText:
    """Tests covering text search with encoding and case-sensitivity options."""

    def test_search_text_finds_known_ascii_string(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that search_text locates a known ASCII literal in the document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x00\x00" + b"INTELLICRACK" + b"\x00\x00"
        f = tmp_path / "text.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, int]] = _run(bridge.search_text("INTELLICRACK", encoding="ascii"))
        assert results
        assert results[0]["offset"] == 2

    def test_search_text_case_insensitive_finds_lowercase(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that case-insensitive search matches lower-case variants.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"intellicrack"
        f = tmp_path / "lower.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, int]] = _run(bridge.search_text("INTELLICRACK", encoding="ascii", case_sensitive=False))
        assert results

    def test_search_text_case_sensitive_no_match_on_wrong_case(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that case-sensitive search does not match wrong-case text.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"intellicrack"
        f = tmp_path / "wrong_case.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, int]] = _run(bridge.search_text("INTELLICRACK", encoding="ascii", case_sensitive=True))
        assert not results

    def test_search_text_result_length_matches_byte_length_of_string(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that search_text result length equals the byte length of the target.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        target = "HELLO"
        payload = target.encode("ascii") + b"\x00"
        f = tmp_path / "hello.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, int]] = _run(bridge.search_text(target, encoding="ascii"))
        assert results[0]["length"] == len(target)


class TestBridgeSearchRegex:
    """Tests covering regex-based binary search."""

    def test_search_regex_finds_pattern_match(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that search_regex returns matches for a valid regex pattern.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"ABC123DEF456"
        f = tmp_path / "regex.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, int]] = _run(bridge.search_regex(r"[A-Z]{3}"))
        assert results

    def test_search_regex_no_match_returns_empty_list(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that search_regex returns an empty list when no match exists.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"123456"
        f = tmp_path / "nore.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, int]] = _run(bridge.search_regex(r"[A-Z]{10}"))
        assert not results


class TestBridgeSearchNumeric:
    """Tests covering numeric value search in binary documents."""

    def test_search_numeric_finds_known_uint32_value(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that search_numeric locates a known little-endian uint32.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        target_value = 0xDEADBEEF
        payload = b"\x00" * 8 + struct.pack("<I", target_value) + b"\x00" * 8
        f = tmp_path / "numeric.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, int]] = _run(bridge.search_numeric(target_value, size=4, value_type="uint", endianness="little"))
        assert results
        assert results[0]["offset"] == 8

    def test_search_numeric_result_has_correct_length(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that search_numeric result length equals the size parameter.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = struct.pack("<H", 0x1234) + b"\x00" * 8
        f = tmp_path / "num16.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, int]] = _run(bridge.search_numeric(0x1234, size=2, value_type="uint", endianness="little"))
        assert results[0]["length"] == 2


class TestBridgeReplaceBytes:
    """Tests covering find-and-replace byte operations."""

    def test_replace_bytes_returns_count(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that replace_bytes returns the number of replacements made.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\xaa\xbb" * 4 + b"\xff"
        f = tmp_path / "replace.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        count: int = _run(bridge.replace_bytes("AA BB", "CC DD"))
        assert count == 4

    def test_replace_bytes_modifies_document_content(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that the document bytes are updated after replace_bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\xaa\xbb\xff"
        f = tmp_path / "mod.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        _run(bridge.replace_bytes("AA BB", "CC DD"))
        read_back: str = _run(bridge.read_bytes(0, 2))
        assert read_back == "CC DD"
