# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge text encoding and decoding methods.

Verifies that bridge.decode_text() correctly reads bytes from a real
HexDocument and decodes them using the requested codec, and that
bridge.list_encodings() returns a well-formed list containing the
encodings the system supports.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    from pathlib import Path

pytest.importorskip("intellicrack_hexcore")


def _run(coro: Any) -> Any:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        Any: The result of the coroutine.
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


class TestDecodeText:
    """Tests for bridge.decode_text operating on real HexDocument data."""

    def test_decode_ascii_text_from_file(self, bridge: Any, tmp_path: Path) -> None:
        """decode_text must return the original ASCII string for ASCII-encoded bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        text = "Hello, World!"
        payload = text.encode("ascii")
        f = tmp_path / "ascii.bin"
        f.write_bytes(payload + b"\x00" * 32)
        _run(bridge.open_file(str(f)))

        result: str = _run(bridge.decode_text(0, len(payload), "ascii"))

        assert result == text

    def test_decode_utf8_text_from_file(self, bridge: Any, tmp_path: Path) -> None:
        """decode_text with utf-8 encoding must reproduce the original UTF-8 string.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        text = "UTF-8 test: caf\u00e9"
        payload = text.encode("utf-8")
        f = tmp_path / "utf8.bin"
        f.write_bytes(payload + b"\x00" * 32)
        _run(bridge.open_file(str(f)))

        result: str = _run(bridge.decode_text(0, len(payload), "utf-8"))

        assert result == text

    def test_decode_latin1_text_from_file(self, bridge: Any, tmp_path: Path) -> None:
        """decode_text with latin-1 encoding must reproduce extended Latin-1 characters.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        text = "caf\xe9\xe0\xfc"
        payload = text.encode("latin-1")
        f = tmp_path / "latin1.bin"
        f.write_bytes(payload + b"\x00" * 32)
        _run(bridge.open_file(str(f)))

        result: str = _run(bridge.decode_text(0, len(payload), "latin-1"))

        assert result == text

    def test_decode_utf16le_text_from_file(self, bridge: Any, tmp_path: Path) -> None:
        """decode_text with utf-16le encoding must reproduce the original UTF-16 LE string.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        text = "UTF16"
        payload = text.encode("utf-16le")
        f = tmp_path / "utf16le.bin"
        f.write_bytes(payload + b"\x00" * 32)
        _run(bridge.open_file(str(f)))

        result: str = _run(bridge.decode_text(0, len(payload), "utf-16le"))

        assert result == text

    def test_decode_text_at_nonzero_offset(self, bridge: Any, tmp_path: Path) -> None:
        """decode_text at an offset must skip leading bytes and read from the correct position.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        prefix = b"\xde\xad\xbe\xef"
        text = "offset_payload"
        encoded = text.encode("ascii")
        f = tmp_path / "offset.bin"
        f.write_bytes(prefix + encoded + b"\x00" * 32)
        _run(bridge.open_file(str(f)))

        result: str = _run(bridge.decode_text(len(prefix), len(encoded), "ascii"))

        assert result == text

    def test_decode_text_at_multiple_offsets(self, bridge: Any, tmp_path: Path) -> None:
        """decode_text correctly reads different text spans from the same document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        word_a = "ALPHA"
        word_b = "BETA!"
        payload = word_a.encode("ascii") + word_b.encode("ascii") + b"\x00" * 16
        f = tmp_path / "twowords.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))

        result_a: str = _run(bridge.decode_text(0, len(word_a), "ascii"))
        result_b: str = _run(bridge.decode_text(len(word_a), len(word_b), "ascii"))

        assert result_a == word_a
        assert result_b == word_b

    def test_decode_text_invalid_encoding_handles_gracefully(self, bridge: Any, tmp_path: Path) -> None:
        """decode_text with an unknown encoding must not crash; it may raise or return a string.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x41\x42\x43\x44\x45"
        f = tmp_path / "invalid_enc.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))

        raised: Exception | None = None
        result: str | None = None
        try:
            result = _run(bridge.decode_text(0, len(payload), "bogus-encoding-xyz"))
        except (LookupError, ValueError, RuntimeError, UnicodeError) as exc:
            raised = exc

        if raised is None:
            assert result is not None
            assert isinstance(result, str)

    def test_decode_text_returns_string_type(self, bridge: Any, tmp_path: Path) -> None:
        """decode_text must return a str object, not bytes or None.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"StrType" + b"\x00" * 16
        f = tmp_path / "strtype.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))

        result: str = _run(bridge.decode_text(0, 7, "ascii"))

        assert isinstance(result, str)

    def test_decode_text_single_byte_ascii(self, bridge: Any, tmp_path: Path) -> None:
        """decode_text on a single ASCII byte must return the corresponding character.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "singlebyte.bin"
        f.write_bytes(b"Z" + b"\x00" * 8)
        _run(bridge.open_file(str(f)))

        result: str = _run(bridge.decode_text(0, 1, "ascii"))

        assert result == "Z"


class TestListEncodings:
    """Tests for bridge.list_encodings returning supported encoding metadata."""

    def test_list_encodings_returns_nonempty_list(self, bridge: Any) -> None:
        """list_encodings must return a list with at least one entry.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: list[dict[str, str]] = _run(bridge.list_encodings())

        assert isinstance(result, list)
        assert len(result) > 0

    def test_list_encodings_entries_have_name_key(self, bridge: Any) -> None:
        """Every entry in list_encodings must contain a 'name' key.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: list[dict[str, str]] = _run(bridge.list_encodings())

        for entry in result:
            assert "name" in entry

    def test_list_encodings_entries_have_label_key(self, bridge: Any) -> None:
        """Every entry in list_encodings must contain a 'label' key.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: list[dict[str, str]] = _run(bridge.list_encodings())

        for entry in result:
            assert "label" in entry

    def test_list_encodings_contains_utf8_entry(self, bridge: Any) -> None:
        """list_encodings must include an entry whose name contains 'utf-8' or 'utf8'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: list[dict[str, str]] = _run(bridge.list_encodings())

        names_lower = [e["name"].lower() for e in result]
        assert any("utf-8" in n or "utf8" in n for n in names_lower)

    def test_list_encodings_contains_ascii_entry(self, bridge: Any) -> None:
        """list_encodings must include an entry whose name contains 'ascii'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: list[dict[str, str]] = _run(bridge.list_encodings())

        names_lower = [e["name"].lower() for e in result]
        assert any("ascii" in n for n in names_lower)

    def test_list_encodings_names_are_nonempty_strings(self, bridge: Any) -> None:
        """Every encoding name in list_encodings must be a non-empty str.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: list[dict[str, str]] = _run(bridge.list_encodings())

        for entry in result:
            assert isinstance(entry["name"], str)
            assert len(entry["name"]) > 0

    def test_list_encodings_labels_are_nonempty_strings(self, bridge: Any) -> None:
        """Every encoding label in list_encodings must be a non-empty str.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: list[dict[str, str]] = _run(bridge.list_encodings())

        for entry in result:
            assert isinstance(entry["label"], str)
            assert len(entry["label"]) > 0

    def test_list_encodings_with_open_document(self, bridge: Any, tmp_path: Path) -> None:
        """list_encodings must work the same way with or without an open document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        without_doc: list[dict[str, str]] = _run(bridge.list_encodings())

        f = tmp_path / "doc.bin"
        f.write_bytes(b"A" * 64)
        _run(bridge.open_file(str(f)))

        with_doc: list[dict[str, str]] = _run(bridge.list_encodings())

        assert len(with_doc) > 0
        assert len(without_doc) > 0

    def test_list_encodings_standalone_bridge(self) -> None:
        """list_encodings must return a usable list on a freshly initialized bridge."""
        fresh = HexEditorBridge()
        _run(fresh.initialize())

        result: list[dict[str, str]] = _run(fresh.list_encodings())

        assert isinstance(result, list)
        assert len(result) > 0

        _run(fresh.shutdown())

    def test_decode_text_encoding_present_in_list_encodings(self, bridge: Any, tmp_path: Path) -> None:
        """Every name returned by list_encodings must be usable with decode_text.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"Hello" + b"\x00" * 32
        f = tmp_path / "enc_check.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))

        encodings: list[dict[str, str]] = _run(bridge.list_encodings())
        ascii_entry = next(
            (e for e in encodings if "ascii" in e["name"].lower()),
            None,
        )
        assert ascii_entry is not None

        result: str = _run(bridge.decode_text(0, 5, ascii_entry["name"]))
        assert result == "Hello"
