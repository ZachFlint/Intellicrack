# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument text encoding and decoding methods."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    import types

    from intellicrack_hexcore import HexDocument


class TestDecodeText:
    """Tests for the decode_text() method on HexDocument.

    Verifies that decode_text() correctly interprets byte sequences as text
    for UTF-8, ASCII, and Latin-1 encodings, including exact string equality
    for known embedded payloads.
    """

    def test_decode_utf8_hello_world(self, hexcore: types.ModuleType) -> None:
        """Verify that decode_text() returns 'Hello, World!' for UTF-8 encoded bytes at offset 0.

        Args:
            hexcore: The native hexcore module fixture.
        """
        text = "Hello, World!"
        encoded = text.encode("utf-8")
        data = encoded + b"\x00" * 100
        doc = hexcore.HexDocument.open_bytes(data)
        result = doc.decode_text(0, len(encoded), "utf-8")
        assert result == text

    def test_decode_ascii_text(self, hexcore: types.ModuleType) -> None:
        """Verify that decode_text() returns the original ASCII string for ASCII-encoded data.

        Args:
            hexcore: The native hexcore module fixture.
        """
        text = "Intellicrack"
        encoded = text.encode("ascii")
        data = encoded + b"\x00" * 50
        doc = hexcore.HexDocument.open_bytes(data)
        result = doc.decode_text(0, len(encoded), "ascii")
        assert result == text

    def test_decode_latin1_text(self, hexcore: types.ModuleType) -> None:
        """Verify that decode_text() returns the original string for Latin-1 encoded bytes.

        Args:
            hexcore: The native hexcore module fixture.
        """
        text = "caf\xe9"
        encoded = text.encode("latin-1")
        data = encoded + b"\x00" * 50
        doc = hexcore.HexDocument.open_bytes(data)
        result = doc.decode_text(0, len(encoded), "latin-1")
        assert result == text

    def test_decode_at_non_zero_offset(self, hexcore: types.ModuleType) -> None:
        """Verify that decode_text() at a non-zero offset reads from the correct position.

        Args:
            hexcore: The native hexcore module fixture.
        """
        prefix = b"\x00\x00\x00\x00"
        text = "offset_text"
        encoded = text.encode("utf-8")
        data = prefix + encoded + b"\x00" * 50
        doc = hexcore.HexDocument.open_bytes(data)
        result = doc.decode_text(len(prefix), len(encoded), "utf-8")
        assert result == text

    def test_decode_returns_string(self, hexcore: types.ModuleType) -> None:
        """Verify that decode_text() returns a str object.

        Args:
            hexcore: The native hexcore module fixture.
        """
        data = b"test" + b"\x00" * 10
        doc = hexcore.HexDocument.open_bytes(data)
        result = doc.decode_text(0, 4, "utf-8")
        assert isinstance(result, str)

    def test_decode_utf8_multibyte_codepoint(self, hexcore: types.ModuleType) -> None:
        """Verify that decode_text() handles multi-byte UTF-8 codepoints correctly.

        Args:
            hexcore: The native hexcore module fixture.
        """
        text = "\u00e9\u00e0\u00fc"
        encoded = text.encode("utf-8")
        data = encoded + b"\x00" * 20
        doc = hexcore.HexDocument.open_bytes(data)
        result = doc.decode_text(0, len(encoded), "utf-8")
        assert result == text


class TestEncodeText:
    """Tests for the encode_text_to_bytes() method on HexDocument.

    Verifies that encode_text_to_bytes() produces the correct byte representation
    for UTF-8, ASCII, and Latin-1 encoded strings, and that the roundtrip of
    encode then decode reproduces the original text.
    """

    def test_encode_utf8_returns_bytes(self, hexcore: types.ModuleType) -> None:
        """Verify that encode_text_to_bytes() returns a bytes object for UTF-8.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(b"\x00" * 16)
        result = doc.encode_text_to_bytes("Hello", "utf-8")
        assert isinstance(result, bytes)

    def test_encode_utf8_matches_python_encode(self, hexcore: types.ModuleType) -> None:
        """Verify that encode_text_to_bytes() for UTF-8 matches Python's str.encode('utf-8').

        Args:
            hexcore: The native hexcore module fixture.
        """
        text = "Hello, World!"
        doc = hexcore.HexDocument.open_bytes(b"\x00" * 16)
        result = doc.encode_text_to_bytes(text, "utf-8")
        assert result == text.encode("utf-8")

    def test_encode_ascii_matches_python_encode(self, hexcore: types.ModuleType) -> None:
        """Verify that encode_text_to_bytes() for ASCII matches Python's str.encode('ascii').

        Args:
            hexcore: The native hexcore module fixture.
        """
        text = "Intellicrack"
        doc = hexcore.HexDocument.open_bytes(b"\x00" * 16)
        result = doc.encode_text_to_bytes(text, "ascii")
        assert result == text.encode("ascii")

    def test_encode_latin1_matches_python_encode(self, hexcore: types.ModuleType) -> None:
        """Verify that encode_text_to_bytes() for Latin-1 matches Python's str.encode('latin-1').

        Args:
            hexcore: The native hexcore module fixture.
        """
        text = "caf\xe9"
        doc = hexcore.HexDocument.open_bytes(b"\x00" * 16)
        result = doc.encode_text_to_bytes(text, "latin-1")
        assert result == text.encode("latin-1")

    def test_encode_decode_roundtrip_utf8(self, hexcore: types.ModuleType) -> None:
        """Verify that encoding then decoding a UTF-8 string produces the original text.

        Args:
            hexcore: The native hexcore module fixture.
        """
        original = "Roundtrip UTF-8 test"
        doc = hexcore.HexDocument.open_bytes(b"\x00" * 64)
        encoded = doc.encode_text_to_bytes(original, "utf-8")
        doc2 = hexcore.HexDocument.open_bytes(encoded)
        result = doc2.decode_text(0, len(encoded), "utf-8")
        assert result == original

    def test_encode_decode_roundtrip_ascii(self, hexcore: types.ModuleType) -> None:
        """Verify that encoding then decoding an ASCII string produces the original text.

        Args:
            hexcore: The native hexcore module fixture.
        """
        original = "ASCII roundtrip"
        doc = hexcore.HexDocument.open_bytes(b"\x00" * 32)
        encoded = doc.encode_text_to_bytes(original, "ascii")
        doc2 = hexcore.HexDocument.open_bytes(encoded)
        result = doc2.decode_text(0, len(encoded), "ascii")
        assert result == original


class TestListEncodings:
    """Tests for the list_encodings() method on HexDocument.

    Verifies that list_encodings() returns a non-empty list of (name, label) tuples
    and that common encodings such as UTF-8 and ASCII are present.
    """

    def test_list_encodings_returns_nonempty_list(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that list_encodings() returns a non-empty list.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result: list[tuple[str, str]] = sample_doc_from_bytes.list_encodings()
        assert isinstance(result, list)
        assert result

    def test_list_encodings_entries_are_two_tuples(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that each entry in list_encodings() is a tuple of exactly 2 elements.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result: list[tuple[str, str]] = sample_doc_from_bytes.list_encodings()
        for entry in result:
            assert len(entry) == 2

    def test_list_encodings_entries_are_strings(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that each element in every list_encodings() tuple is a string.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result: list[tuple[str, str]] = sample_doc_from_bytes.list_encodings()
        for name, label in result:
            assert isinstance(name, str)
            assert isinstance(label, str)

    def test_list_encodings_contains_utf8(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that list_encodings() includes an entry whose name contains 'utf-8'.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result: list[tuple[str, str]] = sample_doc_from_bytes.list_encodings()
        names_lower = [name.lower() for name, _label in result]
        assert any("utf-8" in n or "utf8" in n for n in names_lower)

    def test_list_encodings_contains_ascii(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that list_encodings() includes an entry whose name contains 'ascii'.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result: list[tuple[str, str]] = sample_doc_from_bytes.list_encodings()
        names_lower = [name.lower() for name, _label in result]
        assert any("ascii" in n for n in names_lower)

    def test_list_encodings_names_are_nonempty(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that every encoding name in list_encodings() is a non-empty string.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result: list[tuple[str, str]] = sample_doc_from_bytes.list_encodings()
        for name, _label in result:
            assert len(name) > 0


class TestEncodingRoundtrips:
    """Tests for encode/decode roundtrips across multiple supported encodings.

    Verifies that for each supported encoding, encoding a simple ASCII-safe
    string and decoding it back produces the original text without data loss.
    """

    @pytest.mark.parametrize(
        "encoding",
        ["utf-8", "ascii", "latin-1", "utf-16le", "utf-16be"],
    )
    def test_roundtrip_encode_decode(self, hexcore: types.ModuleType, encoding: str) -> None:
        """Verify that encoding then decoding a string reproduces the original for the given encoding.

        Args:
            hexcore: The native hexcore module fixture.
            encoding: The encoding name to use for the roundtrip test.
        """
        original = "Hello World"
        doc = hexcore.HexDocument.open_bytes(b"\x00" * 64)
        encoded = doc.encode_text_to_bytes(original, encoding)
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0
        doc2 = hexcore.HexDocument.open_bytes(encoded)
        result = doc2.decode_text(0, len(encoded), encoding)
        assert result == original

    def test_utf16le_bom_absent_roundtrip(self, hexcore: types.ModuleType) -> None:
        """Verify that UTF-16 LE encoding without BOM roundtrips correctly.

        Args:
            hexcore: The native hexcore module fixture.
        """
        original = "Test"
        doc = hexcore.HexDocument.open_bytes(b"\x00" * 32)
        encoded = doc.encode_text_to_bytes(original, "utf-16le")
        doc2 = hexcore.HexDocument.open_bytes(encoded)
        result = doc2.decode_text(0, len(encoded), "utf-16le")
        assert result == original

    def test_latin1_extended_chars_roundtrip(self, hexcore: types.ModuleType) -> None:
        """Verify that Latin-1 extended characters encode and decode without loss.

        Args:
            hexcore: The native hexcore module fixture.
        """
        original = "\xe9\xe0\xfc\xf6"
        doc = hexcore.HexDocument.open_bytes(b"\x00" * 16)
        encoded = doc.encode_text_to_bytes(original, "latin-1")
        doc2 = hexcore.HexDocument.open_bytes(encoded)
        result = doc2.decode_text(0, len(encoded), "latin-1")
        assert result == original


class TestDecodeTextEdgeCases:
    """Tests for edge cases in decode_text() error handling.

    Verifies that decoding a zero-length range returns an empty string and that
    decoding bytes that are invalid for the chosen encoding either returns
    replacement characters or raises a predictable exception rather than
    crashing silently.
    """

    def test_decode_zero_length_returns_empty_string(self, hexcore: types.ModuleType) -> None:
        """Verify that decode_text() on a zero-length range returns an empty string.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(b"ABCDEF")
        result = doc.decode_text(0, 0, "utf-8")
        assert not result

    def test_decode_invalid_utf8_uses_replacement_characters(self, hexcore: types.ModuleType) -> None:
        """Verify decode_text() substitutes U+FFFD for each invalid UTF-8 byte sequence.

        The encoding_rs UTF-8 decoder follows the WHATWG encoding spec and never
        raises for recognised encodings; it replaces invalid byte sequences with
        U+FFFD.  Python's bytes.decode('utf-8', errors='replace') uses the same
        per-byte replacement policy and serves as the independent oracle.

        Args:
            hexcore: The native hexcore module fixture.
        """
        invalid_utf8 = bytes([0x80, 0xFF, 0xFE, 0xC0, 0x80])
        expected: str = invalid_utf8.decode("utf-8", errors="replace")
        doc = hexcore.HexDocument.open_bytes(invalid_utf8 + b"\x00" * 10)
        result: str = doc.decode_text(0, len(invalid_utf8), "utf-8")
        assert result == expected

    def test_decode_single_ascii_byte(self, hexcore: types.ModuleType) -> None:
        """Verify that decode_text() on a single ASCII byte returns a one-character string.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(b"Z" + b"\x00" * 10)
        result = doc.decode_text(0, 1, "ascii")
        assert result == "Z"

    def test_decode_exact_document_length(self, hexcore: types.ModuleType) -> None:
        """Verify that decode_text() spanning the entire document returns all characters.

        Args:
            hexcore: The native hexcore module fixture.
        """
        text = "Full document"
        encoded = text.encode("utf-8")
        doc = hexcore.HexDocument.open_bytes(encoded)
        result = doc.decode_text(0, len(encoded), "utf-8")
        assert result == text
