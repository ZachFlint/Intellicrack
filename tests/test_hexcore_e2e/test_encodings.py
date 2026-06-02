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

    Verifies that decode_text() correctly interprets byte sequences as text for
    UTF-8, ASCII, and Latin-1 encodings using independently-derived oracles, and
    that it distinguishes encodings (the same bytes decode differently per
    encoding) rather than echoing the input string.
    """

    def test_decode_utf8_multibyte_and_distinguishes_from_latin1(self, hexcore: types.ModuleType) -> None:
        """Verify UTF-8 decoding of multibyte content and that Latin-1 of the same bytes differs.

        Embeds the UTF-8 encoding of a string containing a multibyte codepoint and
        confirms decode_text reproduces the original under UTF-8. The same bytes
        (all in the 0xA0-0xFF range where Latin-1 is a pure byte-to-codepoint
        identity) decoded as Latin-1 must instead yield the per-byte oracle, proving
        the encoding argument actually drives decoding rather than echoing input.

        Args:
            hexcore: The native hexcore module fixture.
        """
        text = "café"
        encoded = text.encode("utf-8")
        assert encoded == bytes([0x63, 0x61, 0x66, 0xC3, 0xA9])
        data = encoded + b"\x00" * 16
        doc = hexcore.HexDocument.open_bytes(data)
        assert doc.decode_text(0, len(encoded), "utf-8") == text
        latin1_oracle = "".join(chr(b) for b in encoded)
        assert doc.decode_text(0, len(encoded), "latin-1") == latin1_oracle
        assert latin1_oracle == "cafÃ©"
        assert latin1_oracle != text

    def test_decode_invalid_utf8_uses_replacement_characters(self, hexcore: types.ModuleType) -> None:
        """Verify decode_text replaces each invalid UTF-8 byte with U+FFFD, preserving valid bytes.

        Drives a sequence of two standalone continuation/invalid bytes followed by
        a valid ASCII byte. The lossy oracle is exactly two U+FFFD replacement
        characters then 'A'; this confirms invalid input is handled deterministically
        rather than crashing or silently dropping data.

        Args:
            hexcore: The native hexcore module fixture.
        """
        invalid = bytes([0x80, 0xFF, 0x41])
        doc = hexcore.HexDocument.open_bytes(invalid + b"\x00" * 8)
        result = doc.decode_text(0, len(invalid), "utf-8")
        assert result == "��A"
        assert [ord(c) for c in result] == [0xFFFD, 0xFFFD, 0x41]

    def test_decode_ascii_masks_high_bit(self, hexcore: types.ModuleType) -> None:
        """Verify ASCII decoding maps each byte to chr(byte & 0x7F) for high-bit bytes.

        The independent oracle is bit arithmetic: ASCII mode masks the high bit, so
        0xE9 -> 'i' (0x69) and 0xFF -> chr(0x7F). Asserting against the arithmetic
        oracle (not Python's strict ascii codec, which would raise) gates the
        bridge's actual documented behavior.

        Args:
            hexcore: The native hexcore module fixture.
        """
        raw = bytes([0x41, 0xE9, 0xFF, 0x80, 0x7A])
        doc = hexcore.HexDocument.open_bytes(raw + b"\x00" * 4)
        result = doc.decode_text(0, len(raw), "ascii")
        expected = "".join(chr(b & 0x7F) for b in raw)
        assert result == expected
        assert result == "Ai\x7f\x00z"

    def test_decode_latin1_high_range_matches_whatwg_table(self, hexcore: types.ModuleType) -> None:
        """Verify the Latin-1 decode of bytes 0x80-0xFF matches the WHATWG windows-1252 index.

        The bridge's ``latin-1`` decoder follows the WHATWG/encoding spec, which for
        the 0xA0-0xFF range is a pure byte-to-codepoint identity and for the 0x80-0x9F
        (C1) range uses the published windows-1252 index. The oracle for the C1 range
        is taken directly from that public standard, not from the implementation; the
        upper range is asserted as identity. A regression to a different table fails.

        Args:
            hexcore: The native hexcore module fixture.
        """
        whatwg_c1: dict[int, int] = {
            0x80: 0x20AC,
            0x82: 0x201A,
            0x83: 0x0192,
            0x85: 0x2026,
            0x86: 0x2020,
            0x89: 0x2030,
            0x8A: 0x0160,
            0x91: 0x2018,
            0x92: 0x2019,
            0x99: 0x2122,
            0x9C: 0x0153,
            0x9F: 0x0178,
        }
        raw = bytes(range(0x80, 0x100))
        doc = hexcore.HexDocument.open_bytes(raw)
        result = doc.decode_text(0, len(raw), "latin-1")
        assert len(result) == 128
        for byte_val, codepoint in whatwg_c1.items():
            assert ord(result[byte_val - 0x80]) == codepoint
        for byte_val in range(0xA0, 0x100):
            assert ord(result[byte_val - 0x80]) == byte_val

    def test_decode_at_multiple_offsets_and_boundaries(self, hexcore: types.ModuleType) -> None:
        """Verify decode_text reads from the exact requested offset across several positions.

        Lays three distinct ASCII tokens at known offsets in one buffer and decodes
        each independently, asserting the exact token at each offset including the
        final token that ends at the last document byte. Decoding a zero-length span
        and an out-of-range offset both yield empty strings.

        Args:
            hexcore: The native hexcore module fixture.
        """
        head = b"HEAD"
        mid = b"MIDDLE"
        tail = b"TAILEND"
        gap = b"\x00\x00\x00"
        data = head + gap + mid + gap + tail
        doc = hexcore.HexDocument.open_bytes(data)

        assert doc.decode_text(0, len(head), "ascii") == "HEAD"
        mid_offset = len(head) + len(gap)
        assert doc.decode_text(mid_offset, len(mid), "ascii") == "MIDDLE"
        tail_offset = mid_offset + len(mid) + len(gap)
        assert doc.decode_text(tail_offset, len(tail), "ascii") == "TAILEND"
        assert tail_offset + len(tail) == len(data)
        zero_span = doc.decode_text(mid_offset, 0, "ascii")
        assert not zero_span
        assert len(zero_span) == 0
        out_of_range = doc.decode_text(len(data) + 5, 4, "ascii")
        assert not out_of_range
        assert len(out_of_range) == 0

    def test_decode_unknown_encoding_raises_value_error(self, hexcore: types.ModuleType) -> None:
        """Verify decode_text raises ValueError for an unsupported encoding name.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(b"data" + b"\x00" * 4)
        with pytest.raises(ValueError, match="encoding"):
            doc.decode_text(0, 4, "not-a-real-encoding")

    def test_decode_utf8_multibyte_codepoint(self, hexcore: types.ModuleType) -> None:
        """Verify that decode_text() handles multi-byte UTF-8 codepoints correctly.

        Args:
            hexcore: The native hexcore module fixture.
        """
        text = "éàü"
        encoded = text.encode("utf-8")
        assert len(encoded) == 6
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

    def test_encode_utf8_matches_known_byte_sequence(self, hexcore: types.ModuleType) -> None:
        """Verify UTF-8 encoding produces the exact known byte sequence for multibyte text.

        Uses a hand-derived UTF-8 byte oracle for a string with an accented and a
        Euro-sign codepoint so the test does not merely mirror str.encode but pins
        the concrete bytes the bridge must emit.

        Args:
            hexcore: The native hexcore module fixture.
        """
        text = "Aé€"
        doc = hexcore.HexDocument.open_bytes(b"\x00" * 16)
        result = doc.encode_text_to_bytes(text, "utf-8")
        assert result == bytes([0x41, 0xC3, 0xA9, 0xE2, 0x82, 0xAC])
        assert result == text.encode("utf-8")

    def test_encode_ascii_matches_python_encode(self, hexcore: types.ModuleType) -> None:
        """Verify that encode_text_to_bytes() for ASCII matches Python's str.encode('ascii').

        Args:
            hexcore: The native hexcore module fixture.
        """
        text = "Intellicrack"
        doc = hexcore.HexDocument.open_bytes(b"\x00" * 16)
        result = doc.encode_text_to_bytes(text, "ascii")
        assert result == b"Intellicrack"
        assert result == text.encode("ascii")

    def test_encode_latin1_matches_known_byte_sequence(self, hexcore: types.ModuleType) -> None:
        """Verify Latin-1 encoding emits one byte per codepoint equal to that codepoint.

        Args:
            hexcore: The native hexcore module fixture.
        """
        text = "caf\xe9\xff"
        doc = hexcore.HexDocument.open_bytes(b"\x00" * 16)
        result = doc.encode_text_to_bytes(text, "latin-1")
        assert result == bytes([0x63, 0x61, 0x66, 0xE9, 0xFF])
        assert result == text.encode("latin-1")

    def test_encode_decode_roundtrip_utf8(self, hexcore: types.ModuleType) -> None:
        """Verify that encoding then decoding a UTF-8 string produces the original text.

        Args:
            hexcore: The native hexcore module fixture.
        """
        original = "Roundtrip UTF-8 test üé"
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

    Verifies that list_encodings() returns a list of (name, label) string tuples
    that includes the core encodings the encode/decode paths support.
    """

    def test_list_encodings_returns_well_formed_string_tuples(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify every list_encodings entry is a 2-tuple of non-empty strings.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result: list[tuple[str, str]] = sample_doc_from_bytes.list_encodings()
        assert isinstance(result, list)
        assert result
        for entry in result:
            assert isinstance(entry, tuple)
            assert len(entry) == 2
            name, label = entry
            assert isinstance(name, str)
            assert isinstance(label, str)
            assert name
            assert label

    def test_list_encodings_advertises_supported_encodings(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify list_encodings advertises the encodings the decode path actually supports.

        Cross-checks the advertised list against the encodings proven decodable
        elsewhere in this module: every advertised name must successfully decode a
        real byte, and the core families (UTF-8 and ASCII) must be present.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result: list[tuple[str, str]] = sample_doc_from_bytes.list_encodings()
        names_lower = [name.lower() for name, _label in result]
        assert any("utf-8" in n or "utf8" in n for n in names_lower)
        assert any("ascii" in n for n in names_lower)
        probe = sample_doc_from_bytes
        for name, _label in result:
            decoded = probe.decode_text(0x41, 1, name)
            assert isinstance(decoded, str)
            assert len(decoded) >= 1


class TestEncodingRoundtrips:
    """Tests for encode/decode roundtrips across multiple supported encodings.

    Verifies that for each supported encoding, encoding a string and decoding it
    back reproduces the original text, and that the intermediate bytes match an
    independent Python-codec oracle.
    """

    @pytest.mark.parametrize(
        "encoding",
        ["utf-8", "ascii", "latin-1", "utf-16le", "utf-16be"],
    )
    def test_roundtrip_matches_python_codec_oracle(self, hexcore: types.ModuleType, encoding: str) -> None:
        """Verify encode bytes match the Python codec and decode reproduces the original.

        Args:
            hexcore: The native hexcore module fixture.
            encoding: The encoding name to use for the roundtrip test.
        """
        original = "Hello World"
        python_codec = {"utf-16le": "utf-16-le", "utf-16be": "utf-16-be"}.get(encoding, encoding)
        oracle_bytes = original.encode(python_codec)
        doc = hexcore.HexDocument.open_bytes(b"\x00" * 64)
        encoded = doc.encode_text_to_bytes(original, encoding)
        assert encoded == oracle_bytes
        doc2 = hexcore.HexDocument.open_bytes(encoded)
        result = doc2.decode_text(0, len(encoded), encoding)
        assert result == original

    def test_utf16le_odd_trailing_byte_yields_replacement(self, hexcore: types.ModuleType) -> None:
        """Verify a UTF-16LE buffer with a dangling odd byte decodes the pair and replaces the remainder.

        Builds 'A' as UTF-16LE (0x41 0x00) followed by a lone 0x42 byte. The 16-bit
        pair decodes to 'A'; the trailing single byte cannot form a code unit and
        becomes U+FFFD, a deterministic, independently-known result.

        Args:
            hexcore: The native hexcore module fixture.
        """
        data = bytes([0x41, 0x00, 0x42])
        doc = hexcore.HexDocument.open_bytes(data)
        result = doc.decode_text(0, len(data), "utf-16le")
        assert result == "A�"

    def test_latin1_extended_chars_roundtrip(self, hexcore: types.ModuleType) -> None:
        """Verify that Latin-1 extended characters encode and decode without loss.

        Args:
            hexcore: The native hexcore module fixture.
        """
        original = "\xe9\xe0\xfc\xf6"
        doc = hexcore.HexDocument.open_bytes(b"\x00" * 16)
        encoded = doc.encode_text_to_bytes(original, "latin-1")
        assert encoded == bytes([0xE9, 0xE0, 0xFC, 0xF6])
        doc2 = hexcore.HexDocument.open_bytes(encoded)
        result = doc2.decode_text(0, len(encoded), "latin-1")
        assert result == original


class TestDecodeTextEdgeCases:
    """Tests for edge cases in decode_text() length and span handling."""

    def test_decode_zero_length_returns_empty_string(self, hexcore: types.ModuleType) -> None:
        """Verify that decode_text() on a zero-length range returns an empty string.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(b"ABCDEF")
        result = doc.decode_text(0, 0, "utf-8")
        assert not result
        assert len(result) == 0

    def test_decode_length_past_end_truncates_to_available(self, hexcore: types.ModuleType) -> None:
        """Verify a length spanning past the document end decodes only the available bytes.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(b"AB")
        assert doc.decode_text(0, 10, "ascii") == "AB"

    def test_decode_single_ascii_byte(self, hexcore: types.ModuleType) -> None:
        """Verify that decode_text() on a single ASCII byte returns a one-character string.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(b"Z" + b"\x00" * 10)
        assert doc.decode_text(0, 1, "ascii") == "Z"

    def test_decode_exact_document_length(self, hexcore: types.ModuleType) -> None:
        """Verify that decode_text() spanning the entire document returns all characters.

        Args:
            hexcore: The native hexcore module fixture.
        """
        text = "Full document"
        encoded = text.encode("utf-8")
        doc = hexcore.HexDocument.open_bytes(encoded)
        assert doc.decode_text(0, len(encoded), "utf-8") == text
