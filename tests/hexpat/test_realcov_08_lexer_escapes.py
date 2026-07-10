# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Escape-sequence and literal error-path coverage for the HexPat lexer.

These tests exercise the error and decoding branches of
``HexPatLexer._scan_escape`` and the character-literal scanner that the
existing lexer suite leaves uncovered: unknown escapes, malformed ``\x``
escapes, empty and unterminated character literals, truncated escapes at
end-of-input, and correct decoding of the ``\0`` and ``\r`` escapes. Every
case drives the real tokenizer and asserts on the concrete decoded token value
or the raised :class:`HexPatParseError` message.
"""

from __future__ import annotations

import pytest

from intellicrack.core.hexpat.errors import HexPatParseError
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.tokens import TokenType


class TestLexerEscapeErrors:
    """Cover the error branches of ``_scan_escape`` and character scanning."""

    def test_unknown_escape_sequence_raises(self) -> None:
        r"""An unrecognised escape such as ``\z`` raises with a precise message."""
        with pytest.raises(HexPatParseError, match="Unknown escape"):
            HexPatLexer('"\\z"').tokenize()

    def test_invalid_hex_escape_raises(self) -> None:
        r"""A ``\x`` escape with non-hex digits raises ``Invalid \x escape``."""
        with pytest.raises(HexPatParseError, match=r"Invalid \\x escape"):
            HexPatLexer('"\\xgg"').tokenize()

    def test_truncated_escape_at_eof_raises(self) -> None:
        """A backslash as the final byte raises ``Truncated escape sequence``.

        The trailing backslash begins an escape but no character follows before
        end-of-input, so ``_scan_escape`` reports a truncated sequence.
        """
        with pytest.raises(HexPatParseError, match="Truncated escape sequence"):
            HexPatLexer('"abc\\').tokenize()

    def test_empty_char_literal_raises(self) -> None:
        """An empty char literal ``''`` raises ``Empty character literal``."""
        with pytest.raises(HexPatParseError, match="Empty character literal"):
            HexPatLexer("''").tokenize()

    def test_unterminated_char_literal_raises(self) -> None:
        """A char literal missing its closing quote raises ``Unterminated``."""
        with pytest.raises(HexPatParseError, match="Unterminated character literal"):
            HexPatLexer("'a").tokenize()


class TestLexerEscapeDecoding:
    """Cover the successful decoding branches of ``_scan_escape``."""

    def test_null_escape_decodes_to_nul(self) -> None:
        r"""The ``\0`` escape decodes to a NUL byte inside a string literal."""
        tokens = HexPatLexer('"a\\0b"').tokenize()
        assert tokens[0].type == TokenType.STRING_LITERAL
        assert tokens[0].value == "a\x00b"

    def test_carriage_return_escape_decodes(self) -> None:
        r"""The ``\r`` escape decodes to a carriage return character."""
        tokens = HexPatLexer('"x\\ry"').tokenize()
        assert tokens[0].value == "x\ry"

    def test_hex_escape_decodes_to_codepoint(self) -> None:
        r"""A valid ``\x41`` escape decodes to the character ``A``."""
        tokens = HexPatLexer('"\\x41"').tokenize()
        assert tokens[0].value == "A"

    def test_escaped_quote_in_char_literal(self) -> None:
        """A char literal of an escaped single quote decodes correctly."""
        tokens = HexPatLexer("'\\''").tokenize()
        assert tokens[0].type == TokenType.CHAR_LITERAL
        assert tokens[0].value == "'"
