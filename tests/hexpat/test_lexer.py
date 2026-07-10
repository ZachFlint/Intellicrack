# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""Tests for the HexPat lexer."""

from __future__ import annotations

import pytest

from intellicrack.core.hexpat.errors import HexPatParseError
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.tokens import TokenType


class TestLexerTokenTypes:
    """Tests for HexPat lexer token type recognition and error handling."""

    def test_simple_struct(self) -> None:
        """Verify struct declaration tokenizes into correct keyword and punctuation types."""
        tokens = HexPatLexer("struct Foo { u32 x; };").tokenize()
        types = [t.type for t in tokens[:-1]]
        assert types == [
            TokenType.STRUCT,
            TokenType.IDENTIFIER,
            TokenType.LBRACE,
            TokenType.U32,
            TokenType.IDENTIFIER,
            TokenType.SEMICOLON,
            TokenType.RBRACE,
            TokenType.SEMICOLON,
        ]

    def test_hex_literal(self) -> None:
        """Verify hexadecimal literal is parsed as a NUMBER token with correct value."""
        tokens = HexPatLexer("0xDEADBEEF").tokenize()
        assert tokens[0].type == TokenType.NUMBER
        assert tokens[0].value == str(0xDEADBEEF)

    def test_binary_literal(self) -> None:
        """Verify binary literal is parsed as a NUMBER token with correct value."""
        tokens = HexPatLexer("0b10110").tokenize()
        assert tokens[0].type == TokenType.NUMBER
        assert tokens[0].value == str(0b10110)

    def test_octal_literal(self) -> None:
        """Verify octal literal is parsed as a NUMBER token with correct value."""
        tokens = HexPatLexer("0o777").tokenize()
        assert tokens[0].type == TokenType.NUMBER
        assert tokens[0].value == str(0o777)

    def test_float_literal(self) -> None:
        """Verify decimal float is parsed as a FLOAT_LITERAL token."""
        tokens = HexPatLexer("3.14").tokenize()
        assert tokens[0].type == TokenType.FLOAT_LITERAL
        assert tokens[0].value == "3.14"

    def test_float_exponent(self) -> None:
        """Verify scientific notation is parsed as a FLOAT_LITERAL token."""
        tokens = HexPatLexer("1e5").tokenize()
        assert tokens[0].type == TokenType.FLOAT_LITERAL

    def test_string_literal_escapes(self) -> None:
        """Verify escape sequences in string literals are decoded correctly."""
        tokens = HexPatLexer(r'"hello\nworld\t\x41"').tokenize()
        assert tokens[0].type == TokenType.STRING_LITERAL
        assert tokens[0].value == "hello\nworld\tA"

    def test_char_literal(self) -> None:
        """Verify single-quoted character is parsed as a CHAR_LITERAL token."""
        tokens = HexPatLexer("'A'").tokenize()
        assert tokens[0].type == TokenType.CHAR_LITERAL
        assert tokens[0].value == "A"

    def test_all_keywords(self) -> None:
        """Verify all reserved keywords are recognized as their respective token types."""
        keywords = [
            "struct",
            "union",
            "enum",
            "bitfield",
            "if",
            "else",
            "match",
            "while",
            "for",
            "fn",
            "return",
            "break",
            "continue",
            "namespace",
            "using",
            "try",
            "catch",
        ]
        for kw in keywords:
            tokens = HexPatLexer(kw).tokenize()
            assert tokens[0].type.value == kw, f"keyword {kw} not recognized"

    def test_multichar_operators(self) -> None:
        """Verify multi-character operators map to correct token types."""
        cases = {
            "==": TokenType.EQ,
            "!=": TokenType.NE,
            "<=": TokenType.LE_OP,
            ">=": TokenType.GE_OP,
            "<<": TokenType.LSHIFT,
            ">>": TokenType.RSHIFT,
            "&&": TokenType.DOUBLE_AMPERSAND,
            "||": TokenType.DOUBLE_PIPE,
            "::": TokenType.DOUBLE_COLON,
            "->": TokenType.ARROW,
            "<<=": TokenType.LSHIFT_ASSIGN,
            ">>=": TokenType.RSHIFT_ASSIGN,
            "[[": TokenType.DOUBLE_LBRACKET,
            "]]": TokenType.DOUBLE_RBRACKET,
        }
        for source, expected in cases.items():
            tokens = HexPatLexer(source).tokenize()
            assert tokens[0].type == expected, f"operator {source!r} -> {tokens[0].type}"

    def test_line_comment(self) -> None:
        """Verify line comments are stripped and surrounding tokens are preserved."""
        tokens = HexPatLexer("u8 x; // comment\nu16 y;").tokenize()
        types = [t.type for t in tokens if t.type != TokenType.EOF]
        assert types == [TokenType.U8, TokenType.IDENTIFIER, TokenType.SEMICOLON, TokenType.U16, TokenType.IDENTIFIER, TokenType.SEMICOLON]

    def test_block_comment_nested(self) -> None:
        """Verify nested block comments are handled correctly."""
        tokens = HexPatLexer("u8 /* /* nested */ */ x;").tokenize()
        types = [t.type for t in tokens if t.type != TokenType.EOF]
        assert types == [TokenType.U8, TokenType.IDENTIFIER, TokenType.SEMICOLON]

    def test_dollar_and_at(self) -> None:
        """Verify dollar and at symbols are parsed as DOLLAR and AT tokens."""
        tokens = HexPatLexer("$ @").tokenize()
        assert tokens[0].type == TokenType.DOLLAR
        assert tokens[1].type == TokenType.AT

    def test_ellipsis(self) -> None:
        """Verify three consecutive dots are parsed as an ELLIPSIS token."""
        tokens = HexPatLexer("...").tokenize()
        assert tokens[0].type == TokenType.ELLIPSIS

    def test_unterminated_string_raises(self) -> None:
        """Verify unterminated string literal raises HexPatParseError with correct context.

        The lexer must raise on the opening quote character (column 1, line 1)
        because the string ``'"hello'`` never receives a closing quote.  The
        precondition verifies the lexer starts in a clean state (position 0,
        line 1) to confirm the error occurs during tokenization itself rather
        than during some prior initialisation step.  The exception message must
        name the exact fault ("Unterminated string") rather than a generic
        parse error.
        """
        lexer = HexPatLexer('"hello')
        initial_pos: int = getattr(lexer, "_pos")
        initial_line: int = getattr(lexer, "_line")
        assert initial_pos == 0, "precondition: lexer must not have consumed any input before tokenize()"
        assert initial_line == 1, "precondition: lexer must start on line 1"
        with pytest.raises(HexPatParseError, match="Unterminated string"):
            lexer.tokenize()

    def test_unterminated_block_comment_raises(self) -> None:
        """Verify unterminated block comment raises HexPatParseError."""
        with pytest.raises(HexPatParseError, match="Unterminated block"):
            HexPatLexer("/* no end").tokenize()

    def test_unexpected_char_raises(self) -> None:
        """Verify unexpected control character raises HexPatParseError."""
        with pytest.raises(HexPatParseError):
            HexPatLexer("\x01").tokenize()

    def test_number_with_underscores(self) -> None:
        """Verify numeric literals with underscore separators are parsed correctly."""
        tokens = HexPatLexer("1_000_000").tokenize()
        assert tokens[0].type == TokenType.NUMBER
        assert tokens[0].value == "1000000"

    def test_line_tracking(self) -> None:
        """Verify tokens record correct line numbers across newlines."""
        tokens = HexPatLexer("a\nb\nc").tokenize()
        assert tokens[0].line == 1
        assert tokens[1].line == 2
        assert tokens[2].line == 3
