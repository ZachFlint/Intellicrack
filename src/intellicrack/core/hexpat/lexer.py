# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
# This file is part of Intellicrack. See LICENSE for details.

"""Lexer for the HexPat pattern language."""

from __future__ import annotations

from intellicrack.core.hexpat.errors import HexPatParseError
from intellicrack.core.hexpat.tokens import KEYWORDS, Token, TokenType


class HexPatLexer:
    """
    Tokenizer for the HexPat pattern language.

    Converts raw source text into a flat list of Token objects.  The final
    token in the returned list is always an EOF token.

    Attributes:
        _source: The raw source text being tokenized.
        _pos: Current character position within _source.
        _line: Current 1-based source line number.
        _column: Current 1-based source column number.
        _file_path: Source file path reported in error messages.
        _tokens: Accumulated list of tokens produced so far.
    """

    def __init__(self, source: str, file_path: str = "<input>") -> None:
        """
        Initialize the lexer with source text.

        Args:
            source: The raw source text to tokenize.
            file_path: Optional file path used in error messages.
        """
        self._source = source
        self._pos = 0
        self._line = 1
        self._column = 1
        self._file_path = file_path
        self._tokens: list[Token] = []

    def tokenize(self) -> list[Token]:
        """
        Tokenize the source into a list of Tokens.

        Returns:
            A list of Token objects ending with an EOF token.

        Raises:
            HexPatParseError: If an unexpected character is encountered.
        """
        while self._pos < len(self._source):
            self._scan_token()
        self._tokens.append(Token(TokenType.EOF, "", self._line, self._column))
        return self._tokens

    def _peek(self, offset: int = 0) -> str:
        """
        Return the character at pos+offset without consuming it.

        Args:
            offset: How many characters ahead to look.

        Returns:
            The character at the requested position, or empty string if past end.
        """
        idx = self._pos + offset
        return self._source[idx] if idx < len(self._source) else ""

    def _advance(self) -> str:
        """
        Consume and return the current character, updating position tracking.

        Returns:
            The consumed character.
        """
        ch = self._source[self._pos]
        self._pos += 1
        if ch == "\n":
            self._line += 1
            self._column = 1
        else:
            self._column += 1
        return ch

    def _match(self, expected: str) -> bool:
        """
        Consume the next character if it matches expected.

        Args:
            expected: The single character to match.

        Returns:
            True if the character was consumed, False otherwise.
        """
        if self._pos < len(self._source) and self._source[self._pos] == expected:
            self._advance()
            return True
        return False

    def _add(self, ttype: TokenType, value: str, line: int, column: int) -> None:
        """
        Append a Token to the internal token list.

        Args:
            ttype: The token type.
            value: The raw source text for the token.
            line: The 1-based line number of the token start.
            column: The 1-based column number of the token start.
        """
        self._tokens.append(Token(ttype, value, line, column))

    def _error(self, msg: str, line: int, column: int) -> HexPatParseError:
        """
        Create a HexPatParseError at the given source location.

        Args:
            msg: The error description.
            line: The 1-based line number of the error.
            column: The 1-based column number of the error.

        Returns:
            A HexPatParseError ready to be raised.
        """
        return HexPatParseError(msg, line, column, self._file_path)

    def _skip_whitespace(self) -> bool:
        """
        Skip whitespace characters.

        Returns:
            True if any whitespace was skipped.
        """
        ch = self._peek()
        if ch in {" ", "\t", "\r", "\n"}:
            self._advance()
            return True
        return False

    def _skip_line_comment(self) -> bool:
        """
        Skip a single-line comment starting with //.

        Returns:
            True if a line comment was skipped.
        """
        if self._peek() == "/" and self._peek(1) == "/":
            while self._pos < len(self._source) and self._peek() != "\n":
                self._advance()
            return True
        return False

    def _skip_block_comment(self) -> bool:
        """
        Skip a block comment delimited by /* and */, supporting nesting.

        Returns:
            True if a block comment was skipped.

        Raises:
            HexPatParseError: If the block comment is not terminated.
        """
        if self._peek() != "/" or self._peek(1) != "*":
            return False
        line = self._line
        col = self._column
        self._advance()
        self._advance()
        depth = 1
        while self._pos < len(self._source):
            if self._peek() == "/" and self._peek(1) == "*":
                self._advance()
                self._advance()
                depth += 1
            elif self._peek() == "*" and self._peek(1) == "/":
                self._advance()
                self._advance()
                depth -= 1
                if depth == 0:
                    return True
            else:
                self._advance()
        msg = "Unterminated block comment"
        raise self._error(msg, line, col)

    def _scan_string(self, line: int, col: int) -> None:
        """
        Scan a double-quoted string literal and emit a STRING_LITERAL token.

        Args:
            line: The 1-based line number where the string started.
            col: The 1-based column number where the string started.

        Raises:
            HexPatParseError: If the string is unterminated or contains an
                invalid escape sequence.
        """
        self._advance()
        buf: list[str] = []
        while self._pos < len(self._source):
            ch = self._peek()
            if ch == '"':
                self._advance()
                self._add(TokenType.STRING_LITERAL, "".join(buf), line, col)
                return
            if ch == "\n":
                msg = "Unterminated string literal"
                raise self._error(msg, line, col)
            if ch == "\\":
                self._advance()
                buf.append(self._scan_escape(line, col))
            else:
                buf.append(ch)
                self._advance()
        msg = "Unterminated string literal"
        raise self._error(msg, line, col)

    def _scan_char(self, line: int, col: int) -> None:
        """
        Scan a single-quoted character literal and emit a CHAR_LITERAL token.

        Args:
            line: The 1-based line number where the literal started.
            col: The 1-based column number where the literal started.

        Raises:
            HexPatParseError: If the literal is empty, unterminated, or contains
                an invalid escape sequence.
        """
        self._advance()
        if self._pos >= len(self._source):
            msg = "Unterminated character literal"
            raise self._error(msg, line, col)
        ch = self._peek()
        if ch == "\\":
            self._advance()
            value = self._scan_escape(line, col)
        elif ch == "'":
            msg = "Empty character literal"
            raise self._error(msg, line, col)
        else:
            value = ch
            self._advance()
        if self._pos >= len(self._source) or self._peek() != "'":
            msg = "Unterminated character literal"
            raise self._error(msg, line, col)
        self._advance()
        self._add(TokenType.CHAR_LITERAL, value, line, col)

    def _scan_escape(self, line: int, col: int) -> str:
        """
        Scan a single escape sequence (after the backslash has been consumed).

        Args:
            line: The 1-based line number where the escape started.
            col: The 1-based column number where the escape started.

        Returns:
            The decoded character or characters.

        Raises:
            HexPatParseError: If the escape sequence is invalid or truncated.
        """
        if self._pos >= len(self._source):
            msg = "Truncated escape sequence"
            raise self._error(msg, line, col)
        ch = self._source[self._pos]
        self._advance()
        simple = {
            "n": "\n",
            "t": "\t",
            "r": "\r",
            "\\": "\\",
            '"': '"',
            "'": "'",
            "0": "\0",
        }
        if ch in simple:
            return simple[ch]
        if ch == "x":
            hex_digits: list[str] = []
            for _ in range(2):
                if self._pos < len(self._source) and self._source[self._pos] in "0123456789abcdefABCDEF":
                    hex_digits.append(self._source[self._pos])
                    self._advance()
                else:
                    msg = "Invalid \\x escape sequence"
                    raise self._error(msg, line, col)
            return chr(int("".join(hex_digits), 16))
        msg = f"Unknown escape sequence \\{ch}"
        raise self._error(msg, line, col)

    def _scan_number(self, line: int, col: int) -> None:
        """
        Scan an integer or float literal and emit a NUMBER or FLOAT_LITERAL token.

        Handles decimal, hexadecimal (0x/0X), binary (0b/0B), octal (0o/0O)
        integers and decimal floating-point numbers with optional exponents.

        Args:
            line: The 1-based line number where the literal started.
            col: The 1-based column number where the literal started.

        Raises:
            HexPatParseError: If the numeric literal has an invalid format.
        """
        start = self._pos
        ch = self._peek()

        if ch == "0" and self._peek(1) in {"x", "X"}:
            self._advance()
            self._advance()
            if self._pos >= len(self._source) or self._source[self._pos] not in "0123456789abcdefABCDEF_":
                msg = "Invalid hexadecimal literal"
                raise self._error(msg, line, col)
            while self._pos < len(self._source) and self._source[self._pos] in "0123456789abcdefABCDEF_":
                self._advance()
            raw = self._source[start : self._pos].replace("_", "")
            self._add(TokenType.NUMBER, str(int(raw, 16)), line, col)
            return

        if ch == "0" and self._peek(1) in {"b", "B"}:
            self._advance()
            self._advance()
            if self._pos >= len(self._source) or self._source[self._pos] not in "01_":
                msg = "Invalid binary literal"
                raise self._error(msg, line, col)
            while self._pos < len(self._source) and self._source[self._pos] in "01_":
                self._advance()
            raw = self._source[start : self._pos].replace("_", "")
            self._add(TokenType.NUMBER, str(int(raw, 2)), line, col)
            return

        if ch == "0" and self._peek(1) in {"o", "O"}:
            self._advance()
            self._advance()
            if self._pos >= len(self._source) or self._source[self._pos] not in "01234567_":
                msg = "Invalid octal literal"
                raise self._error(msg, line, col)
            while self._pos < len(self._source) and self._source[self._pos] in "01234567_":
                self._advance()
            raw = self._source[start : self._pos].replace("_", "")
            self._add(TokenType.NUMBER, str(int(raw, 8)), line, col)
            return

        while self._pos < len(self._source) and (self._source[self._pos].isdigit() or self._source[self._pos] == "_"):
            self._advance()

        is_float = False
        if (
            self._pos < len(self._source)
            and self._source[self._pos] == "."
            and (self._pos + 1 < len(self._source) and self._source[self._pos + 1].isdigit())
        ):
            is_float = True
            self._advance()
            while self._pos < len(self._source) and (self._source[self._pos].isdigit() or self._source[self._pos] == "_"):
                self._advance()

        if self._pos < len(self._source) and self._source[self._pos] in {"e", "E"}:
            is_float = True
            self._advance()
            if self._pos < len(self._source) and self._source[self._pos] in {"+", "-"}:
                self._advance()
            if self._pos >= len(self._source) or not self._source[self._pos].isdigit():
                msg = "Invalid float exponent"
                raise self._error(msg, line, col)
            while self._pos < len(self._source) and self._source[self._pos].isdigit():
                self._advance()

        raw = self._source[start : self._pos].replace("_", "")
        if is_float:
            self._add(TokenType.FLOAT_LITERAL, raw, line, col)
        else:
            self._add(TokenType.NUMBER, str(int(raw, 10)), line, col)

    def _scan_identifier(self, line: int, col: int) -> None:
        """
        Scan an identifier or keyword and emit the appropriate token.

        Args:
            line: The 1-based line number where the identifier started.
            col: The 1-based column number where the identifier started.
        """
        start = self._pos
        while self._pos < len(self._source) and (self._source[self._pos].isalnum() or self._source[self._pos] == "_"):
            self._advance()
        text = self._source[start : self._pos]
        ttype = KEYWORDS.get(text, TokenType.IDENTIFIER)
        self._add(ttype, text, line, col)

    def _scan_operator(self, ch: str, line: int, col: int) -> None:
        """
        Emit a token for an operator or multi-character punctuation.

        Args:
            ch: The first character of the operator, already consumed.
            line: The 1-based line number of the operator start.
            col: The 1-based column number of the operator start.

        Raises:
            HexPatParseError: If an incomplete operator sequence is encountered.
        """
        if ch == "!":
            if self._match("="):
                self._add(TokenType.NE, "!=", line, col)
            else:
                self._add(TokenType.BANG, ch, line, col)
        elif ch == "%":
            if self._match("="):
                self._add(TokenType.PERCENT_ASSIGN, "%=", line, col)
            else:
                self._add(TokenType.PERCENT, ch, line, col)
        elif ch == "&":
            if self._match("&"):
                self._add(TokenType.DOUBLE_AMPERSAND, "&&", line, col)
            elif self._match("="):
                self._add(TokenType.AMPERSAND_ASSIGN, "&=", line, col)
            else:
                self._add(TokenType.AMPERSAND, ch, line, col)
        elif ch == "*":
            if self._match("="):
                self._add(TokenType.STAR_ASSIGN, "*=", line, col)
            else:
                self._add(TokenType.STAR, ch, line, col)
        elif ch == "+":
            if self._match("="):
                self._add(TokenType.PLUS_ASSIGN, "+=", line, col)
            else:
                self._add(TokenType.PLUS, ch, line, col)
        elif ch == "-":
            if self._match(">"):
                self._add(TokenType.ARROW, "->", line, col)
            elif self._match("="):
                self._add(TokenType.MINUS_ASSIGN, "-=", line, col)
            else:
                self._add(TokenType.MINUS, ch, line, col)
        elif ch == ".":
            if self._match("."):
                if self._match("."):
                    self._add(TokenType.ELLIPSIS, "...", line, col)
                else:
                    raise self._error("Expected '...' but got '..'", line, col)
            else:
                self._add(TokenType.DOT, ch, line, col)
        elif ch == "/":
            if self._match("="):
                self._add(TokenType.SLASH_ASSIGN, "/=", line, col)
            else:
                self._add(TokenType.SLASH, ch, line, col)
        elif ch == ":":
            if self._match(":"):
                self._add(TokenType.DOUBLE_COLON, "::", line, col)
            else:
                self._add(TokenType.COLON, ch, line, col)
        elif ch == "<":
            if self._match("<"):
                if self._match("="):
                    self._add(TokenType.LSHIFT_ASSIGN, "<<=", line, col)
                else:
                    self._add(TokenType.LSHIFT, "<<", line, col)
            elif self._match("="):
                self._add(TokenType.LE_OP, "<=", line, col)
            else:
                self._add(TokenType.LT, ch, line, col)
        elif ch == "=":
            if self._match("="):
                self._add(TokenType.EQ, "==", line, col)
            else:
                self._add(TokenType.ASSIGN, ch, line, col)
        elif ch == ">":
            if self._match(">"):
                if self._match("="):
                    self._add(TokenType.RSHIFT_ASSIGN, ">>=", line, col)
                else:
                    self._add(TokenType.RSHIFT, ">>", line, col)
            elif self._match("="):
                self._add(TokenType.GE_OP, ">=", line, col)
            else:
                self._add(TokenType.GT, ch, line, col)
        elif ch == "[":
            if self._match("["):
                self._add(TokenType.DOUBLE_LBRACKET, "[[", line, col)
            else:
                self._add(TokenType.LBRACKET, ch, line, col)
        elif ch == "]":
            if self._match("]"):
                self._add(TokenType.DOUBLE_RBRACKET, "]]", line, col)
            else:
                self._add(TokenType.RBRACKET, ch, line, col)
        elif ch == "^":
            if self._match("^"):
                self._add(TokenType.DOUBLE_CARET, "^^", line, col)
            elif self._match("="):
                self._add(TokenType.CARET_ASSIGN, "^=", line, col)
            else:
                self._add(TokenType.CARET, ch, line, col)
        elif ch == "|":
            if self._match("|"):
                self._add(TokenType.DOUBLE_PIPE, "||", line, col)
            elif self._match("="):
                self._add(TokenType.PIPE_ASSIGN, "|=", line, col)
            else:
                self._add(TokenType.PIPE, ch, line, col)
        else:
            msg = f"Unexpected character: {ch!r}"
            raise self._error(msg, line, col)

    def _scan_token(self) -> None:
        """
        Scan and emit the next token from the current position.

        Raises:
            HexPatParseError: If an unexpected character is encountered.
        """
        while self._pos < len(self._source):
            if self._skip_whitespace():
                continue
            if self._skip_line_comment():
                continue
            if self._skip_block_comment():
                continue
            break

        if self._pos >= len(self._source):
            return

        line = self._line
        col = self._column
        ch = self._peek()

        if ch == '"':
            self._scan_string(line, col)
            return

        if ch == "'":
            self._scan_char(line, col)
            return

        if ch.isdigit():
            self._scan_number(line, col)
            return

        if ch.isalpha() or ch == "_":
            self._scan_identifier(line, col)
            return

        self._advance()
        singles: dict[str, TokenType] = {
            "{": TokenType.LBRACE,
            "}": TokenType.RBRACE,
            "(": TokenType.LPAREN,
            ")": TokenType.RPAREN,
            ";": TokenType.SEMICOLON,
            ",": TokenType.COMMA,
            "?": TokenType.QUESTION,
            "$": TokenType.DOLLAR,
            "@": TokenType.AT,
            "#": TokenType.HASH,
            "~": TokenType.TILDE,
        }
        if ch in singles:
            self._add(singles[ch], ch, line, col)
        else:
            self._scan_operator(ch, line, col)
