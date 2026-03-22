# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Token types and Token dataclass for the HexPat pattern language lexer."""

from __future__ import annotations

import enum
from dataclasses import dataclass


class TokenType(enum.Enum):
    """Token types produced by the HexPat lexer."""

    STRUCT = "struct"
    UNION = "union"
    ENUM = "enum"
    BITFIELD = "bitfield"
    IF = "if"
    ELSE = "else"
    MATCH = "match"
    WHILE = "while"
    FOR = "for"
    FN = "fn"
    RETURN = "return"
    BREAK = "break"
    CONTINUE = "continue"
    NAMESPACE = "namespace"
    USING = "using"
    IN = "in"
    TRY = "try"
    CATCH = "catch"

    U8 = "u8"
    U16 = "u16"
    U32 = "u32"
    U64 = "u64"
    U128 = "u128"
    S8 = "s8"
    S16 = "s16"
    S32 = "s32"
    S64 = "s64"
    S128 = "s128"
    FLOAT = "float"
    DOUBLE = "double"
    CHAR = "char"
    CHAR16 = "char16"
    BOOL = "bool"
    STR = "str"
    AUTO = "auto"
    PADDING = "padding"

    LE = "le"
    BE = "be"

    SIZEOF = "sizeof"
    ADDRESSOF = "addressof"
    TYPENAMEOF = "typenameof"

    THIS = "this"
    PARENT = "parent"
    REF = "ref"
    OUT = "out"
    CONST = "const"

    NUMBER = "number"
    FLOAT_LITERAL = "float_literal"
    STRING_LITERAL = "string_literal"
    CHAR_LITERAL = "char_literal"
    TRUE_KW = "true"
    FALSE_KW = "false"
    NULL_KW = "null"

    IDENTIFIER = "identifier"

    LBRACE = "{"
    RBRACE = "}"
    LBRACKET = "["
    RBRACKET = "]"
    LPAREN = "("
    RPAREN = ")"
    SEMICOLON = ";"
    COMMA = ","
    DOT = "."
    COLON = ":"

    DOUBLE_LBRACKET = "[["
    DOUBLE_RBRACKET = "]]"

    DOLLAR = "$"
    AT = "@"
    HASH = "#"
    ARROW = "->"
    DOUBLE_COLON = "::"
    ELLIPSIS = "..."

    EQ = "=="
    NE = "!="
    LT = "<"
    GT = ">"
    LE_OP = "<="
    GE_OP = ">="

    DOUBLE_AMPERSAND = "&&"
    DOUBLE_PIPE = "||"
    DOUBLE_CARET = "^^"
    BANG = "!"

    AMPERSAND = "&"
    PIPE = "|"
    CARET = "^"
    TILDE = "~"
    LSHIFT = "<<"
    RSHIFT = ">>"

    PLUS = "+"
    MINUS = "-"
    STAR = "*"
    SLASH = "/"
    PERCENT = "%"

    ASSIGN = "="
    PLUS_ASSIGN = "+="
    MINUS_ASSIGN = "-="
    STAR_ASSIGN = "*="
    SLASH_ASSIGN = "/="
    PERCENT_ASSIGN = "%="
    AMPERSAND_ASSIGN = "&="
    PIPE_ASSIGN = "|="
    CARET_ASSIGN = "^="
    LSHIFT_ASSIGN = "<<="
    RSHIFT_ASSIGN = ">>="

    QUESTION = "?"

    EOF = "eof"


@dataclass(frozen=True)
class Token:
    """A single lexer token.

    Attributes:
        type: The token type.
        value: The raw source text of the token.
        line: Source line number (1-based).
        column: Source column number (1-based).
    """

    type: TokenType
    value: str
    line: int
    column: int


KEYWORDS: dict[str, TokenType] = {
    "struct": TokenType.STRUCT,
    "union": TokenType.UNION,
    "enum": TokenType.ENUM,
    "bitfield": TokenType.BITFIELD,
    "if": TokenType.IF,
    "else": TokenType.ELSE,
    "match": TokenType.MATCH,
    "while": TokenType.WHILE,
    "for": TokenType.FOR,
    "fn": TokenType.FN,
    "return": TokenType.RETURN,
    "break": TokenType.BREAK,
    "continue": TokenType.CONTINUE,
    "namespace": TokenType.NAMESPACE,
    "using": TokenType.USING,
    "in": TokenType.IN,
    "try": TokenType.TRY,
    "catch": TokenType.CATCH,
    "u8": TokenType.U8,
    "u16": TokenType.U16,
    "u32": TokenType.U32,
    "u64": TokenType.U64,
    "u128": TokenType.U128,
    "s8": TokenType.S8,
    "s16": TokenType.S16,
    "s32": TokenType.S32,
    "s64": TokenType.S64,
    "s128": TokenType.S128,
    "float": TokenType.FLOAT,
    "double": TokenType.DOUBLE,
    "char": TokenType.CHAR,
    "char16": TokenType.CHAR16,
    "bool": TokenType.BOOL,
    "str": TokenType.STR,
    "auto": TokenType.AUTO,
    "padding": TokenType.PADDING,
    "le": TokenType.LE,
    "be": TokenType.BE,
    "sizeof": TokenType.SIZEOF,
    "addressof": TokenType.ADDRESSOF,
    "typenameof": TokenType.TYPENAMEOF,
    "this": TokenType.THIS,
    "parent": TokenType.PARENT,
    "ref": TokenType.REF,
    "out": TokenType.OUT,
    "const": TokenType.CONST,
    "true": TokenType.TRUE_KW,
    "false": TokenType.FALSE_KW,
    "null": TokenType.NULL_KW,
}

PRIMITIVE_TYPES: frozenset[TokenType] = frozenset({
    TokenType.U8,
    TokenType.U16,
    TokenType.U32,
    TokenType.U64,
    TokenType.U128,
    TokenType.S8,
    TokenType.S16,
    TokenType.S32,
    TokenType.S64,
    TokenType.S128,
    TokenType.FLOAT,
    TokenType.DOUBLE,
    TokenType.CHAR,
    TokenType.CHAR16,
    TokenType.BOOL,
    TokenType.STR,
    TokenType.AUTO,
    TokenType.PADDING,
})

ENDIANNESS_TOKENS: frozenset[TokenType] = frozenset({
    TokenType.LE,
    TokenType.BE,
})

ASSIGNMENT_OPS: frozenset[TokenType] = frozenset({
    TokenType.ASSIGN,
    TokenType.PLUS_ASSIGN,
    TokenType.MINUS_ASSIGN,
    TokenType.STAR_ASSIGN,
    TokenType.SLASH_ASSIGN,
    TokenType.PERCENT_ASSIGN,
    TokenType.AMPERSAND_ASSIGN,
    TokenType.PIPE_ASSIGN,
    TokenType.CARET_ASSIGN,
    TokenType.LSHIFT_ASSIGN,
    TokenType.RSHIFT_ASSIGN,
})
