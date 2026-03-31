# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""HexPat DSL compiler: lexer, parser, and JSON codegen.

Compiles a C-like pattern definition language (.hexpat)
into JSON template definitions consumable by the Rust hex editor core.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from typing import Any

from intellicrack.core.logging import get_logger


_logger = get_logger("core.hexpat_compiler")


class HexPatError(Exception):
    """
    Error raised during HexPat DSL compilation.

    Args:
        message: Human-readable error description.
        line: Source line number where the error occurred.
        column: Source column number where the error occurred.
    """

    def __init__(self, message: str, line: int = 0, column: int = 0) -> None:
        self.message = message
        self.line = line
        self.column = column
        super().__init__(f"line {line}, col {column}: {message}")


class TokenType(enum.Enum):
    """Token types produced by the lexer."""

    STRUCT = "struct"
    UNION = "union"
    ENUM = "enum"
    BITFIELD = "bitfield"
    IF = "if"
    ELSE = "else"
    MATCH = "match"
    WHILE = "while"
    FOR = "for"
    U8 = "u8"
    U16 = "u16"
    U32 = "u32"
    U64 = "u64"
    S8 = "s8"
    S16 = "s16"
    S32 = "s32"
    S64 = "s64"
    FLOAT = "float"
    DOUBLE = "double"
    CHAR = "char"
    CHAR16 = "char16"
    BOOL = "bool"
    U128 = "u128"
    S128 = "s128"
    PADDING = "padding"
    LE = "le"
    BE = "be"
    SIZEOF = "sizeof"
    ADDRESSOF = "addressof"
    IDENTIFIER = "identifier"
    NUMBER = "number"
    STRING_LITERAL = "string"
    LBRACE = "{"
    RBRACE = "}"
    LBRACKET = "["
    RBRACKET = "]"
    LPAREN = "("
    RPAREN = ")"
    SEMICOLON = ";"
    COMMA = ","
    COLON = ":"
    STAR = "*"
    DOT = "."
    PLUS = "+"
    MINUS = "-"
    SLASH = "/"
    PERCENT = "%"
    AMPERSAND = "&"
    PIPE = "|"
    CARET = "^"
    TILDE = "~"
    BANG = "!"
    ASSIGN = "="
    EQUALS = "=="
    NOT_EQUALS = "!="
    LESS = "<"
    GREATER = ">"
    LESS_EQUAL = "<="
    GREATER_EQUAL = ">="
    LSHIFT = "<<"
    RSHIFT = ">>"
    DOUBLE_LBRACKET = "[["
    DOUBLE_RBRACKET = "]]"
    DOLLAR = "$"
    EOF = "eof"


@dataclass
class Token:
    """
    A lexer token.

    Attributes:
        type: Token type.
        value: Raw text of the token.
        line: Source line number.
        column: Source column number.
    """

    type: TokenType
    value: str
    line: int
    column: int


_KEYWORD_MAP: dict[str, TokenType] = {
    "struct": TokenType.STRUCT,
    "union": TokenType.UNION,
    "enum": TokenType.ENUM,
    "bitfield": TokenType.BITFIELD,
    "if": TokenType.IF,
    "else": TokenType.ELSE,
    "match": TokenType.MATCH,
    "while": TokenType.WHILE,
    "for": TokenType.FOR,
    "u8": TokenType.U8,
    "u16": TokenType.U16,
    "u32": TokenType.U32,
    "u64": TokenType.U64,
    "s8": TokenType.S8,
    "s16": TokenType.S16,
    "s32": TokenType.S32,
    "s64": TokenType.S64,
    "float": TokenType.FLOAT,
    "double": TokenType.DOUBLE,
    "char": TokenType.CHAR,
    "char16": TokenType.CHAR16,
    "bool": TokenType.BOOL,
    "u128": TokenType.U128,
    "s128": TokenType.S128,
    "padding": TokenType.PADDING,
    "le": TokenType.LE,
    "be": TokenType.BE,
    "sizeof": TokenType.SIZEOF,
    "addressof": TokenType.ADDRESSOF,
}

_RUNTIME_ONLY_TOKENS: frozenset[TokenType] = frozenset({
    TokenType.MATCH,
    TokenType.WHILE,
    TokenType.FOR,
})

_PRIMITIVE_TOKENS: frozenset[TokenType] = frozenset({
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
})

_TYPE_MAP: dict[str, dict[str, str]] = {
    "u8": {"type": "UInt8"},
    "u16": {"type": "UInt16"},
    "u32": {"type": "UInt32"},
    "u64": {"type": "UInt64"},
    "s8": {"type": "Int8"},
    "s16": {"type": "Int16"},
    "s32": {"type": "Int32"},
    "s64": {"type": "Int64"},
    "float": {"type": "Float32"},
    "double": {"type": "Float64"},
    "char": {"type": "Char"},
    "char16": {"type": "Char16"},
    "bool": {"type": "Bool"},
    "u128": {"type": "UInt128"},
    "s128": {"type": "Int128"},
}


@dataclass
class NumberLiteral:
    """
    Numeric literal expression node.

    Attributes:
        value: Integer value.
    """

    value: int


@dataclass
class StringLiteral:
    """
    String literal expression node.

    Attributes:
        value: String content (without quotes).
    """

    value: str


@dataclass
class IdentifierExpr:
    """
    Identifier reference expression node.

    Attributes:
        name: Identifier name.
    """

    name: str


@dataclass
class DollarExpr:
    """Current offset ($) expression node."""


@dataclass
class SizeofExpr:
    """
    Sizeof() expression node.

    Attributes:
        target: Name of the target type or field.
    """

    target: str


@dataclass
class BinaryExpr:
    """
    Binary operator expression node.

    Attributes:
        op: Operator string.
        left: Left operand.
        right: Right operand.
    """

    op: str
    left: ExprNode
    right: ExprNode


@dataclass
class UnaryExpr:
    """
    Unary operator expression node.

    Attributes:
        op: Operator string.
        operand: Operand expression.
    """

    op: str
    operand: ExprNode


@dataclass
class AddressofExpr:
    """
    Addressof() expression node.

    Attributes:
        target: Name of the target field.
    """

    target: str


ExprNode = NumberLiteral | StringLiteral | IdentifierExpr | DollarExpr | SizeofExpr | AddressofExpr | BinaryExpr | UnaryExpr


@dataclass
class PrimitiveType:
    """
    Primitive type AST node.

    Attributes:
        name: Type name (e.g. "u8", "u32").
    """

    name: str


@dataclass
class StructRefType:
    """
    Struct reference type AST node.

    Attributes:
        name: Referenced struct name.
    """

    name: str


@dataclass
class PaddingType:
    """
    Padding type AST node.

    Attributes:
        size: Size expression.
    """

    size: ExprNode


@dataclass
class PointerType:
    """
    Pointer type AST node.

    Attributes:
        pointee: The type this pointer points to.
        line: Source line number.
        column: Source column number.
    """

    pointee: TypeNode
    line: int
    column: int


TypeNode = PrimitiveType | StructRefType | PaddingType | PointerType


@dataclass
class FieldNode:
    """
    Field declaration AST node.

    Attributes:
        name: Field name.
        type_node: Type of the field.
        endianness: Endianness prefix or None.
        array_size: Array size expression or None.
        annotations: Annotation key-value pairs.
    """

    name: str
    type_node: TypeNode
    endianness: str | None = None
    array_size: ExprNode | None = None
    annotations: dict[str, ExprNode] = field(default_factory=dict)


@dataclass
class ConditionalField:
    """
    Conditional field declaration AST node.

    Attributes:
        condition: Condition expression.
        true_fields: Fields if condition is true.
        false_fields: Fields if condition is false.
    """

    condition: ExprNode
    true_fields: list[FieldNode | ConditionalField]
    false_fields: list[FieldNode | ConditionalField]


@dataclass
class StructDecl:
    """
    Struct declaration AST node.

    Attributes:
        name: Struct name.
        fields: List of field nodes.
    """

    name: str
    fields: list[FieldNode | ConditionalField]


@dataclass
class UnionDecl:
    """
    Union declaration AST node.

    Attributes:
        name: Union name.
        fields: List of field nodes.
    """

    name: str
    fields: list[FieldNode]


@dataclass
class EnumDecl:
    """
    Enum declaration AST node.

    Attributes:
        name: Enum name.
        backing_type: Backing integer type.
        values: List of (name, value) pairs.
    """

    name: str
    backing_type: TypeNode
    values: list[tuple[str, int]]


@dataclass
class BitfieldDecl:
    """
    Bitfield declaration AST node.

    Attributes:
        name: Bitfield name.
        fields: List of (name, bit_width) pairs.
    """

    name: str
    fields: list[tuple[str, int]]


DeclNode = StructDecl | UnionDecl | EnumDecl | BitfieldDecl


_SINGLE_CHAR_TOKENS: dict[str, TokenType] = {
    "$": TokenType.DOLLAR,
    "{": TokenType.LBRACE,
    "}": TokenType.RBRACE,
    "(": TokenType.LPAREN,
    ")": TokenType.RPAREN,
    ";": TokenType.SEMICOLON,
    ",": TokenType.COMMA,
    ":": TokenType.COLON,
    ".": TokenType.DOT,
    "+": TokenType.PLUS,
    "-": TokenType.MINUS,
    "/": TokenType.SLASH,
    "%": TokenType.PERCENT,
    "~": TokenType.TILDE,
    "^": TokenType.CARET,
    "*": TokenType.STAR,
    "&": TokenType.AMPERSAND,
    "|": TokenType.PIPE,
}


class HexPatLexer:
    """
    Tokenizer for HexPat DSL source code.

    Args:
        source: Source code string to tokenize.
    """

    def __init__(self, source: str) -> None:
        self._source = source
        self._pos = 0
        self._line = 1
        self._col = 1
        self._tokens: list[Token] = []

    def tokenize(self) -> list[Token]:
        """
        Tokenize the entire source into a list of tokens.

        Returns:
            list[Token]: List of tokens including a trailing EOF token.

        Raises:
            HexPatError: On unterminated strings or unexpected characters.
        """
        while self._pos < len(self._source):
            self._skip_whitespace_and_comments()
            if self._pos >= len(self._source):
                break
            ch = self._source[self._pos]

            if ch == '"':
                self._read_string()
            elif ch in _SINGLE_CHAR_TOKENS:
                tt = _SINGLE_CHAR_TOKENS[ch]
                self._tokens.append(Token(tt, ch, self._line, self._col))
                self._advance()
            elif ch in {"[", "]", "!", "=", "<", ">"}:
                self._read_multi_char_operator(ch)
            elif ch.isdigit():
                self._read_number()
            elif ch.isalpha() or ch == "_":
                self._read_identifier()
            else:
                msg = f"unexpected character '{ch}'"
                raise HexPatError(msg, self._line, self._col)

        self._tokens.append(Token(TokenType.EOF, "", self._line, self._col))
        return self._tokens

    def _read_multi_char_operator(self, ch: str) -> None:
        """
        Read a potentially multi-character operator token.

        Args:
            ch: The current character.
        """
        nxt = self._peek(1)
        if ch == "[":
            if nxt == "[":
                self._tokens.append(Token(TokenType.DOUBLE_LBRACKET, "[[", self._line, self._col))
                self._advance()
            else:
                self._tokens.append(Token(TokenType.LBRACKET, "[", self._line, self._col))
            self._advance()
        elif ch == "]":
            if nxt == "]":
                self._tokens.append(Token(TokenType.DOUBLE_RBRACKET, "]]", self._line, self._col))
                self._advance()
            else:
                self._tokens.append(Token(TokenType.RBRACKET, "]", self._line, self._col))
            self._advance()
        elif ch == "!":
            if nxt == "=":
                self._tokens.append(Token(TokenType.NOT_EQUALS, "!=", self._line, self._col))
                self._advance()
            else:
                self._tokens.append(Token(TokenType.BANG, "!", self._line, self._col))
            self._advance()
        elif ch == "=":
            if nxt == "=":
                self._tokens.append(Token(TokenType.EQUALS, "==", self._line, self._col))
                self._advance()
            else:
                self._tokens.append(Token(TokenType.ASSIGN, "=", self._line, self._col))
            self._advance()
        elif ch == "<":
            if nxt == "=":
                self._tokens.append(Token(TokenType.LESS_EQUAL, "<=", self._line, self._col))
                self._advance()
                self._advance()
            elif nxt == "<":
                self._tokens.append(Token(TokenType.LSHIFT, "<<", self._line, self._col))
                self._advance()
                self._advance()
            else:
                self._tokens.append(Token(TokenType.LESS, "<", self._line, self._col))
                self._advance()
        elif ch == ">":
            if nxt == "=":
                self._tokens.append(Token(TokenType.GREATER_EQUAL, ">=", self._line, self._col))
                self._advance()
                self._advance()
            elif nxt == ">":
                self._tokens.append(Token(TokenType.RSHIFT, ">>", self._line, self._col))
                self._advance()
                self._advance()
            else:
                self._tokens.append(Token(TokenType.GREATER, ">", self._line, self._col))
                self._advance()

    def _advance(self) -> None:
        """Advance the position by one character."""
        if self._pos < len(self._source):
            if self._source[self._pos] == "\n":
                self._line += 1
                self._col = 1
            else:
                self._col += 1
            self._pos += 1

    def _peek(self, offset: int = 0) -> str:
        """
        Peek at a character at current position plus offset.

        Args:
            offset: Number of characters ahead to look.

        Returns:
            str: Character at position, or empty string if out of bounds.
        """
        idx = self._pos + offset
        return self._source[idx] if idx < len(self._source) else ""

    def _skip_whitespace_and_comments(self) -> None:
        """
        Skip whitespace and comments.

        Raises:
            HexPatError: If a block comment is not terminated.
        """
        while self._pos < len(self._source):
            ch = self._source[self._pos]
            if ch in {" ", "\t", "\r", "\n"}:
                self._advance()
            elif ch == "/" and self._peek(1) == "/":
                while self._pos < len(self._source) and self._source[self._pos] != "\n":
                    self._advance()
            elif ch == "/" and self._peek(1) == "*":
                comment_line = self._line
                comment_col = self._col
                self._advance()
                self._advance()
                found_end = False
                while self._pos < len(self._source):
                    if self._source[self._pos] == "*" and self._peek(1) == "/":
                        self._advance()
                        self._advance()
                        found_end = True
                        break
                    self._advance()
                if not found_end:
                    msg = "unterminated block comment"
                    raise HexPatError(msg, comment_line, comment_col)
            else:
                break

    def _read_string(self) -> None:
        """
        Read a string literal token.

        Raises:
            HexPatError: If the string literal is not terminated.
        """
        start_line = self._line
        start_col = self._col
        self._advance()
        chars: list[str] = []
        while self._pos < len(self._source):
            ch = self._source[self._pos]
            self._advance()
            if ch == "\\":
                if self._pos < len(self._source):
                    esc = self._source[self._pos]
                    escape_map = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"'}
                    chars.append(escape_map.get(esc, esc))
                    self._advance()
            elif ch == '"':
                self._tokens.append(Token(TokenType.STRING_LITERAL, "".join(chars), start_line, start_col))
                return
            else:
                chars.append(ch)
        msg = "unterminated string literal"
        raise HexPatError(msg, start_line, start_col)

    def _read_number(self) -> None:
        """Read a numeric literal token."""
        start_line = self._line
        start_col = self._col
        start_pos = self._pos

        if self._source[self._pos] == "0" and self._peek(1) in {"x", "X"}:
            self._advance()
            self._advance()
            while self._pos < len(self._source) and (self._source[self._pos].isdigit() or self._source[self._pos] in "abcdefABCDEF"):
                self._advance()
        else:
            while self._pos < len(self._source) and self._source[self._pos].isdigit():
                self._advance()

        text = self._source[start_pos : self._pos]
        self._tokens.append(Token(TokenType.NUMBER, text, start_line, start_col))

    def _read_identifier(self) -> None:
        """Read an identifier or keyword token."""
        start_line = self._line
        start_col = self._col
        start_pos = self._pos
        while self._pos < len(self._source) and (self._source[self._pos].isalnum() or self._source[self._pos] == "_"):
            self._advance()
        text = self._source[start_pos : self._pos]
        token_type = _KEYWORD_MAP.get(text, TokenType.IDENTIFIER)
        self._tokens.append(Token(token_type, text, start_line, start_col))


class HexPatParser:
    """
    Recursive descent parser for HexPat DSL.

    Args:
        tokens: List of tokens from the lexer.
    """

    def __init__(self, tokens: list[Token]) -> None:
        self._tokens = tokens
        self._pos = 0

    def parse(self) -> list[DeclNode]:
        """
        Parse the token stream into a list of declarations.

        Returns:
            list[DeclNode]: List of parsed declaration AST nodes.
        """
        decls: list[DeclNode] = []
        while not self._at_end():
            decl = self._parse_declaration()
            if decl is not None:
                decls.append(decl)
        return decls

    def _current(self) -> Token:
        """
        Get the current token.

        Returns:
            Token: Current token.
        """
        return self._tokens[self._pos]

    def _at_end(self) -> bool:
        """
        Check if at the end of tokens.

        Returns:
            bool: True if at EOF.
        """
        return self._current().type == TokenType.EOF

    def _advance(self) -> Token:
        """
        Advance and return the current token.

        Returns:
            Token: The token that was current before advancing.
        """
        tok = self._current()
        if not self._at_end():
            self._pos += 1
        return tok

    def _expect(self, tt: TokenType) -> Token:
        """
        Expect and consume a specific token type.

        Args:
            tt: Expected token type.

        Returns:
            Token: The consumed token.

        Raises:
            HexPatError: If current token doesn't match expected type.
        """
        tok = self._current()
        if tok.type != tt:
            msg = f"expected {tt.value}, got '{tok.value}'"
            raise HexPatError(msg, tok.line, tok.column)
        return self._advance()

    def _match(self, *types: TokenType) -> Token | None:
        """
        Consume token if it matches any of the given types.

        Args:
            *types: Token types to match against.

        Returns:
            Token | None: Consumed token, or None if no match.
        """
        return self._advance() if self._current().type in types else None

    def _parse_declaration(self) -> DeclNode | None:
        """
        Parse a top-level declaration.

        Returns:
            DeclNode | None: Parsed declaration or None.

        Raises:
            HexPatError: On unexpected tokens.
        """
        tok = self._current()
        if tok.type == TokenType.STRUCT:
            return self._parse_struct()
        if tok.type == TokenType.UNION:
            return self._parse_union()
        if tok.type == TokenType.ENUM:
            return self._parse_enum()
        if tok.type == TokenType.BITFIELD:
            return self._parse_bitfield()
        if tok.type in _RUNTIME_ONLY_TOKENS:
            msg = (
                f"'{tok.value}' is a runtime construct that cannot be compiled "
                f"to a static JSON template; use the HexPat interpreter "
                f"for patterns containing {tok.value} statements"
            )
            raise HexPatError(msg, tok.line, tok.column)
        if tok.type == TokenType.SEMICOLON:
            self._advance()
            return None
        if tok.type == TokenType.IDENTIFIER and tok.value in {
            "fn",
            "namespace",
            "using",
            "const",
            "return",
            "break",
            "continue",
        }:
            self._skip_construct()
            return None
        msg = f"expected declaration, got '{tok.value}'"
        raise HexPatError(msg, tok.line, tok.column)

    def _skip_construct(self) -> None:
        """Skip an unsupported construct by consuming tokens until balanced."""
        brace_depth = 0
        while not self._at_end():
            tok = self._advance()
            if tok.type == TokenType.LBRACE:
                brace_depth += 1
            elif tok.type == TokenType.RBRACE:
                if brace_depth <= 1:
                    self._match(TokenType.SEMICOLON)
                    return
                brace_depth -= 1
            elif tok.type == TokenType.SEMICOLON and brace_depth == 0:
                return

    def _parse_struct(self) -> StructDecl:
        """
        Parse a struct declaration.

        Returns:
            StructDecl: Parsed struct declaration.
        """
        self._expect(TokenType.STRUCT)
        name_tok = self._expect(TokenType.IDENTIFIER)
        self._expect(TokenType.LBRACE)
        fields = self._parse_field_list()
        self._expect(TokenType.RBRACE)
        self._match(TokenType.SEMICOLON)
        return StructDecl(name=name_tok.value, fields=fields)

    def _parse_union(self) -> UnionDecl:
        """
        Parse a union declaration.

        Returns:
            UnionDecl: Parsed union declaration.
        """
        self._expect(TokenType.UNION)
        name_tok = self._expect(TokenType.IDENTIFIER)
        self._expect(TokenType.LBRACE)
        fields: list[FieldNode] = []
        while self._current().type != TokenType.RBRACE and not self._at_end():
            f = self._parse_field()
            if isinstance(f, FieldNode):
                fields.append(f)
        self._expect(TokenType.RBRACE)
        self._match(TokenType.SEMICOLON)
        return UnionDecl(name=name_tok.value, fields=fields)

    def _parse_enum(self) -> EnumDecl:
        """
        Parse an enum declaration with optional auto-incrementing values.

        Returns:
            EnumDecl: Parsed enum declaration.
        """
        self._expect(TokenType.ENUM)
        name_tok = self._expect(TokenType.IDENTIFIER)
        self._expect(TokenType.COLON)
        backing = self._parse_type_spec()
        self._expect(TokenType.LBRACE)
        values: list[tuple[str, int]] = []
        counter = 0
        while self._current().type != TokenType.RBRACE and not self._at_end():
            val_name = self._expect(TokenType.IDENTIFIER)
            if self._match(TokenType.ASSIGN):
                val_num = self._expect(TokenType.NUMBER)
                counter = int(val_num.value, 0)
            values.append((val_name.value, counter))
            counter += 1
            self._match(TokenType.COMMA)
        self._expect(TokenType.RBRACE)
        self._match(TokenType.SEMICOLON)
        return EnumDecl(name=name_tok.value, backing_type=backing, values=values)

    def _parse_bitfield(self) -> BitfieldDecl:
        """
        Parse a bitfield declaration.

        Returns:
            BitfieldDecl: Parsed bitfield declaration.
        """
        self._expect(TokenType.BITFIELD)
        name_tok = self._expect(TokenType.IDENTIFIER)
        self._expect(TokenType.LBRACE)
        fields: list[tuple[str, int]] = []
        while self._current().type != TokenType.RBRACE and not self._at_end():
            field_name = self._expect(TokenType.IDENTIFIER)
            self._expect(TokenType.COLON)
            width_tok = self._expect(TokenType.NUMBER)
            width = int(width_tok.value, 0)
            fields.append((field_name.value, width))
            self._expect(TokenType.SEMICOLON)
        self._expect(TokenType.RBRACE)
        self._match(TokenType.SEMICOLON)
        return BitfieldDecl(name=name_tok.value, fields=fields)

    def _parse_field_list(self) -> list[FieldNode | ConditionalField]:
        """
        Parse a list of fields within braces.

        Returns:
            list[FieldNode | ConditionalField]: Parsed field list.
        """
        fields: list[FieldNode | ConditionalField] = []
        while self._current().type != TokenType.RBRACE and not self._at_end():
            f = self._parse_field()
            fields.append(f)
        return fields

    def _parse_field(self) -> FieldNode | ConditionalField:
        """
        Parse a single field or conditional.

        Returns:
            FieldNode | ConditionalField: Parsed field node.
        """
        if self._current().type == TokenType.IF:
            return self._parse_conditional()

        endianness: str | None = None
        if self._current().type in {TokenType.LE, TokenType.BE}:
            endianness = self._advance().value.lower()

        if self._current().type == TokenType.PADDING:
            return self._parse_padding_field(endianness)

        type_node: TypeNode = self._parse_type_spec()

        if self._current().type == TokenType.STAR:
            star_tok = self._advance()
            type_node = PointerType(
                pointee=type_node,
                line=star_tok.line,
                column=star_tok.column,
            )

        name_tok = self._expect(TokenType.IDENTIFIER)

        array_size: ExprNode | None = None
        if self._current().type == TokenType.LBRACKET:
            self._advance()
            array_size = self._parse_expression()
            self._expect(TokenType.RBRACKET)

        annotations: dict[str, ExprNode] = {}
        if self._current().type == TokenType.DOUBLE_LBRACKET:
            annotations = self._parse_annotations()

        self._expect(TokenType.SEMICOLON)
        return FieldNode(
            name=name_tok.value,
            type_node=type_node,
            endianness=endianness,
            array_size=array_size,
            annotations=annotations,
        )

    def _parse_padding_field(self, endianness: str | None) -> FieldNode:
        """
        Parse a padding field declaration.

        Args:
            endianness: Endianness prefix or None.

        Returns:
            FieldNode: Parsed padding field node.
        """
        self._expect(TokenType.PADDING)
        self._expect(TokenType.LBRACKET)
        size_expr = self._parse_expression()
        self._expect(TokenType.RBRACKET)

        annotations: dict[str, ExprNode] = {}
        if self._current().type == TokenType.DOUBLE_LBRACKET:
            annotations = self._parse_annotations()

        self._expect(TokenType.SEMICOLON)
        return FieldNode(
            name="_padding",
            type_node=PaddingType(size=size_expr),
            endianness=endianness,
            annotations=annotations,
        )

    def _parse_conditional(self) -> ConditionalField:
        """
        Parse a conditional field block.

        Returns:
            ConditionalField: Parsed conditional field.
        """
        self._expect(TokenType.IF)
        self._expect(TokenType.LPAREN)
        condition = self._parse_expression()
        self._expect(TokenType.RPAREN)
        self._expect(TokenType.LBRACE)
        true_fields = self._parse_field_list()
        self._expect(TokenType.RBRACE)

        false_fields: list[FieldNode | ConditionalField] = []
        if self._current().type == TokenType.ELSE:
            self._advance()
            self._expect(TokenType.LBRACE)
            false_fields = self._parse_field_list()
            self._expect(TokenType.RBRACE)

        return ConditionalField(
            condition=condition,
            true_fields=true_fields,
            false_fields=false_fields,
        )

    def _parse_type_spec(self) -> TypeNode:
        """
        Parse a type specifier.

        Returns:
            TypeNode: Parsed type node.

        Raises:
            HexPatError: On unknown type.
        """
        tok = self._current()
        if tok.type in _PRIMITIVE_TOKENS:
            self._advance()
            return PrimitiveType(name=tok.value.lower())
        if tok.type == TokenType.PADDING:
            self._advance()
            self._expect(TokenType.LBRACKET)
            size_expr = self._parse_expression()
            self._expect(TokenType.RBRACKET)
            return PaddingType(size=size_expr)
        if tok.type == TokenType.IDENTIFIER:
            self._advance()
            return StructRefType(name=tok.value)
        msg = f"expected type, got '{tok.value}'"
        raise HexPatError(msg, tok.line, tok.column)

    def _parse_annotations(self) -> dict[str, ExprNode]:
        """
        Parse an annotation block ``[[ ... ]]``.

        Returns:
            dict[str, ExprNode]: Parsed annotations.
        """
        self._expect(TokenType.DOUBLE_LBRACKET)
        annotations: dict[str, ExprNode] = {}
        while self._current().type != TokenType.DOUBLE_RBRACKET and not self._at_end():
            key_tok = self._expect(TokenType.IDENTIFIER)
            self._expect(TokenType.LPAREN)
            value_expr = self._parse_expression()
            self._expect(TokenType.RPAREN)
            annotations[key_tok.value] = value_expr
            self._match(TokenType.COMMA)
        self._expect(TokenType.DOUBLE_RBRACKET)
        return annotations

    def _parse_expression(self) -> ExprNode:
        """
        Parse an expression.

        Returns:
            ExprNode: Parsed expression node.
        """
        return self._parse_comparison()

    def _parse_comparison(self) -> ExprNode:
        """
        Parse a comparison expression.

        Returns:
            ExprNode: Parsed expression.
        """
        left = self._parse_additive()
        while self._current().type in {
            TokenType.EQUALS,
            TokenType.NOT_EQUALS,
            TokenType.LESS,
            TokenType.GREATER,
            TokenType.LESS_EQUAL,
            TokenType.GREATER_EQUAL,
        }:
            op_tok = self._advance()
            right = self._parse_additive()
            left = BinaryExpr(op=op_tok.value, left=left, right=right)
        return left

    def _parse_additive(self) -> ExprNode:
        """
        Parse an additive expression.

        Returns:
            ExprNode: Parsed expression.
        """
        left = self._parse_multiplicative()
        while self._current().type in {TokenType.PLUS, TokenType.MINUS}:
            op_tok = self._advance()
            right = self._parse_multiplicative()
            left = BinaryExpr(op=op_tok.value, left=left, right=right)
        return left

    def _parse_multiplicative(self) -> ExprNode:
        """
        Parse a multiplicative expression.

        Returns:
            ExprNode: Parsed expression.
        """
        left = self._parse_unary()
        while self._current().type in {TokenType.STAR, TokenType.SLASH, TokenType.PERCENT}:
            op_tok = self._advance()
            right = self._parse_unary()
            left = BinaryExpr(op=op_tok.value, left=left, right=right)
        return left

    def _parse_unary(self) -> ExprNode:
        """
        Parse a unary expression.

        Returns:
            ExprNode: Parsed expression.
        """
        if self._current().type in {TokenType.MINUS, TokenType.TILDE, TokenType.BANG}:
            op_tok = self._advance()
            operand = self._parse_unary()
            return UnaryExpr(op=op_tok.value, operand=operand)
        return self._parse_primary()

    def _parse_primary(self) -> ExprNode:
        """
        Parse a primary expression.

        Returns:
            ExprNode: Parsed expression.

        Raises:
            HexPatError: On unexpected token.
        """
        tok = self._current()
        if tok.type == TokenType.NUMBER:
            self._advance()
            return NumberLiteral(value=int(tok.value, 0))
        if tok.type == TokenType.STRING_LITERAL:
            self._advance()
            return StringLiteral(value=tok.value)
        if tok.type == TokenType.DOLLAR:
            self._advance()
            return DollarExpr()
        if tok.type == TokenType.SIZEOF:
            self._advance()
            self._expect(TokenType.LPAREN)
            target = self._expect(TokenType.IDENTIFIER)
            self._expect(TokenType.RPAREN)
            return SizeofExpr(target=target.value)
        if tok.type == TokenType.ADDRESSOF:
            self._advance()
            self._expect(TokenType.LPAREN)
            target = self._expect(TokenType.IDENTIFIER)
            self._expect(TokenType.RPAREN)
            return AddressofExpr(target=target.value)
        if tok.type == TokenType.IDENTIFIER:
            self._advance()
            return IdentifierExpr(name=tok.value)
        if tok.type == TokenType.LPAREN:
            self._advance()
            expr = self._parse_expression()
            self._expect(TokenType.RPAREN)
            return expr
        msg = f"expected expression, got '{tok.value}'"
        raise HexPatError(msg, tok.line, tok.column)


class HexPatCodegen:
    """
    Generates JSON template definitions from a HexPat AST.

    Args:
        declarations: List of parsed declaration nodes.
    """

    def __init__(self, declarations: list[DeclNode]) -> None:
        self._decls = declarations
        self._nested_structs: dict[str, StructDecl] = {}
        self._nested_unions: dict[str, UnionDecl] = {}
        self._nested_enums: dict[str, EnumDecl] = {}
        self._nested_bitfields: dict[str, BitfieldDecl] = {}
        self._collect_nested()

    def _collect_nested(self) -> None:
        """Index nested declarations by name for StructRef resolution."""
        for decl in self._decls:
            if isinstance(decl, StructDecl):
                self._nested_structs[decl.name] = decl
            elif isinstance(decl, UnionDecl):
                self._nested_unions[decl.name] = decl
            elif isinstance(decl, EnumDecl):
                self._nested_enums[decl.name] = decl
            else:
                self._nested_bitfields[decl.name] = decl

    def generate(self) -> dict[str, Any]:
        """
        Generate the JSON template dict from all declarations.

        Returns:
            dict[str, Any]: JSON-serializable template definition.

        Raises:
            HexPatError: If no struct declaration is found.
        """
        main_struct: StructDecl | None = next((decl for decl in self._decls if isinstance(decl, StructDecl)), None)
        if main_struct is None:
            msg = "no struct declaration found"
            raise HexPatError(msg)

        fields: list[dict[str, Any]] = []
        for f in main_struct.fields:
            fields.extend(self._gen_field(f))

        types: dict[str, dict[str, Any]] = {}
        for decl in self._decls:
            if isinstance(decl, StructDecl) and decl.name != main_struct.name:
                struct_fields: list[dict[str, Any]] = []
                for f in decl.fields:
                    struct_fields.extend(self._gen_field(f))
                types[decl.name] = {"kind": "struct", "fields": struct_fields}
            elif isinstance(decl, UnionDecl):
                union_fields: list[dict[str, Any]] = []
                for f in decl.fields:
                    union_fields.extend(self._gen_field(f))
                types[decl.name] = {"kind": "union", "fields": union_fields}
            elif isinstance(decl, EnumDecl):
                backing = self._gen_type(decl.backing_type)
                types[decl.name] = {
                    "kind": "enum",
                    "backing_type": backing,
                    "values": list(decl.values),
                }
            elif isinstance(decl, BitfieldDecl):
                types[decl.name] = {
                    "kind": "bitfield",
                    "fields": list(decl.fields),
                }

        result: dict[str, Any] = {
            "name": main_struct.name,
            "description": f"{main_struct.name} (compiled from HexPat DSL)",
            "default_endianness": "little",
            "fields": fields,
        }
        if types:
            result["types"] = types
        return result

    def _gen_field(self, node: FieldNode | ConditionalField) -> list[dict[str, Any]]:
        """
        Generate field definition dicts from a field node.

        Conditionals may produce multiple fields (if + else branches).

        Args:
            node: Field or conditional field AST node.

        Returns:
            list[dict[str, Any]]: List of JSON field definitions.
        """
        if isinstance(node, ConditionalField):
            return self._gen_conditional(node)
        return [self._gen_regular_field(node)]

    def _gen_regular_field(self, node: FieldNode) -> dict[str, Any]:
        """
        Generate a regular field definition dict.

        Args:
            node: Field AST node.

        Returns:
            dict[str, Any]: JSON field definition.
        """
        field_type = self._gen_type(node.type_node)

        if isinstance(node.type_node, PointerType):
            pointee = node.type_node.pointee
            if isinstance(pointee, StructRefType):
                target = pointee.name
                ptr_base: dict[str, Any] = {"type": "UInt64"}
            elif isinstance(pointee, PrimitiveType):
                target = ""
                ptr_base = dict(_TYPE_MAP.get(pointee.name, {"type": "UInt32"}))
            else:
                target = ""
                ptr_base = {"type": "UInt32"}
            field_type = {
                "type": "Pointer",
                "params": {
                    "pointer_type": ptr_base,
                    "target_template": target,
                },
            }
        elif node.array_size is not None:
            if isinstance(node.array_size, NumberLiteral):
                field_type = {
                    "type": "Array",
                    "params": {
                        "element_type": field_type,
                        "count": node.array_size.value,
                    },
                }
            elif isinstance(node.array_size, IdentifierExpr):
                field_type = {
                    "type": "DynamicArray",
                    "params": {
                        "element_type": field_type,
                        "count_field": node.array_size.name,
                    },
                }
            else:
                field_type = {
                    "type": "Array",
                    "params": {
                        "element_type": field_type,
                        "count": self._eval_const_expr(node.array_size),
                    },
                }

        result: dict[str, Any] = {
            "name": node.name,
            "field_type": field_type,
            "description": "",
        }

        if node.endianness is not None:
            result["endianness"] = "little" if node.endianness == "le" else "big"

        validation: dict[str, Any] = {}
        for key, expr in node.annotations.items():
            if key == "color" and isinstance(expr, StringLiteral):
                result["color"] = expr.value
            elif key == "description" and isinstance(expr, StringLiteral):
                result["description"] = expr.value
            elif key == "validate" and isinstance(expr, NumberLiteral):
                validation["expected_value"] = expr.value
            elif key == "min" and isinstance(expr, NumberLiteral):
                validation["min_value"] = expr.value
            elif key == "max" and isinstance(expr, NumberLiteral):
                validation["max_value"] = expr.value

        if validation:
            result["validation"] = validation

        return result

    def _gen_conditional(self, node: ConditionalField) -> list[dict[str, Any]]:
        """
        Generate conditional field definition dicts.

        For if/else constructs, emits the true-branch as a Conditional field.
        If false_fields exist, emits a second Conditional with inverted op.

        Args:
            node: Conditional field AST node.

        Returns:
            list[dict[str, Any]]: One or two JSON conditional field definitions.
        """
        condition_field = ""
        condition_value = 0
        condition_op = "Eq"

        if isinstance(node.condition, BinaryExpr):
            if isinstance(node.condition.left, IdentifierExpr):
                condition_field = node.condition.left.name
            if isinstance(node.condition.right, NumberLiteral):
                condition_value = node.condition.right.value
            op_map: dict[str, str] = {
                "==": "Eq",
                "!=": "Ne",
                ">": "Gt",
                "<": "Lt",
                ">=": "Ge",
                "<=": "Le",
                "&": "BitAnd",
            }
            condition_op = op_map.get(node.condition.op, "Eq")
        elif isinstance(node.condition, IdentifierExpr):
            condition_field = node.condition.name
            condition_value = 0
            condition_op = "Ne"

        true_inner: list[dict[str, Any]] = []
        for f in node.true_fields:
            true_inner.extend(self._gen_field(f))

        results: list[dict[str, Any]] = [
            {
                "name": f"_if_{condition_field}",
                "field_type": {
                    "type": "Conditional",
                    "params": {
                        "condition_field": condition_field,
                        "condition_value": condition_value,
                        "condition_op": condition_op,
                        "fields": true_inner,
                    },
                },
                "description": "",
            },
        ]

        if node.false_fields:
            invert_map: dict[str, str] = {
                "Eq": "Ne",
                "Ne": "Eq",
                "Gt": "Le",
                "Lt": "Ge",
                "Ge": "Lt",
                "Le": "Gt",
                "BitAnd": "Eq",
            }
            inverted_op = invert_map.get(condition_op, "Ne")
            inv_value = condition_value
            if condition_op == "BitAnd":
                inv_value = 0

            else_inner: list[dict[str, Any]] = []
            for f in node.false_fields:
                else_inner.extend(self._gen_field(f))

            results.append({
                "name": f"_else_{condition_field}",
                "field_type": {
                    "type": "Conditional",
                    "params": {
                        "condition_field": condition_field,
                        "condition_value": inv_value,
                        "condition_op": inverted_op,
                        "fields": else_inner,
                    },
                },
                "description": "",
            })

        return results

    def _gen_type(self, type_node: TypeNode) -> dict[str, Any]:
        """
        Generate a JSON field type from a type node.

        Args:
            type_node: Type AST node.

        Returns:
            dict[str, Any]: JSON field type.
        """
        if isinstance(type_node, PrimitiveType):
            mapped = _TYPE_MAP.get(type_node.name)
            return dict(mapped) if mapped is not None else {"type": "UInt8"}
        if isinstance(type_node, PaddingType):
            size = self._eval_const_expr(type_node.size)
            return {"type": "Padding", "params": size}
        if isinstance(type_node, PointerType):
            inner = self._gen_type(type_node.pointee)
            return {
                "type": "Pointer",
                "params": {"pointer_type": inner, "target_template": ""},
            }

        if type_node.name in self._nested_enums:
            enum_decl = self._nested_enums[type_node.name]
            backing = self._gen_type(enum_decl.backing_type)
            return {
                "type": "Enum",
                "params": {
                    "backing_type": backing,
                    "values": list(enum_decl.values),
                },
            }
        return {"type": "StructRef", "params": type_node.name}

    @staticmethod
    def _eval_const_expr(expr: ExprNode) -> int:
        """
        Evaluate a constant expression at compile time.

        Args:
            expr: Expression node to evaluate.

        Returns:
            int: Evaluated integer value.
        """
        if isinstance(expr, NumberLiteral):
            return expr.value
        if isinstance(expr, BinaryExpr):
            left = HexPatCodegen._eval_const_expr(expr.left)
            right = HexPatCodegen._eval_const_expr(expr.right)
            if expr.op == "+":
                return left + right
            if expr.op == "-":
                return left - right
            if expr.op == "*":
                return left * right
            if expr.op == "/" and right != 0:
                return left // right
            return left % right if expr.op == "%" and right != 0 else 0
        if isinstance(expr, UnaryExpr) and expr.op == "-":
            return -HexPatCodegen._eval_const_expr(expr.operand)
        return 0


class HexPatCompiler:
    """
    Compiles HexPat DSL source code into JSON template definitions.

    Orchestrates the lexer, parser, and codegen pipeline.
    """

    @staticmethod
    def compile(source: str) -> str:
        """
        Compile DSL source to a JSON string.

        Args:
            source: HexPat DSL source code.

        Returns:
            str: JSON template definition string.
        """
        result = HexPatCompiler.compile_to_dict(source)
        return json.dumps(result, indent=2)

    @staticmethod
    def compile_to_dict(source: str) -> dict[str, Any]:
        """
        Compile DSL source to a Python dict.

        Args:
            source: HexPat DSL source code.

        Returns:
            dict[str, Any]: JSON-compatible template definition dict.
        """
        lexer = HexPatLexer(source)
        tokens = lexer.tokenize()
        parser = HexPatParser(tokens)
        declarations = parser.parse()
        codegen = HexPatCodegen(declarations)
        result = codegen.generate()
        _logger.debug("hexpat_compiled", template_name=result.get("name", ""))
        return result
