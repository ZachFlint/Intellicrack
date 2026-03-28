# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
# This file is part of Intellicrack. See LICENSE for details.

"""Recursive-descent parser with Pratt-style operator precedence for the HexPat pattern language."""

from __future__ import annotations

from typing import TYPE_CHECKING

from intellicrack.core.hexpat.ast_nodes import (
    AddressOfExpr,
    ArraySubscriptExpr,
    ArrayType,
    AssignExpr,
    AutoType,
    BinaryExpr,
    BitfieldDecl,
    BitfieldEntry,
    BoolLiteral,
    BreakStmt,
    CastExpr,
    CharLiteral,
    ConditionalField,
    ContinueStmt,
    DollarExpr,
    EnumDecl,
    EnumEntry,
    ExprStmt,
    FieldDecl,
    FloatLiteral,
    ForStmt,
    FunctionCallExpr,
    FunctionDecl,
    FunctionParam,
    IdentifierExpr,
    MatchArm,
    MatchStmt,
    MemberAccessExpr,
    NamedType,
    NamespaceAccessExpr,
    NamespaceDecl,
    NullLiteral,
    NumberLiteral,
    PaddingType,
    PlacementStmt,
    PointerType,
    PrimitiveType,
    ReturnStmt,
    SizeofExpr,
    StringLiteral,
    StructDecl,
    TernaryExpr,
    TryStmt,
    TypeNameOfExpr,
    UnaryExpr,
    UnionDecl,
    UsingDecl,
    VarDecl,
    WhileStmt,
)
from intellicrack.core.hexpat.errors import HexPatParseError
from intellicrack.core.hexpat.tokens import (
    ASSIGNMENT_OPS,
    ENDIANNESS_TOKENS,
    PRIMITIVE_TYPES,
    Token,
    TokenType,
)


if TYPE_CHECKING:
    from intellicrack.core.hexpat.ast_nodes import DeclNode, ExprNode, StmtNode, TypeNode


_INFIX_BP: dict[TokenType, tuple[int, int]] = {
    TokenType.ASSIGN: (1, 2),
    TokenType.PLUS_ASSIGN: (1, 2),
    TokenType.MINUS_ASSIGN: (1, 2),
    TokenType.STAR_ASSIGN: (1, 2),
    TokenType.SLASH_ASSIGN: (1, 2),
    TokenType.PERCENT_ASSIGN: (1, 2),
    TokenType.AMPERSAND_ASSIGN: (1, 2),
    TokenType.PIPE_ASSIGN: (1, 2),
    TokenType.CARET_ASSIGN: (1, 2),
    TokenType.LSHIFT_ASSIGN: (1, 2),
    TokenType.RSHIFT_ASSIGN: (1, 2),
    TokenType.QUESTION: (3, 4),
    TokenType.DOUBLE_PIPE: (5, 6),
    TokenType.DOUBLE_CARET: (7, 8),
    TokenType.DOUBLE_AMPERSAND: (9, 10),
    TokenType.PIPE: (11, 12),
    TokenType.CARET: (13, 14),
    TokenType.AMPERSAND: (15, 16),
    TokenType.EQ: (17, 18),
    TokenType.NE: (17, 18),
    TokenType.LT: (19, 20),
    TokenType.GT: (19, 20),
    TokenType.LE_OP: (19, 20),
    TokenType.GE_OP: (19, 20),
    TokenType.LSHIFT: (21, 22),
    TokenType.RSHIFT: (21, 22),
    TokenType.PLUS: (23, 24),
    TokenType.MINUS: (23, 24),
    TokenType.STAR: (25, 26),
    TokenType.SLASH: (25, 26),
    TokenType.PERCENT: (25, 26),
    TokenType.DOT: (29, 30),
    TokenType.DOUBLE_COLON: (29, 30),
    TokenType.LBRACKET: (29, 30),
    TokenType.LPAREN: (29, 30),
}

_UNARY_RIGHT_BP: int = 27
_EOF_TOKEN = Token(TokenType.EOF, "", 0, 0)


class HexPatParser:
    """Recursive-descent parser for the HexPat .hexpat pattern language.

    Consumes a flat list of tokens produced by the lexer and builds an AST
    consisting of top-level declarations and statements.

    Attributes:
        _tokens: The flat list of tokens to parse.
        _pos: Current position in the token list.
        _file_path: Source file path used in error messages.
    """

    def __init__(
        self,
        tokens: list[Token],
        file_path: str = "<input>",
    ) -> None:
        """Initialise the parser with a token stream.

        Args:
            tokens: Flat token list produced by the lexer.
            file_path: Source file path used for error location reporting.
        """
        self._tokens: list[Token] = tokens
        self._pos: int = 0
        self._file_path: str = file_path

    def parse(self) -> list[DeclNode | StmtNode]:
        """Parse the token stream into a list of top-level declarations and statements.

        Returns:
            Ordered list of top-level AST nodes.

        Raises:
            HexPatParseError: When a syntax error is encountered.
        """
        nodes: list[DeclNode | StmtNode] = []
        while not self._at_end():
            if self._current().type == TokenType.SEMICOLON:
                self._advance()
                continue
            annotations = self._try_parse_annotations()
            tt = self._current().type
            if tt == TokenType.STRUCT:
                nodes.append(self._parse_struct(annotations))
            elif tt == TokenType.UNION:
                nodes.append(self._parse_union(annotations))
            elif tt == TokenType.ENUM:
                nodes.append(self._parse_enum())
            elif tt == TokenType.BITFIELD:
                nodes.append(self._parse_bitfield(annotations))
            elif tt == TokenType.FN:
                nodes.append(self._parse_function())
            elif tt == TokenType.NAMESPACE:
                nodes.append(self._parse_namespace())
            elif tt == TokenType.USING:
                nodes.append(self._parse_using())
            else:
                nodes.append(self._parse_top_level_statement())
        return nodes

    def _current(self) -> Token:
        """Return the current token without consuming it.

        Returns:
            Current token, or an EOF token if past the end.
        """
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return _EOF_TOKEN

    def _peek(self, offset: int = 1) -> Token:
        """Return the token at current position plus offset without consuming.

        Args:
            offset: Number of positions ahead to look.

        Returns:
            Token at the requested position, or an EOF token if past the end.
        """
        idx = self._pos + offset
        if idx < len(self._tokens):
            return self._tokens[idx]
        return _EOF_TOKEN

    def _advance(self) -> Token:
        """Consume and return the current token.

        Returns:
            The token that was current before advancing.
        """
        tok = self._current()
        if self._pos < len(self._tokens):
            self._pos += 1
        return tok

    def _expect(self, tt: TokenType) -> Token:
        """Consume the current token if it matches the expected type.

        Args:
            tt: Expected token type.

        Returns:
            The consumed token.

        Raises:
            HexPatParseError: When the current token does not match.
        """
        tok = self._current()
        if tok.type != tt:
            msg = f"Expected '{tt.value}', got '{tok.value}'"
            raise self._error(msg)
        return self._advance()

    def _match(self, *types: TokenType) -> bool:
        """Consume the current token if it matches any of the given types.

        Args:
            *types: Token types to match against.

        Returns:
            True if a token was consumed, False otherwise.
        """
        if self._current().type in types:
            self._advance()
            return True
        return False

    def _at_end(self) -> bool:
        """Check whether the token stream is exhausted.

        Returns:
            True if at EOF.
        """
        return self._current().type == TokenType.EOF

    def _error(self, msg: str) -> HexPatParseError:
        """Create a parse error anchored at the current token position.

        Args:
            msg: Human-readable error description.

        Returns:
            A HexPatParseError instance (not yet raised).
        """
        tok = self._current()
        return HexPatParseError(msg, tok.line, tok.column, self._file_path)

    def _save(self) -> int:
        """Save the current parser position.

        Returns:
            Current position index.
        """
        return self._pos

    def _restore(self, pos: int) -> None:
        """Restore the parser to a previously saved position.

        Args:
            pos: Position index to restore to.
        """
        self._pos = pos

    def _try_parse_annotations(self) -> tuple[tuple[str, ExprNode | None], ...]:
        """Attempt to parse an annotation block if one is present.

        Returns:
            Parsed annotations or an empty tuple when no annotation block follows.
        """
        if self._current().type != TokenType.DOUBLE_LBRACKET:
            return ()
        return self._parse_annotations()

    def _parse_annotations(self) -> tuple[tuple[str, ExprNode | None], ...]:
        """Parse a double-bracket annotation block.

        Returns:
            Tuple of (name, optional_expr) annotation pairs.

        Raises:
            HexPatParseError: When the annotation syntax is malformed.
        """
        self._expect(TokenType.DOUBLE_LBRACKET)
        items: list[tuple[str, ExprNode | None]] = []
        while self._current().type != TokenType.DOUBLE_RBRACKET and not self._at_end():
            name_tok = self._expect(TokenType.IDENTIFIER)
            expr: ExprNode | None = None
            if self._current().type == TokenType.LPAREN:
                self._advance()
                if self._current().type != TokenType.RPAREN:
                    expr = self._parse_expression()
                self._expect(TokenType.RPAREN)
            items.append((name_tok.value, expr))
            if not self._match(TokenType.COMMA):
                break
        self._expect(TokenType.DOUBLE_RBRACKET)
        return tuple(items)

    def _parse_type(self) -> TypeNode:
        """Parse a type specifier, including optional array suffix.

        Returns:
            A TypeNode representing the parsed type.

        Raises:
            HexPatParseError: When no valid type can be parsed at the current position.
        """
        endianness: str | None = None
        if self._current().type in ENDIANNESS_TOKENS:
            endianness = self._advance().value

        tok = self._current()

        if tok.type == TokenType.STAR:
            self._advance()
            inner = self._parse_type()
            return PointerType(pointee=inner, line=tok.line, column=tok.column)

        if tok.type == TokenType.AUTO:
            self._advance()
            return AutoType(line=tok.line, column=tok.column)

        if tok.type == TokenType.PADDING:
            self._advance()
            self._expect(TokenType.LBRACKET)
            size_expr = self._parse_expression()
            self._expect(TokenType.RBRACKET)
            return PaddingType(size=size_expr, line=tok.line, column=tok.column)

        base: TypeNode
        if tok.type in PRIMITIVE_TYPES:
            self._advance()
            base = PrimitiveType(
                name=tok.value,
                endianness=endianness,
                line=tok.line,
                column=tok.column,
            )
        elif tok.type == TokenType.IDENTIFIER:
            self._advance()
            namespace: str | None = None
            name = tok.value
            if self._current().type == TokenType.DOUBLE_COLON:
                self._advance()
                member_tok = self._expect(TokenType.IDENTIFIER)
                namespace = name
                name = member_tok.value
            base = NamedType(
                name=name,
                namespace=namespace,
                line=tok.line,
                column=tok.column,
            )
        else:
            msg = f"Expected type, got '{tok.value}'"
            raise self._error(msg)

        if self._current().type == TokenType.LBRACKET:
            arr_tok = self._current()
            self._advance()
            if self._current().type == TokenType.WHILE:
                self._advance()
                self._expect(TokenType.LPAREN)
                while_cond = self._parse_expression()
                self._expect(TokenType.RPAREN)
                self._expect(TokenType.RBRACKET)
                return ArrayType(
                    element=base,
                    size=None,
                    while_condition=while_cond,
                    line=arr_tok.line,
                    column=arr_tok.column,
                )
            arr_size = self._parse_expression()
            self._expect(TokenType.RBRACKET)
            return ArrayType(
                element=base,
                size=arr_size,
                while_condition=None,
                line=arr_tok.line,
                column=arr_tok.column,
            )

        return base

    def _parse_expression(self, min_bp: int = 0) -> ExprNode:
        """Parse an expression using Pratt-style operator precedence.

        Args:
            min_bp: Minimum binding power threshold for infix operators.

        Returns:
            Parsed expression node.

        Raises:
            HexPatParseError: When no valid expression can be parsed.
        """
        left = self._parse_prefix()

        while True:
            tok = self._current()
            bp_pair = _INFIX_BP.get(tok.type)
            if bp_pair is None:
                break
            l_bp, r_bp = bp_pair
            if l_bp < min_bp:
                break

            if tok.type == TokenType.QUESTION:
                self._advance()
                true_expr = self._parse_expression()
                self._expect(TokenType.COLON)
                false_expr = self._parse_expression(r_bp - 1)
                left = TernaryExpr(
                    condition=left,
                    true_expr=true_expr,
                    false_expr=false_expr,
                    line=tok.line,
                    column=tok.column,
                )
                continue

            if tok.type in ASSIGNMENT_OPS:
                self._advance()
                right = self._parse_expression(l_bp)
                left = AssignExpr(
                    target=left,
                    op=tok.value,
                    value=right,
                    line=tok.line,
                    column=tok.column,
                )
                continue

            if tok.type == TokenType.DOT:
                self._advance()
                member_tok = self._expect(TokenType.IDENTIFIER)
                left = MemberAccessExpr(
                    object_expr=left,
                    member=member_tok.value,
                    line=tok.line,
                    column=tok.column,
                )
                continue

            if tok.type == TokenType.DOUBLE_COLON:
                self._advance()
                member_tok = self._expect(TokenType.IDENTIFIER)
                left = NamespaceAccessExpr(
                    namespace=left,
                    member=member_tok.value,
                    line=tok.line,
                    column=tok.column,
                )
                continue

            if tok.type == TokenType.LBRACKET:
                self._advance()
                index = self._parse_expression()
                self._expect(TokenType.RBRACKET)
                left = ArraySubscriptExpr(
                    array=left,
                    index=index,
                    line=tok.line,
                    column=tok.column,
                )
                continue

            if tok.type == TokenType.LPAREN:
                self._advance()
                args: list[ExprNode] = []
                while self._current().type != TokenType.RPAREN and not self._at_end():
                    args.append(self._parse_expression())
                    if not self._match(TokenType.COMMA):
                        break
                self._expect(TokenType.RPAREN)
                left = FunctionCallExpr(
                    callee=left,
                    arguments=tuple(args),
                    line=tok.line,
                    column=tok.column,
                )
                continue

            self._advance()
            right = self._parse_expression(r_bp)
            left = BinaryExpr(
                op=tok.value,
                left=left,
                right=right,
                line=tok.line,
                column=tok.column,
            )

        return left

    def _parse_prefix(self) -> ExprNode:
        """Parse a prefix expression (literal, identifier, unary operator, grouping).

        Returns:
            Parsed prefix expression node.

        Raises:
            HexPatParseError: When no valid prefix can be parsed.
        """
        tok = self._current()

        if tok.type == TokenType.NUMBER:
            self._advance()
            return NumberLiteral(
                value=int(tok.value, 0),
                line=tok.line,
                column=tok.column,
            )

        if tok.type == TokenType.FLOAT_LITERAL:
            self._advance()
            return FloatLiteral(
                value=float(tok.value),
                line=tok.line,
                column=tok.column,
            )

        if tok.type == TokenType.STRING_LITERAL:
            self._advance()
            return StringLiteral(
                value=tok.value,
                line=tok.line,
                column=tok.column,
            )

        if tok.type == TokenType.CHAR_LITERAL:
            self._advance()
            return CharLiteral(
                value=tok.value,
                line=tok.line,
                column=tok.column,
            )

        if tok.type == TokenType.TRUE_KW:
            self._advance()
            return BoolLiteral(value=True, line=tok.line, column=tok.column)

        if tok.type == TokenType.FALSE_KW:
            self._advance()
            return BoolLiteral(value=False, line=tok.line, column=tok.column)

        if tok.type == TokenType.NULL_KW:
            self._advance()
            return NullLiteral(line=tok.line, column=tok.column)

        if tok.type == TokenType.DOLLAR:
            self._advance()
            return DollarExpr(line=tok.line, column=tok.column)

        if tok.type == TokenType.THIS:
            self._advance()
            return IdentifierExpr(name="this", line=tok.line, column=tok.column)

        if tok.type == TokenType.PARENT:
            self._advance()
            return IdentifierExpr(name="parent", line=tok.line, column=tok.column)

        if tok.type == TokenType.IDENTIFIER:
            self._advance()
            return IdentifierExpr(name=tok.value, line=tok.line, column=tok.column)

        if tok.type == TokenType.SIZEOF:
            self._advance()
            self._expect(TokenType.LPAREN)
            saved = self._save()
            target: ExprNode | TypeNode
            try:
                target = self._parse_type()
                if self._current().type != TokenType.RPAREN:
                    self._restore(saved)
                    target = self._parse_expression()
            except HexPatParseError:
                self._restore(saved)
                target = self._parse_expression()
            self._expect(TokenType.RPAREN)
            return SizeofExpr(target=target, line=tok.line, column=tok.column)

        if tok.type == TokenType.ADDRESSOF:
            self._advance()
            self._expect(TokenType.LPAREN)
            inner_expr = self._parse_expression()
            self._expect(TokenType.RPAREN)
            return AddressOfExpr(target=inner_expr, line=tok.line, column=tok.column)

        if tok.type == TokenType.TYPENAMEOF:
            self._advance()
            self._expect(TokenType.LPAREN)
            inner_expr2 = self._parse_expression()
            self._expect(TokenType.RPAREN)
            return TypeNameOfExpr(target=inner_expr2, line=tok.line, column=tok.column)

        if tok.type == TokenType.BANG:
            self._advance()
            operand = self._parse_expression(_UNARY_RIGHT_BP)
            return UnaryExpr(op="!", operand=operand, line=tok.line, column=tok.column)

        if tok.type == TokenType.MINUS:
            self._advance()
            operand2 = self._parse_expression(_UNARY_RIGHT_BP)
            return UnaryExpr(op="-", operand=operand2, line=tok.line, column=tok.column)

        if tok.type == TokenType.TILDE:
            self._advance()
            operand3 = self._parse_expression(_UNARY_RIGHT_BP)
            return UnaryExpr(op="~", operand=operand3, line=tok.line, column=tok.column)

        if tok.type == TokenType.LPAREN:
            return self._parse_paren_or_cast()

        msg = f"Unexpected token '{tok.value}' in expression"
        raise self._error(msg)

    def _parse_paren_or_cast(self) -> ExprNode:
        """Parse a parenthesised expression or a cast expression.

        Returns:
            A CastExpr when the form is (Type)(expr), otherwise the inner expression.

        Raises:
            HexPatParseError: When neither parse succeeds.
        """
        tok = self._current()
        self._expect(TokenType.LPAREN)

        saved = self._save()
        cast_result: CastExpr | None = None
        try:
            type_node = self._parse_type()
            if self._current().type == TokenType.RPAREN:
                self._advance()
                if self._current().type == TokenType.LPAREN:
                    self._advance()
                    cast_expr = self._parse_expression()
                    self._expect(TokenType.RPAREN)
                    cast_result = CastExpr(
                        target_type=type_node,
                        expr=cast_expr,
                        line=tok.line,
                        column=tok.column,
                    )
        except HexPatParseError:
            pass
        if cast_result is not None:
            return cast_result
        self._restore(saved)

        inner = self._parse_expression()
        self._expect(TokenType.RPAREN)
        return inner

    def _parse_block(self, allow_fields: bool = False) -> tuple[StmtNode, ...]:
        """Parse a brace-enclosed block of statements.

        Args:
            allow_fields: When True, field declarations are permitted within the block.

        Returns:
            Tuple of statement nodes forming the block body.

        Raises:
            HexPatParseError: When the block syntax is malformed.
        """
        self._expect(TokenType.LBRACE)
        stmts: list[StmtNode] = []
        while self._current().type != TokenType.RBRACE and not self._at_end():
            stmts.append(self._parse_statement(allow_fields=allow_fields))
        self._expect(TokenType.RBRACE)
        return tuple(stmts)

    def _parse_statement(self, allow_fields: bool = False) -> StmtNode:
        """Parse a single statement.

        Args:
            allow_fields: When True, type-name-followed-by-identifier is parsed as a
                field declaration rather than an expression statement.

        Returns:
            A statement AST node.

        Raises:
            HexPatParseError: When no valid statement can be parsed.
        """
        tok = self._current()

        if tok.type == TokenType.IF:
            return self._parse_if_stmt()

        if tok.type == TokenType.WHILE:
            return self._parse_while_stmt()

        if tok.type == TokenType.FOR:
            return self._parse_for_stmt()

        if tok.type == TokenType.MATCH:
            return self._parse_match_stmt()

        if tok.type == TokenType.TRY:
            return self._parse_try_stmt()

        if tok.type == TokenType.RETURN:
            return self._parse_return_stmt()

        if tok.type == TokenType.BREAK:
            self._advance()
            self._expect(TokenType.SEMICOLON)
            return BreakStmt(line=tok.line, column=tok.column)

        if tok.type == TokenType.CONTINUE:
            self._advance()
            self._expect(TokenType.SEMICOLON)
            return ContinueStmt(line=tok.line, column=tok.column)

        if tok.type == TokenType.CONST:
            return self._parse_const_decl()

        if tok.type in ENDIANNESS_TOKENS:
            endianness = self._advance().value
            return self._parse_field_or_placement(
                endianness=endianness,
                in_struct_body=allow_fields,
            )

        if tok.type in PRIMITIVE_TYPES or tok.type == TokenType.AUTO:
            return self._parse_field_or_placement(
                endianness=None,
                in_struct_body=allow_fields,
            )

        if tok.type == TokenType.IDENTIFIER:
            if allow_fields and self._looks_like_field():
                return self._parse_field_or_placement(
                    endianness=None,
                    in_struct_body=True,
                )
            return self._parse_expr_or_placement_stmt(allow_fields=allow_fields)

        return self._parse_expr_stmt()

    def _looks_like_field(self) -> bool:
        """Check whether the current position starts a field declaration.

        Uses look-ahead without consuming tokens.

        Returns:
            True when the token sequence looks like a field or placement declaration.
        """
        saved = self._save()
        result = self._check_field_lookahead()
        self._restore(saved)
        return result

    def _check_field_lookahead(self) -> bool:
        """Perform the actual field lookahead check without save/restore.

        Returns:
            True when the current token sequence matches a field declaration pattern.
        """
        if self._current().type == TokenType.IDENTIFIER:
            self._advance()
            if self._current().type == TokenType.DOUBLE_COLON:
                self._advance()
                if self._current().type == TokenType.IDENTIFIER:
                    self._advance()
                else:
                    return False
        elif self._current().type in PRIMITIVE_TYPES:
            self._advance()
        else:
            return False
        return self._current().type in {TokenType.IDENTIFIER, TokenType.STAR}

    def _parse_expr_or_placement_stmt(self, allow_fields: bool) -> StmtNode:
        """Parse an expression statement or a top-level placement statement.

        Attempts to parse a placement (type + name + optional offset) and falls
        back to a plain expression statement when that fails.

        Args:
            allow_fields: Whether field declarations are currently permitted.

        Returns:
            A PlacementStmt or ExprStmt node.

        Raises:
            HexPatParseError: When neither form parses successfully.
        """
        saved = self._save()
        try:
            stmt = self._parse_field_or_placement(
                endianness=None,
                in_struct_body=allow_fields,
            )
        except HexPatParseError:
            self._restore(saved)
            return self._parse_expr_stmt()
        else:
            return stmt

    def _parse_expr_stmt(self) -> ExprStmt:
        """Parse an expression used as a statement.

        Returns:
            An ExprStmt node.

        Raises:
            HexPatParseError: When no expression can be parsed.
        """
        tok = self._current()
        expr = self._parse_expression()
        self._expect(TokenType.SEMICOLON)
        return ExprStmt(expr=expr, line=tok.line, column=tok.column)

    def _parse_top_level_statement(self) -> DeclNode | StmtNode:
        """Parse a single top-level statement or placement declaration.

        Returns:
            A top-level AST node.

        Raises:
            HexPatParseError: When no valid statement can be parsed.
        """
        tok = self._current()

        if tok.type == TokenType.CONST:
            return self._parse_const_decl()

        if tok.type in ENDIANNESS_TOKENS:
            endianness = self._advance().value
            return self._parse_field_or_placement(
                endianness=endianness,
                in_struct_body=False,
            )

        if tok.type in PRIMITIVE_TYPES or tok.type == TokenType.AUTO:
            return self._parse_field_or_placement(endianness=None, in_struct_body=False)

        if tok.type == TokenType.IDENTIFIER:
            saved = self._save()
            try:
                field_stmt = self._parse_field_or_placement(
                    endianness=None,
                    in_struct_body=False,
                )
            except HexPatParseError:
                self._restore(saved)
            else:
                return field_stmt

        return self._parse_expr_stmt()

    def _parse_const_decl(self) -> VarDecl:
        """Parse a const variable declaration: ``const [Type] name = expr;``.

        Returns:
            A VarDecl node with is_const set to True.

        Raises:
            HexPatParseError: When the declaration syntax is malformed.
        """
        tok = self._expect(TokenType.CONST)
        type_node: TypeNode | None = None
        saved = self._save()
        try:
            type_node = self._parse_type()
            if self._current().type != TokenType.IDENTIFIER:
                self._restore(saved)
                type_node = None
        except HexPatParseError:
            self._restore(saved)
            type_node = None

        name_tok = self._expect(TokenType.IDENTIFIER)
        initializer: ExprNode | None = None
        if self._match(TokenType.ASSIGN):
            initializer = self._parse_expression()
        self._expect(TokenType.SEMICOLON)
        return VarDecl(
            name=name_tok.value,
            type_node=type_node,
            initializer=initializer,
            is_const=True,
            line=tok.line,
            column=tok.column,
        )

    def _parse_field_or_placement(
        self,
        endianness: str | None,
        in_struct_body: bool,
    ) -> FieldDecl | PlacementStmt:
        """Parse a field declaration or placement statement.

        Args:
            endianness: Pre-parsed endianness specifier, or None.
            in_struct_body: When True, produces a FieldDecl; otherwise a PlacementStmt.

        Returns:
            A FieldDecl when inside a struct/union body, or a PlacementStmt at top level.

        Raises:
            HexPatParseError: When the field/placement syntax is malformed.
        """
        tok = self._current()
        type_node = self._parse_type()

        if endianness is not None and isinstance(type_node, PrimitiveType) and type_node.endianness is None:
            type_node = PrimitiveType(
                name=type_node.name,
                endianness=endianness,
                line=type_node.line,
                column=type_node.column,
            )

        is_pointer = False
        if self._current().type == TokenType.STAR:
            self._advance()
            is_pointer = True

        if isinstance(type_node, PaddingType) and self._current().type == TokenType.SEMICOLON:
            self._advance()
            return FieldDecl(
                name="_padding",
                type_node=type_node,
                array_size=None,
                while_condition=None,
                at_offset=None,
                is_pointer=False,
                annotations=(),
                endianness=endianness,
                line=tok.line,
                column=tok.column,
            )

        name_tok = self._expect(TokenType.IDENTIFIER)

        array_size: ExprNode | None = None
        while_condition: ExprNode | None = None
        if self._current().type == TokenType.LBRACKET:
            self._advance()
            if self._current().type == TokenType.WHILE:
                self._advance()
                self._expect(TokenType.LPAREN)
                while_condition = self._parse_expression()
                self._expect(TokenType.RPAREN)
            else:
                array_size = self._parse_expression()
            self._expect(TokenType.RBRACKET)

        at_offset: ExprNode | None = None
        if self._current().type == TokenType.AT:
            self._advance()
            at_offset = self._parse_expression()

        annotations: tuple[tuple[str, ExprNode | None], ...] = ()
        if self._current().type == TokenType.DOUBLE_LBRACKET:
            annotations = self._parse_annotations()

        if in_struct_body:
            self._expect(TokenType.SEMICOLON)
            return FieldDecl(
                name=name_tok.value,
                type_node=type_node,
                array_size=array_size,
                while_condition=while_condition,
                at_offset=at_offset,
                is_pointer=is_pointer,
                annotations=annotations,
                endianness=endianness,
                line=tok.line,
                column=tok.column,
            )

        in_section: ExprNode | None = None
        if self._current().type == TokenType.IN:
            self._advance()
            in_section = self._parse_expression()

        self._expect(TokenType.SEMICOLON)
        return PlacementStmt(
            type_node=type_node,
            name=name_tok.value,
            at_offset=at_offset,
            annotations=annotations,
            in_section=in_section,
            array_size=array_size,
            while_condition=while_condition,
            line=tok.line,
            column=tok.column,
        )

    def _parse_if_stmt(self) -> ConditionalField:
        """Parse an if/else-if/else conditional statement.

        Returns:
            A ConditionalField node.

        Raises:
            HexPatParseError: When the if-statement syntax is malformed.
        """
        tok = self._expect(TokenType.IF)
        self._expect(TokenType.LPAREN)
        condition = self._parse_expression()
        self._expect(TokenType.RPAREN)
        true_fields = self._parse_block(allow_fields=True)
        false_fields: tuple[StmtNode, ...] = ()
        if self._current().type == TokenType.ELSE:
            self._advance()
            false_fields = (self._parse_if_stmt(),) if self._current().type == TokenType.IF else self._parse_block(allow_fields=True)
        return ConditionalField(
            condition=condition,
            true_fields=true_fields,
            false_fields=false_fields,
            line=tok.line,
            column=tok.column,
        )

    def _parse_while_stmt(self) -> WhileStmt:
        """Parse a while loop statement.

        Returns:
            A WhileStmt node.

        Raises:
            HexPatParseError: When the while-statement syntax is malformed.
        """
        tok = self._expect(TokenType.WHILE)
        self._expect(TokenType.LPAREN)
        condition = self._parse_expression()
        self._expect(TokenType.RPAREN)
        body = self._parse_block(allow_fields=False)
        return WhileStmt(condition=condition, body=body, line=tok.line, column=tok.column)

    def _parse_for_stmt(self) -> ForStmt:
        """Parse a for loop statement.

        Returns:
            A ForStmt node.

        Raises:
            HexPatParseError: When the for-statement syntax is malformed.
        """
        tok = self._expect(TokenType.FOR)
        self._expect(TokenType.LPAREN)

        init: StmtNode | None = None
        if self._current().type != TokenType.SEMICOLON:
            if self._current().type == TokenType.CONST:
                init = self._parse_const_decl()
            else:
                init_tok = self._current()
                init_expr = self._parse_expression()
                self._expect(TokenType.SEMICOLON)
                init = ExprStmt(
                    expr=init_expr,
                    line=init_tok.line,
                    column=init_tok.column,
                )
        else:
            self._advance()

        condition: ExprNode | None = None
        if self._current().type != TokenType.SEMICOLON:
            condition = self._parse_expression()
        self._expect(TokenType.SEMICOLON)

        update: ExprNode | None = None
        if self._current().type != TokenType.RPAREN:
            update = self._parse_expression()
        self._expect(TokenType.RPAREN)

        body = self._parse_block(allow_fields=False)
        return ForStmt(
            init=init,
            condition=condition,
            update=update,
            body=body,
            line=tok.line,
            column=tok.column,
        )

    def _parse_match_stmt(self) -> MatchStmt:
        """Parse a match statement.

        Returns:
            A MatchStmt node.

        Raises:
            HexPatParseError: When the match-statement syntax is malformed.
        """
        tok = self._expect(TokenType.MATCH)
        self._expect(TokenType.LPAREN)
        value = self._parse_expression()
        self._expect(TokenType.RPAREN)
        self._expect(TokenType.LBRACE)

        arms: list[MatchArm] = []
        while self._current().type != TokenType.RBRACE and not self._at_end():
            arm_tok = self._current()
            is_wildcard = False
            patterns: list[ExprNode] = []

            if self._current().type == TokenType.IDENTIFIER and self._current().value == "_":
                self._advance()
                is_wildcard = True
            else:
                patterns.append(self._parse_expression())
                while self._current().type == TokenType.PIPE:
                    self._advance()
                    patterns.append(self._parse_expression())

            self._expect(TokenType.COLON)
            arm_body = self._parse_block(allow_fields=False)
            if self._current().type == TokenType.COMMA:
                self._advance()

            arms.append(
                MatchArm(
                    patterns=tuple(patterns),
                    is_wildcard=is_wildcard,
                    body=arm_body,
                    line=arm_tok.line,
                    column=arm_tok.column,
                )
            )

        self._expect(TokenType.RBRACE)
        return MatchStmt(value=value, arms=tuple(arms), line=tok.line, column=tok.column)

    def _parse_try_stmt(self) -> TryStmt:
        """Parse a try/catch statement.

        Returns:
            A TryStmt node.

        Raises:
            HexPatParseError: When the try-statement syntax is malformed.
        """
        tok = self._expect(TokenType.TRY)
        try_body = self._parse_block(allow_fields=False)
        self._expect(TokenType.CATCH)
        catch_body = self._parse_block(allow_fields=False)
        return TryStmt(
            try_body=try_body,
            catch_body=catch_body,
            line=tok.line,
            column=tok.column,
        )

    def _parse_return_stmt(self) -> ReturnStmt:
        """Parse a return statement.

        Returns:
            A ReturnStmt node.

        Raises:
            HexPatParseError: When the return-statement syntax is malformed.
        """
        tok = self._expect(TokenType.RETURN)
        value: ExprNode | None = None
        if self._current().type != TokenType.SEMICOLON:
            value = self._parse_expression()
        self._expect(TokenType.SEMICOLON)
        return ReturnStmt(value=value, line=tok.line, column=tok.column)

    def _parse_struct(
        self,
        annotations: tuple[tuple[str, ExprNode | None], ...],
    ) -> StructDecl:
        """Parse a struct declaration.

        Args:
            annotations: Pre-parsed annotation pairs collected before the struct keyword.

        Returns:
            A StructDecl node.

        Raises:
            HexPatParseError: When the struct syntax is malformed.
        """
        tok = self._expect(TokenType.STRUCT)
        name_tok = self._expect(TokenType.IDENTIFIER)
        parent: str | None = None
        if self._current().type == TokenType.COLON:
            self._advance()
            parent = self._expect(TokenType.IDENTIFIER).value
        body = self._parse_block(allow_fields=True)
        return StructDecl(
            name=name_tok.value,
            parent=parent,
            body=body,
            annotations=annotations,
            line=tok.line,
            column=tok.column,
        )

    def _parse_union(
        self,
        annotations: tuple[tuple[str, ExprNode | None], ...],
    ) -> UnionDecl:
        """Parse a union declaration.

        Args:
            annotations: Pre-parsed annotation pairs collected before the union keyword.

        Returns:
            A UnionDecl node.

        Raises:
            HexPatParseError: When the union syntax is malformed.
        """
        tok = self._expect(TokenType.UNION)
        name_tok = self._expect(TokenType.IDENTIFIER)
        body = self._parse_block(allow_fields=True)
        return UnionDecl(
            name=name_tok.value,
            body=body,
            annotations=annotations,
            line=tok.line,
            column=tok.column,
        )

    def _parse_enum(self) -> EnumDecl:
        """Parse an enum declaration.

        Returns:
            An EnumDecl node.

        Raises:
            HexPatParseError: When the enum syntax is malformed.
        """
        tok = self._expect(TokenType.ENUM)
        name_tok = self._expect(TokenType.IDENTIFIER)
        self._expect(TokenType.COLON)
        backing_type = self._parse_type()
        self._expect(TokenType.LBRACE)

        entries: list[EnumEntry] = []
        while self._current().type != TokenType.RBRACE and not self._at_end():
            entry_tok = self._expect(TokenType.IDENTIFIER)
            entry_value: ExprNode | None = None
            if self._current().type == TokenType.ASSIGN:
                self._advance()
                entry_value = self._parse_expression()
            entries.append(
                EnumEntry(
                    name=entry_tok.value,
                    value=entry_value,
                    line=entry_tok.line,
                    column=entry_tok.column,
                )
            )
            if not self._match(TokenType.COMMA):
                break

        self._expect(TokenType.RBRACE)
        return EnumDecl(
            name=name_tok.value,
            backing_type=backing_type,
            entries=tuple(entries),
            line=tok.line,
            column=tok.column,
        )

    def _parse_bitfield(
        self,
        annotations: tuple[tuple[str, ExprNode | None], ...],
    ) -> BitfieldDecl:
        """Parse a bitfield declaration.

        Args:
            annotations: Pre-parsed annotation pairs collected before the bitfield keyword.

        Returns:
            A BitfieldDecl node.

        Raises:
            HexPatParseError: When the bitfield syntax is malformed.
        """
        tok = self._expect(TokenType.BITFIELD)
        name_tok = self._expect(TokenType.IDENTIFIER)
        self._expect(TokenType.LBRACE)

        entries: list[BitfieldEntry] = []
        while self._current().type != TokenType.RBRACE and not self._at_end():
            entry_tok = self._expect(TokenType.IDENTIFIER)
            self._expect(TokenType.COLON)
            width = self._parse_expression()
            self._expect(TokenType.SEMICOLON)
            entries.append(
                BitfieldEntry(
                    name=entry_tok.value,
                    width=width,
                    line=entry_tok.line,
                    column=entry_tok.column,
                )
            )

        self._expect(TokenType.RBRACE)
        return BitfieldDecl(
            name=name_tok.value,
            entries=tuple(entries),
            annotations=annotations,
            line=tok.line,
            column=tok.column,
        )

    def _parse_function(self) -> FunctionDecl:
        """Parse a function declaration.

        Returns:
            A FunctionDecl node.

        Raises:
            HexPatParseError: When the function syntax is malformed.
        """
        tok = self._expect(TokenType.FN)
        name_tok = self._expect(TokenType.IDENTIFIER)
        self._expect(TokenType.LPAREN)

        params: list[FunctionParam] = []
        while self._current().type != TokenType.RPAREN and not self._at_end():
            param_tok = self._current()
            is_ref = False
            if self._current().type in {TokenType.REF, TokenType.OUT}:
                self._advance()
                is_ref = True

            param_type = self._parse_type()
            param_name_tok = self._expect(TokenType.IDENTIFIER)
            default_value: ExprNode | None = None
            if self._current().type == TokenType.ASSIGN:
                self._advance()
                default_value = self._parse_expression()
            params.append(
                FunctionParam(
                    name=param_name_tok.value,
                    type_node=param_type,
                    is_ref=is_ref,
                    default_value=default_value,
                    line=param_tok.line,
                    column=param_tok.column,
                )
            )
            if not self._match(TokenType.COMMA):
                break

        self._expect(TokenType.RPAREN)

        return_type: TypeNode | None = None
        if self._current().type == TokenType.ARROW:
            self._advance()
            return_type = self._parse_type()

        body = self._parse_block(allow_fields=False)
        return FunctionDecl(
            name=name_tok.value,
            params=tuple(params),
            return_type=return_type,
            body=body,
            line=tok.line,
            column=tok.column,
        )

    def _parse_namespace(self) -> NamespaceDecl:
        """Parse a namespace declaration.

        Returns:
            A NamespaceDecl node.

        Raises:
            HexPatParseError: When the namespace syntax is malformed.
        """
        tok = self._expect(TokenType.NAMESPACE)
        name_tok = self._expect(TokenType.IDENTIFIER)
        self._expect(TokenType.LBRACE)

        body: list[DeclNode] = []
        while self._current().type != TokenType.RBRACE and not self._at_end():
            annotations = self._try_parse_annotations()
            tt = self._current().type
            if tt == TokenType.STRUCT:
                body.append(self._parse_struct(annotations))
            elif tt == TokenType.UNION:
                body.append(self._parse_union(annotations))
            elif tt == TokenType.ENUM:
                body.append(self._parse_enum())
            elif tt == TokenType.BITFIELD:
                body.append(self._parse_bitfield(annotations))
            elif tt == TokenType.FN:
                body.append(self._parse_function())
            elif tt == TokenType.NAMESPACE:
                body.append(self._parse_namespace())
            elif tt == TokenType.USING:
                body.append(self._parse_using())
            else:
                msg = f"Expected declaration inside namespace, got '{self._current().value}'"
                raise self._error(msg)

        self._expect(TokenType.RBRACE)
        return NamespaceDecl(
            name=name_tok.value,
            body=tuple(body),
            line=tok.line,
            column=tok.column,
        )

    def _parse_using(self) -> UsingDecl:
        """Parse a using (type alias) declaration.

        Returns:
            A UsingDecl node.

        Raises:
            HexPatParseError: When the using declaration syntax is malformed.
        """
        tok = self._expect(TokenType.USING)
        alias_tok = self._expect(TokenType.IDENTIFIER)
        self._expect(TokenType.ASSIGN)
        target = self._parse_type()
        self._expect(TokenType.SEMICOLON)
        return UsingDecl(
            alias=alias_tok.value,
            target=target,
            line=tok.line,
            column=tok.column,
        )
