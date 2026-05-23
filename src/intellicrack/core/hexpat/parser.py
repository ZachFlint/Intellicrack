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
    TemplateParam,
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
from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from intellicrack.core.hexpat.ast_nodes import DeclNode, ExprNode, StmtNode, TypeNode


_logger = get_logger(__name__)


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


class HexPatAggregateParseError(HexPatParseError):
    """Aggregated parser error produced when recovery collects multiple errors.

    Subclasses :class:`HexPatParseError` so existing handlers continue to catch it. Carries the full list of collected errors via
    :attr:`errors`, and exposes a summary message that enumerates every error so callers do not silently lose information about secondary
    failures.
    """

    def __init__(self, errors: tuple[HexPatParseError, ...]) -> None:
        """Initialize the aggregate error from a non-empty tuple of parse errors.

        Args:
            errors: Tuple of collected :class:`HexPatParseError` instances; must
                contain at least one element. The first error's location is
                preserved as the headline location of the aggregate so existing
                tooling that reads ``line``/``column`` continues to work.

        Raises:
            ValueError: If ``errors`` is empty.
        """
        if not errors:
            msg = "HexPatAggregateParseError requires at least one collected error"
            raise ValueError(msg)
        self.errors: tuple[HexPatParseError, ...] = errors
        first: HexPatParseError = errors[0]
        if len(errors) == 1:
            summary: str = first.message
        else:
            details: list[str] = []
            total: int = len(errors)
            for idx, err in enumerate(errors, start=1):
                location: str = ""
                if err.line > 0:
                    location = f" at {err.line}:{err.column}" if err.column > 0 else f" at line {err.line}"
                details.append(f"  [{idx}/{total}]{location}: {err.message}")
            joined: str = "\n".join(details)
            summary = f"{total} parse errors collected:\n{joined}"
        super().__init__(
            summary,
            first.line,
            first.column,
            first.file,
        )


class HexPatParser:
    """Recursive-descent parser for the HexPat .hexpat pattern language.

    Consumes a flat list of tokens produced by the lexer and builds an AST consisting of top-level declarations and statements.
    """

    def __init__(
        self,
        tokens: list[Token],
        file_path: str = "<input>",
    ) -> None:
        """Initialize the HexPatParser with a token stream.

        Args:
            tokens: Flat token list produced by the lexer.
            file_path: Source file path used for error location reporting.
        """
        self._tokens: list[Token] = tokens
        self._pos: int = 0
        self.file_path: str = file_path
        self._errors: list[HexPatParseError] = []
        _logger.debug(
            "hexpat_parser_initialized",
            file_path=file_path,
            token_count=len(tokens),
        )

    @property
    def errors(self) -> list[HexPatParseError]:
        """Return all parse errors collected during recovery-mode parsing.

        Returns:
            list[HexPatParseError]: Errors collected by ``parse()``; empty if none.
        """
        return list(self._errors)

    def parse(self) -> list[DeclNode | StmtNode]:
        """Parse the token stream into a list of top-level declarations and statements.

        The parser attempts to recover from individual top-level syntax errors by
        collecting the raised :class:`HexPatParseError` into :attr:`errors` and
        synchronising to the next top-level boundary (``;`` or ``}``). After the
        entire token stream has been processed, all collected errors are surfaced
        to the caller as a single :class:`HexPatAggregateParseError` whose message
        enumerates every collected error and whose :attr:`errors` attribute holds
        the full list, so callers never silently lose information about secondary
        failures.

        Returns:
            list[DeclNode | StmtNode]: Ordered list of top-level AST nodes parsed
                from the token stream.

        Raises:
            HexPatAggregateParseError: When one or more syntax errors were
                collected. Subclass of :class:`HexPatParseError` so existing
                ``except HexPatParseError`` clauses still catch it.
        """
        nodes: list[DeclNode | StmtNode] = []
        while not self._at_end():
            if self._current().type == TokenType.SEMICOLON:
                self._advance()
                continue
            try:
                node = self._parse_top_level_node()
            except HexPatParseError as err:
                _logger.debug(
                    "hexpat_parse_recover",
                    error=err.message,
                    line=err.line,
                    column=err.column,
                    file_path=self.file_path,
                )
                self._errors.append(err)
                self._synchronise()
                continue
            nodes.append(node)
        if self._errors:
            _logger.warning("hexpat_parse_failed", error_count=len(self._errors), file_path=self.file_path)
            raise HexPatAggregateParseError(tuple(self._errors))
        return nodes

    def _parse_top_level_node(self) -> DeclNode | StmtNode:
        """Parse a single top-level declaration or statement.

        Returns:
            DeclNode | StmtNode: The parsed top-level node.
        """
        annotations = self._try_parse_annotations()
        tt = self._current().type
        if tt == TokenType.STRUCT:
            return self._parse_struct(annotations)
        if tt == TokenType.UNION:
            return self._parse_union(annotations)
        if tt == TokenType.ENUM:
            return self._parse_enum(annotations)
        if tt == TokenType.BITFIELD:
            return self._parse_bitfield(annotations)
        if tt == TokenType.FN:
            return self._parse_function()
        if tt == TokenType.NAMESPACE:
            return self._parse_namespace()
        if tt == TokenType.USING:
            return self._parse_using()
        return self._parse_top_level_statement()

    def _synchronise(self) -> None:
        """Advance the token cursor past the next top-level statement boundary.

        Consumes tokens until a ``;`` is consumed, a closing ``}`` is consumed at brace depth zero, or EOF is reached. Nested braces are
        tracked so an unterminated body does not cause spurious early exits.
        """
        depth = 0
        while not self._at_end():
            tt = self._current().type
            if tt == TokenType.LBRACE:
                depth += 1
                self._advance()
                continue
            if tt == TokenType.RBRACE:
                if depth == 0:
                    self._advance()
                    return
                depth -= 1
                self._advance()
                continue
            if tt == TokenType.SEMICOLON and depth == 0:
                self._advance()
                return
            self._advance()

    def _current(self) -> Token:
        """Return the current token without consuming it.

        Returns:
            Token: Current token, or an EOF token if past the end.
        """
        return self._tokens[self._pos] if self._pos < len(self._tokens) else _EOF_TOKEN

    def _peek(self, offset: int = 1) -> Token:
        """Return the token at current position plus offset without consuming.

        Args:
            offset: Number of positions ahead to look.

        Returns:
            Token: Token at the requested position, or an EOF token if past the end.
        """
        idx = self._pos + offset
        return self._tokens[idx] if idx < len(self._tokens) else _EOF_TOKEN

    def _advance(self) -> Token:
        """Consume and return the current token.

        Returns:
            Token: The token that was current before advancing.
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
            Token: The consumed token.

        Raises:
            HexPatParseError: If the input is malformed.
        """
        tok = self._current()
        if tok.type != tt:
            msg = f"Expected '{tt.value}', got '{tok.value}'"
            raise HexPatParseError(msg, tok.line, tok.column, self.file_path)
        return self._advance()

    def _match(self, *types: TokenType) -> bool:
        """Consume the current token if it matches any of the given types.

        Args:
            *types: Token types to match against.

        Returns:
            bool: True if a token was consumed, False otherwise.
        """
        if self._current().type in types:
            self._advance()
            return True
        return False

    def _at_end(self) -> bool:
        """Check whether the token stream is exhausted.

        Returns:
            bool: True if at EOF.
        """
        return self._current().type == TokenType.EOF

    def _save(self) -> int:
        """Save the current parser position.

        Returns:
            int: Current position index.
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
            tuple[tuple[str, ExprNode | None], ...]: Parsed annotations or an empty tuple when no annotation block follows.
        """
        if self._current().type != TokenType.DOUBLE_LBRACKET:
            return ()
        return self._parse_annotations()

    def _parse_annotations(self) -> tuple[tuple[str, ExprNode | None], ...]:
        """Parse a double-bracket annotation block.

        Returns:
            tuple[tuple[str, ExprNode | None], ...]: Tuple of (name, optional_expr) annotation pairs.
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
            TypeNode: A TypeNode representing the parsed type.

        Raises:
            HexPatParseError: If the input is malformed.
        """
        endianness: str | None = None
        if self._current().type in ENDIANNESS_TOKENS:
            endianness = self._advance().value

        tok = self._current()

        if tok.type == TokenType.STAR:
            self._advance()
            inner = self._parse_type()
            return PointerType(
                pointee=inner,
                line=tok.line,
                column=tok.column,
                endianness=endianness,
            )

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
                while self._current().type == TokenType.DOUBLE_COLON:
                    self._advance()
                    next_tok = self._expect(TokenType.IDENTIFIER)
                    namespace = f"{namespace}::{name}"
                    name = next_tok.value
            template_args: tuple[ExprNode, ...] = ()
            if self._current().type == TokenType.LT:
                template_args = self._parse_template_args()
            base = NamedType(
                name=name,
                namespace=namespace,
                line=tok.line,
                column=tok.column,
                endianness=endianness,
                template_args=template_args,
            )
        else:
            msg = f"Expected type, got '{tok.value}'"
            raise HexPatParseError(msg, tok.line, tok.column, self.file_path)

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
                    endianness=endianness,
                )
            arr_size = self._parse_expression()
            self._expect(TokenType.RBRACKET)
            return ArrayType(
                element=base,
                size=arr_size,
                while_condition=None,
                line=arr_tok.line,
                column=arr_tok.column,
                endianness=endianness,
            )

        return base

    def _parse_template_args(self) -> tuple[ExprNode, ...]:
        """Parse a template argument list of the form ``<arg1, arg2, ...>``.

        Returns:
            tuple[ExprNode, ...]: The parsed template argument expressions.
        """
        self._expect(TokenType.LT)
        args: list[ExprNode] = []
        if self._current().type != TokenType.GT:
            args.append(self._parse_template_arg())
            while self._match(TokenType.COMMA):
                args.append(self._parse_template_arg())
        self._expect(TokenType.GT)
        return tuple(args)

    def _parse_template_arg(self) -> ExprNode:
        """Parse a single template argument expression.

        Parsed with a minimum binding power above comparison operators so that
        a trailing ``>`` terminates the argument list rather than being
        consumed as a greater-than operator.

        Returns:
            ExprNode: The parsed template argument expression.
        """
        return self._parse_expression(min_bp=21)

    def _parse_template_params(self) -> tuple[TemplateParam, ...]:
        """Parse a template parameter list of the form ``<T, auto N, TypeHint Name>``.

        Each parameter is one of ``IDENTIFIER``, ``auto IDENTIFIER``, or
        ``IDENTIFIER IDENTIFIER`` (type hint followed by parameter name).

        Returns:
            tuple[TemplateParam, ...]: The parsed template parameters.
        """
        self._expect(TokenType.LT)
        params: list[TemplateParam] = []
        if self._current().type != TokenType.GT:
            params.append(self._parse_template_param())
            while self._match(TokenType.COMMA):
                params.append(self._parse_template_param())
        self._expect(TokenType.GT)
        return tuple(params)

    def _parse_template_param(self) -> TemplateParam:
        """Parse a single template parameter declaration.

        Returns:
            TemplateParam: The parsed template parameter.
        """
        start_tok = self._current()
        is_auto = False
        type_hint: str | None = None
        if self._current().type == TokenType.AUTO:
            self._advance()
            is_auto = True
            name_tok = self._expect(TokenType.IDENTIFIER)
        else:
            first = self._expect(TokenType.IDENTIFIER)
            if self._current().type == TokenType.IDENTIFIER:
                type_hint = first.value
                name_tok = self._advance()
            else:
                name_tok = first
        return TemplateParam(
            name=name_tok.value,
            is_auto=is_auto,
            type_hint=type_hint,
            line=start_tok.line,
            column=start_tok.column,
        )

    def _parse_expression(self, min_bp: int = 0) -> ExprNode:
        """Parse an expression using Pratt-style operator precedence.

        Args:
            min_bp: Minimum binding power threshold for infix operators.

        Returns:
            ExprNode: Parsed expression node.
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
            ExprNode: Parsed prefix expression node.

        Raises:
            HexPatParseError: If the input is malformed.
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
                _logger.debug("hexpat_parser_backtrack", context="sizeof", line=tok.line, column=tok.column)
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
        raise HexPatParseError(msg, tok.line, tok.column, self.file_path)

    def _parse_paren_or_cast(self) -> ExprNode:
        """Parse a parenthesised expression or a cast expression.

        Returns:
            ExprNode: A CastExpr when the form is (Type)(expr), otherwise the inner expression.
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
        except HexPatParseError as exc:
            _logger.warning(
                "hexpat_parser_cast_backtrack",
                file_path=self.file_path,
                line=tok.line,
                column=tok.column,
                error=str(exc),
            )
        if cast_result is not None:
            return cast_result
        self._restore(saved)

        inner = self._parse_expression()
        self._expect(TokenType.RPAREN)
        return inner

    def _parse_block(self, *, allow_fields: bool = False) -> tuple[StmtNode, ...]:
        """Parse a brace-enclosed block of statements.

        Args:
            allow_fields: When True, field declarations are permitted within the block.

        Returns:
            tuple[StmtNode, ...]: Tuple of statement nodes forming the block body.
        """
        self._expect(TokenType.LBRACE)
        stmts: list[StmtNode] = []
        while self._current().type != TokenType.RBRACE and not self._at_end():
            stmts.append(self._parse_statement(allow_fields=allow_fields))
        self._expect(TokenType.RBRACE)
        return tuple(stmts)

    def _parse_statement(self, *, allow_fields: bool = False) -> StmtNode:
        """Parse a single statement.

        Args:
            allow_fields: When True, type-name-followed-by-identifier is parsed as a
                field declaration rather than an expression statement.

        Returns:
            StmtNode: A statement AST node.
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
            bool: True when the token sequence looks like a field or placement declaration.
        """
        saved = self._save()
        result = self._check_field_lookahead()
        self._restore(saved)
        return result

    def _check_field_lookahead(self) -> bool:
        """Perform the actual field lookahead check without save/restore.

        Returns:
            bool: True when the current token sequence matches a field declaration pattern.
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

    def _parse_expr_or_placement_stmt(self, *, allow_fields: bool) -> StmtNode:
        """Parse an expression statement or a top-level placement statement.

        Attempts to parse a placement (type + name + optional offset) and falls
        back to a plain expression statement when that fails.

        Args:
            allow_fields: Whether field declarations are currently permitted.

        Returns:
            StmtNode: A PlacementStmt or ExprStmt node.
        """
        saved = self._save()
        try:
            stmt = self._parse_field_or_placement(
                endianness=None,
                in_struct_body=allow_fields,
            )
        except HexPatParseError:
            _logger.debug("hexpat_parser_backtrack", context="placement_vs_expr")
            self._restore(saved)
            return self._parse_expr_stmt()
        else:
            return stmt

    def _parse_expr_stmt(self) -> ExprStmt:
        """Parse an expression used as a statement.

        Returns:
            ExprStmt: An ExprStmt node.
        """
        tok = self._current()
        expr = self._parse_expression()
        self._expect(TokenType.SEMICOLON)
        return ExprStmt(expr=expr, line=tok.line, column=tok.column)

    def _parse_top_level_statement(self) -> DeclNode | StmtNode:
        """Parse a single top-level statement or placement declaration.

        Returns:
            DeclNode | StmtNode: A top-level AST node.
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
                _logger.debug("hexpat_parser_backtrack", context="top_level_placement")
                self._restore(saved)
            else:
                return field_stmt

        return self._parse_expr_stmt()

    def _parse_const_decl(self) -> VarDecl:
        """Parse a const variable declaration: ``const [Type] name = expr;``.

        Returns:
            VarDecl: A VarDecl node with is_const set to True.
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
            _logger.debug("hexpat_parser_backtrack", context="typed_const")
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
        *,
        in_struct_body: bool,
    ) -> FieldDecl | PlacementStmt:
        """Parse a field declaration or placement statement.

        Args:
            endianness: Pre-parsed endianness specifier, or None.
            in_struct_body: When True, produces a FieldDecl; otherwise a PlacementStmt.

        Returns:
            FieldDecl | PlacementStmt: A FieldDecl when inside a struct/union body, or a PlacementStmt at top level.
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
            ConditionalField: A ConditionalField node.
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
            WhileStmt: A WhileStmt node.
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
            ForStmt: A ForStmt node.
        """
        tok = self._expect(TokenType.FOR)
        self._expect(TokenType.LPAREN)

        init: StmtNode | None = None
        if self._current().type == TokenType.SEMICOLON:
            self._advance()

        elif self._current().type == TokenType.CONST:
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
            MatchStmt: A MatchStmt node.
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
                ),
            )

        self._expect(TokenType.RBRACE)
        return MatchStmt(value=value, arms=tuple(arms), line=tok.line, column=tok.column)

    def _parse_try_stmt(self) -> TryStmt:
        """Parse a try/catch statement.

        Returns:
            TryStmt: A TryStmt node.
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
            ReturnStmt: A ReturnStmt node.
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
            StructDecl: A StructDecl node.
        """
        tok = self._expect(TokenType.STRUCT)
        name_tok = self._expect(TokenType.IDENTIFIER)
        template_params: tuple[TemplateParam, ...] = ()
        if self._current().type == TokenType.LT:
            template_params = self._parse_template_params()
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
            template_params=template_params,
        )

    def _parse_union(
        self,
        annotations: tuple[tuple[str, ExprNode | None], ...],
    ) -> UnionDecl:
        """Parse a union declaration.

        Args:
            annotations: Pre-parsed annotation pairs collected before the union keyword.

        Returns:
            UnionDecl: A UnionDecl node.
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

    def _parse_enum(
        self,
        annotations: tuple[tuple[str, ExprNode | None], ...] = (),
    ) -> EnumDecl:
        """Parse an enum declaration.

        Args:
            annotations: Pre-parsed annotation pairs collected before the enum keyword.

        Returns:
            EnumDecl: An EnumDecl node.
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
            entry_value_end: ExprNode | None = None
            if self._current().type == TokenType.ASSIGN:
                self._advance()
                entry_value = self._parse_expression()
                if self._current().type == TokenType.ELLIPSIS:
                    self._advance()
                    entry_value_end = self._parse_expression()
            entries.append(
                EnumEntry(
                    name=entry_tok.value,
                    value=entry_value,
                    line=entry_tok.line,
                    column=entry_tok.column,
                    value_end=entry_value_end,
                ),
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
            annotations=annotations,
        )

    def _parse_bitfield(
        self,
        annotations: tuple[tuple[str, ExprNode | None], ...],
    ) -> BitfieldDecl:
        """Parse a bitfield declaration.

        Args:
            annotations: Pre-parsed annotation pairs collected before the bitfield keyword.

        Returns:
            BitfieldDecl: A BitfieldDecl node.
        """
        tok = self._expect(TokenType.BITFIELD)
        name_tok = self._expect(TokenType.IDENTIFIER)
        self._expect(TokenType.LBRACE)

        entries: list[BitfieldEntry] = []
        while self._current().type != TokenType.RBRACE and not self._at_end():
            entries.append(self._parse_bitfield_entry())

        self._expect(TokenType.RBRACE)
        return BitfieldDecl(
            name=name_tok.value,
            entries=tuple(entries),
            annotations=annotations,
            line=tok.line,
            column=tok.column,
        )

    def _parse_bitfield_entry(self) -> BitfieldEntry:
        """Parse a single bitfield entry line such as ``name : width;`` or ``padding : 4;``.

        Accepts an optional type hint before the entry name. Recognised type
        hint tokens are ``signed``/``unsigned`` (identifiers) and any
        primitive integer type token. A leading ``padding`` keyword produces
        an anonymous padding entry with ``is_padding`` set to True.

        Returns:
            BitfieldEntry: The parsed bitfield entry.

        Raises:
            HexPatParseError: If the input is malformed.
        """
        tok = self._current()
        type_hint: str | None = None
        is_padding = False
        entry_name: str
        entry_line = tok.line
        entry_column = tok.column

        if tok.type == TokenType.PADDING:
            self._advance()
            is_padding = True
            entry_name = "padding"
        elif tok.type in PRIMITIVE_TYPES:
            self._advance()
            type_hint = tok.value
            name_tok = self._expect(TokenType.IDENTIFIER)
            entry_name = name_tok.value
            entry_line = name_tok.line
            entry_column = name_tok.column
        elif tok.type == TokenType.IDENTIFIER:
            self._advance()
            if tok.value in {"signed", "unsigned"} and self._current().type == TokenType.IDENTIFIER:
                type_hint = tok.value
                name_tok = self._advance()
                entry_name = name_tok.value
                entry_line = name_tok.line
                entry_column = name_tok.column
            elif tok.value in {"signed", "unsigned"} and self._current().type == TokenType.PADDING:
                type_hint = tok.value
                self._advance()
                is_padding = True
                entry_name = "padding"
            else:
                entry_name = tok.value
        else:
            msg = f"Expected bitfield entry, got '{tok.value}'"
            raise HexPatParseError(msg, tok.line, tok.column, self.file_path)

        self._expect(TokenType.COLON)
        width = self._parse_expression()
        self._expect(TokenType.SEMICOLON)
        return BitfieldEntry(
            name=entry_name,
            width=width,
            line=entry_line,
            column=entry_column,
            type_hint=type_hint,
            is_padding=is_padding,
        )

    def _parse_function(self) -> FunctionDecl:
        """Parse a function declaration.

        Returns:
            FunctionDecl: A FunctionDecl node.
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
            is_varargs = False
            if self._current().type == TokenType.ELLIPSIS:
                self._advance()
                is_varargs = True
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
                    is_varargs=is_varargs,
                ),
            )
            if is_varargs or not self._match(TokenType.COMMA):
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
            NamespaceDecl: A NamespaceDecl node.

        Raises:
            HexPatParseError: If the input is malformed.
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
                body.append(self._parse_enum(annotations))
            elif tt == TokenType.BITFIELD:
                body.append(self._parse_bitfield(annotations))
            elif tt == TokenType.FN:
                body.append(self._parse_function())
            elif tt == TokenType.NAMESPACE:
                body.append(self._parse_namespace())
            elif tt == TokenType.USING:
                body.append(self._parse_using())
            else:
                err_tok = self._current()
                msg = f"Expected declaration inside namespace, got '{err_tok.value}'"
                raise HexPatParseError(msg, err_tok.line, err_tok.column, self.file_path)

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
            UsingDecl: A UsingDecl node.
        """
        tok = self._expect(TokenType.USING)
        alias_tok = self._expect(TokenType.IDENTIFIER)
        template_params: tuple[TemplateParam, ...] = ()
        if self._current().type == TokenType.LT:
            template_params = self._parse_template_params()
        self._expect(TokenType.ASSIGN)
        target = self._parse_type()
        self._expect(TokenType.SEMICOLON)
        return UsingDecl(
            alias=alias_tok.value,
            target=target,
            line=tok.line,
            column=tok.column,
            template_params=template_params,
        )
