# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""HexPat DSL compiler that emits JSON templates from the shared AST.

This module is a thin compatibility/code-generation layer that delegates
lexing and parsing to the canonical HexPat pipeline in
``intellicrack.core.hexpat`` and walks the resulting AST to produce a
JSON template definition consumable by the Rust hex editor core.

The lexer, parser, AST, and error types are re-exported from this module
for backward compatibility with previously published symbol paths.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Final


if TYPE_CHECKING:
    from collections.abc import Sequence

from intellicrack.core.hexpat._pragma import PragmaInfo
from intellicrack.core.hexpat.ast_nodes import (
    AddressOfExpr,
    ArrayType,
    AutoType,
    BinaryExpr,
    BitfieldDecl,
    BitfieldEntry,
    BoolLiteral,
    CharLiteral,
    ConditionalField,
    DeclNode,
    DollarExpr,
    EnumDecl,
    EnumEntry,
    ExprNode,
    ExprStmt,
    FieldDecl,
    FloatLiteral,
    ForStmt,
    FunctionDecl,
    IdentifierExpr,
    MatchStmt,
    NamedType,
    NamespaceDecl,
    NullLiteral,
    NumberLiteral,
    PaddingType,
    PlacementStmt,
    PointerType,
    PrimitiveType,
    SizeofExpr,
    StmtNode,
    StringLiteral,
    StructDecl,
    TryStmt,
    TypeNameOfExpr,
    TypeNode,
    UnaryExpr,
    UnionDecl,
    UsingDecl,
    VarDecl,
    WhileStmt,
)
from intellicrack.core.hexpat.errors import HexPatError, HexPatParseError
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatParser
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor
from intellicrack.core.hexpat.tokens import Token, TokenType
from intellicrack.core.logging import get_logger


_logger = get_logger(__name__)


__all__: list[str] = [
    "HexPatCodegen",
    "HexPatCompiler",
    "HexPatError",
    "HexPatLexer",
    "HexPatParser",
    "Token",
    "TokenType",
]


_TYPE_MAP: Final[dict[str, dict[str, str]]] = {
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


_COMPARISON_OP_MAP: Final[dict[str, str]] = {
    "==": "Eq",
    "!=": "Ne",
    ">": "Gt",
    "<": "Lt",
    ">=": "Ge",
    "<=": "Le",
    "&": "BitAnd",
}


_INVERT_OP_MAP: Final[dict[str, str]] = {
    "Eq": "Ne",
    "Ne": "Eq",
    "Gt": "Le",
    "Lt": "Ge",
    "Ge": "Lt",
    "Le": "Gt",
    "BitAnd": "BitAndZero",
    "BitAndZero": "BitAnd",
}


_ENDIANNESS_MAP: Final[dict[str, str]] = {"le": "little", "be": "big"}


_RUNTIME_DECL_LABELS: Final[dict[type, str]] = {
    FunctionDecl: "function",
    NamespaceDecl: "namespace",
    UsingDecl: "using",
}


_RUNTIME_STMT_LABELS: Final[dict[type, str]] = {
    WhileStmt: "while",
    ForStmt: "for",
    MatchStmt: "match",
    TryStmt: "try",
    VarDecl: "var",
    ExprStmt: "expression statement",
}


_RUNTIME_STMT_TYPES: Final[tuple[type, ...]] = tuple(_RUNTIME_STMT_LABELS.keys())


class HexPatCodegen:
    """Generates JSON template definitions from a HexPat AST.

    Walks the shared HexPat AST produced by
    ``intellicrack.core.hexpat.parser.HexPatParser`` and emits a
    JSON-serializable template definition. Runtime constructs that have no
    static representation are rejected during the walk.
    """

    def __init__(
        self,
        declarations: Sequence[DeclNode | StmtNode],
        pragma: PragmaInfo | None = None,
    ) -> None:
        """Initialize the HexPatCodegen with parsed top-level AST nodes.

        Top-level runtime-only declarations and statements raise
        :class:`HexPatError` from :meth:`_reject_runtime_top_level`.

        Args:
            declarations: Sequence of top-level AST nodes produced by
                :class:`HexPatParser`. Items typically include
                :class:`StructDecl`, :class:`UnionDecl`, :class:`EnumDecl`,
                and :class:`BitfieldDecl`. Top-level placement statements
                or other ``StmtNode`` values are rejected at construction
                time as they have no representation in the static JSON
                template.
            pragma: Optional preprocessor-extracted ``#pragma`` metadata to
                propagate into the emitted JSON template. When supplied, the
                template's ``default_endianness``, ``description``, ``author``,
                and ``magic_detection`` fields are populated from the pragma
                values; otherwise the codegen falls back to inert defaults.
        """
        self._reject_runtime_top_level(declarations)
        self._decls: list[DeclNode] = [node for node in declarations if isinstance(node, (StructDecl, UnionDecl, EnumDecl, BitfieldDecl))]
        self._nested_enums: dict[str, EnumDecl] = {decl.name: decl for decl in self._decls if isinstance(decl, EnumDecl)}
        self._pragma: PragmaInfo = pragma if pragma is not None else PragmaInfo()
        _logger.debug(
            "hexpat_codegen_initialized",
            declaration_count=len(self._decls),
            pragma_endian=self._pragma.endian,
            pragma_base_address=self._pragma.base_address,
            pragma_bitfield_order=self._pragma.bitfield_order,
        )

    @staticmethod
    def _reject_runtime_top_level(declarations: Sequence[DeclNode | StmtNode]) -> None:
        """Reject top-level runtime-only declarations and statements.

        Args:
            declarations: Sequence of top-level AST nodes.

        Raises:
            HexPatError: If any node is a runtime-only declaration or
                statement that has no representation in the static JSON
                template.
        """
        for decl in declarations:
            decl_type = type(decl)
            decl_label = _RUNTIME_DECL_LABELS.get(decl_type)
            if decl_label is not None:
                msg = (
                    f"'{decl_label}' is a runtime construct that cannot be "
                    f"compiled to a static JSON template; use the HexPat "
                    f"interpreter for patterns containing {decl_label} "
                    f"declarations"
                )
                raise HexPatError(msg, decl.line, decl.column)
            stmt_label = _RUNTIME_STMT_LABELS.get(decl_type)
            if stmt_label is not None:
                msg = (
                    f"top-level '{stmt_label}' is a runtime construct that "
                    f"cannot be compiled to a static JSON template; use the "
                    f"HexPat interpreter for patterns containing "
                    f"{stmt_label} statements"
                )
                raise HexPatError(msg, decl.line, decl.column)

    def generate(self) -> dict[str, Any]:
        """Generate the JSON template dict from all declarations.

        Honours preprocessor-extracted ``#pragma`` metadata (when supplied at
        construction) by populating the template's ``default_endianness``,
        ``description``, ``author``, and ``magic_detection`` fields from the
        corresponding pragma values. ``#pragma base_address`` and
        ``#pragma bitfield_order`` are recorded under a ``pragma_metadata``
        key so downstream consumers can apply them when materialising the
        template against binary data.

        Returns:
            dict[str, Any]: JSON-serializable template definition.

        Raises:
            HexPatError: If no struct declaration is found.
        """
        main_struct: StructDecl | None = next(
            (decl for decl in self._decls if isinstance(decl, StructDecl)),
            None,
        )
        if main_struct is None:
            msg = "no struct declaration found"
            _logger.error("hexpat_generate_no_struct_declaration")
            raise HexPatError(msg)

        fields: list[dict[str, Any]] = []
        for stmt in main_struct.body:
            fields.extend(self._gen_field(stmt))

        types: dict[str, dict[str, Any]] = {}
        for decl in self._decls:
            if isinstance(decl, StructDecl) and decl.name != main_struct.name:
                struct_fields: list[dict[str, Any]] = []
                for stmt in decl.body:
                    struct_fields.extend(self._gen_field(stmt))
                types[decl.name] = {"kind": "struct", "fields": struct_fields}
            elif isinstance(decl, UnionDecl):
                union_fields: list[dict[str, Any]] = []
                for stmt in decl.body:
                    union_fields.extend(self._gen_field(stmt))
                types[decl.name] = {"kind": "union", "fields": union_fields}
            elif isinstance(decl, EnumDecl):
                backing = self._gen_type(decl.backing_type)
                types[decl.name] = {
                    "kind": "enum",
                    "backing_type": backing,
                    "values": self._gen_enum_values(decl.entries),
                }
            elif isinstance(decl, BitfieldDecl):
                types[decl.name] = {
                    "kind": "bitfield",
                    "fields": self._gen_bitfield_entries(decl.entries),
                }

        endian_value: str = self._pragma.endian if self._pragma.endian in {"little", "big"} else "little"
        description: str = self._pragma.description or f"{main_struct.name} (compiled from HexPat DSL)"

        result: dict[str, Any] = {
            "name": main_struct.name,
            "description": description,
            "default_endianness": endian_value,
            "fields": fields,
        }

        if self._pragma.author:
            result["author"] = self._pragma.author

        if self._pragma.magic:
            offset_val, magic_bytes = self._pragma.magic[0]
            result["magic_detection"] = {
                "offset": offset_val,
                "bytes": list(magic_bytes),
            }

        default_pragma = PragmaInfo()
        pragma_metadata: dict[str, Any] = {}
        if self._pragma.base_address != default_pragma.base_address:
            pragma_metadata["base_address"] = self._pragma.base_address
        if self._pragma.bitfield_order != default_pragma.bitfield_order:
            pragma_metadata["bitfield_order"] = self._pragma.bitfield_order
        if self._pragma.mime != default_pragma.mime:
            pragma_metadata["mime"] = self._pragma.mime
        if self._pragma.pointer_size != default_pragma.pointer_size:
            pragma_metadata["pointer_size"] = self._pragma.pointer_size
        if pragma_metadata:
            result["pragma_metadata"] = pragma_metadata

        if types:
            result["types"] = types
        return result

    def _gen_enum_values(
        self,
        entries: tuple[EnumEntry, ...],
    ) -> list[tuple[str, int]]:
        """Compute concrete integer values for enum entries.

        Auto-incrementing semantics match the original HexPat compiler:
        explicit ``= value`` resets the counter; subsequent entries are
        emitted with the previous counter incremented by one. If an entry
        value is not a compile-time integer constant,
        :meth:`_eval_const_expr` raises :class:`HexPatError`.

        Args:
            entries: Tuple of enum entries from an :class:`EnumDecl`.

        Returns:
            list[tuple[str, int]]: List of ``(name, value)`` pairs ready
            for JSON emission.
        """
        result: list[tuple[str, int]] = []
        counter = 0
        for entry in entries:
            if entry.value is not None:
                counter = self._eval_const_expr(entry.value)
            result.append((entry.name, counter))
            counter += 1
        return result

    @staticmethod
    def _gen_bitfield_entries(
        entries: tuple[BitfieldEntry, ...],
    ) -> list[tuple[str, int]]:
        """Convert bitfield AST entries into ``(name, width)`` JSON pairs.

        If a bitfield width expression is not a compile-time integer
        constant, :meth:`_eval_const_expr` raises :class:`HexPatError`.

        Args:
            entries: Tuple of bitfield entries from a :class:`BitfieldDecl`.

        Returns:
            list[tuple[str, int]]: List of ``(name, width)`` pairs.
        """
        result: list[tuple[str, int]] = []
        for entry in entries:
            width = HexPatCodegen._eval_const_expr(entry.width)
            result.append((entry.name, width))
        return result

    def _gen_field(self, node: StmtNode) -> list[dict[str, Any]]:
        """Generate field definition dicts from a struct/union body statement.

        Conditionals may produce multiple fields (if + else branches).

        Args:
            node: An AST statement node from a struct or union body.

        Returns:
            list[dict[str, Any]]: List of JSON field definitions.

        Raises:
            HexPatError: If the node is a runtime-only construct that has
                no static JSON representation.
        """
        if isinstance(node, ConditionalField):
            return self._gen_conditional(node)
        if isinstance(node, FieldDecl):
            return [self._gen_regular_field(node)]
        if isinstance(node, _RUNTIME_STMT_TYPES):
            label = _RUNTIME_STMT_LABELS[type(node)]
            msg = (
                f"'{label}' is a runtime construct that cannot be compiled "
                f"to a static JSON template; use the HexPat interpreter "
                f"for patterns containing {label} statements"
            )
            line = getattr(node, "line", 0)
            column = getattr(node, "column", 0)
            raise HexPatError(msg, line, column)
        if isinstance(node, PlacementStmt):
            msg = "top-level placement statements are not supported inside a struct/union body when compiling to JSON"
            line = getattr(node, "line", 0)
            column = getattr(node, "column", 0)
            raise HexPatError(msg, line, column)
        msg = f"unsupported AST node '{type(node).__name__}' in struct body"
        line = getattr(node, "line", 0)
        column = getattr(node, "column", 0)
        raise HexPatError(msg, line, column)

    def _gen_regular_field(self, node: FieldDecl) -> dict[str, Any]:
        """Generate a regular field definition dict.

        Args:
            node: Field AST node.

        Returns:
            dict[str, Any]: JSON field definition.

        Raises:
            HexPatError: If a constituent expression cannot be evaluated at
                compile time.
        """
        type_node = node.type_node
        array_size_expr = node.array_size
        while_condition_expr = node.while_condition

        if while_condition_expr is not None:
            msg = "while-conditioned arrays are runtime constructs and cannot be compiled to a static JSON template"
            raise HexPatError(msg, node.line, node.column)

        if isinstance(type_node, ArrayType):
            if type_node.while_condition is not None:
                msg = "while-conditioned arrays are runtime constructs and cannot be compiled to a static JSON template"
                raise HexPatError(msg, node.line, node.column)
            array_size_expr = type_node.size
            type_node = type_node.element

        field_type = self._gen_type(type_node)

        if node.is_pointer or isinstance(type_node, PointerType):
            pointee = type_node.pointee if isinstance(type_node, PointerType) else type_node
            if isinstance(pointee, NamedType):
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
        elif array_size_expr is not None:
            if isinstance(array_size_expr, NumberLiteral):
                field_type = {
                    "type": "Array",
                    "params": {
                        "element_type": field_type,
                        "count": array_size_expr.value,
                    },
                }
            elif isinstance(array_size_expr, IdentifierExpr):
                field_type = {
                    "type": "DynamicArray",
                    "params": {
                        "element_type": field_type,
                        "count_field": array_size_expr.name,
                    },
                }
            else:
                field_type = {
                    "type": "Array",
                    "params": {
                        "element_type": field_type,
                        "count": self._eval_const_expr(array_size_expr),
                    },
                }

        result: dict[str, Any] = {
            "name": node.name,
            "field_type": field_type,
            "description": "",
        }

        endianness = self._resolve_endianness(node)
        if endianness is not None:
            result["endianness"] = endianness

        validation: dict[str, Any] = {}
        for key, expr in node.annotations:
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

    @staticmethod
    def _resolve_endianness(node: FieldDecl) -> str | None:
        """Resolve the endianness keyword for a field into the JSON form.

        Endianness may appear on the FieldDecl itself (via a leading
        ``le``/``be`` token), or carried along on the underlying type when
        the parser folds the prefix into a :class:`PrimitiveType`,
        :class:`ArrayType`, or :class:`PointerType`.

        Args:
            node: The field declaration node.

        Returns:
            str | None: ``"little"`` or ``"big"`` when an endianness
            specifier was present, otherwise ``None``.
        """
        keyword = node.endianness or getattr(node.type_node, "endianness", None)
        if keyword is None:
            return None
        return _ENDIANNESS_MAP.get(keyword.lower())

    def _gen_conditional(self, node: ConditionalField) -> list[dict[str, Any]]:
        """Generate conditional field definition dicts.

        For ``if``/``else`` constructs, emits the true-branch as a
        ``Conditional`` field. If ``false_fields`` is non-empty, emits a
        second ``Conditional`` with an inverted comparison so the two
        emitted ``Conditional`` instructions partition the space of the
        original predicate exactly.

        The Rust runtime exposes a dedicated :code:`BitAndZero` opcode whose
        semantics are :code:`(field & mask) == 0`, the natural inverse of
        :code:`BitAnd` (:code:`(field & mask) != 0`). Bit-mask ``if``/``else``
        pairs are therefore lowered to :code:`BitAnd` for the true-branch and
        :code:`BitAndZero` for the else-branch, preserving the user's
        intended semantics for arbitrary payload bits.

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
            condition_op = _COMPARISON_OP_MAP.get(node.condition.op, "Eq")
        elif isinstance(node.condition, IdentifierExpr):
            condition_field = node.condition.name
            condition_value = 0
            condition_op = "Ne"

        true_inner: list[dict[str, Any]] = []
        for stmt in node.true_fields:
            true_inner.extend(self._gen_field(stmt))

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
            inverted_op = _INVERT_OP_MAP.get(condition_op, "Ne")

            else_inner: list[dict[str, Any]] = []
            for stmt in node.false_fields:
                else_inner.extend(self._gen_field(stmt))

            results.append({
                "name": f"_else_{condition_field}",
                "field_type": {
                    "type": "Conditional",
                    "params": {
                        "condition_field": condition_field,
                        "condition_value": condition_value,
                        "condition_op": inverted_op,
                        "fields": else_inner,
                    },
                },
                "description": "",
            })

        return results

    def _gen_type(self, type_node: TypeNode) -> dict[str, Any]:
        """Generate a JSON field type from a type AST node.

        Args:
            type_node: Type AST node.

        Returns:
            dict[str, Any]: JSON field type.

        Raises:
            HexPatError: If the type cannot be expressed in the static JSON
                template (e.g. ``auto`` types, while-conditioned arrays).
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
        if isinstance(type_node, ArrayType):
            if type_node.while_condition is not None:
                msg = "while-conditioned arrays are runtime constructs and cannot be compiled to a static JSON template"
                raise HexPatError(msg, type_node.line, type_node.column)
            element = self._gen_type(type_node.element)
            if type_node.size is None:
                msg = "array type missing a compile-time size"
                raise HexPatError(msg, type_node.line, type_node.column)
            count = self._eval_const_expr(type_node.size)
            return {
                "type": "Array",
                "params": {"element_type": element, "count": count},
            }
        if isinstance(type_node, AutoType):
            msg = "'auto' types cannot be resolved at compile time; use the HexPat interpreter for patterns relying on type inference"
            raise HexPatError(msg, type_node.line, type_node.column)
        if type_node.name in self._nested_enums:
            enum_decl = self._nested_enums[type_node.name]
            backing = self._gen_type(enum_decl.backing_type)
            return {
                "type": "Enum",
                "params": {
                    "backing_type": backing,
                    "values": self._gen_enum_values(enum_decl.entries),
                },
            }
        return {"type": "StructRef", "params": type_node.name}

    @staticmethod
    def _eval_const_expr(expr: ExprNode) -> int:
        """Evaluate a constant expression at compile time.

        Only pure-constant integer expressions built from numeric literals,
        the unary minus operator, and the arithmetic binary operators
        (``+``, ``-``, ``*``, ``/``, ``%``) are supported. Runtime-evaluated
        forms such as identifiers, ``sizeof``/``addressof``, the current
        offset marker, shift operators, and bitwise operators are deferred
        to the interpreter and therefore rejected here rather than being
        silently folded to zero.

        Args:
            expr: Expression node to evaluate.

        Returns:
            int: Evaluated integer value.

        Raises:
            HexPatError: If the expression is not a supported compile-time
                constant or if a division or modulo by zero is encountered.
        """
        if isinstance(expr, NumberLiteral):
            return expr.value
        if isinstance(expr, BoolLiteral):
            return 1 if expr.value else 0
        if isinstance(expr, CharLiteral):
            return ord(expr.value) if expr.value else 0
        if isinstance(expr, UnaryExpr):
            if expr.op == "-":
                return -HexPatCodegen._eval_const_expr(expr.operand)
            msg = f"unary operator '{expr.op}' is not a compile-time constant expression"
            raise HexPatError(msg, expr.line, expr.column)
        if isinstance(expr, BinaryExpr):
            left = HexPatCodegen._eval_const_expr(expr.left)
            right = HexPatCodegen._eval_const_expr(expr.right)
            if expr.op == "+":
                return left + right
            if expr.op == "-":
                return left - right
            if expr.op == "*":
                return left * right
            if expr.op == "/":
                if right == 0:
                    msg = "division by zero in constant expression"
                    raise HexPatError(msg, expr.line, expr.column)
                return left // right
            if expr.op == "%":
                if right == 0:
                    msg = "modulo by zero in constant expression"
                    raise HexPatError(msg, expr.line, expr.column)
                return left % right
            msg = f"binary operator '{expr.op}' is not a compile-time constant expression"
            raise HexPatError(msg, expr.line, expr.column)
        if isinstance(expr, IdentifierExpr):
            msg = f"identifier '{expr.name}' cannot be resolved at compile time; use a numeric literal"
            raise HexPatError(msg, expr.line, expr.column)
        if isinstance(expr, SizeofExpr):
            target_repr = getattr(expr.target, "name", type(expr.target).__name__)
            msg = f"sizeof({target_repr}) is not a compile-time constant expression"
            raise HexPatError(msg, expr.line, expr.column)
        if isinstance(expr, AddressOfExpr):
            target_repr = getattr(expr.target, "name", type(expr.target).__name__)
            msg = f"addressof({target_repr}) is not a compile-time constant expression"
            raise HexPatError(msg, expr.line, expr.column)
        if isinstance(expr, TypeNameOfExpr):
            msg = "typenameof(...) is not a compile-time constant expression"
            raise HexPatError(msg, expr.line, expr.column)
        if isinstance(expr, DollarExpr):
            msg = "current-offset marker '$' is not a compile-time constant expression"
            raise HexPatError(msg, expr.line, expr.column)
        if isinstance(expr, FloatLiteral):
            msg = "float literal cannot be used where an integer constant is required"
            raise HexPatError(msg, expr.line, expr.column)
        if isinstance(expr, StringLiteral):
            msg = "string literal cannot be used where an integer constant is required"
            raise HexPatError(msg, expr.line, expr.column)
        if isinstance(expr, NullLiteral):
            msg = "null literal cannot be used where an integer constant is required"
            raise HexPatError(msg, expr.line, expr.column)
        label = type(expr).__name__
        msg = f"{label} is not a compile-time constant expression"
        raise HexPatError(msg, expr.line, expr.column)


class HexPatCompiler:
    """Compiles HexPat DSL source code into JSON template definitions.

    Orchestrates the lexer, parser, and codegen pipeline. Lexing and
    parsing are delegated to the canonical implementations in
    ``intellicrack.core.hexpat``; this class adds AST-walk validation and
    the static JSON code generator.
    """

    @staticmethod
    def compile(source: str) -> str:
        """Compile DSL source to a JSON string.

        On lexing, parsing, or code-generation failure,
        :meth:`compile_to_dict` raises :class:`HexPatError`.

        Args:
            source: HexPat DSL source code.

        Returns:
            str: JSON template definition string.
        """
        result = HexPatCompiler.compile_to_dict(source)
        return json.dumps(result, indent=2)

    @staticmethod
    def compile_to_dict(source: str) -> dict[str, Any]:
        """Compile DSL source to a Python dict.

        Runs the full preprocessor on ``source`` so that ``#pragma`` directives
        (``endian``, ``base_address``, ``bitfield_order``, ``author``,
        ``description``, ``magic``, ``mime``, ``pointer_size``) are honoured by
        the generated static template. Without this step the codegen would
        silently fall back to inert defaults (``little`` endian, generic
        description, no magic detection), which the audit identified as a
        codegen-behaviour drift.

        Args:
            source: HexPat DSL source code.

        Returns:
            dict[str, Any]: JSON-compatible template definition dict.

        Raises:
            HexPatError: If preprocessing, lexing, parsing, or code generation
                fails.
        """
        preprocessor = HexPatPreprocessor()
        try:
            processed_source, pragma = preprocessor.process(source)
        except HexPatError as exc:
            _logger.exception("hexpat_compile_preprocess_failed", file=exc.file, line=exc.line)
            raise HexPatError(exc.message, exc.line, exc.column, exc.file) from exc

        lexer = HexPatLexer(processed_source)
        tokens = lexer.tokenize()
        parser = HexPatParser(tokens)
        try:
            declarations = parser.parse()
        except HexPatParseError as exc:
            _logger.exception("hexpat_compile_parse_failed", file=exc.file, line=exc.line)
            raise HexPatError(exc.message, exc.line, exc.column, exc.file) from exc
        codegen = HexPatCodegen(list(declarations), pragma=pragma)
        result = codegen.generate()
        _logger.debug(
            "hexpat_compiled",
            template_name=result.get("name", ""),
            pragma_endian=pragma.endian,
            pragma_base_address=pragma.base_address,
        )
        return result
