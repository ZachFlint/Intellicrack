# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
# This file is part of Intellicrack. See LICENSE for details.
"""AST node dataclasses for the HexPat .hexpat pattern language parser."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NumberLiteral:
    """An integer literal expression node.

    Attributes:
        value: The integer value of the literal.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    value: int
    line: int
    column: int


@dataclass(frozen=True)
class FloatLiteral:
    """A floating-point literal expression node.

    Attributes:
        value: The float value of the literal.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    value: float
    line: int
    column: int


@dataclass(frozen=True)
class StringLiteral:
    """A string literal expression node.

    Attributes:
        value: The string value of the literal.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    value: str
    line: int
    column: int


@dataclass(frozen=True)
class CharLiteral:
    """A single-character literal expression node.

    Attributes:
        value: The single-character string value.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    value: str
    line: int
    column: int


@dataclass(frozen=True)
class BoolLiteral:
    """A boolean literal expression node.

    Attributes:
        value: The boolean value of the literal.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    value: bool
    line: int
    column: int


@dataclass(frozen=True)
class NullLiteral:
    """A null literal expression node representing the null value.

    Attributes:
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    line: int
    column: int


@dataclass(frozen=True)
class IdentifierExpr:
    """An identifier reference expression node.

    Attributes:
        name: The identifier name.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    name: str
    line: int
    column: int


@dataclass(frozen=True)
class DollarExpr:
    """A dollar-sign expression node representing the current binary offset.

    Attributes:
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    line: int
    column: int


@dataclass(frozen=True)
class SizeofExpr:
    """A sizeof expression node that evaluates the size of a type or expression.

    Attributes:
        target: The expression or type whose size is evaluated.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    target: ExprNode | TypeNode
    line: int
    column: int


@dataclass(frozen=True)
class AddressOfExpr:
    """An address-of expression node that yields the address of an expression.

    Attributes:
        target: The expression whose address is taken.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    target: ExprNode
    line: int
    column: int


@dataclass(frozen=True)
class TypeNameOfExpr:
    """A type-name-of expression node that yields the type name of an expression.

    Attributes:
        target: The expression whose type name is retrieved.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    target: ExprNode
    line: int
    column: int


@dataclass(frozen=True)
class BinaryExpr:
    """A binary operation expression node.

    Attributes:
        op: The operator string (e.g., "+", "-", "==", "&&").
        left: The left-hand side expression operand.
        right: The right-hand side expression operand.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    op: str
    left: ExprNode
    right: ExprNode
    line: int
    column: int


@dataclass(frozen=True)
class UnaryExpr:
    """A unary operation expression node.

    Attributes:
        op: The operator string (e.g., "-", "!", "~").
        operand: The expression operand.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    op: str
    operand: ExprNode
    line: int
    column: int


@dataclass(frozen=True)
class TernaryExpr:
    """A ternary conditional expression node (condition ? true_expr : false_expr).

    Attributes:
        condition: The boolean condition expression.
        true_expr: The expression evaluated when condition is true.
        false_expr: The expression evaluated when condition is false.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    condition: ExprNode
    true_expr: ExprNode
    false_expr: ExprNode
    line: int
    column: int


@dataclass(frozen=True)
class FunctionCallExpr:
    """A function call expression node.

    Attributes:
        callee: The expression that resolves to the callable.
        arguments: The tuple of argument expressions passed to the function.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    callee: ExprNode
    arguments: tuple[ExprNode, ...]
    line: int
    column: int


@dataclass(frozen=True)
class MemberAccessExpr:
    """A member access expression node (e.g., object.member).

    Attributes:
        object_expr: The expression representing the object being accessed.
        member: The name of the member being accessed.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    object_expr: ExprNode
    member: str
    line: int
    column: int


@dataclass(frozen=True)
class NamespaceAccessExpr:
    """A namespace-qualified member access expression node (e.g., ns::member).

    Attributes:
        namespace: The expression representing the namespace.
        member: The name of the member within the namespace.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    namespace: ExprNode
    member: str
    line: int
    column: int


@dataclass(frozen=True)
class ArraySubscriptExpr:
    """An array subscript expression node (e.g., array[index]).

    Attributes:
        array: The array expression being subscripted.
        index: The index expression.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    array: ExprNode
    index: ExprNode
    line: int
    column: int


@dataclass(frozen=True)
class CastExpr:
    """A type cast expression node.

    Attributes:
        target_type: The type to cast to.
        expr: The expression being cast.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    target_type: TypeNode
    expr: ExprNode
    line: int
    column: int


@dataclass(frozen=True)
class AssignExpr:
    """An assignment expression node (e.g., target = value, target += value).

    Attributes:
        target: The expression being assigned to.
        op: The assignment operator string (e.g., "=", "+=", "-=").
        value: The expression whose value is assigned.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    target: ExprNode
    op: str
    value: ExprNode
    line: int
    column: int


@dataclass(frozen=True)
class PrimitiveType:
    """A primitive built-in type node (e.g., u8, s32, float, bool).

    Attributes:
        name: The primitive type name such as "u8", "s32", "float", or "bool".
        endianness: Optional endianness specifier ("le", "be", or None for default).
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    name: str
    endianness: str | None
    line: int
    column: int


@dataclass(frozen=True)
class NamedType:
    """A user-defined named type reference node.

    Attributes:
        name: The type name identifier.
        namespace: Optional namespace qualifier for the type.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
        endianness: Optional endianness specifier ("le", "be", or None) applied to the reference.
        template_args: Tuple of template argument expressions supplied at instantiation.
    """

    name: str
    namespace: str | None
    line: int
    column: int
    endianness: str | None = None
    template_args: tuple[ExprNode, ...] = ()


@dataclass(frozen=True)
class PointerType:
    """A pointer type node referencing another type.

    Attributes:
        pointee: The type that this pointer points to.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
        endianness: Optional endianness specifier ("le", "be", or None) applied to the pointer.
    """

    pointee: TypeNode
    line: int
    column: int
    endianness: str | None = None


@dataclass(frozen=True)
class ArrayType:
    """An array type node with optional fixed size or while-condition for dynamic arrays.

    Attributes:
        element: The element type of the array.
        size: Optional expression specifying the number of elements.
        while_condition: Optional expression used for while-loop array sizing.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
        endianness: Optional endianness specifier ("le", "be", or None) applied to the array.
    """

    element: TypeNode
    size: ExprNode | None
    while_condition: ExprNode | None
    line: int
    column: int
    endianness: str | None = None


@dataclass(frozen=True)
class PaddingType:
    """A padding type node representing a fixed-size gap in a structure layout.

    Attributes:
        size: The expression determining the padding size in bytes.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    size: ExprNode
    line: int
    column: int


@dataclass(frozen=True)
class AutoType:
    """An auto type node indicating that the type should be inferred.

    Attributes:
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    line: int
    column: int


@dataclass(frozen=True)
class FieldDecl:
    """A field declaration statement node within a struct or union body.

    Attributes:
        name: The field name identifier.
        type_node: The type of the field.
        array_size: Optional expression for fixed-size array fields.
        while_condition: Optional expression for dynamic while-loop array fields.
        at_offset: Optional expression specifying an explicit placement offset.
        is_pointer: Whether this field is declared as a pointer.
        annotations: Tuple of name-value pairs representing field attributes.
        endianness: Optional endianness override for this field.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    name: str
    type_node: TypeNode
    array_size: ExprNode | None
    while_condition: ExprNode | None
    at_offset: ExprNode | None
    is_pointer: bool
    annotations: tuple[tuple[str, ExprNode | None], ...]
    endianness: str | None
    line: int
    column: int


@dataclass(frozen=True)
class ConditionalField:
    """A conditional field statement node (if/else branching inside a struct body).

    Attributes:
        condition: The boolean condition expression.
        true_fields: The statements included when condition is true.
        false_fields: The statements included when condition is false.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    condition: ExprNode
    true_fields: tuple[StmtNode, ...]
    false_fields: tuple[StmtNode, ...]
    line: int
    column: int


@dataclass(frozen=True)
class VarDecl:
    """A variable declaration statement node.

    Attributes:
        name: The variable name identifier.
        type_node: Optional explicit type annotation for the variable.
        initializer: Optional initializer expression.
        is_const: Whether this variable is declared as a constant.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    name: str
    type_node: TypeNode | None
    initializer: ExprNode | None
    is_const: bool
    line: int
    column: int


@dataclass(frozen=True)
class ReturnStmt:
    """A return statement node.

    Attributes:
        value: The optional expression whose value is returned.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    value: ExprNode | None
    line: int
    column: int


@dataclass(frozen=True)
class BreakStmt:
    """A break statement node that exits the innermost loop or match.

    Attributes:
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    line: int
    column: int


@dataclass(frozen=True)
class ContinueStmt:
    """A continue statement node that skips to the next iteration of the innermost loop.

    Attributes:
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    line: int
    column: int


@dataclass(frozen=True)
class WhileStmt:
    """A while loop statement node.

    Attributes:
        condition: The loop continuation condition expression.
        body: The sequence of statements forming the loop body.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    condition: ExprNode
    body: tuple[StmtNode, ...]
    line: int
    column: int


@dataclass(frozen=True)
class ForStmt:
    """A for loop statement node.

    Attributes:
        init: Optional initialization statement executed before the loop.
        condition: Optional loop continuation condition expression.
        update: Optional update expression evaluated after each iteration.
        body: The sequence of statements forming the loop body.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    init: StmtNode | None
    condition: ExprNode | None
    update: ExprNode | None
    body: tuple[StmtNode, ...]
    line: int
    column: int


@dataclass(frozen=True)
class MatchArm:
    """A single arm of a match statement, associating patterns with a body.

    Attributes:
        patterns: The tuple of expressions used as match patterns.
        is_wildcard: Whether this arm is the default wildcard catch-all case.
        body: The sequence of statements executed when this arm matches.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    patterns: tuple[ExprNode, ...]
    is_wildcard: bool
    body: tuple[StmtNode, ...]
    line: int
    column: int


@dataclass(frozen=True)
class MatchStmt:
    """A match statement node that dispatches control based on a value.

    Attributes:
        value: The expression whose value is matched against the arms.
        arms: The ordered tuple of match arms to test against.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    value: ExprNode
    arms: tuple[MatchArm, ...]
    line: int
    column: int


@dataclass(frozen=True)
class TryStmt:
    """A try/catch statement node for error handling.

    Attributes:
        try_body: The statements in the try block.
        catch_body: The statements in the catch block executed on error.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    try_body: tuple[StmtNode, ...]
    catch_body: tuple[StmtNode, ...]
    line: int
    column: int


@dataclass(frozen=True)
class ExprStmt:
    """An expression used as a statement node.

    Attributes:
        expr: The expression evaluated for its side effects.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    expr: ExprNode
    line: int
    column: int


@dataclass(frozen=True)
class PlacementStmt:
    """A placement statement node that places a typed field at an explicit address.

    Attributes:
        type_node: The type being placed in memory.
        name: The name assigned to the placed field.
        at_offset: Optional explicit offset expression for the placement.
        annotations: Tuple of name-value pairs representing placement attributes.
        in_section: Optional expression naming the section the placement belongs to.
        array_size: Optional expression giving the fixed array length.
        while_condition: Optional expression for a while-terminated array.
        is_pointer: Whether the placed field is a pointer (``Type *name``)
            whose stored integer addresses a dereferenced pointee.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    type_node: TypeNode
    name: str
    at_offset: ExprNode | None
    annotations: tuple[tuple[str, ExprNode | None], ...]
    in_section: ExprNode | None
    array_size: ExprNode | None
    while_condition: ExprNode | None
    is_pointer: bool
    line: int
    column: int


@dataclass(frozen=True)
class FunctionParam:
    """A single parameter in a function declaration.

    Attributes:
        name: The parameter name identifier.
        type_node: The declared type of the parameter.
        is_ref: Whether this parameter is passed by reference.
        default_value: Optional default value expression for this parameter.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
        is_varargs: Whether this parameter is a variadic (``...``) trailing parameter.
    """

    name: str
    type_node: TypeNode
    is_ref: bool
    default_value: ExprNode | None
    line: int
    column: int
    is_varargs: bool = False


@dataclass(frozen=True)
class TemplateParam:
    """A single template parameter declared on a generic struct or using alias.

    Attributes:
        name: The template parameter identifier.
        is_auto: Whether the parameter is declared with the ``auto`` keyword.
        type_hint: Optional non-``auto`` type-name hint preceding the parameter name.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    name: str
    is_auto: bool
    type_hint: str | None
    line: int
    column: int


@dataclass(frozen=True)
class StructDecl:
    """A struct declaration node defining a composite binary layout type.

    Attributes:
        name: The struct type name identifier.
        parent: Optional name of the parent struct this struct inherits from.
        body: The ordered tuple of field statements in the struct body.
        annotations: Tuple of name-value pairs representing struct attributes.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
        template_params: Tuple of template parameters declared on the struct.
    """

    name: str
    parent: str | None
    body: tuple[StmtNode, ...]
    annotations: tuple[tuple[str, ExprNode | None], ...]
    line: int
    column: int
    template_params: tuple[TemplateParam, ...] = ()


@dataclass(frozen=True)
class UnionDecl:
    """A union declaration node defining overlapping binary layout alternatives.

    Attributes:
        name: The union type name identifier.
        body: The ordered tuple of field statements in the union body.
        annotations: Tuple of name-value pairs representing union attributes.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    name: str
    body: tuple[StmtNode, ...]
    annotations: tuple[tuple[str, ExprNode | None], ...]
    line: int
    column: int


@dataclass(frozen=True)
class EnumEntry:
    """A single entry within an enum declaration.

    Attributes:
        name: The enum entry name identifier.
        value: Optional expression specifying an explicit numeric value for this entry.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
        value_end: Optional upper-bound expression when the entry declares an inclusive range.
    """

    name: str
    value: ExprNode | None
    line: int
    column: int
    value_end: ExprNode | None = None


@dataclass(frozen=True)
class EnumDecl:
    """An enum declaration node defining a set of named constants.

    Attributes:
        name: The enum type name identifier.
        backing_type: The underlying primitive type that stores enum values.
        entries: The ordered tuple of enum entries.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
        annotations: Tuple of name-value pairs representing enum attributes.
    """

    name: str
    backing_type: TypeNode
    entries: tuple[EnumEntry, ...]
    line: int
    column: int
    annotations: tuple[tuple[str, ExprNode | None], ...] = ()


@dataclass(frozen=True)
class BitfieldEntry:
    """A single bit-width entry within a bitfield declaration.

    Attributes:
        name: The bitfield entry name identifier.
        width: The expression specifying the number of bits for this entry.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
        type_hint: Optional storage or signedness hint (e.g. ``signed``, ``unsigned``, ``u8``).
        is_padding: Whether this entry is an anonymous ``padding`` bitfield entry.
    """

    name: str
    width: ExprNode
    line: int
    column: int
    type_hint: str | None = None
    is_padding: bool = False


@dataclass(frozen=True)
class BitfieldDecl:
    """A bitfield declaration node defining bit-packed fields within an integer.

    Attributes:
        name: The bitfield type name identifier.
        entries: The ordered tuple of bit-width entries.
        annotations: Tuple of name-value pairs representing bitfield attributes.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    name: str
    entries: tuple[BitfieldEntry, ...]
    annotations: tuple[tuple[str, ExprNode | None], ...]
    line: int
    column: int


@dataclass(frozen=True)
class FunctionDecl:
    """A function declaration node defining a callable pattern function.

    Attributes:
        name: The function name identifier.
        params: The ordered tuple of function parameters.
        return_type: Optional declared return type of the function.
        body: The sequence of statements forming the function body.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    name: str
    params: tuple[FunctionParam, ...]
    return_type: TypeNode | None
    body: tuple[StmtNode, ...]
    line: int
    column: int


@dataclass(frozen=True)
class NamespaceDecl:
    """A namespace declaration node grouping related declarations under a qualified name.

    Attributes:
        name: The namespace identifier.
        body: The ordered tuple of declarations within the namespace.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
    """

    name: str
    body: tuple[DeclNode, ...]
    line: int
    column: int


@dataclass(frozen=True)
class UsingDecl:
    """A using declaration node that creates a type alias.

    Attributes:
        alias: The new type alias name.
        target: The type that the alias refers to.
        line: Source line number where this node appears.
        column: Source column number where this node appears.
        template_params: Tuple of template parameters declared on the alias.
    """

    alias: str
    target: TypeNode
    line: int
    column: int
    template_params: tuple[TemplateParam, ...] = ()


type ExprNode = (
    NumberLiteral
    | FloatLiteral
    | StringLiteral
    | CharLiteral
    | BoolLiteral
    | NullLiteral
    | IdentifierExpr
    | DollarExpr
    | SizeofExpr
    | AddressOfExpr
    | TypeNameOfExpr
    | BinaryExpr
    | UnaryExpr
    | TernaryExpr
    | FunctionCallExpr
    | MemberAccessExpr
    | NamespaceAccessExpr
    | ArraySubscriptExpr
    | CastExpr
    | AssignExpr
)

type TypeNode = PrimitiveType | NamedType | PointerType | ArrayType | PaddingType | AutoType

type StmtNode = (
    FieldDecl
    | ConditionalField
    | VarDecl
    | ReturnStmt
    | BreakStmt
    | ContinueStmt
    | WhileStmt
    | ForStmt
    | MatchStmt
    | TryStmt
    | ExprStmt
    | PlacementStmt
)

type DeclNode = StructDecl | UnionDecl | EnumDecl | BitfieldDecl | FunctionDecl | NamespaceDecl | UsingDecl
