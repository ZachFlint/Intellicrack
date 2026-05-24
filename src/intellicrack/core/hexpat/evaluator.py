# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
# This file is part of Intellicrack. See LICENSE for details.
"""Core tree-walking evaluator for the HexPat .hexpat pattern language."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Literal,
    cast as _cast,
)

from intellicrack.core.hexpat.ast_nodes import (
    AddressOfExpr,
    ArraySubscriptExpr,
    ArrayType,
    AssignExpr,
    AutoType,
    BinaryExpr,
    BitfieldDecl,
    BoolLiteral,
    BreakStmt,
    CastExpr,
    CharLiteral,
    ConditionalField,
    DollarExpr,
    EnumDecl,
    ExprStmt,
    FieldDecl,
    FloatLiteral,
    ForStmt,
    FunctionCallExpr,
    FunctionDecl,
    IdentifierExpr,
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
from intellicrack.core.hexpat.errors import HexPatRuntimeError, HexPatTypeError
from intellicrack.core.hexpat.type_system import (
    BitfieldTypeInfo,
    BuiltinTypes,
    EnumTypeInfo,
    HexPatType,
    StructTypeInfo,
    UnionTypeInfo,
)
from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any, ClassVar

    from intellicrack.core.hexpat._pragma import PragmaInfo
    from intellicrack.core.hexpat.ast_nodes import DeclNode, ExprNode, StmtNode, TypeNode
    from intellicrack.core.hexpat.data_reader import DataReader
    from intellicrack.core.hexpat.type_system import TypeRegistry


_logger = get_logger(__name__)


class _BreakSignalError(Exception):
    """Internal control-flow error raised by a break statement."""


class _ContinueSignalError(Exception):
    """Internal control-flow error raised by a continue statement."""


class _ReturnSignalError(Exception):
    """Internal control-flow error raised by a return statement."""

    def __init__(self, value: PatternValue) -> None:
        """Initialize the _ReturnSignalError with the returned value.

        Args:
            value: The PatternValue being returned from the function.
        """
        super().__init__()
        self.value: PatternValue = value


_PrimValue = int | float | str | bytes | bool | None


@dataclass
class BuiltinCallable:
    """Wrapper for a built-in Python callable stored as a PatternValue.

    Attributes:
        fn: The underlying Python callable accepting PatternValue arguments.
        name: The name of the built-in function.
    """

    fn: Callable[..., PatternValue]
    name: str


@dataclass
class _EvaluatorReflectionProvider:
    """Concrete reflection provider exposing :class:`HexPatEvaluator` state.

    The dataclass mirrors the optional callable-field protocol consumed by
    :mod:`intellicrack.core.hexpat.stdlib`. Splitting this provider into the
    evaluator module avoids a circular import between the evaluator and the
    stdlib while still letting the interpreter wire reflection at runtime.

    Attributes:
        has_attribute: Callback answering ``std::core::has_attribute``.
        get_attribute_argument: Callback answering ``std::core::get_attribute_argument``.
        member_count: Callback answering ``std::core::member_count``.
        has_member: Callback answering ``std::core::has_member``.
        formatted_value: Callback answering ``std::core::formatted_value``.
        is_valid_enum: Callback answering ``std::core::is_valid_enum``.
        set_pattern_color: Callback implementing ``std::core::set_pattern_color``.
        set_display_name: Callback implementing ``std::core::set_display_name``.
        set_pattern_comment: Callback implementing ``std::core::set_pattern_comment``.
        set_pattern_palette_colors: Callback implementing ``std::core::set_pattern_palette_colors``.
        reset_pattern_palette: Callback implementing ``std::core::reset_pattern_palette``.
        execute_function: Callback dispatching ``std::core::execute_function``.
    """

    has_attribute: Callable[[PatternValue, str], bool]
    get_attribute_argument: Callable[[PatternValue, str, int], PatternValue]
    member_count: Callable[[PatternValue], int]
    has_member: Callable[[PatternValue, str], bool]
    formatted_value: Callable[[PatternValue], str]
    is_valid_enum: Callable[[PatternValue], bool]
    set_pattern_color: Callable[[PatternValue, int], None]
    set_display_name: Callable[[PatternValue, str], None]
    set_pattern_comment: Callable[[PatternValue, str], None]
    set_pattern_palette_colors: Callable[[list[int]], None]
    reset_pattern_palette: Callable[[], None]
    execute_function: Callable[[str, list[PatternValue]], PatternValue]


@dataclass
class PatternValue:
    """A runtime value produced during pattern evaluation.

    Attributes:
        value: The underlying runtime value — either a primitive, a user-defined
            function AST node, or a built-in callable wrapper.
        type_info: Optional resolved primitive type for this value.
        offset: Byte offset in the data source where this value was read.
        size: Number of bytes consumed by this value.
        members: Named child values for struct/union instances.
    """

    value: _PrimValue | FunctionDecl | BuiltinCallable
    type_info: HexPatType | None = None
    offset: int = 0
    size: int = 0
    members: dict[str, PatternValue] = field(default_factory=dict)


class EvalScope:
    """Lexical scope with parent-chain variable resolution."""

    def __init__(self, parent: EvalScope | None = None) -> None:
        """Initialize the EvalScope with an optional parent scope.

        Args:
            parent: The enclosing parent scope, or None for root scope.
        """
        self._bindings: dict[str, PatternValue] = {}
        self._parent: EvalScope | None = parent

    def get(self, name: str) -> PatternValue | None:
        """Look up a variable by name, searching parent scopes on miss.

        Args:
            name: The variable name to look up.

        Returns:
            PatternValue | None: The PatternValue bound to the name, or None if not found.
        """
        if name in self._bindings:
            return self._bindings[name]
        return self._parent.get(name) if self._parent is not None else None

    def set(self, name: str, value: PatternValue) -> bool:
        """Update an existing variable in the nearest enclosing scope.

        Args:
            name: The variable name to update.
            value: The new PatternValue to assign.

        Returns:
            bool: True if the variable was found and updated, False otherwise.
        """
        if name in self._bindings:
            self._bindings[name] = value
            return True
        return self._parent.set(name, value) if self._parent is not None else False

    def define(self, name: str, value: PatternValue) -> None:
        """Define a new variable in the current scope level.

        Args:
            name: The variable name to define.
            value: The PatternValue to bind to the name.
        """
        self._bindings[name] = value

    @property
    def bindings(self) -> dict[str, PatternValue]:
        """Public read-only view of the current scope's variable bindings.

        Returns:
            dict[str, PatternValue]: The dictionary of variable bindings in this scope level.
        """
        return self._bindings


def _extract_members_dict(
    source: dict[str, Any],
    key: str,
    *,
    pop: bool,
) -> dict[str, PatternValue] | None:
    """Extract a ``dict[str, PatternValue]`` entry from a parsed-field result.

    Args:
        source: The parsed-field result dictionary to read from.
        key: The internal metadata key to look up.
        pop: When True, remove the key after reading; when False, only read.

    Returns:
        dict[str, PatternValue] | None: The typed members dictionary, or None
        when the key is absent or its value is not a dict.
    """
    raw: object = source.pop(key, None) if pop else source.get(key)
    if not isinstance(raw, dict):
        return None
    typed: dict[object, object] = _cast("dict[object, object]", raw)
    return {k_obj: v_obj for k_obj, v_obj in typed.items() if isinstance(k_obj, str) and isinstance(v_obj, PatternValue)}


def _make_parsed_field(
    name: str,
    offset: int,
    size: int,
    raw_bytes: bytes,
    display_value: str,
    children: list[dict[str, Any]],
    color: str,
    description: str,
) -> dict[str, Any]:
    """Build a standardised parsed-field result dictionary.

    Args:
        name: The field name.
        offset: Byte offset of this field in the data source.
        size: Number of bytes this field occupies.
        raw_bytes: The raw bytes read for this field.
        display_value: Human-readable string representation of the value.
        children: Child field dictionaries for composite types.
        color: Hex colour string for the UI highlight.
        description: Optional description annotation.

    Returns:
        dict[str, Any]: A dictionary conforming to the Intellicrack parsed-field schema.
    """
    return {
        "name": name,
        "offset": offset,
        "size": size,
        "raw_bytes": list(raw_bytes),
        "display_value": display_value,
        "children": children,
        "color": color,
        "validation_passed": None,
        "description": description,
    }


class HexPatEvaluator:
    """Tree-walking evaluator for HexPat .hexpat pattern programs.

    Walks an AST produced by the parser against binary data supplied via a
    DataReader, producing a list of parsed-field dictionaries suitable for
    display in the Intellicrack hex-editor UI.

    Attributes:
        FIELD_COLORS: Color palette for field highlighting in the hex editor.
    """

    _POINTER_SIZE: ClassVar[int] = 8

    FIELD_COLORS: ClassVar[tuple[str, ...]] = (
        "#E06C75",
        "#61AFEF",
        "#98C379",
        "#E5C07B",
        "#C678DD",
        "#56B6C2",
        "#BE5046",
        "#D19A66",
        "#7EC8E3",
        "#C3E88D",
    )

    def __init__(
        self,
        data_reader: DataReader,
        type_registry: TypeRegistry,
        pragma: PragmaInfo,
    ) -> None:
        """Initialize the HexPatEvaluator with data access and type information.

        Args:
            data_reader: Byte-access wrapper over the binary data.
            type_registry: Registry of all user-defined types.
            pragma: Parsed pragma directives controlling evaluation behaviour.
        """
        self._data: DataReader = data_reader
        self._types: TypeRegistry = type_registry
        self._pragma: PragmaInfo = pragma
        self._offset: int = pragma.base_address
        self._scope: EvalScope = EvalScope()
        self._results: list[dict[str, Any]] = []
        self._depth: int = 0
        self._pattern_count: int = 0
        self._array_index_stack: list[int] = []
        self._default_endian: str = pragma.endian or "little"
        self._color_index: int = 0
        self._pointer_size: int = pragma.pointer_size
        self._namespace_stack: list[str] = []
        self._type_node_aliases: dict[str, TypeNode] = {}
        self._template_args_stack: list[dict[str, ExprNode | TypeNode]] = []
        self._reflection_overrides: dict[int, dict[str, object]] = {}
        self._field_color_palette: tuple[str, ...] | None = None
        self._builtins: dict[str, BuiltinCallable] = self._build_builtins()
        _logger.debug(
            "hexpat_evaluator_initialized",
            base_address=self._offset,
            default_endian=self._default_endian,
            pointer_size=self._pointer_size,
            data_size=self._data.size,
        )

    @property
    def scope(self) -> EvalScope:
        """The current top-level evaluation scope.

        Returns:
            EvalScope: The current EvalScope used for variable bindings.
        """
        return self._scope

    def current_array_index(self) -> int:
        """Return the live array iteration index for the active loop.

        The evaluator pushes an entry onto its array-index stack each time it
        begins instantiating an array element and pops on completion. The
        topmost entry corresponds to the inner-most iteration; when no array
        is active, ``0`` is returned to mirror the documented stdlib default.

        Returns:
            int: The active array iteration index, or ``0`` outside of any
            array-element instantiation.
        """
        return self._array_index_stack[-1] if self._array_index_stack else 0

    def set_default_endian(self, endian: str) -> None:
        """Update the evaluator's default endian for subsequent primitive reads.

        Args:
            endian: ``"little"`` or ``"big"``. Other values are ignored to
                preserve existing semantics.
        """
        if endian in {"little", "big"}:
            self._default_endian = endian

    def reflection_provider(self) -> _EvaluatorReflectionProvider:
        """Build a reflection provider exposing evaluator metadata.

        The returned object is duck-typed against the optional callable
        attribute layout consumed by the stdlib reflection-provider hook.
        Each callable forwards to a small helper that operates on the
        supplied :class:`PatternValue` and the evaluator's live type
        registry.

        Returns:
            _EvaluatorReflectionProvider: A reflection-provider container
            exposing every callable hook required by ``std::core::*``.
        """
        return _EvaluatorReflectionProvider(
            has_attribute=self._reflect_has_attribute,
            get_attribute_argument=self._reflect_get_attribute_argument,
            member_count=self._reflect_member_count,
            has_member=self._reflect_has_member,
            formatted_value=self._reflect_formatted_value,
            is_valid_enum=self._reflect_is_valid_enum,
            set_pattern_color=self._reflect_set_pattern_color,
            set_display_name=self._reflect_set_display_name,
            set_pattern_comment=self._reflect_set_pattern_comment,
            set_pattern_palette_colors=self._reflect_set_pattern_palette_colors,
            reset_pattern_palette=self._reflect_reset_pattern_palette,
            execute_function=self._reflect_execute_function,
        )

    def _reflect_has_attribute(self, pattern: PatternValue, attribute: str) -> bool:
        """Return whether ``pattern`` carries a field-annotation named ``attribute``.

        Args:
            pattern: The reflected pattern value.
            attribute: The annotation name to test for.

        Returns:
            bool: ``True`` when the type referenced by the pattern has an
            annotation with the given name.
        """
        decl_annotations = self._reflection_annotations(pattern)
        return any(name == attribute for name, _ in decl_annotations)

    def _reflect_get_attribute_argument(
        self,
        pattern: PatternValue,
        attribute: str,
        index: int,
    ) -> PatternValue:
        """Return the ``index``-th argument of ``attribute`` on ``pattern``.

        Args:
            pattern: The reflected pattern value.
            attribute: The annotation name whose arguments are queried.
            index: Zero-based argument index. Currently only ``0`` is
                supported because annotations carry a single expression.

        Returns:
            PatternValue: A PatternValue wrapping the resolved annotation
                argument.

        Raises:
            HexPatRuntimeError: When the annotation is missing, has no
                expression body, or ``index`` exceeds the available count.
        """
        for name, expr in self._reflection_annotations(pattern):
            if name == attribute:
                if expr is None:
                    msg = f"std::core::get_attribute_argument: '{attribute}' has no value"
                    raise HexPatRuntimeError(msg)
                if index != 0:
                    msg = f"std::core::get_attribute_argument: index {index} out of range"
                    raise HexPatRuntimeError(msg)
                return self._eval_expr(expr)
        msg = f"std::core::get_attribute_argument: attribute '{attribute}' not found"
        raise HexPatRuntimeError(msg)

    @staticmethod
    def _reflect_member_count(pattern: PatternValue) -> int:
        """Return the number of structurally exposed members on ``pattern``.

        Args:
            pattern: The reflected pattern value.

        Returns:
            int: The cardinality of ``pattern.members``.
        """
        return len(pattern.members)

    @staticmethod
    def _reflect_has_member(pattern: PatternValue, name: str) -> bool:
        """Return whether ``pattern`` exposes a structurally visible member ``name``.

        Args:
            pattern: The reflected pattern value.
            name: The candidate member identifier.

        Returns:
            bool: ``True`` when ``name`` is present in ``pattern.members``.
        """
        return name in pattern.members

    def _reflect_formatted_value(self, pattern: PatternValue) -> str:
        """Return a formatted string representation of ``pattern``.

        Args:
            pattern: The reflected pattern value.

        Returns:
            str: The output of :meth:`_format_value` applied to the pattern's
                primitive value and resolved type.
        """
        return self._format_value(pattern.value, pattern.type_info)

    def _reflect_is_valid_enum(self, pattern: PatternValue) -> bool:
        """Return whether ``pattern`` carries a value matching a declared enum entry.

        Args:
            pattern: The reflected pattern value, expected to carry an enum
                primitive value.

        Returns:
            bool: ``True`` when the pattern's value is in the registered enum
                members for its declared type.
        """
        type_info = pattern.type_info
        if type_info is None:
            return False
        resolved = self._types.resolve(type_info.name)
        if not isinstance(resolved, EnumTypeInfo):
            return False
        return pattern.value in resolved.members.values() if isinstance(pattern.value, int) else False

    def _reflect_set_pattern_color(self, pattern: PatternValue, color: int) -> None:
        """Record an RGBA8 pattern colour override on the supplied pattern.

        Args:
            pattern: The reflected pattern value.
            color: The 32-bit RGBA8 color word to attach.
        """
        self._reflection_overrides.setdefault(id(pattern), {})["color"] = color

    def _reflect_set_display_name(self, pattern: PatternValue, name: str) -> None:
        """Override the displayed name for ``pattern``.

        Args:
            pattern: The reflected pattern value.
            name: The display name to record.
        """
        self._reflection_overrides.setdefault(id(pattern), {})["display_name"] = name

    def _reflect_set_pattern_comment(self, pattern: PatternValue, comment: str) -> None:
        """Attach a comment annotation to ``pattern``.

        Args:
            pattern: The reflected pattern value.
            comment: The comment text to record.
        """
        self._reflection_overrides.setdefault(id(pattern), {})["comment"] = comment

    def _reflect_set_pattern_palette_colors(self, colors: list[int]) -> None:
        """Replace the rotating palette with ``colors``.

        The palette stays effective for subsequent fields placed during
        evaluation. The ``FIELD_COLORS`` class-level palette is intentionally
        left untouched; the override is held on the instance.

        Args:
            colors: New palette entries as RGBA8 integers.
        """
        if colors:
            self._field_color_palette = tuple(f"#{c & 0xFFFFFFFF:08X}" for c in colors)
            self._color_index = 0

    def _reflect_reset_pattern_palette(self) -> None:
        """Restore the default palette and reset the rotation index."""
        self._field_color_palette = None
        self._color_index = 0

    def _reflect_execute_function(self, function_name: str, args: list[PatternValue]) -> PatternValue:
        """Invoke a previously declared user-defined function by name.

        Args:
            function_name: The fully qualified or unqualified function name.
            args: The argument list forwarded to the function call.

        Returns:
            PatternValue: The function's return value.

        Raises:
            HexPatRuntimeError: When ``function_name`` does not resolve to a
                declared :class:`FunctionDecl`.
        """
        binding = self._scope.get(function_name)
        if binding is None:
            msg = f"std::core::execute_function: undefined function '{function_name}'"
            raise HexPatRuntimeError(msg)
        if not isinstance(binding.value, FunctionDecl):
            msg = f"std::core::execute_function: '{function_name}' is not a callable function"
            raise HexPatRuntimeError(msg)
        return self._call_user_function(binding.value, args)

    def _reflection_annotations(self, pattern: PatternValue) -> tuple[tuple[str, ExprNode | None], ...]:
        """Return the annotation tuple recorded on the type referenced by ``pattern``.

        Args:
            pattern: The reflected pattern value.

        Returns:
            tuple[tuple[str, ExprNode | None], ...]: The annotations declared
            on the pattern's resolved struct/union/enum/bitfield type, or an
            empty tuple when the pattern lacks a registered type.
        """
        type_info = pattern.type_info
        if type_info is None:
            return ()
        resolved = self._types.resolve(type_info.name)
        if isinstance(resolved, StructTypeInfo):
            return resolved.decl.annotations
        if isinstance(resolved, UnionTypeInfo):
            return resolved.decl.annotations
        if isinstance(resolved, EnumTypeInfo):
            return resolved.decl.annotations
        if isinstance(resolved, BitfieldTypeInfo):
            return resolved.decl.annotations
        return ()

    @staticmethod
    def _normalize_endian(endian: str | None) -> str | None:
        """Normalize parser endianness tokens to DataReader format.

        Args:
            endian: Endianness from the parser ("le", "be") or evaluator
                ("little", "big"), or None.

        Returns:
            str | None: Normalized endianness string ("little" or "big"), or None.
        """
        if endian == "le":
            return "little"
        return "big" if endian == "be" else endian

    def evaluate(self, program: list[DeclNode | StmtNode]) -> list[dict[str, Any]]:
        """Evaluate a top-level program node list against the binary data.

        Iterates through all declarations and statements at the top level,
        collecting placement results.

        Args:
            program: The ordered list of top-level AST nodes.

        Returns:
            list[dict[str, Any]]: A list of parsed-field dictionaries, one per top-level placement.
        """
        for node in program:
            if isinstance(
                node,
                StructDecl | UnionDecl | EnumDecl | BitfieldDecl | FunctionDecl | NamespaceDecl | UsingDecl,
            ):
                self._eval_decl(node)
            else:
                self._eval_stmt(node)
        return self._results

    def _next_color(self) -> str:
        """Return the next colour from the rotation and advance the index.

        When a custom palette has been installed via the reflection hook
        ``std::core::set_pattern_palette_colors``, that palette drives the
        rotation; otherwise the default :data:`FIELD_COLORS` palette is used.

        Returns:
            str: A hex colour string such as "#E06C75".
        """
        palette = self._field_color_palette or self.FIELD_COLORS
        color = palette[self._color_index % len(palette)]
        self._color_index += 1
        return color

    @staticmethod
    def _format_value(
        value: _PrimValue | FunctionDecl | BuiltinCallable,
        type_info: HexPatType | None,
    ) -> str:
        """Format a runtime value as a human-readable display string.

        Args:
            value: The raw Python value to format.
            type_info: Optional type metadata for formatting decisions.

        Returns:
            str: A formatted string representation of the value.
        """
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, float):
            if math.isnan(value):
                return "NaN"
            if math.isinf(value):
                return "+Inf" if value > 0 else "-Inf"
            return f"{value:.6g}"
        if isinstance(value, int):
            if type_info is not None and type_info.signed:
                return str(value)
            return f"0x{value:X}"
        if isinstance(value, bytes):
            return value.hex()
        if isinstance(value, (BuiltinCallable, FunctionDecl)):
            return "<function>"
        if type_info is not None and type_info.name in {"char", "char16"}:
            return f"'{value}'"
        return str(value)

    def _eval_decl(self, node: DeclNode) -> None:
        """Register a declaration in the type registry and/or scope.

        Args:
            node: The declaration AST node to process.
        """
        ns = "::".join(self._namespace_stack) if self._namespace_stack else None
        if isinstance(node, StructDecl):
            self._types.register_struct(node, namespace=ns)
        elif isinstance(node, UnionDecl):
            self._types.register_union(node, namespace=ns)
        elif isinstance(node, EnumDecl):
            self._register_enum(node, namespace=ns)
        elif isinstance(node, BitfieldDecl):
            self._types.register_bitfield(node, namespace=ns)
        elif isinstance(node, FunctionDecl):
            fn_value = PatternValue(value=node)
            self._scope.define(node.name, fn_value)
            if ns:
                self._scope.define(f"{ns}::{node.name}", fn_value)
        elif isinstance(node, NamespaceDecl):
            self._eval_namespace_decl(node)
        else:
            self._register_using(node)

    def _register_namespaced(self, name: str) -> None:
        """Register a namespace-qualified alias for a type when inside a namespace.

        Args:
            name: The unqualified type name.
        """
        if self._namespace_stack:
            qualified = "::".join(self._namespace_stack) + "::" + name
            self._types.register_alias(qualified, name)

    def _register_enum(self, node: EnumDecl, namespace: str | None = None) -> None:
        """Register an enum declaration with resolved member values.

        Args:
            node: The enum AST declaration to register.
            namespace: Optional ``::``-joined namespace prefix used for the
                qualified registration mirror.

        Raises:
            HexPatTypeError: If the backing type cannot be resolved to a primitive.
        """
        backing = self._resolve_type_node_to_primitive(node.backing_type)
        if backing is None:
            msg = f"enum '{node.name}': cannot resolve backing type"
            raise HexPatTypeError(msg, node.line, node.column)
        members: dict[str, int] = {}
        next_value = 0
        for entry in node.entries:
            if entry.value is not None:
                pv = self._eval_expr(entry.value)
                raw_int = pv.value
                if not isinstance(raw_int, int):
                    msg = f"enum '{node.name}' entry '{entry.name}': value must be integer"
                    raise HexPatTypeError(msg, entry.line, entry.column)
                next_value = raw_int
            members[entry.name] = next_value
            next_value += 1
        self._types.register_enum(node, backing, members, namespace=namespace)

    def _register_using(self, node: UsingDecl) -> None:
        """Register a type alias from a using declaration.

        Plain primitive and named-type targets are registered as scalar
        aliases in the type registry. Composite targets (arrays, pointers,
        padding) cannot collapse into a single registry name, so they are
        recorded as type-node aliases on the evaluator instead and resolved
        lazily on every reference. The qualified namespace alias is also
        recorded so a path such as ``std::time::Time = u64`` resolves both
        as ``Time`` (inside the namespace) and as ``std::time::Time``.

        Args:
            node: The using declaration AST node.
        """
        if isinstance(node.target, PrimitiveType):
            self._types.register_alias(node.alias, node.target.name)
            self._register_namespaced(node.alias)
            return
        if isinstance(node.target, NamedType):
            target_name = node.target.name
            if node.target.namespace:
                target_name = f"{node.target.namespace}::{target_name}"
            self._types.register_alias(node.alias, target_name)
            self._register_namespaced(node.alias)
            return
        self._type_node_aliases[node.alias] = node.target
        if self._namespace_stack:
            qualified = "::".join(self._namespace_stack) + "::" + node.alias
            self._type_node_aliases[qualified] = node.target

    def _eval_namespace_decl(self, node: NamespaceDecl) -> None:
        """Evaluate a namespace declaration, registering its members.

        Args:
            node: The namespace declaration AST node.
        """
        ns_scope = EvalScope(parent=self._scope)
        saved_scope = self._scope
        self._scope = ns_scope
        self._namespace_stack.append(node.name)
        for decl in node.body:
            self._eval_decl(decl)
        self._namespace_stack.pop()
        self._scope = saved_scope
        ns_value = PatternValue(value=node.name)
        ns_value.members.update(ns_scope.bindings)
        self._scope.define(node.name, ns_value)

    def _eval_stmt(self, node: StmtNode) -> None:
        """Evaluate a statement node for its effect.

        Args:
            node: The statement AST node to evaluate.

        Raises:
            _BreakSignalError: When a break statement is encountered.
            _ContinueSignalError: When a continue statement is encountered.
            _ReturnSignalError: When a return statement is encountered.
        """
        if isinstance(node, FieldDecl):
            result = self._eval_field(node, self._offset)
            if result is not None:
                self._results.append(result)
        elif isinstance(node, PlacementStmt):
            self._eval_placement(node)
        elif isinstance(node, ConditionalField):
            self._eval_conditional(node)
        elif isinstance(node, VarDecl):
            self._eval_var_decl(node)
        elif isinstance(node, WhileStmt):
            self._eval_while(node)
        elif isinstance(node, ForStmt):
            self._eval_for(node)
        elif isinstance(node, MatchStmt):
            self._eval_match(node)
        elif isinstance(node, TryStmt):
            self._eval_try(node)
        elif isinstance(node, ExprStmt):
            self._eval_expr(node.expr)
        elif isinstance(node, ReturnStmt):
            if node.value is not None:
                raise _ReturnSignalError(self._eval_expr(node.value))
            raise _ReturnSignalError(PatternValue(value=None))
        elif isinstance(node, BreakStmt):
            raise _BreakSignalError
        else:
            raise _ContinueSignalError

    def _eval_conditional(self, node: ConditionalField) -> None:
        """Evaluate a conditional field branching construct.

        Args:
            node: The conditional field AST node.
        """
        cond = self._eval_expr(node.condition)
        branch = node.true_fields if _truthy(cond) else node.false_fields
        for stmt in branch:
            self._eval_stmt(stmt)

    def _eval_var_decl(self, node: VarDecl) -> None:
        """Evaluate a variable declaration.

        Args:
            node: The variable declaration AST node.
        """
        value = self._eval_expr(node.initializer) if node.initializer is not None else PatternValue(value=None)
        self._scope.define(node.name, value)

    def _eval_while(self, node: WhileStmt) -> None:
        """Evaluate a while loop statement.

        Args:
            node: The while loop AST node.
        """
        while True:
            cond = self._eval_expr(node.condition)
            if not _truthy(cond):
                break
            try:
                for stmt in node.body:
                    self._eval_stmt(stmt)
            except _BreakSignalError:
                _logger.warning("hexpat_while_break", line=node.line, column=node.column)
                break
            except _ContinueSignalError:
                _logger.warning("hexpat_while_continue", line=node.line, column=node.column)
                continue

    def _eval_for(self, node: ForStmt) -> None:
        """Evaluate a C-style for loop statement.

        Args:
            node: The for loop AST node.
        """
        loop_scope = EvalScope(parent=self._scope)
        saved_scope = self._scope
        self._scope = loop_scope
        try:
            if node.init is not None:
                self._eval_stmt(node.init)
            while True:
                if node.condition is not None:
                    cond = self._eval_expr(node.condition)
                    if not _truthy(cond):
                        break
                try:
                    for stmt in node.body:
                        self._eval_stmt(stmt)
                except _BreakSignalError:
                    _logger.warning("hexpat_for_break", line=node.line, column=node.column)
                    break
                except _ContinueSignalError:
                    _logger.warning("hexpat_for_continue", line=node.line, column=node.column)
                if node.update is not None:
                    self._eval_expr(node.update)
        finally:
            self._scope = saved_scope

    def _eval_match(self, node: MatchStmt) -> None:
        """Evaluate a match statement by testing value against arms.

        Args:
            node: The match statement AST node.
        """
        subject = self._eval_expr(node.value)
        for arm in node.arms:
            if arm.is_wildcard:
                for stmt in arm.body:
                    self._eval_stmt(stmt)
                return
            for pattern_expr in arm.patterns:
                pattern_val = self._eval_expr(pattern_expr)
                if _values_equal(subject, pattern_val):
                    for stmt in arm.body:
                        self._eval_stmt(stmt)
                    return

    def _eval_try(self, node: TryStmt) -> None:
        """Evaluate a try/catch error-handling block.

        Args:
            node: The try statement AST node.
        """
        try:
            for stmt in node.try_body:
                self._eval_stmt(stmt)
        except (HexPatRuntimeError, HexPatTypeError):
            _logger.warning("hexpat_try_caught", line=node.line, column=node.column)
            for stmt in node.catch_body:
                self._eval_stmt(stmt)

    def _eval_placement(self, node: PlacementStmt) -> None:
        """Evaluate a top-level placement statement, instantiating a type.

        Args:
            node: The placement statement AST node.

        Raises:
            HexPatRuntimeError: If the pattern limit is exceeded.
        """
        if self._pattern_count >= self._pragma.pattern_limit:
            _logger.error(
                "hexpat_pattern_limit_exceeded",
                pattern_limit=self._pragma.pattern_limit,
                line=node.line,
                column=node.column,
            )
            msg = f"pattern limit {self._pragma.pattern_limit} exceeded"
            raise HexPatRuntimeError(msg, node.line, node.column)
        target_offset = self._offset
        if node.at_offset is not None:
            ov = self._eval_expr(node.at_offset)
            if isinstance(ov.value, int):
                target_offset = ov.value

        color = self._next_color()
        description = self._extract_description(node.annotations)

        type_node: TypeNode = node.type_node
        if node.array_size is not None or node.while_condition is not None:
            type_node = ArrayType(
                element=node.type_node,
                size=node.array_size,
                while_condition=node.while_condition,
                line=node.line,
                column=node.column,
            )

        result = self._instantiate_type(
            type_node,
            node.name,
            target_offset,
            color,
            description,
            endianness=None,
        )
        if result is not None:
            self._results.append(result)
            self._pattern_count += 1
            res_size = int(result["size"])
            if node.at_offset is None:
                self._offset = target_offset + res_size
            raw_value = result.pop("_value", None)
            bound_value: _PrimValue | FunctionDecl | BuiltinCallable = (
                raw_value if isinstance(raw_value, (int, float, str, bool, bytes)) else None
            )
            nested_members = _extract_members_dict(result, "_members", pop=True)
            element_members = _extract_members_dict(result, "_element_members", pop=True)
            bound_val = PatternValue(
                value=bound_value,
                offset=int(result["offset"]),
                size=res_size,
            )
            if nested_members is not None:
                bound_val.members.update(nested_members)
            if element_members is not None:
                bound_val.members.update(element_members)
            self._scope.define(node.name, bound_val)

    def _instantiate_type(
        self,
        type_node: TypeNode,
        var_name: str,
        offset: int,
        color: str,
        description: str,
        endianness: str | None,
    ) -> dict[str, Any] | None:
        """Instantiate a type node at a given offset, returning a parsed-field dict.

        Args:
            type_node: The type node to instantiate.
            var_name: The variable name for the resulting field.
            offset: Byte offset at which to instantiate the type.
            color: Hex colour string for UI highlighting.
            description: Optional description annotation.
            endianness: Optional endianness override.

        Returns:
            dict[str, Any] | None: A parsed-field dictionary, or None if no data was consumed.

        Raises:
            HexPatTypeError: If the type cannot be resolved.
        """
        eff_endian = endianness or self._default_endian

        if isinstance(type_node, PaddingType):
            sz_pv = self._eval_expr(type_node.size)
            sz = sz_pv.value if isinstance(sz_pv.value, int) else 1
            raw = self._data.read(offset, sz)
            return _make_parsed_field(var_name, offset, sz, raw, "padding", [], color, description)

        if isinstance(type_node, PrimitiveType):
            eff_endian = self._normalize_endian(type_node.endianness) or eff_endian
            ptype = self._types.resolve_primitive(type_node.name, eff_endian)
            if ptype is None:
                msg = f"unknown primitive type '{type_node.name}'"
                raise HexPatTypeError(msg, type_node.line, type_node.column)
            pv = self._read_primitive(ptype, offset)
            actual_size = pv.size if ptype.size <= 0 else ptype.size
            raw = self._data.read(offset, actual_size)
            display = self._format_value(pv.value, ptype)
            result = _make_parsed_field(var_name, offset, actual_size, raw, display, [], color, description)
            result["_value"] = pv.value
            return result

        if isinstance(type_node, NamedType):
            return self._instantiate_named_type(type_node, var_name, offset, color, description)

        if isinstance(type_node, ArrayType):
            return self._eval_array_type(type_node, var_name, offset, color, description, eff_endian)

        if isinstance(type_node, PointerType):
            return self._instantiate_pointer_type(type_node, var_name, offset, color, description, eff_endian)

        return None

    def _pointer_storage_primitive(
        self,
        type_node: PointerType,
        eff_endian: str,
    ) -> HexPatType:
        """Resolve the primitive used to store a pointer's integer address.

        Prefers an explicit ``storage_type`` attribute on the pointer node when
        present. Otherwise, selects the unsigned primitive matching the pragma
        ``pointer_size``: 1 -> u8, 2 -> u16, 4 -> u32, 8 -> u64.

        Args:
            type_node: The PointerType AST node being instantiated.
            eff_endian: Effective endianness to apply to the storage primitive.

        Returns:
            HexPatType: The primitive HexPatType used to decode the pointer address.
        """
        storage: object = getattr(type_node, "storage_type", None)
        if isinstance(storage, str):
            prim = self._types.resolve_primitive(storage, eff_endian)
            if prim is not None:
                return prim
        size_to_name: dict[int, str] = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}
        prim_name = size_to_name.get(self._pointer_size, "u64")
        resolved = self._types.resolve_primitive(prim_name, eff_endian)
        if resolved is not None:
            return resolved
        return HexPatType(prim_name, self._pointer_size, signed=False, endian=eff_endian)

    def _instantiate_pointer_type(
        self,
        type_node: PointerType,
        var_name: str,
        offset: int,
        color: str,
        description: str,
        eff_endian: str,
    ) -> dict[str, Any] | None:
        """Instantiate a pointer type, reading the address and dereferencing the pointee.

        Reads the pointer storage integer at ``offset``, saves the current
        ``$`` offset, recursively instantiates the pointee at the decoded
        address as a single child, then restores ``$``.

        Args:
            type_node: The PointerType AST node to instantiate.
            var_name: The variable name for the resulting field.
            offset: Byte offset at which to read the pointer storage.
            color: Hex colour string for UI highlighting.
            description: Optional description annotation.
            eff_endian: Effective endianness for the pointer storage read.

        Returns:
            dict[str, Any] | None: A parsed-field dictionary for the pointer, with one child
            holding the dereferenced pointee, or None if no data could be read.
        """
        ptr_type = self._pointer_storage_primitive(type_node, eff_endian)
        ptr_size = ptr_type.size if ptr_type.size > 0 else self._pointer_size
        pv = self._read_primitive(ptr_type, offset)
        raw = self._data.read(offset, ptr_size)
        decoded = pv.value if isinstance(pv.value, int) else 0
        display = self._format_value(pv.value, ptr_type)

        saved_offset = self._offset
        self._offset = decoded
        try:
            pointee_field = self._instantiate_type(
                type_node.pointee,
                f"*{var_name}",
                decoded,
                color,
                "",
                eff_endian,
            )
        finally:
            self._offset = saved_offset

        children: list[dict[str, Any]] = [pointee_field] if pointee_field is not None else []
        return _make_parsed_field(var_name, offset, ptr_size, raw, f"*{display}", children, color, description)

    def _instantiate_named_type(
        self,
        type_node: NamedType,
        var_name: str,
        offset: int,
        color: str,
        description: str,
    ) -> dict[str, Any] | None:
        """Instantiate a named (user-defined) type at a given offset.

        Args:
            type_node: The NamedType AST node to resolve and instantiate.
            var_name: The variable name for this field.
            offset: Byte offset at which to instantiate the type.
            color: Hex colour string for UI highlighting.
            description: Optional description annotation.

        Returns:
            dict[str, Any] | None: A parsed-field dictionary, or None if no data was consumed.

        Raises:
            HexPatTypeError: If the type name cannot be resolved.
        """
        lookup_name = type_node.name
        if type_node.namespace:
            lookup_name = f"{type_node.namespace}::{type_node.name}"
        template_arg = self._lookup_template_arg(type_node.name)
        if template_arg is not None:
            return self._instantiate_type(template_arg, var_name, offset, color, description, endianness=None)
        node_alias = self._type_node_aliases.get(lookup_name)
        if node_alias is None and type_node.namespace:
            node_alias = self._type_node_aliases.get(type_node.name)
        if node_alias is not None:
            return self._instantiate_type(
                node_alias,
                var_name,
                offset,
                color,
                description,
                endianness=None,
            )
        if type_node.template_args:
            template_result = self._instantiate_template_named_type(
                type_node,
                lookup_name,
                var_name,
                offset,
                color,
                description,
            )
            if template_result is not None:
                return template_result
        resolved = self._types.resolve(lookup_name)
        if resolved is None and type_node.namespace:
            resolved = self._types.resolve(type_node.name)
        if resolved is None:
            from intellicrack.core.hexpat.type_system import BuiltinTypes

            suggestions = sorted([name for name in BuiltinTypes.all_names() if name.startswith(lookup_name) or lookup_name in name])
            msg = f"unknown type '{lookup_name}'"
            if suggestions:
                msg = f"{msg} (did you mean one of: {', '.join(suggestions)}?)"
            raise HexPatTypeError(msg, type_node.line, type_node.column)
        if isinstance(resolved, HexPatType):
            pv = self._read_primitive(resolved, offset)
            raw = self._data.read(offset, resolved.size)
            display = self._format_value(pv.value, resolved)
            return _make_parsed_field(var_name, offset, resolved.size, raw, display, [], color, description)
        if isinstance(resolved, StructTypeInfo):
            return self._eval_struct_instance(resolved.name, resolved, var_name, offset, color, description)
        if isinstance(resolved, UnionTypeInfo):
            return self._eval_union_instance(resolved.name, resolved, var_name, offset, color, description)
        if isinstance(resolved, EnumTypeInfo):
            return self._eval_enum_instance(resolved.name, resolved, var_name, offset, color, description)
        return self._eval_bitfield_instance(resolved.name, resolved, var_name, offset, color, description)

    def _eval_struct_instance(
        self,
        name: str,
        type_info: StructTypeInfo,
        var_name: str,
        offset: int,
        color: str,
        description: str,
    ) -> dict[str, Any]:
        """Instantiate a struct type at a given offset.

        Args:
            name: The struct type name.
            type_info: The resolved struct type info.
            var_name: The variable name for this field.
            offset: Byte offset at which to read the struct.
            color: Hex colour string for UI highlighting.
            description: Optional description annotation.

        Returns:
            dict[str, Any]: A parsed-field dictionary with children for each struct member.

        Raises:
            HexPatRuntimeError: If recursion depth is exceeded.
        """
        self._depth += 1
        if self._depth > self._pragma.eval_depth:
            self._depth -= 1
            _logger.error(
                "hexpat_struct_eval_depth_exceeded",
                struct_name=name,
                eval_depth_limit=self._pragma.eval_depth,
                data_offset=offset,
            )
            msg = f"maximum evaluation depth {self._pragma.eval_depth} exceeded"
            raise HexPatRuntimeError(msg, offset=offset)

        saved_offset = self._offset
        saved_scope = self._scope
        saved_depth = self._depth
        self._offset = offset
        struct_scope = EvalScope(parent=saved_scope)
        self._scope = struct_scope

        children: list[dict[str, Any]] = []
        members: dict[str, PatternValue] = {}
        total_size = 0
        raw: bytes = b""

        try:
            if type_info.parent is not None:
                parent_resolved = self._types.resolve(type_info.parent)
                if isinstance(parent_resolved, StructTypeInfo):
                    parent_result = self._eval_struct_instance(parent_resolved.name, parent_resolved, "__parent__", self._offset, color, "")
                    children.extend(parent_result.get("children", []))
                    self._offset += int(parent_result["size"])
                    parent_members = _extract_members_dict(parent_result, "_members", pop=True)
                    if parent_members is not None:
                        members |= parent_members

            for stmt in type_info.decl.body:
                self._eval_stmt_collect(stmt, children)

            total_size = self._offset - offset
            raw = self._data.read(offset, max(total_size, 0))
            members.update(struct_scope.bindings)
        finally:
            self._offset = saved_offset
            self._scope = saved_scope
            self._depth = saved_depth - 1

        result = _make_parsed_field(var_name, offset, total_size, raw, name, children, color, description)
        result["_members"] = members
        return result

    def _eval_union_instance(
        self,
        name: str,
        type_info: UnionTypeInfo,
        var_name: str,
        offset: int,
        color: str,
        description: str,
    ) -> dict[str, Any]:
        """Instantiate a union type at a given offset.

        All members start at the same offset; the union size is the maximum child size.

        Args:
            name: The union type name.
            type_info: The resolved union type info.
            var_name: The variable name for this field.
            offset: Byte offset at which to read the union.
            color: Hex colour string for UI highlighting.
            description: Optional description annotation.

        Returns:
            dict[str, Any]: A parsed-field dictionary with children for each union alternative.

        Raises:
            HexPatRuntimeError: If recursion depth is exceeded.
        """
        self._depth += 1
        if self._depth > self._pragma.eval_depth:
            self._depth -= 1
            _logger.error(
                "hexpat_union_eval_depth_exceeded",
                union_name=name,
                eval_depth_limit=self._pragma.eval_depth,
                data_offset=offset,
            )
            msg = f"maximum evaluation depth {self._pragma.eval_depth} exceeded"
            raise HexPatRuntimeError(msg, offset=offset)

        saved_offset = self._offset
        saved_scope = self._scope
        saved_depth = self._depth
        union_scope = EvalScope(parent=saved_scope)
        self._scope = union_scope

        children: list[dict[str, Any]] = []
        members: dict[str, PatternValue] = {}
        max_size = 0
        raw: bytes = b""

        try:
            for stmt in type_info.decl.body:
                self._offset = offset
                self._eval_stmt_collect(stmt, children)
                member_size = self._offset - offset
                max_size = max(max_size, member_size)

            raw = self._data.read(offset, max(max_size, 0))
            members |= union_scope.bindings
        finally:
            self._offset = saved_offset
            self._scope = saved_scope
            self._depth = saved_depth - 1

        result = _make_parsed_field(var_name, offset, max_size, raw, name, children, color, description)
        result["_members"] = members
        return result

    def _eval_enum_instance(
        self,
        _name: str,
        type_info: EnumTypeInfo,
        var_name: str,
        offset: int,
        color: str,
        description: str,
    ) -> dict[str, Any]:
        """Instantiate an enum type at a given offset.

        Args:
            _name: The enum type name (unused, kept for uniform signature).
            type_info: The resolved enum type info.
            var_name: The variable name for this field.
            offset: Byte offset at which to read the enum value.
            color: Hex colour string for UI highlighting.
            description: Optional description annotation.

        Returns:
            dict[str, Any]: A parsed-field dictionary with a display value showing the member name.
        """
        backing = type_info.backing_type
        pv = self._read_primitive(backing, offset)
        raw_int = pv.value if isinstance(pv.value, int) else 0

        member_name = next(
            (k for k, v in type_info.members.items() if v == raw_int),
            None,
        )
        display = f"{member_name} (0x{raw_int:X})" if member_name is not None else f"<unknown> (0x{raw_int:X})"
        raw = self._data.read(offset, backing.size)
        result = _make_parsed_field(var_name, offset, backing.size, raw, display, [], color, description)
        result["_value"] = raw_int
        return result

    def _eval_bitfield_instance(
        self,
        name: str,
        type_info: BitfieldTypeInfo,
        var_name: str,
        offset: int,
        color: str,
        description: str,
    ) -> dict[str, Any]:
        """Instantiate a bitfield type at a given offset.

        Args:
            name: The bitfield type name.
            type_info: The resolved bitfield type info.
            var_name: The variable name for this field.
            offset: Byte offset at which to read the bitfield.
            color: Hex colour string for UI highlighting.
            description: Optional description annotation.

        Returns:
            dict[str, Any]: A parsed-field dictionary with bit-field children.

        Raises:
            HexPatTypeError: If a bit-width expression is not a valid integer.
        """
        total_bits = 0
        bit_widths: list[tuple[str, int]] = []
        for entry in type_info.decl.entries:
            wv = self._eval_expr(entry.width)
            if not isinstance(wv.value, int):
                msg = f"bitfield '{name}' entry '{entry.name}': width must be integer"
                raise HexPatTypeError(msg, entry.line, entry.column)
            bit_widths.append((entry.name, wv.value))
            total_bits += wv.value

        total_bytes = (total_bits + 7) // 8
        raw = self._data.read(offset, total_bytes)
        bf_byteorder: Literal["little", "big"] = "big" if self._default_endian == "big" else "little"
        int_value = int.from_bytes(raw, byteorder=bf_byteorder)

        order = self._resolve_bitfield_order(type_info.decl.annotations)
        children: list[dict[str, Any]] = []
        bit_pos = 0
        for entry_name, width in bit_widths:
            mask = (1 << width) - 1
            shift = (total_bits - bit_pos - width) if order == "left_to_right" else bit_pos
            field_val = (int_value >> shift) & mask
            child_raw = field_val.to_bytes(max((width + 7) // 8, 1), byteorder=bf_byteorder)
            children.append(
                _make_parsed_field(
                    entry_name,
                    offset,
                    (width + 7) // 8,
                    child_raw,
                    f"0x{field_val:X} ({width} bits)",
                    [],
                    color,
                    "",
                ),
            )
            bit_pos += width

        return _make_parsed_field(var_name, offset, total_bytes, raw, name, children, color, description)

    def _resolve_bitfield_order(
        self,
        annotations: tuple[tuple[str, ExprNode | None], ...],
    ) -> str:
        """Resolve the effective bit ordering for a bitfield declaration.

        Annotations matching ``bitfield_order`` override the pragma default.
        Accepted values are ``"left_to_right"`` and ``"right_to_left"``.

        Args:
            annotations: Tuple of annotation name-value pairs on the bitfield declaration.

        Returns:
            str: The resolved ordering, either ``"left_to_right"`` or ``"right_to_left"``.
        """
        for ann_name, ann_expr in annotations:
            if ann_name == "bitfield_order" and ann_expr is not None:
                pv = self._eval_expr(ann_expr)
                if isinstance(pv.value, str) and pv.value in {"left_to_right", "right_to_left"}:
                    return pv.value
        pragma_order = self._pragma.bitfield_order
        return pragma_order if pragma_order in {"left_to_right", "right_to_left"} else "right_to_left"

    def _eval_array_type(
        self,
        type_node: ArrayType,
        var_name: str,
        offset: int,
        color: str,
        description: str,
        endianness: str,
    ) -> dict[str, Any] | None:
        """Instantiate an array type at a given offset.

        Args:
            type_node: The array type AST node.
            var_name: The variable name for this field.
            offset: Byte offset at which to read the array.
            color: Hex colour string for UI highlighting.
            description: Optional description annotation.
            endianness: Effective endianness for element reads.

        Returns:
            dict[str, Any] | None: A parsed-field dictionary containing one child per element, or None.

        Raises:
            HexPatRuntimeError: If the array limit is exceeded.
        """
        elements: list[dict[str, Any]] = []
        element_members: dict[str, PatternValue] = {}
        current_offset = offset
        elem_index = 0

        if type_node.size is not None:
            count_pv = self._eval_expr(type_node.size)
            count = count_pv.value if isinstance(count_pv.value, int) else 0
            for i in range(count):
                if elem_index >= self._pragma.array_limit:
                    msg = f"array limit {self._pragma.array_limit} exceeded"
                    raise HexPatRuntimeError(msg, offset=current_offset)
                self._array_index_stack.append(i)
                elem = self._instantiate_type(
                    type_node.element,
                    f"[{i}]",
                    current_offset,
                    color,
                    "",
                    endianness,
                )
                self._array_index_stack.pop()
                if elem is not None:
                    element_members[f"[{i}]"] = self._element_to_pattern_value(elem)
                    elements.append(elem)
                    current_offset += int(elem["size"])
                elem_index += 1

        elif type_node.while_condition is not None:
            i = 0
            while True:
                if elem_index >= self._pragma.array_limit:
                    msg = f"array limit {self._pragma.array_limit} exceeded"
                    raise HexPatRuntimeError(msg, offset=current_offset)
                self._array_index_stack.append(i)
                cond_pv = self._eval_expr(type_node.while_condition)
                self._array_index_stack.pop()
                if not _truthy(cond_pv):
                    break
                self._array_index_stack.append(i)
                elem = self._instantiate_type(
                    type_node.element,
                    f"[{i}]",
                    current_offset,
                    color,
                    "",
                    endianness,
                )
                self._array_index_stack.pop()
                if elem is None:
                    break
                element_members[f"[{i}]"] = self._element_to_pattern_value(elem)
                elements.append(elem)
                current_offset += int(elem["size"])
                i += 1
                elem_index += 1

        total_size = current_offset - offset
        raw = self._data.read(offset, max(total_size, 0))
        result = _make_parsed_field(var_name, offset, total_size, raw, f"[{len(elements)}]", elements, color, description)
        result["_element_members"] = element_members
        return result

    @staticmethod
    def _element_to_pattern_value(elem: dict[str, Any]) -> PatternValue:
        """Convert an array element result dict into a PatternValue for member access.

        Args:
            elem: The parsed-field dictionary produced by instantiating an array element.

        Returns:
            PatternValue: A PatternValue with primitive ``value``, nested members, and offset/size.
        """
        raw_value = elem.get("_value")
        bound_value: _PrimValue | FunctionDecl | BuiltinCallable = (
            raw_value if isinstance(raw_value, (int, float, str, bool, bytes)) else None
        )
        pv = PatternValue(
            value=bound_value,
            offset=int(elem["offset"]),
            size=int(elem["size"]),
        )
        nested = _extract_members_dict(elem, "_members", pop=False)
        if nested is not None:
            pv.members.update(nested)
        nested_elements = _extract_members_dict(elem, "_element_members", pop=False)
        if nested_elements is not None:
            pv.members.update(nested_elements)
        return pv

    def _eval_field(
        self,
        node: FieldDecl,
        _parent_offset: int,
    ) -> dict[str, Any] | None:
        """Evaluate a field declaration within a struct or union body.

        Args:
            node: The field declaration AST node.
            _parent_offset: The starting offset of the enclosing composite type.

        Returns:
            dict[str, Any] | None: A parsed-field dictionary for this field, or None for padding.
        """
        eff_endian = self._normalize_endian(node.endianness) or self._default_endian
        target_offset = self._offset

        if node.at_offset is not None:
            ov = self._eval_expr(node.at_offset)
            if isinstance(ov.value, int):
                target_offset = ov.value

        color = self._next_color()
        description = self._extract_description(node.annotations)

        is_array = node.array_size is not None or node.while_condition is not None
        if node.is_pointer and is_array:
            return self._eval_array_field(node, target_offset, eff_endian, color, description, pointer_elements=True)

        if node.is_pointer:
            return self._eval_pointer_field(node, target_offset, eff_endian, color, description)

        if is_array:
            return self._eval_array_field(node, target_offset, eff_endian, color, description, pointer_elements=False)

        return self._eval_plain_field(node, target_offset, eff_endian, color, description)

    def _eval_pointer_field(
        self,
        node: FieldDecl,
        target_offset: int,
        eff_endian: str,
        color: str,
        description: str,
    ) -> dict[str, Any]:
        """Evaluate a pointer field declaration.

        The pointer storage integer is read at ``target_offset``, and the
        pointee is recursively instantiated at the decoded address as a
        single child of this field.

        Args:
            node: The field declaration AST node.
            target_offset: Effective byte offset for this field.
            eff_endian: Effective endianness for this field.
            color: Hex colour string for UI highlighting.
            description: Optional description annotation.

        Returns:
            dict[str, Any]: A parsed-field dictionary for this pointer field.
        """
        pointer_node = PointerType(
            pointee=node.type_node,
            line=node.line,
            column=node.column,
        )
        ptr_type = self._pointer_storage_primitive(pointer_node, eff_endian)
        ptr_size = ptr_type.size if ptr_type.size > 0 else self._pointer_size
        pv = self._read_primitive(ptr_type, target_offset)
        raw = self._data.read(target_offset, ptr_size)
        decoded = pv.value if isinstance(pv.value, int) else 0
        display = f"*{self._format_value(pv.value, ptr_type)}"

        saved_offset = self._offset
        self._offset = decoded
        try:
            pointee_field = self._instantiate_type(
                node.type_node,
                f"*{node.name}",
                decoded,
                color,
                "",
                eff_endian,
            )
        finally:
            self._offset = saved_offset

        children: list[dict[str, Any]] = [pointee_field] if pointee_field is not None else []
        result: dict[str, Any] = _make_parsed_field(node.name, target_offset, ptr_size, raw, display, children, color, description)
        if node.at_offset is None:
            self._offset = target_offset + ptr_size
        bound = PatternValue(value=pv.value, type_info=ptr_type, offset=target_offset, size=ptr_size)
        self._scope.define(node.name, bound)
        return result

    def _eval_array_field(
        self,
        node: FieldDecl,
        target_offset: int,
        eff_endian: str,
        color: str,
        description: str,
        *,
        pointer_elements: bool = False,
    ) -> dict[str, Any] | None:
        """Evaluate an array field declaration.

        When ``pointer_elements`` is true the array is interpreted as
        ``T *name[N]``: each slot stores an independent pointer that is read
        from the binary and dereferenced into a pointee instance. The
        advancement of ``$`` reflects the storage size of the pointer
        array, not the cumulative size of the dereferenced pointees.

        Args:
            node: The field declaration AST node.
            target_offset: Effective byte offset for this field.
            eff_endian: Effective endianness for this field.
            color: Hex colour string for UI highlighting.
            description: Optional description annotation.
            pointer_elements: When ``True`` each element is wrapped in a
                :class:`PointerType` before instantiation.

        Returns:
            dict[str, Any] | None: A parsed-field dictionary for this array
            field, or ``None`` when no elements were produced.
        """
        element_node: TypeNode = (
            PointerType(pointee=node.type_node, line=node.line, column=node.column) if pointer_elements else node.type_node
        )
        array_type_node = ArrayType(
            element=element_node,
            size=node.array_size,
            while_condition=node.while_condition,
            line=node.line,
            column=node.column,
        )
        result = self._eval_array_type(array_type_node, node.name, target_offset, color, description, eff_endian)
        if result is not None:
            field_size = int(result["size"])
            if node.at_offset is None:
                self._offset = target_offset + field_size
            bound = PatternValue(value=None, offset=target_offset, size=field_size)
            element_members = _extract_members_dict(result, "_element_members", pop=False)
            if element_members is not None:
                bound.members.update(element_members)
            self._scope.define(node.name, bound)
        return result

    def _eval_plain_field(
        self,
        node: FieldDecl,
        target_offset: int,
        eff_endian: str,
        color: str,
        description: str,
    ) -> dict[str, Any] | None:
        """Evaluate a plain (non-pointer, non-array) field declaration.

        Args:
            node: The field declaration AST node.
            target_offset: Effective byte offset for this field.
            eff_endian: Effective endianness for this field.
            color: Hex colour string for UI highlighting.
            description: Optional description annotation.

        Returns:
            dict[str, Any] | None: A parsed-field dictionary for this field, or None.
        """
        result = self._instantiate_type(node.type_node, node.name, target_offset, color, description, eff_endian)
        if result is not None:
            field_size = int(result["size"])
            if node.at_offset is None:
                self._offset = target_offset + field_size
            raw_value = result.pop("_value", None)
            bound_value: _PrimValue | FunctionDecl | BuiltinCallable = (
                raw_value if isinstance(raw_value, (int, float, str, bool, bytes)) else None
            )
            nested_members = _extract_members_dict(result, "_members", pop=True)
            element_members = _extract_members_dict(result, "_element_members", pop=True)
            bound = PatternValue(value=bound_value, offset=int(result["offset"]), size=field_size)
            if nested_members is not None:
                bound.members.update(nested_members)
            if element_members is not None:
                bound.members.update(element_members)
            self._scope.define(node.name, bound)
        return result

    def _eval_stmt_collect(
        self,
        stmt: StmtNode,
        children: list[dict[str, Any]],
    ) -> None:
        """Evaluate a statement and append any produced fields to children.

        Args:
            stmt: The statement AST node to evaluate.
            children: The list to append produced field dicts to.

        Raises:
            _BreakSignalError: When a break statement is encountered.
            _ContinueSignalError: When a continue statement is encountered.
            _ReturnSignalError: When a return statement is encountered.
        """
        if isinstance(stmt, FieldDecl):
            result = self._eval_field(stmt, self._offset)
            if result is not None:
                children.append(result)
        elif isinstance(stmt, PlacementStmt):
            saved_results = self._results
            self._results = []
            self._eval_placement(stmt)
            children.extend(self._results)
            self._results = saved_results
        elif isinstance(stmt, ConditionalField):
            cond = self._eval_expr(stmt.condition)
            branch = stmt.true_fields if _truthy(cond) else stmt.false_fields
            for s in branch:
                self._eval_stmt_collect(s, children)
        elif isinstance(stmt, VarDecl):
            self._eval_var_decl(stmt)
        elif isinstance(stmt, WhileStmt):
            self._eval_while(stmt)
        elif isinstance(stmt, ForStmt):
            self._eval_for(stmt)
        elif isinstance(stmt, MatchStmt):
            self._eval_match(stmt)
        elif isinstance(stmt, TryStmt):
            self._eval_try(stmt)
        elif isinstance(stmt, ExprStmt):
            self._eval_expr(stmt.expr)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value is not None:
                raise _ReturnSignalError(self._eval_expr(stmt.value))
            raise _ReturnSignalError(PatternValue(value=None))
        elif isinstance(stmt, BreakStmt):
            raise _BreakSignalError
        else:
            raise _ContinueSignalError

    def _read_primitive(self, type_info: HexPatType, offset: int) -> PatternValue:
        """Read a primitive typed value from the data source at the given offset.

        Args:
            type_info: The primitive type descriptor.
            offset: Byte offset in the data source.

        Returns:
            PatternValue: A PatternValue containing the decoded value.

        Raises:
            HexPatTypeError: If the type name is not a recognised primitive.
        """
        endian = type_info.endian or self._default_endian
        name = type_info.name

        value: _PrimValue

        if name == "u8":
            value = self._data.read_u8(offset)
        elif name == "u16":
            value = self._data.read_u16(offset, endian)
        elif name == "u32":
            value = self._data.read_u32(offset, endian)
        elif name == "u64":
            value = self._data.read_u64(offset, endian)
        elif name == "u128":
            value = self._data.read_u128(offset, endian)
        elif name == "s8":
            value = self._data.read_s8(offset)
        elif name == "s16":
            value = self._data.read_s16(offset, endian)
        elif name == "s32":
            value = self._data.read_s32(offset, endian)
        elif name == "s64":
            value = self._data.read_s64(offset, endian)
        elif name == "s128":
            value = self._data.read_s128(offset, endian)
        elif name == "float":
            value = self._data.read_float(offset, endian)
        elif name == "double":
            value = self._data.read_double(offset, endian)
        elif name == "char":
            value = self._data.read_char(offset)
        elif name == "char16":
            value = self._data.read_char16(offset, endian)
        elif name == "bool":
            value = self._data.read_bool(offset)
        elif name == "str":
            decoded, consumed = self._data.read_string(offset)
            return PatternValue(
                value=decoded,
                type_info=type_info,
                offset=offset,
                size=consumed,
            )
        else:
            msg = f"unrecognised primitive type '{name}'"
            raise HexPatTypeError(msg)

        return PatternValue(
            value=value,
            type_info=type_info,
            offset=offset,
            size=type_info.size,
        )

    def _eval_expr(self, node: ExprNode) -> PatternValue:
        """Evaluate an expression node to a runtime PatternValue.

        Args:
            node: The expression AST node to evaluate.

        Returns:
            PatternValue: A PatternValue representing the result of the expression.
        """
        if isinstance(node, (NumberLiteral, FloatLiteral, StringLiteral, CharLiteral, BoolLiteral)):
            return PatternValue(value=node.value)
        if isinstance(node, NullLiteral):
            return PatternValue(value=None)
        if isinstance(node, DollarExpr):
            return PatternValue(value=self._offset)
        if isinstance(node, IdentifierExpr):
            return self._eval_identifier(node)
        if isinstance(node, BinaryExpr):
            return self._eval_binary(node)
        if isinstance(node, UnaryExpr):
            return self._eval_unary(node)
        if isinstance(node, TernaryExpr):
            cond = self._eval_expr(node.condition)
            if _truthy(cond):
                return self._eval_expr(node.true_expr)
            return self._eval_expr(node.false_expr)
        if isinstance(node, FunctionCallExpr):
            return self._eval_call(node)
        if isinstance(node, MemberAccessExpr):
            return self._eval_member_access(node)
        if isinstance(node, NamespaceAccessExpr):
            return self._eval_namespace_access(node)
        if isinstance(node, ArraySubscriptExpr):
            return self._eval_subscript(node)
        if isinstance(node, AssignExpr):
            return self._eval_assign(node)
        if isinstance(node, SizeofExpr):
            return self._eval_sizeof(node)
        if isinstance(node, AddressOfExpr):
            inner = self._eval_expr(node.target)
            return PatternValue(value=inner.offset)
        if isinstance(node, TypeNameOfExpr):
            inner = self._eval_expr(node.target)
            type_name = inner.type_info.name if inner.type_info else "unknown"
            return PatternValue(value=type_name)
        return self._eval_cast(node)

    def _eval_identifier(self, node: IdentifierExpr) -> PatternValue:
        """Evaluate an identifier expression by looking up the variable.

        Args:
            node: The identifier expression AST node.

        Returns:
            PatternValue: The PatternValue bound to the identifier name.

        Raises:
            HexPatRuntimeError: If the identifier is not defined in any scope.
        """
        builtin = self._builtins.get(node.name)
        if builtin is not None:
            return PatternValue(value=builtin)
        value = self._scope.get(node.name)
        if value is None:
            msg = f"undefined variable '{node.name}'"
            raise HexPatRuntimeError(msg, node.line, node.column)
        return value

    def _eval_binary(self, node: BinaryExpr) -> PatternValue:
        """Evaluate a binary expression.

        Args:
            node: The binary expression AST node.

        Returns:
            PatternValue: A PatternValue with the result of applying the operator.

        Raises:
            HexPatRuntimeError: For division by zero or unsupported operations.
        """
        left = self._eval_expr(node.left)
        right = self._eval_expr(node.right)
        lv = left.value
        rv = right.value
        op = node.op

        if op in {"&&", "and"}:
            return PatternValue(value=bool(_truthy(left) and _truthy(right)))
        if op in {"||", "or"}:
            return PatternValue(value=bool(_truthy(left) or _truthy(right)))

        if isinstance(lv, (int, float)) and isinstance(rv, (int, float)):
            numeric_result = self._apply_numeric_op(op, lv, rv, node.line, node.column)
            return PatternValue(value=numeric_result)

        if op in {"==", "!="} and (lv is None or rv is None):
            result_bool = (lv == rv) if op == "==" else (lv != rv)
            return PatternValue(value=result_bool)

        if isinstance(lv, str) and isinstance(rv, str):
            if op == "+":
                return PatternValue(value=lv + rv)
            if op == "==":
                return PatternValue(value=lv == rv)
            if op == "!=":
                return PatternValue(value=lv != rv)

        msg = f"operator '{op}' not supported for these types"
        raise HexPatRuntimeError(msg, node.line, node.column)

    @staticmethod
    def _apply_numeric_op(
        op: str,
        lv: float,
        rv: float,
        line: int,
        column: int,
    ) -> int | float | bool:
        """Apply a binary numeric operator to two numeric values.

        Args:
            op: The operator string.
            lv: The left operand value.
            rv: The right operand value.
            line: Source line for error reporting.
            column: Source column for error reporting.

        Returns:
            int | float | bool: The numeric or boolean result of applying the operator.

        Raises:
            HexPatRuntimeError: For division by zero or unsupported operators.
        """
        if op == "+":
            return lv + rv
        if op == "-":
            return lv - rv
        if op == "*":
            return lv * rv
        if op == "/":
            if rv == 0:
                _logger.error(
                    "hexpat_division_by_zero",
                    operator=op,
                    line=line,
                    column=column,
                )
                msg = "division by zero"
                raise HexPatRuntimeError(msg, line, column)
            return lv / rv if isinstance(lv, float) or isinstance(rv, float) else int(lv) // int(rv)
        if op == "%":
            if rv == 0:
                _logger.error(
                    "hexpat_modulo_by_zero",
                    operator=op,
                    line=line,
                    column=column,
                )
                msg = "modulo by zero"
                raise HexPatRuntimeError(msg, line, column)
            return int(lv) % int(rv)
        if op == "==":
            return lv == rv
        if op == "!=":
            return lv != rv
        if op == "<":
            return lv < rv
        if op == "<=":
            return lv <= rv
        if op == ">":
            return lv > rv
        if op == ">=":
            return lv >= rv
        if op == "&":
            return int(lv) & int(rv)
        if op == "|":
            return int(lv) | int(rv)
        if op == "^":
            return int(lv) ^ int(rv)
        if op == "<<":
            return int(lv) << int(rv)
        if op == ">>":
            return int(lv) >> int(rv)
        if op == "^^":
            return bool(lv) != bool(rv)
        _logger.error(
            "hexpat_unsupported_numeric_operator",
            operator=op,
            line=line,
            column=column,
        )
        msg = f"unsupported operator '{op}' for numeric types"
        raise HexPatRuntimeError(msg, line, column)

    def _eval_unary(self, node: UnaryExpr) -> PatternValue:
        """Evaluate a unary expression.

        Args:
            node: The unary expression AST node.

        Returns:
            PatternValue: A PatternValue with the result of the unary operation.

        Raises:
            HexPatRuntimeError: For unsupported unary operators.
        """
        operand = self._eval_expr(node.operand)
        op = node.op
        val = operand.value

        if op == "-" and ((isinstance(val, int) and not isinstance(val, bool)) or isinstance(val, float)):
            return PatternValue(value=-val)
        if op in {"!", "not"}:
            return PatternValue(value=not _truthy(operand))
        if op == "~" and isinstance(val, int) and not isinstance(val, bool):
            return PatternValue(value=~val)
        msg = f"unsupported unary operator '{op}'"
        raise HexPatRuntimeError(msg, node.line, node.column)

    def _eval_call(self, node: FunctionCallExpr) -> PatternValue:
        """Evaluate a function call expression.

        Args:
            node: The function call AST node.

        Returns:
            PatternValue: The PatternValue returned by the called function.

        Raises:
            HexPatRuntimeError: If the callee is not callable.
        """
        callee = self._eval_expr(node.callee)
        args = [self._eval_expr(a) for a in node.arguments]

        if isinstance(callee.value, BuiltinCallable):
            return callee.value.fn(*args)

        if isinstance(callee.value, FunctionDecl):
            return self._call_user_function(callee.value, args)

        msg = "callee is not callable"
        raise HexPatRuntimeError(msg, node.line, node.column)

    def _call_user_function(
        self,
        decl: FunctionDecl,
        args: list[PatternValue],
    ) -> PatternValue:
        """Call a user-defined pattern function.

        Variadic ``auto ... name`` trailing parameters bind every remaining
        argument into a synthetic :class:`PatternValue` whose ``members`` map
        carries the elements under ``[0]``, ``[1]``, etc. The bound value
        also exposes a ``size`` member equal to the pack length, so library
        helpers using ``std::sizeof_pack`` work transparently.

        Args:
            decl: The function declaration AST node.
            args: The evaluated argument values.

        Returns:
            PatternValue: The PatternValue returned by the function, or null
            when no ``return`` statement runs.

        Raises:
            HexPatRuntimeError: When the caller supplied excess arguments to
                a non-variadic function.
        """
        fn_scope = EvalScope(parent=self._scope)
        last_param = decl.params[-1] if decl.params else None
        is_variadic = last_param is not None and last_param.is_varargs
        for i, param in enumerate(decl.params):
            if param.is_varargs:
                fn_scope.define(param.name, self._build_varargs_pack(args[i:]))
                continue
            if i < len(args):
                fn_scope.define(param.name, args[i])
            elif param.default_value is not None:
                fn_scope.define(param.name, self._eval_expr(param.default_value))
            else:
                fn_scope.define(param.name, PatternValue(value=None))
        if not is_variadic and len(args) > len(decl.params):
            param_count = len(decl.params)
            msg = f"function '{decl.name}' takes {param_count} argument{'s' if param_count != 1 else ''} but {len(args)} were given"
            raise HexPatRuntimeError(msg, decl.line, decl.column)
        saved_scope = self._scope
        self._scope = fn_scope
        try:
            for stmt in decl.body:
                self._eval_stmt(stmt)
        except _ReturnSignalError as sig:
            return sig.value
        finally:
            self._scope = saved_scope
        return PatternValue(value=None)

    @staticmethod
    def _build_varargs_pack(values: list[PatternValue]) -> PatternValue:
        """Bundle a variadic argument tail into a synthetic ``PatternValue``.

        Each element is exposed via the ``[idx]`` indexed member key used by
        :meth:`_eval_subscript`, mirroring how arrays expose their elements.
        A synthetic ``size`` member also carries the pack length so the
        ``std::sizeof_pack`` builtin and user-side ``pack.size`` accesses
        report the correct count.

        Args:
            values: The ordered tail of evaluated arguments.

        Returns:
            PatternValue: A pattern value whose ``members`` map exposes the
            pack contents.
        """
        pack = PatternValue(value=None)
        for idx, pv in enumerate(values):
            pack.members[f"[{idx}]"] = pv
        pack.members["size"] = PatternValue(value=len(values))
        return pack

    def _eval_member_access(self, node: MemberAccessExpr) -> PatternValue:
        """Evaluate a member access expression (obj.member).

        Args:
            node: The member access AST node.

        Returns:
            PatternValue: The PatternValue for the accessed member.

        Raises:
            HexPatRuntimeError: If the member is not found on the object.
        """
        obj = self._eval_expr(node.object_expr)
        member = obj.members.get(node.member)
        if member is not None:
            return member
        msg = f"object has no member '{node.member}'"
        raise HexPatRuntimeError(msg, node.line, node.column)

    def _eval_namespace_access(self, node: NamespaceAccessExpr) -> PatternValue:
        """Evaluate a namespace-qualified access expression (ns::member).

        Resolution order:

        1. Reconstruct the full ``a::b::c::member`` path by walking the chain
           of nested :class:`NamespaceAccessExpr` / :class:`IdentifierExpr`
           nodes from the leftmost component. This recovers the original
           textual identifier from the parser, so multi-segment paths such as
           ``builtin::std::mem::base_address`` map onto a single flat scope
           key without requiring intermediate namespaces to be evaluated.
        2. If the full path is registered in the evaluator builtin table or
           any reachable scope, return the bound :class:`PatternValue`.
        3. Otherwise evaluate the namespace expression normally and look the
           member up among its registered children. This preserves nested
           ``ns_value.members`` access for user-defined namespaces.

        Args:
            node: The namespace access AST node.

        Returns:
            PatternValue: The PatternValue for the accessed namespace member.

        Raises:
            HexPatRuntimeError: If the namespace or member is not found.
        """
        flat_path = self._namespace_path(node)
        if flat_path is not None:
            builtin = self._builtins.get(flat_path)
            if builtin is not None:
                return PatternValue(value=builtin)
            scope_val = self._scope.get(flat_path)
            if scope_val is not None:
                return scope_val
        ns_val = self._eval_expr(node.namespace)
        member = ns_val.members.get(node.member)
        if member is not None:
            return member
        if isinstance(ns_val.value, str):
            qualified = f"{ns_val.value}::{node.member}"
            scope_val = self._scope.get(qualified)
            if scope_val is not None:
                return scope_val
        msg = f"namespace has no member '{node.member}'"
        raise HexPatRuntimeError(msg, node.line, node.column)

    @staticmethod
    def _namespace_path(node: NamespaceAccessExpr) -> str | None:
        """Reconstruct the dotted namespace path from a chain of access nodes.

        Walks the leftmost expression chain starting from ``node``. Returns
        the full ``a::b::c::member`` string when every left-hand component is
        either another :class:`NamespaceAccessExpr` or a single
        :class:`IdentifierExpr`. Returns ``None`` for chains that include
        non-name nodes such as function calls or member-access expressions.

        Args:
            node: The outermost namespace access expression.

        Returns:
            str | None: The flat ``::`` separated path, or ``None`` when the
            chain cannot be reduced to a pure identifier sequence.
        """
        segments: list[str] = [node.member]
        current: ExprNode = node.namespace
        while isinstance(current, NamespaceAccessExpr):
            segments.append(current.member)
            current = current.namespace
        if not isinstance(current, IdentifierExpr):
            return None
        segments.append(current.name)
        segments.reverse()
        return "::".join(segments)

    def _eval_subscript(self, node: ArraySubscriptExpr) -> PatternValue:
        """Evaluate an array subscript expression (arr[idx]).

        Args:
            node: The array subscript AST node.

        Returns:
            PatternValue: The PatternValue for the indexed element.

        Raises:
            HexPatRuntimeError: If the index is out of range or not applicable.
        """
        arr = self._eval_expr(node.array)
        idx_pv = self._eval_expr(node.index)
        idx = idx_pv.value
        if not isinstance(idx, int):
            msg = "array index must be an integer"
            raise HexPatRuntimeError(msg, node.line, node.column)
        member_key = f"[{idx}]"
        child = arr.members.get(member_key)
        if child is not None:
            return child
        if isinstance(arr.value, str) and 0 <= idx < len(arr.value):
            return PatternValue(value=arr.value[idx])
        msg = f"array index {idx} out of range"
        raise HexPatRuntimeError(msg, node.line, node.column)

    def _eval_assign(self, node: AssignExpr) -> PatternValue:
        """Evaluate an assignment expression, updating the target variable or offset.

        Args:
            node: The assignment expression AST node.

        Returns:
            PatternValue: The PatternValue that was assigned.

        Raises:
            HexPatRuntimeError: If the assignment target is unsupported.
        """
        new_val = self._eval_expr(node.value)

        if isinstance(node.target, DollarExpr):
            if isinstance(new_val.value, int):
                if node.op == "=":
                    self._offset = new_val.value
                elif node.op == "+=":
                    self._offset += new_val.value
                elif node.op == "-=":
                    self._offset -= new_val.value
            return PatternValue(value=self._offset)

        if isinstance(node.target, IdentifierExpr):
            name = node.target.name
            existing = self._scope.get(name)
            if node.op != "=" and existing is not None:
                new_val = self._apply_compound_assign(node.op, existing, new_val, node.line, node.column)
            if not self._scope.set(name, new_val):
                self._scope.define(name, new_val)
            return new_val

        if isinstance(node.target, MemberAccessExpr):
            parent = self._eval_expr(node.target.object_expr)
            member_name = node.target.member
            if node.op != "=" and member_name in parent.members:
                new_val = self._apply_compound_assign(node.op, parent.members[member_name], new_val, node.line, node.column)
            parent.members[member_name] = new_val
            return new_val

        msg = "unsupported assignment target"
        raise HexPatRuntimeError(msg, node.line, node.column)

    def _apply_compound_assign(
        self,
        op: str,
        existing: PatternValue,
        new_val: PatternValue,
        line: int,
        column: int,
    ) -> PatternValue:
        """Apply a compound assignment operator to two values.

        Args:
            op: The compound assignment operator string (e.g., "+=", "-=").
            existing: The current value of the target.
            new_val: The right-hand-side value.
            line: Source line for error reporting.
            column: Source column for error reporting.

        Returns:
            PatternValue: The resulting PatternValue after applying the compound operation.

        Raises:
            HexPatRuntimeError: For unsupported operators or type mismatches.
        """
        lv = existing.value
        rv = new_val.value
        if isinstance(lv, (int, float)) and isinstance(rv, (int, float)):
            base_op = op[:-1]
            numeric_result = self._apply_numeric_op(base_op, lv, rv, line, column)
            return PatternValue(value=numeric_result, type_info=existing.type_info)
        msg = f"compound assignment '{op}' not supported for these types"
        raise HexPatRuntimeError(msg, line, column)

    def _eval_sizeof(self, node: SizeofExpr) -> PatternValue:
        """Evaluate a sizeof expression.

        Args:
            node: The sizeof expression AST node.

        Returns:
            PatternValue: A PatternValue containing the size in bytes as an integer.
        """
        target = node.target
        if isinstance(target, (PrimitiveType, NamedType, PointerType, ArrayType, PaddingType, AutoType)):
            size = self._sizeof_type_node(target)
            return PatternValue(value=size)
        pv = self._eval_expr(target)
        return PatternValue(value=pv.size)

    def _sizeof_type_node(self, type_node: TypeNode) -> int:
        """Compute the static byte size of a type node.

        Args:
            type_node: The type node to compute the size of.

        Returns:
            int: The size in bytes, or 0 for variable-size or unknown types.
        """
        if isinstance(type_node, PrimitiveType):
            ptype = self._types.resolve_primitive(type_node.name)
            return ptype.size if ptype is not None and ptype.size > 0 else 0
        if isinstance(type_node, NamedType):
            resolved = self._types.resolve(type_node.name)
            if isinstance(resolved, HexPatType):
                return max(resolved.size, 0)
            if isinstance(resolved, StructTypeInfo):
                return self._sizeof_struct(resolved)
            if isinstance(resolved, UnionTypeInfo):
                return self._sizeof_union(resolved)
            if isinstance(resolved, EnumTypeInfo):
                return resolved.backing_type.size
            if isinstance(resolved, BitfieldTypeInfo):
                return self._sizeof_bitfield(resolved)
        return self._pointer_size if isinstance(type_node, PointerType) else 0

    def _sizeof_struct(self, info: StructTypeInfo) -> int:
        """Compute the total byte size of a struct type.

        Mirrors struct instantiation: includes parent size recursively,
        fixed-size arrays (size * element_size), and the statically-visible
        branch of conditional fields. Placement statements with ``at_offset``
        do not advance the cursor. While-sized arrays contribute zero to the
        static size (matching the caller contract returning 0 for variable
        or unknown sizes).

        Args:
            info: The resolved struct type info.

        Returns:
            int: The total static byte size in bytes, or 0 when it cannot be
            statically determined.
        """
        total = 0
        if info.parent is not None:
            parent_resolved = self._types.resolve(info.parent)
            if isinstance(parent_resolved, StructTypeInfo):
                total += self._sizeof_struct(parent_resolved)
        for stmt in info.decl.body:
            total += self._sizeof_struct_stmt(stmt)
        return total

    def _sizeof_struct_stmt(self, stmt: StmtNode) -> int:
        """Compute the static size contribution of a single struct body statement.

        Args:
            stmt: A statement node from the struct body.

        Returns:
            int: The byte size this statement contributes, or 0 if variable/unknown.
        """
        if isinstance(stmt, FieldDecl):
            return self._sizeof_field_decl(stmt)
        if isinstance(stmt, PlacementStmt):
            return 0 if stmt.at_offset is not None else self._sizeof_placement_stmt(stmt)
        if isinstance(stmt, ConditionalField):
            return self._sizeof_conditional_field(stmt)
        return 0

    def _sizeof_field_decl(self, stmt: FieldDecl) -> int:
        """Compute the static size of a FieldDecl, handling arrays and pointers.

        Args:
            stmt: The field declaration node.

        Returns:
            int: The size in bytes, or 0 if variable/unknown.
        """
        if stmt.is_pointer:
            return self._pointer_size
        element_size = self._sizeof_type_node(stmt.type_node)
        if stmt.array_size is not None:
            size_pv = self._eval_expr(stmt.array_size)
            return element_size * size_pv.value if isinstance(size_pv.value, int) else 0
        return 0 if stmt.while_condition is not None else element_size

    def _sizeof_placement_stmt(self, stmt: PlacementStmt) -> int:
        """Compute the static size contribution of a PlacementStmt.

        Args:
            stmt: The placement statement node.

        Returns:
            int: The size in bytes, or 0 if variable/unknown.
        """
        element_size = self._sizeof_type_node(stmt.type_node)
        if stmt.array_size is not None:
            size_pv = self._eval_expr(stmt.array_size)
            return element_size * size_pv.value if isinstance(size_pv.value, int) else 0
        return 0 if stmt.while_condition is not None else element_size

    def _sizeof_conditional_field(self, stmt: ConditionalField) -> int:
        """Compute the static size of a ConditionalField by evaluating the branch.

        Evaluates the condition statically; selects the true branch when the
        condition is truthy, else the false branch.

        Args:
            stmt: The conditional field node.

        Returns:
            int: The total byte size of the selected branch, or 0 when undetermined.
        """
        try:
            cond = self._eval_expr(stmt.condition)
        except (HexPatRuntimeError, HexPatTypeError):
            _logger.warning("hexpat_sizeof_conditional_eval_failed", line=stmt.line)
            return 0
        branch = stmt.true_fields if _truthy(cond) else stmt.false_fields
        return sum(self._sizeof_struct_stmt(inner) for inner in branch)

    def _sizeof_union(self, info: UnionTypeInfo) -> int:
        """Compute the byte size of a union type (maximum field size).

        Args:
            info: The resolved union type info.

        Returns:
            int: The size of the largest field in bytes.
        """
        max_size = 0
        for stmt in info.decl.body:
            if isinstance(stmt, FieldDecl):
                field_size = self._sizeof_field_decl(stmt)
                max_size = max(max_size, field_size)
            elif isinstance(stmt, PlacementStmt) and stmt.at_offset is None:
                max_size = max(max_size, self._sizeof_placement_stmt(stmt))
            elif isinstance(stmt, ConditionalField):
                max_size = max(max_size, self._sizeof_conditional_field(stmt))
        return max_size

    def _sizeof_bitfield(self, info: BitfieldTypeInfo) -> int:
        """Compute the byte size of a bitfield type.

        Args:
            info: The resolved bitfield type info.

        Returns:
            int: The total size rounded up to the nearest byte.
        """
        total_bits = 0
        for entry in info.decl.entries:
            wv = self._eval_expr(entry.width)
            if isinstance(wv.value, int):
                total_bits += wv.value
        return (total_bits + 7) // 8

    def _eval_cast(self, node: CastExpr) -> PatternValue:
        """Evaluate a type cast expression.

        Casts to a resolved primitive apply numeric coercion with masking or
        float conversion. Casts to a named type resolving to an enum or
        bitfield coerce the source to an integer using the backing primitive.
        Casts to a struct/union target pass the source value through unchanged.

        Args:
            node: The cast expression AST node.

        Returns:
            PatternValue: A PatternValue with the value coerced to the target type.
        """
        value = self._eval_expr(node.expr)
        target_prim = self._resolve_type_node_to_primitive(node.target_type)
        if target_prim is None:
            if isinstance(node.target_type, NamedType):
                resolved = self._types.resolve(node.target_type.name)
                if isinstance(resolved, EnumTypeInfo):
                    return self._coerce_to_integer_primitive(value, resolved.backing_type, node.line, node.column)
                if isinstance(resolved, BitfieldTypeInfo):
                    total_bytes = self._sizeof_bitfield(resolved)
                    bits = total_bytes * 8
                    bf_prim = HexPatType(
                        name=resolved.name,
                        size=total_bytes if total_bytes > 0 else 1,
                        signed=False,
                        endian=self._default_endian,
                    )
                    coerced = self._coerce_to_integer_primitive(value, bf_prim, node.line, node.column)
                    if isinstance(coerced.value, int) and bits > 0:
                        coerced = PatternValue(value=coerced.value & ((1 << bits) - 1), type_info=bf_prim)
                    return coerced
            return value
        return self._cast_to_primitive(value, target_prim, node.line, node.column)

    def _cast_to_primitive(
        self,
        value: PatternValue,
        target_prim: HexPatType,
        line: int,
        column: int,
    ) -> PatternValue:
        """Coerce a PatternValue to a primitive target type.

        Args:
            value: The source PatternValue.
            target_prim: The primitive HexPatType to coerce to.
            line: Source line number for error reporting.
            column: Source column number for error reporting.

        Returns:
            PatternValue: A new PatternValue with the coerced value.
        """
        raw = value.value
        if target_prim.name in {"float", "double"}:
            if isinstance(raw, (int, float)) and not isinstance(raw, bool):
                return PatternValue(value=float(raw), type_info=target_prim)
            return (
                PatternValue(value=float(int(raw)), type_info=target_prim)
                if isinstance(raw, bool)
                else PatternValue(value=raw, type_info=target_prim)
            )
        if target_prim.name == "bool":
            return PatternValue(value=bool(raw), type_info=target_prim)
        return self._coerce_to_integer_primitive(value, target_prim, line, column)

    @staticmethod
    def _coerce_to_integer_primitive(
        value: PatternValue,
        target_prim: HexPatType,
        line: int,
        column: int,
    ) -> PatternValue:
        """Coerce a PatternValue to an integer-backed primitive.

        Applies bit-width masking for sized unsigned primitives and
        two's-complement wrapping for signed primitives. Float sources
        are truncated toward zero; conversion failures (overflow, NaN,
        infinity) raise a runtime error.

        Args:
            value: The source PatternValue.
            target_prim: The primitive HexPatType whose size and signedness govern coercion.
            line: Source line number for error reporting.
            column: Source column number for error reporting.

        Returns:
            PatternValue: A new PatternValue holding an integer coerced to the target's width.

        Raises:
            HexPatRuntimeError: If a float value cannot be converted to an integer.
        """
        raw = value.value
        if isinstance(raw, bool):
            return PatternValue(value=int(raw), type_info=target_prim)
        if isinstance(raw, float):
            if math.isnan(raw) or math.isinf(raw):
                msg = f"cannot convert non-finite float to integer type '{target_prim.name}'"
                raise HexPatRuntimeError(msg, line, column)
            try:
                int_val = int(raw)
            except (OverflowError, ValueError) as exc:
                _logger.warning("hexpat_float_to_int_conversion_failed", target_type=target_prim.name, error=str(exc))
                msg = f"cannot convert float to integer type '{target_prim.name}': {exc}"
                raise HexPatRuntimeError(msg, line, column) from exc
        elif isinstance(raw, int):
            int_val = raw
        elif isinstance(raw, str) and raw:
            int_val = ord(raw[0])
        else:
            return PatternValue(value=raw, type_info=target_prim)

        if target_prim.signed and target_prim.size > 0:
            bits = target_prim.size * 8
            max_signed = (1 << (bits - 1)) - 1
            int_val &= (1 << bits) - 1
            if int_val > max_signed:
                int_val -= 1 << bits
        elif not target_prim.signed and target_prim.size > 0:
            bits = target_prim.size * 8
            int_val &= (1 << bits) - 1
        return PatternValue(value=int_val, type_info=target_prim)

    def _resolve_type_node_to_primitive(self, type_node: TypeNode) -> HexPatType | None:
        """Resolve a type node to a HexPatType primitive if possible.

        Args:
            type_node: The type node to resolve.

        Returns:
            HexPatType | None: A HexPatType if the node is or resolves to a primitive, else None.
        """
        if isinstance(type_node, PrimitiveType):
            return self._types.resolve_primitive(type_node.name, type_node.endianness)
        if isinstance(type_node, NamedType):
            template_arg = self._lookup_template_arg(type_node.name)
            if isinstance(template_arg, (PrimitiveType, NamedType)):
                return self._resolve_type_node_to_primitive(template_arg)
            resolved = self._types.resolve(type_node.name)
            if isinstance(resolved, HexPatType):
                return resolved
        return None

    def _lookup_template_arg(self, name: str) -> TypeNode | None:
        """Return the type-node bound to ``name`` by an active template scope.

        Args:
            name: The unqualified template parameter identifier to resolve.

        Returns:
            TypeNode | None: The bound type node, or ``None`` when the name
            is not a template parameter in any active scope.
        """
        for frame in reversed(self._template_args_stack):
            bound = frame.get(name)
            if isinstance(bound, (PrimitiveType, NamedType, ArrayType, PointerType, PaddingType, AutoType)):
                return bound
        return None

    def _instantiate_template_named_type(
        self,
        type_node: NamedType,
        lookup_name: str,
        var_name: str,
        offset: int,
        color: str,
        description: str,
    ) -> dict[str, Any] | None:
        """Instantiate a generic named type with explicit template arguments.

        Substitutes the supplied template arguments into the declared template
        parameter list and dispatches to the underlying struct/union/etc.
        instantiation. The bindings persist on a stack so nested type
        references inside the body resolve through ``_lookup_template_arg``.
        Argument-count mismatches surface as :class:`HexPatTypeError` from
        :meth:`_bind_template_args`.

        Args:
            type_node: The NamedType AST node carrying ``template_args``.
            lookup_name: The fully qualified name of the underlying type.
            var_name: The variable name for the resulting field.
            offset: Byte offset at which to instantiate the type.
            color: Hex colour string for UI highlighting.
            description: Optional description annotation.

        Returns:
            dict[str, Any] | None: The resulting parsed-field dict, or
            ``None`` when the underlying type cannot be located.
        """
        resolved = self._types.resolve(lookup_name)
        if resolved is None and type_node.namespace:
            resolved = self._types.resolve(type_node.name)
        params: tuple[TemplateParam, ...] = ()
        if isinstance(resolved, StructTypeInfo):
            params = resolved.decl.template_params
        elif resolved is None:
            return None
        bindings = self._bind_template_args(params, type_node.template_args, type_node.line, type_node.column, lookup_name)
        self._template_args_stack.append(bindings)
        try:
            if isinstance(resolved, StructTypeInfo):
                return self._eval_struct_instance(resolved.name, resolved, var_name, offset, color, description)
            if isinstance(resolved, UnionTypeInfo):
                return self._eval_union_instance(resolved.name, resolved, var_name, offset, color, description)
            if isinstance(resolved, EnumTypeInfo):
                return self._eval_enum_instance(resolved.name, resolved, var_name, offset, color, description)
            if isinstance(resolved, BitfieldTypeInfo):
                return self._eval_bitfield_instance(resolved.name, resolved, var_name, offset, color, description)
            pv = self._read_primitive(resolved, offset)
            raw = self._data.read(offset, resolved.size)
            display = self._format_value(pv.value, resolved)
            return _make_parsed_field(var_name, offset, resolved.size, raw, display, [], color, description)
        finally:
            self._template_args_stack.pop()

    def _bind_template_args(
        self,
        params: tuple[TemplateParam, ...],
        args: tuple[ExprNode, ...],
        line: int,
        column: int,
        type_name: str,
    ) -> dict[str, ExprNode | TypeNode]:
        """Bind a tuple of template arguments onto a parameter declaration list.

        Args:
            params: The declared template parameters.
            args: The expressions supplied at the call site. Identifier
                expressions are interpreted as named-type references; numeric
                expressions remain as constant value bindings.
            line: Source line for error reporting.
            column: Source column for error reporting.
            type_name: The fully qualified name of the type being instantiated.

        Returns:
            dict[str, ExprNode | TypeNode]: A name → bound type-node mapping
            for type parameters, plus value-bound expressions for non-auto
            parameters used as numeric template arguments.

        Raises:
            HexPatTypeError: When the argument count does not match the
                declared parameter list.
        """
        if len(args) != len(params):
            msg = (
                f"template type '{type_name}' takes {len(params)} parameter{'s' if len(params) != 1 else ''} but {len(args)} were supplied"
            )
            _logger.warning("bind_template_args_arity_mismatch", type_name=type_name, param_count=len(params), arg_count=len(args))
            raise HexPatTypeError(msg, line, column)
        bindings: dict[str, ExprNode | TypeNode] = {
            param.name: self._template_arg_to_type_node(arg) for param, arg in zip(params, args, strict=True)
        }
        return bindings

    @staticmethod
    def _template_arg_to_type_node(expr: ExprNode) -> TypeNode | ExprNode:
        """Coerce a template-argument expression to a type node when possible.

        Identifier expressions reference user-defined types or primitive
        names, so they map onto :class:`NamedType` references. Other
        expressions are returned unchanged so the evaluator can later treat
        them as runtime values.

        Args:
            expr: The expression appearing inside the ``< ... >`` arguments.

        Returns:
            TypeNode | ExprNode: A type node for identifier-like arguments or
            the original expression otherwise.
        """
        if isinstance(expr, IdentifierExpr):
            primitive = BuiltinTypes.get(expr.name)
            if primitive is not None:
                return PrimitiveType(name=expr.name, endianness=None, line=expr.line, column=expr.column)
            return NamedType(name=expr.name, namespace=None, line=expr.line, column=expr.column)
        return expr

    def _extract_description(
        self,
        annotations: tuple[tuple[str, ExprNode | None], ...],
    ) -> str:
        """Extract a description string from field annotations.

        Args:
            annotations: Tuple of (name, value_expr) annotation pairs.

        Returns:
            str: The description string, or empty string if not present.
        """
        for ann_name, ann_expr in annotations:
            if ann_name == "comment" and ann_expr is not None:
                pv = self._eval_expr(ann_expr)
                if isinstance(pv.value, str):
                    return pv.value
        return ""

    def _build_builtins(self) -> dict[str, BuiltinCallable]:
        """Construct the built-in function table.

        Returns:
            dict[str, BuiltinCallable]: A dict mapping function name to a BuiltinCallable wrapper.
        """
        data = self._data

        def builtin_sizeof(*args: PatternValue) -> PatternValue:
            return PatternValue(value=args[0].size) if args else PatternValue(value=0)

        def builtin_addressof(*args: PatternValue) -> PatternValue:
            return PatternValue(value=args[0].offset) if args else PatternValue(value=0)

        def builtin_typenameof(*args: PatternValue) -> PatternValue:
            if args:
                ti = args[0].type_info
                return PatternValue(value=ti.name if ti else "unknown")
            return PatternValue(value="unknown")

        def builtin_assert(*args: PatternValue) -> PatternValue:
            if args and not _truthy(args[0]):
                assert_default = "assertion failed"
                error_msg = args[1].value if len(args) > 1 else assert_default
                resolved = str(error_msg) if error_msg is not None else assert_default
                _logger.error("hexpat_builtin_assert_failed", assert_message=resolved)
                raise HexPatRuntimeError(resolved)
            return PatternValue(value=None)

        def builtin_read_unsigned(*args: PatternValue) -> PatternValue:
            if len(args) < 2:
                return PatternValue(value=0)
            off = args[0].value
            sz = args[1].value
            if not isinstance(off, int) or not isinstance(sz, int):
                return PatternValue(value=0)
            raw = data.read(off, sz)
            return PatternValue(value=int.from_bytes(raw, byteorder="little"))

        def builtin_read_signed(*args: PatternValue) -> PatternValue:
            if len(args) < 2:
                return PatternValue(value=0)
            off = args[0].value
            sz = args[1].value
            if not isinstance(off, int) or not isinstance(sz, int):
                return PatternValue(value=0)
            raw = data.read(off, sz)
            return PatternValue(value=int.from_bytes(raw, byteorder="little", signed=True))

        def builtin_read_string(*args: PatternValue) -> PatternValue:
            if not args:
                return PatternValue(value="")
            off = args[0].value
            if not isinstance(off, int):
                return PatternValue(value="")
            decoded, _ = data.read_string(off)
            return PatternValue(value=decoded)

        def builtin_find_sequence(*args: PatternValue) -> PatternValue:
            if len(args) < 2:
                return PatternValue(value=-1)
            off = args[0].value
            seq_val = args[1].value
            if isinstance(off, int) and isinstance(seq_val, (bytes, str)):
                pat = seq_val if isinstance(seq_val, bytes) else seq_val.encode()
                return PatternValue(value=data.find_sequence(pat, off))
            return PatternValue(value=-1)

        def builtin_min(*args: PatternValue) -> PatternValue:
            nums = [a.value for a in args if isinstance(a.value, (int, float)) and not isinstance(a.value, bool)]
            return PatternValue(value=min(nums)) if nums else PatternValue(value=0)

        def builtin_max(*args: PatternValue) -> PatternValue:
            nums = [a.value for a in args if isinstance(a.value, (int, float)) and not isinstance(a.value, bool)]
            return PatternValue(value=max(nums)) if nums else PatternValue(value=0)

        def builtin_abs(*args: PatternValue) -> PatternValue:
            if args:
                v = args[0].value
                if isinstance(v, int) and not isinstance(v, bool):
                    return PatternValue(value=abs(v))
                if isinstance(v, float):
                    return PatternValue(value=abs(v))
            return PatternValue(value=0)

        def builtin_strlen(*args: PatternValue) -> PatternValue:
            if args and isinstance(args[0].value, str):
                return PatternValue(value=len(args[0].value))
            return PatternValue(value=0)

        names_and_fns: list[tuple[str, Callable[..., PatternValue]]] = [
            ("sizeof", builtin_sizeof),
            ("addressof", builtin_addressof),
            ("typenameof", builtin_typenameof),
            ("assert", builtin_assert),
            ("read_unsigned", builtin_read_unsigned),
            ("read_signed", builtin_read_signed),
            ("read_string", builtin_read_string),
            ("find_sequence", builtin_find_sequence),
            ("min", builtin_min),
            ("max", builtin_max),
            ("abs", builtin_abs),
            ("strlen", builtin_strlen),
        ]
        return {n: BuiltinCallable(fn=f, name=n) for n, f in names_and_fns}


def _truthy(value: PatternValue) -> bool:
    """Determine the boolean truthiness of a PatternValue.

    Args:
        value: The PatternValue to test.

    Returns:
        bool: True if the value is considered truthy, False otherwise.
    """
    v = value.value
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v != 0
    return bool(v) if isinstance(v, (float, str, bytes)) else True


def _values_equal(a: PatternValue, b: PatternValue) -> bool:
    """Test whether two PatternValues are equal for match-arm comparison.

    Args:
        a: The first value to compare.
        b: The second value to compare.

    Returns:
        bool: True if both values are equal, False otherwise.
    """
    av = a.value
    bv = b.value
    if av is None and bv is None:
        return True
    if isinstance(av, bool) and isinstance(bv, bool):
        return av == bv
    if isinstance(av, (int, float)) and isinstance(bv, (int, float)):
        return av == bv
    return av == bv if isinstance(av, str) and isinstance(bv, str) else False
