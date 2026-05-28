# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
# This file is part of Intellicrack. See LICENSE for details.
"""Runtime type registry for the HexPat pattern language evaluator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from intellicrack.core.hexpat.errors import HexPatTypeError
from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from typing import ClassVar

    from intellicrack.core.hexpat.ast_nodes import (
        BitfieldDecl,
        EnumDecl,
        StructDecl,
        UnionDecl,
    )


_logger = get_logger(__name__)


@dataclass(frozen=True)
class HexPatType:
    """A resolved primitive type.

    Attributes:
        name: The primitive type name, e.g. "u32" or "float".
        size: Byte size of this type, or -1 for variable-size types.
        signed: Whether this is a signed integer type.
        endian: Endianness override ("little", "big"), or None to use the default.
    """

    name: str
    size: int
    signed: bool
    endian: str | None


class BuiltinTypes:
    """Registry of all built-in primitive types for the HexPat pattern language."""

    _TYPES: ClassVar[dict[str, HexPatType]] = {
        "u8": HexPatType("u8", 1, signed=False, endian=None),
        "u16": HexPatType("u16", 2, signed=False, endian=None),
        "u32": HexPatType("u32", 4, signed=False, endian=None),
        "u64": HexPatType("u64", 8, signed=False, endian=None),
        "u128": HexPatType("u128", 16, signed=False, endian=None),
        "s8": HexPatType("s8", 1, signed=True, endian=None),
        "s16": HexPatType("s16", 2, signed=True, endian=None),
        "s32": HexPatType("s32", 4, signed=True, endian=None),
        "s64": HexPatType("s64", 8, signed=True, endian=None),
        "s128": HexPatType("s128", 16, signed=True, endian=None),
        "float": HexPatType("float", 4, signed=False, endian=None),
        "double": HexPatType("double", 8, signed=False, endian=None),
        "char": HexPatType("char", 1, signed=False, endian=None),
        "char16": HexPatType("char16", 2, signed=False, endian=None),
        "bool": HexPatType("bool", 1, signed=False, endian=None),
        "str": HexPatType("str", -1, signed=False, endian=None),
        "padding": HexPatType("padding", -1, signed=False, endian=None),
        "auto": HexPatType("auto", -1, signed=False, endian=None),
    }

    @staticmethod
    def get(name: str) -> HexPatType | None:
        """Return the built-in type for the given name, or None if not found.

        Args:
            name: The primitive type name to look up.

        Returns:
            HexPatType | None: The matching HexPatType, or None if the name is not a built-in type.
        """
        return BuiltinTypes._TYPES.get(name)

    @staticmethod
    def all_names() -> frozenset[str]:
        """Return the frozenset of all built-in primitive type names.

        Returns:
            frozenset[str]: A frozenset containing every supported primitive type name.
        """
        return frozenset(BuiltinTypes._TYPES)

    @staticmethod
    def is_reserved_name(name: str) -> bool:
        """Return whether ``name`` collides with a built-in primitive type.

        Used by :class:`TypeRegistry` registration entry points to reject
        user declarations that would shadow language primitives such as
        ``u32`` or ``float``.

        Args:
            name: Candidate identifier to check.

        Returns:
            bool: ``True`` when ``name`` is a built-in primitive, ``False``
                otherwise.
        """
        return name in BuiltinTypes._TYPES


@dataclass
class StructTypeInfo:
    """Resolved struct type definition.

    Attributes:
        name: The struct type name identifier.
        parent: Optional name of the parent struct this struct inherits from.
        decl: The original AST struct declaration node.
    """

    name: str
    parent: str | None
    decl: StructDecl


@dataclass
class UnionTypeInfo:
    """Resolved union type definition.

    Attributes:
        name: The union type name identifier.
        decl: The original AST union declaration node.
    """

    name: str
    decl: UnionDecl


@dataclass
class EnumTypeInfo:
    """Resolved enum type definition.

    Attributes:
        name: The enum type name identifier.
        backing_type: The primitive type used to store enum values.
        members: Mapping from member name to its integer value.
        decl: The original AST enum declaration node.
    """

    name: str
    backing_type: HexPatType
    members: dict[str, int]
    decl: EnumDecl


@dataclass
class BitfieldTypeInfo:
    """Resolved bitfield type definition.

    Attributes:
        name: The bitfield type name identifier.
        decl: The original AST bitfield declaration node.
    """

    name: str
    decl: BitfieldDecl


class TypeRegistry:
    """Resolves type names to their definitions during pattern evaluation.

    Maintains separate lookup tables for struct, union, enum, bitfield, and alias type definitions. Alias resolution is performed
    transparently through the resolve method.
    """

    def __init__(self) -> None:
        """Initialize the TypeRegistry instance."""
        self._structs: dict[str, StructTypeInfo] = {}
        self._unions: dict[str, UnionTypeInfo] = {}
        self._enums: dict[str, EnumTypeInfo] = {}
        self._bitfields: dict[str, BitfieldTypeInfo] = {}
        self._aliases: dict[str, str] = {}
        self._all_names: set[str] = set()
        _logger.debug("hexpat_type_registry_initialized")

    def _record_qualified(self, name: str, namespace: str | None) -> str | None:
        """Record an aggregate type's local name and return its qualified alias.

        Args:
            name: The unqualified declared name to add to ``_all_names``.
            namespace: Optional ``::``-joined namespace prefix.

        Returns:
            str | None: The fully qualified ``namespace::name`` when a
            namespace is supplied, otherwise ``None``. The qualified name
            (when present) is also added to ``_all_names`` for the caller's
            reverse lookup.
        """
        self._all_names.add(name)
        if not namespace:
            return None
        qualified = f"{namespace}::{name}"
        self._all_names.add(qualified)
        return qualified

    def register_struct(self, decl: StructDecl, namespace: str | None = None) -> None:
        """Register a struct type declaration.

        When ``namespace`` is supplied, the struct is registered under both
        the local ``decl.name`` and the fully qualified ``namespace::name``.
        Local-name collisions resolve to the most recently registered
        declaration; fully qualified registrations never collide unless the
        caller actually re-declares the same qualified path.

        Args:
            decl: The struct AST declaration to register.
            namespace: Optional ``::``-joined namespace prefix.

        Raises:
            HexPatTypeError: When ``decl.name`` collides with a built-in
                primitive type.
        """
        if BuiltinTypes.is_reserved_name(decl.name):
            _logger.error(
                "hexpat_struct_redeclares_builtin",
                name=decl.name,
                namespace=namespace,
                line=decl.line,
                column=decl.column,
            )
            msg = f"cannot redeclare built-in type '{decl.name}'"
            raise HexPatTypeError(msg, decl.line, decl.column)
        info = StructTypeInfo(name=decl.name, parent=decl.parent, decl=decl)
        self._structs[decl.name] = info
        qualified = self._record_qualified(decl.name, namespace)
        if qualified is not None:
            self._structs[qualified] = info

    def register_union(self, decl: UnionDecl, namespace: str | None = None) -> None:
        """Register a union type declaration.

        Args:
            decl: The union AST declaration to register.
            namespace: Optional ``::``-joined namespace prefix; when set the
                union is also registered under the qualified path.

        Raises:
            HexPatTypeError: When ``decl.name`` collides with a built-in
                primitive type.
        """
        if BuiltinTypes.is_reserved_name(decl.name):
            msg = f"cannot redeclare built-in type '{decl.name}'"
            raise HexPatTypeError(msg, decl.line, decl.column)
        info = UnionTypeInfo(name=decl.name, decl=decl)
        self._unions[decl.name] = info
        qualified = self._record_qualified(decl.name, namespace)
        if qualified is not None:
            self._unions[qualified] = info

    def register_enum(
        self,
        decl: EnumDecl,
        backing: HexPatType,
        members: dict[str, int],
        namespace: str | None = None,
    ) -> None:
        """Register an enum type declaration with its resolved backing type and member values.

        Args:
            decl: The enum AST declaration to register.
            backing: The resolved primitive type that backs the enum values.
            members: Mapping from enum member name to its integer value.
            namespace: Optional ``::``-joined namespace prefix; when set the
                enum is also registered under the qualified path.

        Raises:
            HexPatTypeError: When ``decl.name`` collides with a built-in
                primitive type.
        """
        if BuiltinTypes.is_reserved_name(decl.name):
            msg = f"cannot redeclare built-in type '{decl.name}'"
            raise HexPatTypeError(msg, decl.line, decl.column)
        info = EnumTypeInfo(
            name=decl.name,
            backing_type=backing,
            members=members,
            decl=decl,
        )
        self._enums[decl.name] = info
        qualified = self._record_qualified(decl.name, namespace)
        if qualified is not None:
            self._enums[qualified] = info

    def register_bitfield(self, decl: BitfieldDecl, namespace: str | None = None) -> None:
        """Register a bitfield type declaration.

        Args:
            decl: The bitfield AST declaration to register.
            namespace: Optional ``::``-joined namespace prefix; when set the
                bitfield is also registered under the qualified path.

        Raises:
            HexPatTypeError: When ``decl.name`` collides with a built-in
                primitive type.
        """
        if BuiltinTypes.is_reserved_name(decl.name):
            msg = f"cannot redeclare built-in type '{decl.name}'"
            raise HexPatTypeError(msg, decl.line, decl.column)
        info = BitfieldTypeInfo(name=decl.name, decl=decl)
        self._bitfields[decl.name] = info
        qualified = self._record_qualified(decl.name, namespace)
        if qualified is not None:
            self._bitfields[qualified] = info

    def register_alias(
        self,
        alias: str,
        target_name: str,
        line: int = 0,
        column: int = 0,
    ) -> None:
        """Register a type alias mapping ``alias`` to ``target_name``.

        Args:
            alias: The alias name to register.
            target_name: The name of the type that the alias resolves to.
            line: Source line of the originating ``using`` declaration, used
                when raising :class:`HexPatTypeError`.
            column: Source column of the originating ``using`` declaration,
                used when raising :class:`HexPatTypeError`.

        Raises:
            HexPatTypeError: When ``alias`` collides with a built-in
                primitive type.
        """
        if BuiltinTypes.is_reserved_name(alias):
            msg = f"cannot redeclare built-in type '{alias}'"
            raise HexPatTypeError(msg, line, column)
        self._aliases[alias] = target_name
        self._all_names.add(alias)

    def user_type_names(self) -> frozenset[str]:
        """Return every currently-registered user type name.

        Includes both unqualified and ``namespace::``-qualified aliases.
        The result excludes built-in primitive type names; combine with
        :meth:`BuiltinTypes.all_names` to obtain the full identifier
        completion set.

        Returns:
            frozenset[str]: Snapshot of user-declared identifiers.
        """
        return frozenset(self._all_names)

    def resolve(self, name: str) -> HexPatType | StructTypeInfo | UnionTypeInfo | EnumTypeInfo | BitfieldTypeInfo | None:
        """Resolve a type name to its definition, following aliases.

        Checks built-in primitives, then user-defined structs, unions, enums,
        bitfields, and finally aliases. Alias chains are followed recursively up
        to a fixed depth to prevent infinite loops.

        Args:
            name: The type name to resolve.

        Returns:
            HexPatType | StructTypeInfo | UnionTypeInfo | EnumTypeInfo | BitfieldTypeInfo | None: The resolved type info, or None if the name is not registered.
        """
        visited: set[str] = set()
        current = name
        while current not in visited:
            visited.add(current)
            builtin = BuiltinTypes.get(current)
            if builtin is not None:
                return builtin
            if current in self._structs:
                return self._structs[current]
            if current in self._unions:
                return self._unions[current]
            if current in self._enums:
                return self._enums[current]
            if current in self._bitfields:
                return self._bitfields[current]
            if current in self._aliases:
                current = self._aliases[current]
            else:
                break
        return None

    def resolve_primitive(
        self,
        name: str,
        endian: str | None = None,
    ) -> HexPatType | None:
        """Resolve a type name to a primitive HexPatType, optionally overriding endianness.

        Follows aliases until a primitive type is found. Returns None if the
        resolved type is not a primitive.

        Args:
            name: The type name to resolve.
            endian: Optional endianness override ("little" or "big") applied to
                the returned HexPatType.

        Returns:
            HexPatType | None: A HexPatType with the requested endianness applied, or None if the
            name does not resolve to a primitive type.
        """
        resolved = self.resolve(name)
        if not isinstance(resolved, HexPatType):
            return None
        if endian is None or endian == resolved.endian:
            return resolved
        return HexPatType(
            name=resolved.name,
            size=resolved.size,
            signed=resolved.signed,
            endian=endian,
        )
