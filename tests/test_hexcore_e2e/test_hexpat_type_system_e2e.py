# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for the HexPat type system: BuiltinTypes registry and TypeRegistry."""

from __future__ import annotations

import pytest


pytest.importorskip("intellicrack.core.hexpat.type_system", reason="hexpat type_system not available")

from intellicrack.core.hexpat.ast_nodes import (
    EnumDecl,
    PrimitiveType,
    StructDecl,
    UnionDecl,
)
from intellicrack.core.hexpat.type_system import (
    BuiltinTypes,
    EnumTypeInfo,
    HexPatType,
    StructTypeInfo,
    TypeRegistry,
    UnionTypeInfo,
)


_EXPECTED_BUILTIN_NAMES: frozenset[str] = frozenset({
    "u8",
    "u16",
    "u32",
    "u64",
    "s8",
    "s16",
    "s32",
    "s64",
    "float",
    "double",
    "char",
    "char16",
    "bool",
    "str",
    "padding",
    "auto",
})


class TestBuiltinTypes:
    """Tests for the BuiltinTypes static registry."""

    def test_get_u8_returns_hexpat_type(self) -> None:
        """BuiltinTypes.get('u8') returns a HexPatType instance.

        Returns:
            None
        """
        result = BuiltinTypes.get("u8")
        assert isinstance(result, HexPatType)

    def test_get_u8_size_is_one(self) -> None:
        """BuiltinTypes.get('u8') has size 1.

        Returns:
            None
        """
        result = BuiltinTypes.get("u8")
        assert result is not None
        assert result.size == 1

    def test_get_u8_is_unsigned(self) -> None:
        """BuiltinTypes.get('u8') is unsigned (signed=False).

        Returns:
            None
        """
        result = BuiltinTypes.get("u8")
        assert result is not None
        assert result.signed is False

    def test_get_s32_size_is_four(self) -> None:
        """BuiltinTypes.get('s32') has size 4.

        Returns:
            None
        """
        result = BuiltinTypes.get("s32")
        assert result is not None
        assert result.size == 4

    def test_get_s32_is_signed(self) -> None:
        """BuiltinTypes.get('s32') is signed (signed=True).

        Returns:
            None
        """
        result = BuiltinTypes.get("s32")
        assert result is not None
        assert result.signed is True

    def test_get_float_size_is_four(self) -> None:
        """BuiltinTypes.get('float') has size 4.

        Returns:
            None
        """
        result = BuiltinTypes.get("float")
        assert result is not None
        assert result.size == 4

    def test_get_double_size_is_eight(self) -> None:
        """BuiltinTypes.get('double') has size 8.

        Returns:
            None
        """
        result = BuiltinTypes.get("double")
        assert result is not None
        assert result.size == 8

    def test_get_nonexistent_returns_none(self) -> None:
        """BuiltinTypes.get with an unknown name returns None.

        Returns:
            None
        """
        result = BuiltinTypes.get("nonexistent_type")
        assert result is None

    def test_all_names_returns_frozenset(self) -> None:
        """BuiltinTypes.all_names() returns a frozenset.

        Returns:
            None
        """
        names = BuiltinTypes.all_names()
        assert isinstance(names, frozenset)

    def test_all_names_contains_expected_types(self) -> None:
        """BuiltinTypes.all_names() contains all expected primitive type names.

        Returns:
            None
        """
        names = BuiltinTypes.all_names()
        assert names >= _EXPECTED_BUILTIN_NAMES


class TestTypeRegistry:
    """Tests for the TypeRegistry class."""

    def test_register_struct_resolve_returns_struct_type_info(self) -> None:
        """Registering a struct and resolving its name returns StructTypeInfo.

        Returns:
            None
        """
        registry = TypeRegistry()
        decl = StructDecl(
            name="TestStruct",
            parent=None,
            body=(),
            annotations=(),
            line=1,
            column=1,
        )
        registry.register_struct(decl)
        result = registry.resolve("TestStruct")
        assert isinstance(result, StructTypeInfo)

    def test_register_struct_name_preserved(self) -> None:
        """StructTypeInfo resolved from registry has the correct name.

        Returns:
            None
        """
        registry = TypeRegistry()
        decl = StructDecl(
            name="MyStruct",
            parent=None,
            body=(),
            annotations=(),
            line=1,
            column=1,
        )
        registry.register_struct(decl)
        result = registry.resolve("MyStruct")
        assert isinstance(result, StructTypeInfo)
        assert result.name == "MyStruct"

    def test_register_struct_with_parent(self) -> None:
        """StructTypeInfo resolved from registry carries the parent name.

        Returns:
            None
        """
        registry = TypeRegistry()
        decl = StructDecl(
            name="Child",
            parent="Parent",
            body=(),
            annotations=(),
            line=1,
            column=1,
        )
        registry.register_struct(decl)
        result = registry.resolve("Child")
        assert isinstance(result, StructTypeInfo)
        assert result.parent == "Parent"

    def test_register_alias_resolve_follows_to_primitive(self) -> None:
        """Registering an alias for u32 resolves transparently to HexPatType.

        Returns:
            None
        """
        registry = TypeRegistry()
        registry.register_alias("DWORD", "u32")
        result = registry.resolve("DWORD")
        assert isinstance(result, HexPatType)
        assert result.name == "u32"

    def test_resolve_primitive_u32_returns_hex_pat_type(self) -> None:
        """Resolving the primitive 'u32' returns a HexPatType instance.

        Returns:
            None
        """
        registry = TypeRegistry()
        result = registry.resolve("u32")
        assert isinstance(result, HexPatType)

    def test_resolve_primitive_u32_size_is_four(self) -> None:
        """Resolving 'u32' yields size 4.

        Returns:
            None
        """
        registry = TypeRegistry()
        result = registry.resolve("u32")
        assert isinstance(result, HexPatType)
        assert result.size == 4

    def test_resolve_primitive_with_endian_override(self) -> None:
        """resolve_primitive with endian override returns a new HexPatType with that endian.

        Returns:
            None
        """
        registry = TypeRegistry()
        result = registry.resolve_primitive("u32", endian="big")
        assert result is not None
        assert result.endian == "big"

    def test_resolve_primitive_endian_override_preserves_size(self) -> None:
        """resolve_primitive with endian override preserves the original type size.

        Returns:
            None
        """
        registry = TypeRegistry()
        result = registry.resolve_primitive("u16", endian="little")
        assert result is not None
        assert result.size == 2

    def test_resolve_unknown_name_returns_none(self) -> None:
        """Resolving an unknown type name returns None.

        Returns:
            None
        """
        registry = TypeRegistry()
        result = registry.resolve("CompletelyUnknown")
        assert result is None

    def test_register_enum_resolve_returns_enum_type_info(self) -> None:
        """Registering an enum and resolving its name returns EnumTypeInfo.

        Returns:
            None
        """
        registry = TypeRegistry()
        backing = BuiltinTypes.get("u8")
        assert backing is not None
        decl = EnumDecl(
            name="MyEnum",
            backing_type=_make_primitive_type_node("u8"),
            entries=(),
            line=1,
            column=1,
        )
        members: dict[str, int] = {"A": 0, "B": 1}
        registry.register_enum(decl, backing, members)
        result = registry.resolve("MyEnum")
        assert isinstance(result, EnumTypeInfo)

    def test_register_enum_members_preserved(self) -> None:
        """EnumTypeInfo resolved from registry carries the registered member mapping.

        Returns:
            None
        """
        registry = TypeRegistry()
        backing = BuiltinTypes.get("u8")
        assert backing is not None
        decl = EnumDecl(
            name="Status",
            backing_type=_make_primitive_type_node("u8"),
            entries=(),
            line=1,
            column=1,
        )
        members: dict[str, int] = {"OK": 0, "ERR": 1}
        registry.register_enum(decl, backing, members)
        result = registry.resolve("Status")
        assert isinstance(result, EnumTypeInfo)
        assert result.members == {"OK": 0, "ERR": 1}

    def test_register_union_resolve_returns_union_type_info(self) -> None:
        """Registering a union and resolving its name returns UnionTypeInfo.

        Returns:
            None
        """
        registry = TypeRegistry()
        decl = UnionDecl(
            name="MyUnion",
            body=(),
            annotations=(),
            line=1,
            column=1,
        )
        registry.register_union(decl)
        result = registry.resolve("MyUnion")
        assert isinstance(result, UnionTypeInfo)


def _make_primitive_type_node(name: str) -> PrimitiveType:
    """Create a minimal PrimitiveType AST node for use in test EnumDecl construction.

    Args:
        name: The primitive type name (e.g. "u8", "u32").

    Returns:
        A PrimitiveType dataclass instance usable as a TypeNode.
    """
    return PrimitiveType(name=name, endianness=None, line=1, column=1)
