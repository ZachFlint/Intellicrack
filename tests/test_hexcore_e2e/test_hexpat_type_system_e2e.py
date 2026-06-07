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
from intellicrack.core.hexpat.errors import HexPatTypeError
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
        """BuiltinTypes.get('u8') returns a HexPatType instance."""
        result = BuiltinTypes.get("u8")
        assert isinstance(result, HexPatType)

    def test_get_u8_size_is_one(self) -> None:
        """BuiltinTypes.get('u8') has size 1."""
        result = BuiltinTypes.get("u8")
        assert result is not None
        assert result.size == 1

    def test_get_u8_is_unsigned(self) -> None:
        """BuiltinTypes.get('u8') is unsigned (signed=False)."""
        result = BuiltinTypes.get("u8")
        assert result is not None
        assert result.signed is False

    def test_get_s32_size_is_four(self) -> None:
        """BuiltinTypes.get('s32') has size 4."""
        result = BuiltinTypes.get("s32")
        assert result is not None
        assert result.size == 4

    def test_get_s32_is_signed(self) -> None:
        """BuiltinTypes.get('s32') is signed (signed=True)."""
        result = BuiltinTypes.get("s32")
        assert result is not None
        assert result.signed is True

    def test_get_float_size_is_four(self) -> None:
        """BuiltinTypes.get('float') has size 4."""
        result = BuiltinTypes.get("float")
        assert result is not None
        assert result.size == 4

    def test_get_double_size_is_eight(self) -> None:
        """BuiltinTypes.get('double') has size 8."""
        result = BuiltinTypes.get("double")
        assert result is not None
        assert result.size == 8

    def test_get_nonexistent_returns_none(self) -> None:
        """BuiltinTypes.get with an unknown name returns None."""
        result = BuiltinTypes.get("nonexistent_type")
        assert result is None

    def test_all_names_returns_frozenset(self) -> None:
        """BuiltinTypes.all_names() returns a frozenset."""
        names = BuiltinTypes.all_names()
        assert isinstance(names, frozenset)

    def test_all_names_contains_expected_types(self) -> None:
        """BuiltinTypes.all_names() contains all expected primitive type names."""
        names = BuiltinTypes.all_names()
        assert names >= _EXPECTED_BUILTIN_NAMES


class TestTypeRegistry:
    """Tests for the TypeRegistry class."""

    def test_register_struct_resolve_returns_struct_type_info(self) -> None:
        """Registering a struct and resolving its name returns StructTypeInfo."""
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
        """StructTypeInfo resolved from registry has the correct name."""
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
        """StructTypeInfo resolved from registry carries the parent name."""
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
        """Registering an alias for u32 resolves transparently to HexPatType."""
        registry = TypeRegistry()
        registry.register_alias("DWORD", "u32")
        result = registry.resolve("DWORD")
        assert isinstance(result, HexPatType)
        assert result.name == "u32"

    def test_resolve_primitive_u32_returns_hex_pat_type(self) -> None:
        """Resolving the primitive 'u32' returns a HexPatType instance."""
        registry = TypeRegistry()
        result = registry.resolve("u32")
        assert isinstance(result, HexPatType)

    def test_resolve_primitive_u32_size_is_four(self) -> None:
        """Resolving 'u32' yields size 4."""
        registry = TypeRegistry()
        result = registry.resolve("u32")
        assert isinstance(result, HexPatType)
        assert result.size == 4

    def test_resolve_primitive_with_endian_override(self) -> None:
        """resolve_primitive with endian override returns a new HexPatType with that endian."""
        registry = TypeRegistry()
        result = registry.resolve_primitive("u32", endian="big")
        assert result is not None
        assert result.endian == "big"

    def test_resolve_primitive_endian_override_preserves_size(self) -> None:
        """resolve_primitive with endian override preserves the original type size."""
        registry = TypeRegistry()
        result = registry.resolve_primitive("u16", endian="little")
        assert result is not None
        assert result.size == 2

    def test_resolve_unknown_name_returns_none(self) -> None:
        """Resolving an unknown type name returns None."""
        registry = TypeRegistry()
        result = registry.resolve("CompletelyUnknown")
        assert result is None

    def test_register_enum_resolve_returns_enum_type_info(self) -> None:
        """Registering an enum and resolving its name returns EnumTypeInfo."""
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
        """EnumTypeInfo resolved from registry carries the registered member mapping."""
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
        """Registering a union and resolving its name returns UnionTypeInfo."""
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


class TestTypeRegistryEdgeCases:
    """Tests for TypeRegistry error paths and edge cases."""

    def test_register_struct_with_builtin_name_raises_hexpat_type_error(self) -> None:
        """Registering a struct whose name shadows a built-in raises HexPatTypeError.

        The production code explicitly checks BuiltinTypes.is_reserved_name and
        raises HexPatTypeError. If that guard is removed, this test goes red.
        """
        registry = TypeRegistry()
        decl = StructDecl(name="u32", parent=None, body=(), annotations=(), line=3, column=7)
        with pytest.raises(HexPatTypeError, match="u32"):
            registry.register_struct(decl)

    def test_register_union_with_builtin_name_raises_hexpat_type_error(self) -> None:
        """Registering a union whose name shadows a built-in raises HexPatTypeError."""
        registry = TypeRegistry()
        decl = UnionDecl(name="float", body=(), annotations=(), line=1, column=1)
        with pytest.raises(HexPatTypeError, match="float"):
            registry.register_union(decl)

    def test_register_alias_with_builtin_name_raises_hexpat_type_error(self) -> None:
        """Registering an alias whose name shadows a built-in raises HexPatTypeError."""
        registry = TypeRegistry()
        with pytest.raises(HexPatTypeError, match="bool"):
            registry.register_alias("bool", "MyBool")

    def test_resolve_unknown_name_returns_none(self) -> None:
        """Resolving a name that was never registered returns None, not an exception."""
        registry = TypeRegistry()
        result = registry.resolve("AbsolutelyNotRegistered_XYZ_987")
        assert result is None

    def test_resolve_circular_alias_returns_none(self) -> None:
        """Circular alias chains resolve to None without infinite looping.

        A -> B -> A is a cycle. The production visited-set guard must break the
        loop and return None.  If the guard is removed, this test hangs or
        raises RecursionError rather than returning None.
        """
        registry = TypeRegistry()
        registry.register_alias("CycleA", "CycleB")
        registry.register_alias("CycleB", "CycleA")
        result = registry.resolve("CycleA")
        assert result is None

    def test_registry_state_isolation(self) -> None:
        """Types registered in one TypeRegistry do not appear in another.

        Each TypeRegistry instance owns its own lookup tables.  A struct
        registered in r1 must not be visible through r2.resolve.
        """
        r1 = TypeRegistry()
        r2 = TypeRegistry()
        decl = StructDecl(name="IsolatedStruct", parent=None, body=(), annotations=(), line=1, column=1)
        r1.register_struct(decl)

        assert r1.resolve("IsolatedStruct") is not None
        assert r2.resolve("IsolatedStruct") is None

    def test_overwrite_struct_registration_uses_latest(self) -> None:
        """Re-registering the same struct name stores the most recent declaration.

        The production code does not raise on collision for user-defined types;
        it simply overwrites. The resolved StructTypeInfo must reflect the
        most recently registered decl.
        """
        registry = TypeRegistry()
        decl_v1 = StructDecl(name="Widget", parent=None, body=(), annotations=(), line=1, column=1)
        decl_v2 = StructDecl(name="Widget", parent="Base", body=(), annotations=(), line=5, column=1)
        registry.register_struct(decl_v1)
        registry.register_struct(decl_v2)
        result = registry.resolve("Widget")
        assert isinstance(result, StructTypeInfo)
        assert result.parent == "Base"

    def test_resolve_primitive_unknown_returns_none(self) -> None:
        """resolve_primitive on an unknown name returns None, not a HexPatType."""
        registry = TypeRegistry()
        result = registry.resolve_primitive("NotAPrimitive")
        assert result is None

    def test_user_type_names_excludes_builtins(self) -> None:
        """user_type_names returns only user-registered names, not built-in primitives.

        Built-in types like 'u32' must never appear in user_type_names even
        though they are resolvable via resolve().
        """
        registry = TypeRegistry()
        decl = StructDecl(name="UserDefined", parent=None, body=(), annotations=(), line=1, column=1)
        registry.register_struct(decl)
        user_names = registry.user_type_names()
        assert "UserDefined" in user_names
        assert "u32" not in user_names
        assert "float" not in user_names


def _make_primitive_type_node(name: str) -> PrimitiveType:
    """Create a minimal PrimitiveType AST node for use in test EnumDecl construction.

    Args:
        name: The primitive type name (e.g. "u8", "u32").

    Returns:
        PrimitiveType: A PrimitiveType dataclass instance usable as a TypeNode.
    """
    return PrimitiveType(name=name, endianness=None, line=1, column=1)
