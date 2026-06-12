# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for the HexPat type system: BuiltinTypes registry and TypeRegistry."""

from __future__ import annotations

import pytest


pytest.importorskip("intellicrack.core.hexpat.type_system", reason="hexpat type_system not available")

from intellicrack.core.hexpat.ast_nodes import (
    BitfieldDecl,
    EnumDecl,
    PrimitiveType,
    StructDecl,
    UnionDecl,
)
from intellicrack.core.hexpat.errors import HexPatTypeError
from intellicrack.core.hexpat.type_system import (
    BitfieldTypeInfo,
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
    "u128",
    "s8",
    "s16",
    "s32",
    "s64",
    "s128",
    "float",
    "double",
    "char",
    "char16",
    "bool",
    "str",
    "padding",
    "auto",
})

_BUILTIN_EXACT_PROPERTIES: tuple[tuple[str, int, bool], ...] = (
    ("u8", 1, False),
    ("u16", 2, False),
    ("u32", 4, False),
    ("u64", 8, False),
    ("u128", 16, False),
    ("s8", 1, True),
    ("s16", 2, True),
    ("s32", 4, True),
    ("s64", 8, True),
    ("s128", 16, True),
    ("float", 4, False),
    ("double", 8, False),
    ("char", 1, False),
    ("char16", 2, False),
    ("bool", 1, False),
    ("str", -1, False),
    ("padding", -1, False),
    ("auto", -1, False),
)


class TestBuiltinTypes:
    """Tests for the BuiltinTypes static registry.

    Each test asserts exact field values known from the HexPat language
    specification, not from re-reading the implementation. Breaking any
    field assignment in BuiltinTypes._TYPES makes the corresponding test red.
    """

    def test_get_u8_exact_fields(self) -> None:
        """BuiltinTypes.get('u8') returns HexPatType with exact name/size/signed/endian.

        The independent oracle is the HexPat spec: u8 is 1 byte, unsigned,
        no default endian override.  Deleting or mis-typing any field
        assignment in _TYPES causes this test to fail.
        """
        result = BuiltinTypes.get("u8")
        assert result is not None, "u8 must be a registered builtin"
        assert result.name == "u8"
        assert result.size == 1
        assert result.signed is False
        assert result.endian is None

    def test_get_u16_exact_fields(self) -> None:
        """BuiltinTypes.get('u16') returns HexPatType with size 2, unsigned, no endian override."""
        result = BuiltinTypes.get("u16")
        assert result is not None, "u16 must be a registered builtin"
        assert result.name == "u16"
        assert result.size == 2
        assert result.signed is False
        assert result.endian is None

    def test_get_u32_exact_fields(self) -> None:
        """BuiltinTypes.get('u32') returns HexPatType with size 4, unsigned, no endian override."""
        result = BuiltinTypes.get("u32")
        assert result is not None, "u32 must be a registered builtin"
        assert result.name == "u32"
        assert result.size == 4
        assert result.signed is False
        assert result.endian is None

    def test_get_u64_exact_fields(self) -> None:
        """BuiltinTypes.get('u64') returns HexPatType with size 8, unsigned, no endian override."""
        result = BuiltinTypes.get("u64")
        assert result is not None, "u64 must be a registered builtin"
        assert result.name == "u64"
        assert result.size == 8
        assert result.signed is False
        assert result.endian is None

    def test_get_u128_exact_fields(self) -> None:
        """BuiltinTypes.get('u128') returns HexPatType with size 16, unsigned, no endian override."""
        result = BuiltinTypes.get("u128")
        assert result is not None, "u128 must be a registered builtin"
        assert result.name == "u128"
        assert result.size == 16
        assert result.signed is False
        assert result.endian is None

    def test_get_s8_exact_fields(self) -> None:
        """BuiltinTypes.get('s8') returns HexPatType with size 1, signed, no endian override."""
        result = BuiltinTypes.get("s8")
        assert result is not None, "s8 must be a registered builtin"
        assert result.name == "s8"
        assert result.size == 1
        assert result.signed is True
        assert result.endian is None

    def test_get_s16_exact_fields(self) -> None:
        """BuiltinTypes.get('s16') returns HexPatType with size 2, signed, no endian override."""
        result = BuiltinTypes.get("s16")
        assert result is not None, "s16 must be a registered builtin"
        assert result.name == "s16"
        assert result.size == 2
        assert result.signed is True
        assert result.endian is None

    def test_get_s32_exact_fields(self) -> None:
        """BuiltinTypes.get('s32') returns HexPatType with size 4, signed, no endian override."""
        result = BuiltinTypes.get("s32")
        assert result is not None, "s32 must be a registered builtin"
        assert result.name == "s32"
        assert result.size == 4
        assert result.signed is True
        assert result.endian is None

    def test_get_s64_exact_fields(self) -> None:
        """BuiltinTypes.get('s64') returns HexPatType with size 8, signed, no endian override."""
        result = BuiltinTypes.get("s64")
        assert result is not None, "s64 must be a registered builtin"
        assert result.name == "s64"
        assert result.size == 8
        assert result.signed is True
        assert result.endian is None

    def test_get_s128_exact_fields(self) -> None:
        """BuiltinTypes.get('s128') returns HexPatType with size 16, signed, no endian override."""
        result = BuiltinTypes.get("s128")
        assert result is not None, "s128 must be a registered builtin"
        assert result.name == "s128"
        assert result.size == 16
        assert result.signed is True
        assert result.endian is None

    def test_get_float_exact_fields(self) -> None:
        """BuiltinTypes.get('float') returns HexPatType with size 4, unsigned, no endian override."""
        result = BuiltinTypes.get("float")
        assert result is not None, "float must be a registered builtin"
        assert result.name == "float"
        assert result.size == 4
        assert result.signed is False
        assert result.endian is None

    def test_get_double_exact_fields(self) -> None:
        """BuiltinTypes.get('double') returns HexPatType with size 8, unsigned, no endian override."""
        result = BuiltinTypes.get("double")
        assert result is not None, "double must be a registered builtin"
        assert result.name == "double"
        assert result.size == 8
        assert result.signed is False
        assert result.endian is None

    def test_get_char_exact_fields(self) -> None:
        """BuiltinTypes.get('char') returns HexPatType with size 1, unsigned, no endian override."""
        result = BuiltinTypes.get("char")
        assert result is not None, "char must be a registered builtin"
        assert result.name == "char"
        assert result.size == 1
        assert result.signed is False
        assert result.endian is None

    def test_get_char16_exact_fields(self) -> None:
        """BuiltinTypes.get('char16') returns HexPatType with size 2, unsigned, no endian override."""
        result = BuiltinTypes.get("char16")
        assert result is not None, "char16 must be a registered builtin"
        assert result.name == "char16"
        assert result.size == 2
        assert result.signed is False
        assert result.endian is None

    def test_get_bool_exact_fields(self) -> None:
        """BuiltinTypes.get('bool') returns HexPatType with size 1, unsigned, no endian override."""
        result = BuiltinTypes.get("bool")
        assert result is not None, "bool must be a registered builtin"
        assert result.name == "bool"
        assert result.size == 1
        assert result.signed is False
        assert result.endian is None

    def test_get_str_exact_fields(self) -> None:
        """BuiltinTypes.get('str') returns HexPatType with size -1 (variable), unsigned."""
        result = BuiltinTypes.get("str")
        assert result is not None, "str must be a registered builtin"
        assert result.name == "str"
        assert result.size == -1
        assert result.signed is False
        assert result.endian is None

    def test_get_padding_exact_fields(self) -> None:
        """BuiltinTypes.get('padding') returns HexPatType with size -1 (variable), unsigned."""
        result = BuiltinTypes.get("padding")
        assert result is not None, "padding must be a registered builtin"
        assert result.name == "padding"
        assert result.size == -1
        assert result.signed is False
        assert result.endian is None

    def test_get_auto_exact_fields(self) -> None:
        """BuiltinTypes.get('auto') returns HexPatType with size -1 (variable), unsigned."""
        result = BuiltinTypes.get("auto")
        assert result is not None, "auto must be a registered builtin"
        assert result.name == "auto"
        assert result.size == -1
        assert result.signed is False
        assert result.endian is None

    def test_get_nonexistent_returns_none(self) -> None:
        """BuiltinTypes.get with an unknown name returns None, not a HexPatType."""
        result = BuiltinTypes.get("nonexistent_type")
        assert result is None

    def test_get_empty_string_returns_none(self) -> None:
        """BuiltinTypes.get('') returns None - empty string is not a valid builtin."""
        result = BuiltinTypes.get("")
        assert result is None

    def test_get_case_sensitive_uppercase_returns_none(self) -> None:
        """BuiltinTypes.get is case-sensitive; 'U32' is not the same as 'u32'."""
        result = BuiltinTypes.get("U32")
        assert result is None

    def test_get_case_sensitive_mixed_returns_none(self) -> None:
        """BuiltinTypes.get('Float') returns None - names are lowercase-only in HexPat."""
        result = BuiltinTypes.get("Float")
        assert result is None

    def test_all_names_exact_set(self) -> None:
        """BuiltinTypes.all_names() returns exactly the 18 expected primitive names.

        The oracle is _EXPECTED_BUILTIN_NAMES - independently derived from the
        HexPat language spec listing every primitive keyword including u128 and
        s128.  Using exact equality (==) means adding or removing any name from
        _TYPES causes this test to fail, unlike a superset check which would
        silently pass if names were removed.
        """
        names = BuiltinTypes.all_names()
        assert names == _EXPECTED_BUILTIN_NAMES, (
            f"all_names() mismatch.\n  Extra  : {names - _EXPECTED_BUILTIN_NAMES}\n  Missing: {_EXPECTED_BUILTIN_NAMES - names}"
        )

    def test_all_names_does_not_contain_garbage(self) -> None:
        """BuiltinTypes.all_names() does not contain any obviously spurious entries."""
        names = BuiltinTypes.all_names()
        assert "nonexistent_type" not in names
        assert "" not in names
        assert "U32" not in names

    def test_is_reserved_name_true_for_all_builtins_including_128bit(self) -> None:
        """BuiltinTypes.is_reserved_name returns True for every known builtin name.

        This includes u128 and s128 which were missing from the previous
        _EXPECTED_BUILTIN_NAMES oracle. If either is removed from _TYPES,
        this test goes red.
        """
        for name in _EXPECTED_BUILTIN_NAMES:
            assert BuiltinTypes.is_reserved_name(name) is True, f"Expected '{name}' to be reserved but is_reserved_name returned False"

    def test_is_reserved_name_false_for_user_defined(self) -> None:
        """BuiltinTypes.is_reserved_name returns False for non-builtin identifiers."""
        assert BuiltinTypes.is_reserved_name("MyStruct") is False
        assert BuiltinTypes.is_reserved_name("") is False
        assert BuiltinTypes.is_reserved_name("U32") is False

    def test_all_builtins_have_correct_size_signed_and_name_stored(self) -> None:
        """Every registered builtin has exact size, signedness, stored name, and no default endian.

        The oracle is _BUILTIN_EXACT_PROPERTIES, independently derived from the
        HexPat language specification. Corrupting any field in BuiltinTypes._TYPES
        causes the corresponding assertion to fail. This test iterates all entries
        so a single accidental swap (e.g. s8 and u8 sizes exchanged) is caught.
        """
        for type_name, expected_size, expected_signed in _BUILTIN_EXACT_PROPERTIES:
            result = BuiltinTypes.get(type_name)
            assert result is not None, f"'{type_name}' must be a registered builtin"
            assert result.size == expected_size, f"'{type_name}' size: got {result.size}, want {expected_size}"
            assert result.signed is expected_signed, f"'{type_name}' signed: got {result.signed}, want {expected_signed}"
            assert result.name == type_name, f"stored name field '{result.name}' must match lookup key '{type_name}'"
            assert result.endian is None, f"'{type_name}' endian must be None (no default override), got {result.endian!r}"

    def test_all_names_returns_frozenset_with_exact_count(self) -> None:
        """BuiltinTypes.all_names() returns a frozenset containing exactly 18 primitive names.

        The return-type check and the cardinality check together guarantee that
        both the collection contract AND the completeness of _TYPES are enforced.
        Deleting _TYPES entries or changing the return type to a list both make
        this test red. The expected count of 18 is the independently-verified
        total of HexPat primitive keywords.
        """
        result = BuiltinTypes.all_names()
        assert isinstance(result, frozenset), f"all_names() must return frozenset, got {type(result).__name__}"
        assert len(result) == len(_EXPECTED_BUILTIN_NAMES), (
            f"all_names() must contain {len(_EXPECTED_BUILTIN_NAMES)} entries, got {len(result)}: {result}"
        )
        assert result == _EXPECTED_BUILTIN_NAMES, (
            f"all_names() content mismatch. Extra: {result - _EXPECTED_BUILTIN_NAMES}, Missing: {_EXPECTED_BUILTIN_NAMES - result}"
        )

    def test_get_returns_identical_object_on_repeated_calls(self) -> None:
        """BuiltinTypes.get returns the same HexPatType object on each call for the same name.

        This validates that _TYPES is a shared class-level dict returning
        pre-created objects, not constructing new ones on each call.
        """
        first = BuiltinTypes.get("u64")
        second = BuiltinTypes.get("u64")
        assert first is not None
        assert first is second, "Repeated calls to BuiltinTypes.get must return the same object"


class TestTypeRegistry:
    """Tests for the TypeRegistry class - core type registration and resolution."""

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

    def test_register_struct_decl_reference_preserved(self) -> None:
        """StructTypeInfo.decl is the same object as the registered decl."""
        registry = TypeRegistry()
        decl = StructDecl(
            name="DeclCheck",
            parent=None,
            body=(),
            annotations=(),
            line=7,
            column=3,
        )
        registry.register_struct(decl)
        result = registry.resolve("DeclCheck")
        assert isinstance(result, StructTypeInfo)
        assert result.decl is decl

    def test_register_alias_resolve_follows_to_primitive(self) -> None:
        """Registering an alias for u32 resolves transparently to HexPatType."""
        registry = TypeRegistry()
        registry.register_alias("DWORD", "u32")
        result = registry.resolve("DWORD")
        assert isinstance(result, HexPatType)
        assert result.name == "u32"
        assert result.size == 4
        assert result.signed is False

    def test_register_alias_multihop_resolves_correctly(self) -> None:
        """A three-hop alias chain A->B->C->u16 resolves to the u16 HexPatType.

        If any link is lost during resolution the chain breaks and result would
        not be a HexPatType with size 2.  This test validates the full chain
        traversal, not just one alias step.
        """
        registry = TypeRegistry()
        registry.register_alias("TypeA", "TypeB")
        registry.register_alias("TypeB", "TypeC")
        registry.register_alias("TypeC", "u16")
        result = registry.resolve("TypeA")
        assert isinstance(result, HexPatType)
        assert result.name == "u16"
        assert result.size == 2

    def test_register_alias_to_struct_resolves_to_struct_type_info(self) -> None:
        """Alias pointing at a struct resolves to StructTypeInfo, not None."""
        registry = TypeRegistry()
        decl = StructDecl(name="Target", parent=None, body=(), annotations=(), line=1, column=1)
        registry.register_struct(decl)
        registry.register_alias("TargetAlias", "Target")
        result = registry.resolve("TargetAlias")
        assert isinstance(result, StructTypeInfo)
        assert result.name == "Target"

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

    def test_resolve_primitive_endian_override_preserves_signedness(self) -> None:
        """resolve_primitive with endian override preserves the original signedness."""
        registry = TypeRegistry()
        result_signed = registry.resolve_primitive("s32", endian="big")
        assert result_signed is not None
        assert result_signed.signed is True
        assert result_signed.size == 4
        assert result_signed.endian == "big"

    def test_resolve_primitive_endian_override_preserves_name(self) -> None:
        """resolve_primitive with endian override preserves the original type name."""
        registry = TypeRegistry()
        result = registry.resolve_primitive("u64", endian="little")
        assert result is not None
        assert result.name == "u64"

    def test_resolve_primitive_none_endian_returns_same_object(self) -> None:
        """resolve_primitive with endian=None returns the identical BuiltinTypes singleton.

        The production code checks ``endian is None or endian == resolved.endian``
        and returns the original resolved HexPatType without constructing a new one.
        If this short-circuit is broken, the test goes red.
        """
        registry = TypeRegistry()
        builtin = BuiltinTypes.get("s64")
        assert builtin is not None
        result = registry.resolve_primitive("s64", endian=None)
        assert result is not None
        assert result is builtin, "resolve_primitive with endian=None must return the same BuiltinTypes singleton"

    def test_resolve_primitive_big_endian_creates_distinct_object(self) -> None:
        """resolve_primitive with endian='big' returns a new HexPatType object.

        The endian-overridden result must not be the same object as the builtin.
        """
        registry = TypeRegistry()
        builtin = BuiltinTypes.get("u32")
        assert builtin is not None
        result = registry.resolve_primitive("u32", endian="big")
        assert result is not None
        assert result is not builtin, "Endian-overridden result must be a new HexPatType, not the builtin singleton"
        assert result.endian == "big"
        assert result.name == "u32"
        assert result.size == 4
        assert result.signed is False

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

    def test_register_enum_backing_type_preserved(self) -> None:
        """EnumTypeInfo resolved from registry carries the exact registered backing type."""
        registry = TypeRegistry()
        backing = BuiltinTypes.get("u32")
        assert backing is not None
        decl = EnumDecl(
            name="WinError",
            backing_type=_make_primitive_type_node("u32"),
            entries=(),
            line=1,
            column=1,
        )
        members: dict[str, int] = {"S_OK": 0, "E_FAIL": 0x80004005}
        registry.register_enum(decl, backing, members)
        result = registry.resolve("WinError")
        assert isinstance(result, EnumTypeInfo)
        assert result.backing_type is backing
        assert result.backing_type.name == "u32"
        assert result.backing_type.size == 4

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

    def test_register_union_name_preserved(self) -> None:
        """UnionTypeInfo resolved from registry carries the registered name."""
        registry = TypeRegistry()
        decl = UnionDecl(name="RawHeader", body=(), annotations=(), line=2, column=5)
        registry.register_union(decl)
        result = registry.resolve("RawHeader")
        assert isinstance(result, UnionTypeInfo)
        assert result.name == "RawHeader"

    def test_register_bitfield_resolve_returns_bitfield_type_info(self) -> None:
        """Registering a bitfield and resolving its name returns BitfieldTypeInfo."""
        registry = TypeRegistry()
        decl = BitfieldDecl(name="Flags", entries=(), annotations=(), line=1, column=1)
        registry.register_bitfield(decl)
        result = registry.resolve("Flags")
        assert isinstance(result, BitfieldTypeInfo)
        assert result.name == "Flags"

    def test_register_bitfield_decl_reference_preserved(self) -> None:
        """BitfieldTypeInfo.decl is the same object as the registered decl."""
        registry = TypeRegistry()
        decl = BitfieldDecl(name="StatusFlags", entries=(), annotations=(), line=3, column=1)
        registry.register_bitfield(decl)
        result = registry.resolve("StatusFlags")
        assert isinstance(result, BitfieldTypeInfo)
        assert result.decl is decl

    def test_register_struct_namespace_qualified_lookup(self) -> None:
        """Struct registered with namespace is resolvable by both local and qualified name."""
        registry = TypeRegistry()
        decl = StructDecl(name="Header", parent=None, body=(), annotations=(), line=1, column=1)
        registry.register_struct(decl, namespace="PE")
        by_local = registry.resolve("Header")
        by_qualified = registry.resolve("PE::Header")
        assert isinstance(by_local, StructTypeInfo)
        assert isinstance(by_qualified, StructTypeInfo)
        assert by_local.name == "Header"
        assert by_qualified.name == "Header"

    def test_register_struct_namespace_same_object_for_local_and_qualified(self) -> None:
        """Local and namespace-qualified lookups return the same StructTypeInfo object.

        The production code registers a single StructTypeInfo under both the
        local name and the qualified name.  If separate objects were created
        for each, identity comparison fails, exposing the regression.
        """
        registry = TypeRegistry()
        decl = StructDecl(name="FileHeader", parent=None, body=(), annotations=(), line=5, column=1)
        registry.register_struct(decl, namespace="PE")
        by_local = registry.resolve("FileHeader")
        by_qualified = registry.resolve("PE::FileHeader")
        assert isinstance(by_local, StructTypeInfo)
        assert isinstance(by_qualified, StructTypeInfo)
        assert by_local is by_qualified, "Local and qualified lookups must return the same StructTypeInfo object"

    def test_register_union_namespace_qualified_lookup(self) -> None:
        """Union registered with namespace is resolvable by both local and qualified name."""
        registry = TypeRegistry()
        decl = UnionDecl(name="Value", body=(), annotations=(), line=1, column=1)
        registry.register_union(decl, namespace="std")
        by_local = registry.resolve("Value")
        by_qualified = registry.resolve("std::Value")
        assert isinstance(by_local, UnionTypeInfo)
        assert isinstance(by_qualified, UnionTypeInfo)

    def test_register_enum_namespace_qualified_lookup(self) -> None:
        """Enum registered with namespace is resolvable by both local and qualified name.

        The production register_enum stores the info under both the unqualified
        and fully qualified keys.  If the qualified entry is missing from
        _enums, the qualified resolve returns None and this test fails.
        """
        registry = TypeRegistry()
        backing = BuiltinTypes.get("u32")
        assert backing is not None
        decl = EnumDecl(
            name="Direction",
            backing_type=_make_primitive_type_node("u32"),
            entries=(),
            line=1,
            column=1,
        )
        members: dict[str, int] = {"North": 0, "East": 1, "South": 2, "West": 3}
        registry.register_enum(decl, backing, members, namespace="Compass")
        by_local = registry.resolve("Direction")
        by_qualified = registry.resolve("Compass::Direction")
        assert isinstance(by_local, EnumTypeInfo)
        assert isinstance(by_qualified, EnumTypeInfo)
        assert by_local is by_qualified, "Local and qualified enum lookups must return the same EnumTypeInfo object"
        assert by_local.members == {"North": 0, "East": 1, "South": 2, "West": 3}

    def test_resolve_struct_priority_over_union_for_same_name(self) -> None:
        """When both struct and union are registered with the same name, struct is returned.

        The resolve() method checks _structs before _unions.  This test validates
        the documented lookup order: builtins -> structs -> unions -> enums ->
        bitfields -> aliases.  If the order changes, the result type changes.
        """
        registry = TypeRegistry()
        struct_decl = StructDecl(name="Mixed", parent=None, body=(), annotations=(), line=1, column=1)
        union_decl = UnionDecl(name="Mixed", body=(), annotations=(), line=2, column=1)
        registry.register_struct(struct_decl)
        registry.register_union(union_decl)
        result = registry.resolve("Mixed")
        assert isinstance(result, StructTypeInfo), "Struct must take priority over union when both share the same name"
        assert result.name == "Mixed"


class TestTypeRegistryEdgeCases:
    """Tests for TypeRegistry error paths and edge cases.

    Each test is designed so that removing or corrupting the corresponding
    production guard makes the test go red.
    """

    def test_register_struct_with_builtin_name_raises_hexpat_type_error(self) -> None:
        """Registering a struct whose name shadows a built-in raises HexPatTypeError.

        The production code explicitly checks BuiltinTypes.is_reserved_name and
        raises HexPatTypeError. If that guard is removed, this test goes red.
        """
        registry = TypeRegistry()
        decl = StructDecl(name="u32", parent=None, body=(), annotations=(), line=3, column=7)
        with pytest.raises(HexPatTypeError, match="u32"):
            registry.register_struct(decl)

    def test_register_struct_with_u128_builtin_name_raises_hexpat_type_error(self) -> None:
        """Registering a struct named 'u128' raises HexPatTypeError.

        u128 is a reserved built-in that the previous test oracle omitted.
        This test validates that the 128-bit builtins are also guarded.
        """
        registry = TypeRegistry()
        decl = StructDecl(name="u128", parent=None, body=(), annotations=(), line=1, column=1)
        with pytest.raises(HexPatTypeError, match="u128"):
            registry.register_struct(decl)

    def test_register_struct_with_s128_builtin_name_raises_hexpat_type_error(self) -> None:
        """Registering a struct named 's128' raises HexPatTypeError."""
        registry = TypeRegistry()
        decl = StructDecl(name="s128", parent=None, body=(), annotations=(), line=1, column=1)
        with pytest.raises(HexPatTypeError, match="s128"):
            registry.register_struct(decl)

    def test_register_union_with_builtin_name_raises_hexpat_type_error(self) -> None:
        """Registering a union whose name shadows a built-in raises HexPatTypeError."""
        registry = TypeRegistry()
        decl = UnionDecl(name="float", body=(), annotations=(), line=1, column=1)
        with pytest.raises(HexPatTypeError, match="float"):
            registry.register_union(decl)

    def test_register_enum_with_builtin_name_raises_hexpat_type_error(self) -> None:
        """Registering an enum whose name shadows a built-in raises HexPatTypeError."""
        registry = TypeRegistry()
        backing = BuiltinTypes.get("u8")
        assert backing is not None
        decl = EnumDecl(
            name="bool",
            backing_type=_make_primitive_type_node("u8"),
            entries=(),
            line=1,
            column=1,
        )
        with pytest.raises(HexPatTypeError, match="bool"):
            registry.register_enum(decl, backing, {})

    def test_register_bitfield_with_builtin_name_raises_hexpat_type_error(self) -> None:
        """Registering a bitfield whose name shadows a built-in raises HexPatTypeError."""
        registry = TypeRegistry()
        decl = BitfieldDecl(name="u8", entries=(), annotations=(), line=1, column=1)
        with pytest.raises(HexPatTypeError, match="u8"):
            registry.register_bitfield(decl)

    def test_register_alias_with_builtin_name_raises_hexpat_type_error(self) -> None:
        """Registering an alias whose name shadows a built-in raises HexPatTypeError."""
        registry = TypeRegistry()
        with pytest.raises(HexPatTypeError, match="bool"):
            registry.register_alias("bool", "MyBool")

    def test_register_alias_with_str_builtin_name_raises_hexpat_type_error(self) -> None:
        """Registering an alias named 'str' raises HexPatTypeError.

        'str' is a reserved built-in type name. Aliasing it must be rejected.
        """
        registry = TypeRegistry()
        with pytest.raises(HexPatTypeError, match="str"):
            registry.register_alias("str", "MyString")

    def test_resolve_unknown_name_returns_none(self) -> None:
        """Resolving a name that was never registered returns None, not an exception."""
        registry = TypeRegistry()
        result = registry.resolve("AbsolutelyNotRegistered_XYZ_987")
        assert result is None

    def test_resolve_undefined_alias_target_returns_none(self) -> None:
        """An alias pointing at a non-existent target resolves to None.

        Registering alias 'MyType' -> 'Nonexistent' is legal, but resolving
        'MyType' must return None because 'Nonexistent' is not in the registry.
        If the resolver incorrectly returns the alias string itself or raises,
        this test fails.
        """
        registry = TypeRegistry()
        registry.register_alias("MyType", "Nonexistent")
        result = registry.resolve("MyType")
        assert result is None, f"Alias pointing to undefined target must resolve to None, got: {result!r}"

    def test_resolve_multihop_alias_to_undefined_returns_none(self) -> None:
        """A multi-hop alias chain ending at an undefined name resolves to None.

        A->B->C where C is undefined must return None, not raise or return
        a partial result.  This validates the 'break' branch in resolve().
        """
        registry = TypeRegistry()
        registry.register_alias("A", "B")
        registry.register_alias("B", "C")
        result = registry.resolve("A")
        assert result is None, f"Multi-hop alias chain ending at undefined target must resolve to None, got: {result!r}"

    def test_resolve_circular_alias_self_loop_returns_none(self) -> None:
        """A self-referential alias (X -> X) resolves to None without infinite looping.

        The production visited-set guard adds the name before following the
        alias, so the loop immediately terminates.  If the guard is removed,
        this test hangs or recurses infinitely.
        """
        registry = TypeRegistry()
        registry.register_alias("SelfRef", "SelfRef")
        result = registry.resolve("SelfRef")
        assert result is None, f"Self-referential alias must resolve to None, got: {result!r}"

    def test_resolve_circular_alias_two_nodes_returns_none(self) -> None:
        """Circular alias chains (A -> B -> A) resolve to None without infinite looping.

        A -> B -> A is a two-node cycle. The production visited-set guard must
        break the loop and return None.  If the guard is removed, this test hangs
        or raises RecursionError rather than returning None.
        """
        registry = TypeRegistry()
        registry.register_alias("CycleA", "CycleB")
        registry.register_alias("CycleB", "CycleA")
        result = registry.resolve("CycleA")
        assert result is None, f"Two-node circular alias must resolve to None, got: {result!r}"

    def test_resolve_circular_alias_three_nodes_returns_none(self) -> None:
        """Circular alias chain A -> B -> C -> A resolves to None without infinite looping.

        A longer cycle must also terminate. Any regression that drops the
        visited-set guard causes this to hang or recurse infinitely.
        """
        registry = TypeRegistry()
        registry.register_alias("TriA", "TriB")
        registry.register_alias("TriB", "TriC")
        registry.register_alias("TriC", "TriA")
        result = registry.resolve("TriA")
        assert result is None, f"Three-node circular alias must resolve to None, got: {result!r}"

    def test_registry_state_isolation_struct_in_r1_invisible_in_r2(self) -> None:
        """Types registered in one TypeRegistry do not appear in another.

        Each TypeRegistry instance owns its own lookup tables.  A struct
        registered in r1 must not be visible through r2.resolve.  If the
        backing dicts were class-level (not instance-level), this test would
        fail by returning the struct from r2.
        """
        r1 = TypeRegistry()
        r2 = TypeRegistry()
        decl = StructDecl(name="IsolatedStruct", parent=None, body=(), annotations=(), line=1, column=1)
        r1.register_struct(decl)

        r1_result = r1.resolve("IsolatedStruct")
        r2_result = r2.resolve("IsolatedStruct")

        assert isinstance(r1_result, StructTypeInfo), "r1 must resolve the registered struct"
        assert r2_result is None, "r2 must not see structs registered in r1"

    def test_registry_state_isolation_enum_in_r1_invisible_in_r2(self) -> None:
        """Enum registered in r1 is invisible in r2 - confirms per-instance dict isolation."""
        r1 = TypeRegistry()
        r2 = TypeRegistry()
        backing = BuiltinTypes.get("u8")
        assert backing is not None
        decl = EnumDecl(
            name="PrivateEnum",
            backing_type=_make_primitive_type_node("u8"),
            entries=(),
            line=1,
            column=1,
        )
        r1.register_enum(decl, backing, {"X": 0})

        r1_result = r1.resolve("PrivateEnum")
        r2_result = r2.resolve("PrivateEnum")

        assert isinstance(r1_result, EnumTypeInfo)
        assert r2_result is None

    def test_registry_state_isolation_alias_in_r1_invisible_in_r2(self) -> None:
        """Alias registered in r1 is invisible in r2 - confirms _aliases dict is per-instance."""
        r1 = TypeRegistry()
        r2 = TypeRegistry()
        r1.register_alias("SharedName", "u32")

        r1_result = r1.resolve("SharedName")
        r2_result = r2.resolve("SharedName")

        assert isinstance(r1_result, HexPatType), "r1 must follow alias to u32 HexPatType"
        assert r2_result is None, "r2 must not see aliases registered in r1"

    def test_registry_state_isolation_bitfield_in_r1_invisible_in_r2(self) -> None:
        """Bitfield registered in r1 is invisible in r2 - confirms _bitfields dict is per-instance.

        This is the previously untested isolation case for bitfields.  If _bitfields
        is a class-level dict, r2 would return the BitfieldTypeInfo, making this test red.
        """
        r1 = TypeRegistry()
        r2 = TypeRegistry()
        decl = BitfieldDecl(name="IsolatedBitfield", entries=(), annotations=(), line=1, column=1)
        r1.register_bitfield(decl)

        r1_result = r1.resolve("IsolatedBitfield")
        r2_result = r2.resolve("IsolatedBitfield")

        assert isinstance(r1_result, BitfieldTypeInfo), "r1 must resolve the registered bitfield"
        assert r2_result is None, "r2 must not see bitfields registered in r1"

    def test_registry_state_isolation_union_in_r1_invisible_in_r2(self) -> None:
        """Union registered in r1 is invisible in r2 - confirms _unions dict is per-instance."""
        r1 = TypeRegistry()
        r2 = TypeRegistry()
        decl = UnionDecl(name="IsolatedUnion", body=(), annotations=(), line=1, column=1)
        r1.register_union(decl)

        r1_result = r1.resolve("IsolatedUnion")
        r2_result = r2.resolve("IsolatedUnion")

        assert isinstance(r1_result, UnionTypeInfo), "r1 must resolve the registered union"
        assert r2_result is None, "r2 must not see unions registered in r1"

    def test_registry_state_isolation_all_names_in_r1_invisible_in_r2(self) -> None:
        """user_type_names from r1 does not appear in a fresh r2 instance.

        If _all_names were a class-level set, r2.user_type_names() would contain
        names registered in r1, exposing the defect.
        """
        r1 = TypeRegistry()
        r2 = TypeRegistry()
        decl = StructDecl(name="R1OnlyType", parent=None, body=(), annotations=(), line=1, column=1)
        r1.register_struct(decl)

        r1_names = r1.user_type_names()
        r2_names = r2.user_type_names()

        assert "R1OnlyType" in r1_names, "r1 must include its own registered name"
        assert "R1OnlyType" not in r2_names, "r2 must not see names registered in r1"

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
        assert result.decl is decl_v2

    def test_resolve_primitive_unknown_returns_none(self) -> None:
        """resolve_primitive on an unknown name returns None, not a HexPatType."""
        registry = TypeRegistry()
        result = registry.resolve_primitive("NotAPrimitive")
        assert result is None

    def test_resolve_primitive_on_struct_name_returns_none(self) -> None:
        """resolve_primitive returns None when the name resolves to a struct, not a primitive.

        The registry contains a struct; resolve_primitive must return None
        because the resolved type is StructTypeInfo, not HexPatType.
        """
        registry = TypeRegistry()
        decl = StructDecl(name="NotPrimitive", parent=None, body=(), annotations=(), line=1, column=1)
        registry.register_struct(decl)
        result = registry.resolve_primitive("NotPrimitive")
        assert result is None, f"resolve_primitive must return None when the resolved type is StructTypeInfo, got: {result!r}"

    def test_resolve_primitive_on_enum_name_returns_none(self) -> None:
        """resolve_primitive returns None when the name resolves to an enum.

        An EnumTypeInfo is not a HexPatType primitive, so resolve_primitive
        must return None rather than the enum info.
        """
        registry = TypeRegistry()
        backing = BuiltinTypes.get("u8")
        assert backing is not None
        decl = EnumDecl(
            name="MyEnumType",
            backing_type=_make_primitive_type_node("u8"),
            entries=(),
            line=1,
            column=1,
        )
        registry.register_enum(decl, backing, {"VAL": 0})
        result = registry.resolve_primitive("MyEnumType")
        assert result is None, f"resolve_primitive must return None for an EnumTypeInfo result, got: {result!r}"

    def test_resolve_primitive_via_alias_chain_to_primitive(self) -> None:
        """resolve_primitive follows an alias chain and returns the final HexPatType.

        When WORD -> u16, resolve_primitive('WORD') must yield the u16 HexPatType
        with size 2 and signed=False.  If alias traversal is skipped, the result
        would be None.
        """
        registry = TypeRegistry()
        registry.register_alias("WORD", "u16")
        result = registry.resolve_primitive("WORD")
        assert result is not None, "resolve_primitive must follow alias chain to builtin"
        assert result.name == "u16"
        assert result.size == 2
        assert result.signed is False

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
        assert "u128" not in user_names
        assert "s128" not in user_names

    def test_user_type_names_includes_alias(self) -> None:
        """user_type_names includes aliases registered by the user."""
        registry = TypeRegistry()
        registry.register_alias("DWORD", "u32")
        user_names = registry.user_type_names()
        assert "DWORD" in user_names

    def test_user_type_names_includes_qualified_name(self) -> None:
        """user_type_names includes the fully qualified namespace::name for namespaced types."""
        registry = TypeRegistry()
        decl = StructDecl(name="Record", parent=None, body=(), annotations=(), line=1, column=1)
        registry.register_struct(decl, namespace="ns")
        user_names = registry.user_type_names()
        assert "Record" in user_names
        assert "ns::Record" in user_names

    def test_user_type_names_returns_frozenset(self) -> None:
        """user_type_names returns a frozenset (immutable snapshot)."""
        registry = TypeRegistry()
        result = registry.user_type_names()
        assert isinstance(result, frozenset)

    def test_user_type_names_snapshot_is_immutable_across_registrations(self) -> None:
        """user_type_names snapshot is not mutated when further types are registered.

        Taking a snapshot, then registering a new type, must not modify the
        existing snapshot.  If user_type_names returned the live internal set
        directly (not a frozenset copy), the old snapshot would change.
        """
        registry = TypeRegistry()
        decl1 = StructDecl(name="FirstType", parent=None, body=(), annotations=(), line=1, column=1)
        registry.register_struct(decl1)
        snapshot_before = registry.user_type_names()

        decl2 = StructDecl(name="SecondType", parent=None, body=(), annotations=(), line=2, column=1)
        registry.register_struct(decl2)
        snapshot_after = registry.user_type_names()

        assert "FirstType" in snapshot_before
        assert "SecondType" not in snapshot_before, "Snapshot taken before SecondType was registered must not contain SecondType"
        assert "FirstType" in snapshot_after
        assert "SecondType" in snapshot_after

    def test_hexpat_type_error_carries_location(self) -> None:
        """HexPatTypeError raised by register_struct carries the correct line and column.

        The error message must contain the builtin name. Line/column attributes
        let the IDE highlight the exact source location of the clash.
        """
        registry = TypeRegistry()
        decl = StructDecl(name="u8", parent=None, body=(), annotations=(), line=42, column=13)
        with pytest.raises(HexPatTypeError) as exc_info:
            registry.register_struct(decl)
        err = exc_info.value
        assert err.line == 42
        assert err.column == 13
        assert "u8" in str(err)

    def test_hexpat_type_error_location_for_alias(self) -> None:
        """HexPatTypeError raised by register_alias carries the line and column from the call.

        register_alias accepts line and column kwargs and threads them into
        HexPatTypeError.  Removing those parameters causes the error to report
        0:0 instead of the real source location.
        """
        registry = TypeRegistry()
        with pytest.raises(HexPatTypeError) as exc_info:
            registry.register_alias("char", "MyChar", line=17, column=5)
        err = exc_info.value
        assert err.line == 17
        assert err.column == 5
        assert "char" in str(err)


def _make_primitive_type_node(name: str) -> PrimitiveType:
    """Create a minimal PrimitiveType AST node for use in test EnumDecl construction.

    Args:
        name: The primitive type name (e.g. "u8", "u32").

    Returns:
        PrimitiveType: A PrimitiveType dataclass instance usable as a TypeNode.
    """
    return PrimitiveType(name=name, endianness=None, line=1, column=1)
