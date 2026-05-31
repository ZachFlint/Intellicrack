# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage for HexPat type_system, completer, and core reflection.

The tests in this module exercise three production surfaces highlighted as
under-covered in audit shard 09b:

* :mod:`type_system` -- struct inheritance layout, composite ``using`` alias
  targets, namespace-qualified registration, and the resolver/``user_type_names``
  contract, validated through the real :class:`HexPatInterpreter` pipeline and
  direct :class:`TypeRegistry` round-trips.
* :mod:`completer` -- :class:`HexPatCompleter` refreshed from the live
  :class:`TypeRegistry` produced by a real interpreter run.
* :mod:`stdlib` ``std::core`` reflection builtins -- dispatched through a real
  :class:`_ReflectionProvider` that records into a real dictionary, with the
  recorded values asserted against the values the builtin was given.

No type resolution or reflection dispatch is mocked; each assertion checks a
concrete computed layout, name set, or recorded reflection value.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.hexpat.ast_nodes import StructDecl
from intellicrack.core.hexpat.completer import HexPatCompleter
from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.errors import HexPatRuntimeError, HexPatTypeError
from intellicrack.core.hexpat.evaluator import PatternValue
from intellicrack.core.hexpat.interpreter import HexPatInterpreter
from intellicrack.core.hexpat.stdlib import BuiltinFunctions
from intellicrack.core.hexpat.type_system import (
    BuiltinTypes,
    HexPatType,
    StructTypeInfo,
    TypeRegistry,
)


if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.fixture
def interp() -> HexPatInterpreter:
    """Provide a fresh HexPatInterpreter.

    Returns:
        HexPatInterpreter: A fresh interpreter instance.
    """
    return HexPatInterpreter()


def _field(results: list[dict[str, Any]], name: str) -> dict[str, Any]:
    """Find a parsed-field dict by name.

    Args:
        results: List of parsed-field dicts from ``execute_bytes``.
        name: The field name to search for.

    Returns:
        dict[str, Any]: The matching field dict.
    """
    found = next((r for r in results if r["name"] == name), None)
    assert found is not None, f"field {name!r} missing from {[r['name'] for r in results]}"
    return found


class TestStructInheritanceLayout:
    """A derived struct embeds its parent's fields ahead of its own."""

    def test_derived_layout_includes_parent_field(self, interp: HexPatInterpreter) -> None:
        """Derived(Base) reads the parent byte at offset 0 then its own at 1.

        Args:
            interp: A fresh interpreter fixture.
        """
        data = bytes([0x11, 0x22]) + bytes(14)
        source = "struct Base { u8 a; };\nstruct Derived : Base { u8 b; };\nDerived d @ 0;"
        results = interp.execute_bytes(source, data)
        d = _field(results, "d")
        assert d["size"] == 2
        children = {c["name"]: c for c in d["children"]}
        assert children["a"]["offset"] == 0
        assert children["a"]["display_value"] == "0x11"
        assert children["b"]["offset"] == 1
        assert children["b"]["display_value"] == "0x22"

    def test_registry_records_parent_name(self) -> None:
        """register_struct preserves the declared parent on StructTypeInfo."""
        interp = HexPatInterpreter()
        interp.execute_bytes(
            "struct Base { u8 a; };\nstruct Derived : Base { u8 b; };\nDerived d @ 0;",
            bytes(8),
        )
        registry = interp.last_type_registry
        assert registry is not None
        derived = registry.resolve("Derived")
        assert isinstance(derived, StructTypeInfo)
        assert derived.parent == "Base"


class TestCompositeAliasTargets:
    """``using`` aliases over array targets instantiate with the right layout."""

    def test_alias_to_u32_array_layout(self, interp: HexPatInterpreter) -> None:
        """Alias Quad = u32[2] yields an 8-byte field with two children.

        Args:
            interp: A fresh interpreter fixture.
        """
        data = bytes(range(16))
        results = interp.execute_bytes("using Quad = u32[2];\nQuad q @ 0;", data)
        q = _field(results, "q")
        assert q["size"] == 8
        assert len(q["children"]) == 2

    def test_alias_to_u8_array_reads_real_values(self, interp: HexPatInterpreter) -> None:
        """Alias Bytes = u8[4] reads the exact bytes from the buffer.

        Args:
            interp: A fresh interpreter fixture.
        """
        data = bytes([0xDE, 0xAD, 0xBE, 0xEF]) + bytes(12)
        results = interp.execute_bytes("using Bytes = u8[4];\nBytes b @ 0;", data)
        b = _field(results, "b")
        assert b["size"] == 4
        assert [c["raw_bytes"][0] for c in b["children"]] == [0xDE, 0xAD, 0xBE, 0xEF]


class TestNamespaceQualifiedRegistration:
    """Namespaced struct declarations register under both name forms."""

    def test_qualified_and_local_names_resolve_to_same_info(self) -> None:
        """A namespaced struct resolves identically via local and qualified name."""
        registry = TypeRegistry()
        decl = StructDecl(
            name="Header",
            parent=None,
            body=(),
            annotations=(),
            line=1,
            column=1,
        )
        registry.register_struct(decl, namespace="fmt")
        local = registry.resolve("Header")
        qualified = registry.resolve("fmt::Header")
        assert isinstance(local, StructTypeInfo)
        assert isinstance(qualified, StructTypeInfo)
        assert local is qualified
        names = registry.user_type_names()
        assert "Header" in names
        assert "fmt::Header" in names

    def test_reserved_primitive_name_is_rejected(self) -> None:
        """Registering a struct named after a primitive raises HexPatTypeError."""
        registry = TypeRegistry()
        decl = StructDecl(
            name="u32",
            parent=None,
            body=(),
            annotations=(),
            line=3,
            column=5,
        )
        with pytest.raises(HexPatTypeError):
            registry.register_struct(decl)


class TestAliasChainResolution:
    """Alias chains resolve through to the terminal primitive type."""

    def test_two_level_alias_resolves_to_primitive(self) -> None:
        """A -> B -> u16 resolves A to the u16 HexPatType."""
        registry = TypeRegistry()
        registry.register_alias("WORD", "u16")
        registry.register_alias("MyWord", "WORD")
        resolved = registry.resolve("MyWord")
        assert isinstance(resolved, HexPatType)
        assert resolved.name == "u16"
        assert resolved.size == 2

    def test_resolve_primitive_endian_override_is_independent(self) -> None:
        """resolve_primitive with an endian override leaves the base type intact."""
        registry = TypeRegistry()
        big = registry.resolve_primitive("u32", endian="big")
        little = registry.resolve_primitive("u32", endian="little")
        assert big is not None
        assert little is not None
        assert big.endian == "big"
        assert little.endian == "little"
        assert big.size == little.size == 4


class TestCompleterFromLiveRegistry:
    """HexPatCompleter merges live user names with builtin primitive names."""

    def test_completer_includes_user_struct_after_real_run(self, interp: HexPatInterpreter) -> None:
        """A struct declared in a real pattern appears in completer output.

        Args:
            interp: A fresh interpreter fixture.
        """
        interp.execute_bytes(
            "struct CustomHeader { u8 a; };\nCustomHeader h @ 0;",
            bytes(8),
        )
        registry = interp.last_type_registry
        assert registry is not None
        completer = HexPatCompleter()
        completer.update_from_registry(registry)
        names = completer.all_type_names()
        assert "CustomHeader" in names
        assert BuiltinTypes.all_names() <= set(names)

    def test_complete_prefix_matches_user_and_builtin(self, interp: HexPatInterpreter) -> None:
        """complete() returns prefix matches drawn from both name sources.

        Args:
            interp: A fresh interpreter fixture.
        """
        interp.execute_bytes(
            "struct Userland { u8 a; };\nUserland u @ 0;",
            bytes(8),
        )
        registry = interp.last_type_registry
        assert registry is not None
        completer = HexPatCompleter()
        completer.update_from_registry(registry)
        assert "Userland" in completer.complete("User")
        assert "u8" in completer.complete("u")

    def test_complete_empty_prefix_returns_all_sorted(self) -> None:
        """complete('') returns every builtin name in sorted order."""
        completer = HexPatCompleter()
        result = completer.complete("")
        assert result == sorted(result)
        assert "u8" in result
        assert "double" in result


class _RecordingReflectionProvider:
    """Real reflection provider that records dispatched calls into a dict.

    ``BuiltinFunctions.set_reflection_provider`` duck-types any object exposing
    the documented reflection callbacks, so this concrete provider exercises
    the genuine dispatch path while capturing the exact pattern and value each
    ``std::core`` builtin forwarded. The recorded values are what the tests
    assert against, so nothing about the dispatch itself is faked.
    """

    def __init__(self) -> None:
        """Initialise the recording dictionary."""
        self.record: dict[str, object] = {}

    def set_pattern_color(self, pattern: PatternValue, color: int) -> None:
        """Record a ``std::core::set_pattern_color`` dispatch.

        Args:
            pattern: The reflected pattern value.
            color: The 32-bit RGBA8 color word forwarded by the builtin.
        """
        self.record["color_target"] = pattern
        self.record["color"] = color

    def set_display_name(self, pattern: PatternValue, name: str) -> None:
        """Record a ``std::core::set_display_name`` dispatch.

        Args:
            pattern: The reflected pattern value.
            name: The display name forwarded by the builtin.
        """
        self.record["name_target"] = pattern
        self.record["display_name"] = name

    def set_pattern_comment(self, pattern: PatternValue, comment: str) -> None:
        """Record a ``std::core::set_pattern_comment`` dispatch.

        Args:
            pattern: The reflected pattern value.
            comment: The comment text forwarded by the builtin.
        """
        self.record["comment_target"] = pattern
        self.record["comment"] = comment

    def has_member(self, pattern: PatternValue, member: str) -> bool:
        """Answer ``std::core::has_member`` from the pattern member dict.

        Args:
            pattern: The reflected pattern value.
            member: The member name to test for.

        Returns:
            bool: ``True`` when ``member`` is a member of ``pattern``.
        """
        return member in pattern.members


class TestCoreReflectionDispatch:
    """std::core reflection builtins dispatch through a real provider."""

    def _provider_and_record(self) -> tuple[_RecordingReflectionProvider, dict[str, object]]:
        """Build a real reflection provider that records into a dict.

        Returns:
            tuple[_RecordingReflectionProvider, dict[str, object]]: The provider
                whose callbacks write into the returned recording dict.
        """
        provider = _RecordingReflectionProvider()
        return provider, provider.record

    def test_set_pattern_color_records_real_value(self) -> None:
        """set_pattern_color forwards the exact pattern and color to the provider."""
        provider, record = self._provider_and_record()
        builtins = BuiltinFunctions(DataReader.from_bytes(bytes(4)))
        builtins.set_reflection_provider(provider)
        target = PatternValue(value=1, offset=0, size=1)
        getattr(builtins, "_core_set_pattern_color")(target, 0xFF0000FF)
        assert record["color"] == 0xFF0000FF
        assert record["color_target"] is target

    def test_set_display_name_records_real_value(self) -> None:
        """set_display_name forwards the exact pattern and name to the provider."""
        provider, record = self._provider_and_record()
        builtins = BuiltinFunctions(DataReader.from_bytes(bytes(4)))
        builtins.set_reflection_provider(provider)
        target = PatternValue(value=1, offset=0, size=1)
        getattr(builtins, "_core_set_display_name")(target, "renamed_field")
        assert record["display_name"] == "renamed_field"
        assert record["name_target"] is target

    def test_set_pattern_comment_records_real_value(self) -> None:
        """set_pattern_comment forwards the exact pattern and comment text."""
        provider, record = self._provider_and_record()
        builtins = BuiltinFunctions(DataReader.from_bytes(bytes(4)))
        builtins.set_reflection_provider(provider)
        target = PatternValue(value=1, offset=0, size=1)
        getattr(builtins, "_core_set_pattern_comment")(target, "checksum field")
        assert record["comment"] == "checksum field"
        assert record["comment_target"] is target

    def test_has_member_reflects_real_struct_members(self) -> None:
        """has_member resolves real members of a struct PatternValue."""
        provider, _record = self._provider_and_record()
        builtins = BuiltinFunctions(DataReader.from_bytes(bytes(4)))
        builtins.set_reflection_provider(provider)
        struct_val = PatternValue(value="S", offset=0, size=2)
        struct_val.members["field_a"] = PatternValue(value=1, offset=0, size=1)
        struct_val.members["field_b"] = PatternValue(value=2, offset=1, size=1)
        present = getattr(builtins, "_core_has_member")(struct_val, "field_a")
        absent = getattr(builtins, "_core_has_member")(struct_val, "missing")
        assert present.value is True
        assert absent.value is False

    def test_member_count_uses_real_member_dict(self) -> None:
        """member_count returns the real number of struct members."""
        builtins = BuiltinFunctions(DataReader.from_bytes(bytes(4)))
        struct_val = PatternValue(value="S", offset=0, size=3)
        struct_val.members["a"] = PatternValue(value=1, offset=0, size=1)
        struct_val.members["b"] = PatternValue(value=2, offset=1, size=1)
        struct_val.members["c"] = PatternValue(value=3, offset=2, size=1)
        result = getattr(builtins, "_core_member_count")(struct_val)
        assert result.value == 3

    def test_unwired_reflection_builtin_raises(self) -> None:
        """A reflection builtin with no provider wired fails loud, not silent."""
        builtins = BuiltinFunctions(DataReader.from_bytes(bytes(4)))
        target = PatternValue(value=1, offset=0, size=1)
        with pytest.raises(HexPatRuntimeError):
            getattr(builtins, "_core_set_pattern_color")(target, 0x10203040)


class TestCoreEndianDispatch:
    """std::core endian state mutation is observable through the public API."""

    def test_set_endian_big_updates_reads(self) -> None:
        """set_endian(big) flips multi-byte reads to big-endian byteorder."""
        reader = DataReader.from_bytes(bytes([0x12, 0x34]))
        builtins = BuiltinFunctions(reader)
        getattr(builtins, "_core_set_endian")(2)
        little: int = getattr(builtins, "_mem_read_unsigned")(0, 2, 0)
        getattr(builtins, "_core_set_endian")(1)
        big: int = getattr(builtins, "_mem_read_unsigned")(0, 2, 0)
        assert little == 0x3412
        assert big == 0x1234
        assert getattr(builtins, "_core_get_endian")() == 1

    def test_set_endian_listener_receives_transition(self) -> None:
        """A registered endian listener observes the resolved endian string."""
        reader = DataReader.from_bytes(bytes(2))
        builtins = BuiltinFunctions(reader)
        seen: list[str] = []
        listener: Callable[[str], None] = seen.append
        builtins.set_endian_listener(listener)
        getattr(builtins, "_core_set_endian")(1)
        assert seen == ["big"]
