# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for complex HexPat pattern constructs via execute_bytes."""

from __future__ import annotations

import struct
from typing import Any

import pytest

from intellicrack.core.hexpat.interpreter import HexPatInterpreter


@pytest.fixture
def interp() -> HexPatInterpreter:
    """Provide a fresh HexPatInterpreter with no custom paths.

    Returns:
        HexPatInterpreter: A fresh interpreter instance.
    """
    return HexPatInterpreter()


def _field(results: list[dict[str, Any]], name: str) -> dict[str, Any]:
    """Find a parsed field dict by name.

    Args:
        results: List of parsed field dicts from execute_bytes.
        name: The field name to search for.

    Returns:
        dict[str, Any]: The matching field dict.

    Raises:
        AssertionError: If no field with the given name is found.
    """
    found = next((r for r in results if r["name"] == name), None)
    assert found is not None, f"Field '{name}' not found in results: {[r['name'] for r in results]}"
    return found


class TestPointers:
    """Tests for pointer type declarations and field placement."""

    def test_pointer_field_has_pointer_display(self, interp: HexPatInterpreter) -> None:
        """A pointer field's display_value starts with '*'.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = struct.pack("<Q", 0x100) + bytes(256)
        source = "u8 *ptr @ 0;"
        results = interp.execute_bytes(source, data)
        assert results[0]["display_value"].startswith("*")

    def test_pointer_field_size_is_eight(self, interp: HexPatInterpreter) -> None:
        """A pointer field consumes exactly 8 bytes.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 *ptr @ 0;"
        results = interp.execute_bytes(source, data)
        assert results[0]["size"] == 8

    def test_placement_at_explicit_offset(self, interp: HexPatInterpreter) -> None:
        """Using @ with an explicit offset places the field at that byte position.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytearray(32)
        data[16] = 0xAB
        source = "u8 far_field @ 16;"
        results = interp.execute_bytes(source, bytes(data))
        assert results[0]["offset"] == 16
        assert results[0]["display_value"] == "0xAB"


class TestUnions:
    """Tests for union type declarations with overlapping members."""

    def test_union_all_members_start_at_same_offset(self, interp: HexPatInterpreter) -> None:
        """All union member fields start at the union's base offset.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = struct.pack("<I", 0xDEADBEEF) + bytes(16)
        source = "union MyUnion {\n    u32 as_u32;\n    u8 bytes[4];\n};\nMyUnion u @ 0;"
        results = interp.execute_bytes(source, data)
        union_field = _field(results, "u")
        children = union_field["children"]
        assert all(c["offset"] == 0 for c in children)

    def test_union_size_is_max_member_size(self, interp: HexPatInterpreter) -> None:
        """A union's total size equals the size of its largest member.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "union Overlap {\n    u8 small;\n    u32 large;\n};\nOverlap o @ 0;"
        results = interp.execute_bytes(source, data)
        union_field = _field(results, "o")
        assert union_field["size"] == 4

    def test_union_members_reflect_same_bytes(self, interp: HexPatInterpreter) -> None:
        """Union u32 member and u8 members read from the same underlying bytes.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([0x78, 0x56, 0x34, 0x12]) + bytes(16)
        source = "union TwoViews {\n    u32 word;\n    u8 byte0;\n};\nTwoViews tv @ 0;"
        results = interp.execute_bytes(source, data)
        tv = _field(results, "tv")
        assert tv["raw_bytes"][0] == 0x78


class TestComputedFields:
    """Tests for fields whose placement offset is computed from prior field values."""

    def test_computed_offset_from_prior_field(self, interp: HexPatInterpreter) -> None:
        """A field placed at an offset derived from another field reads the correct byte.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytearray(64)
        data[0] = 10
        data[10] = 0xCC
        source = "u8 jump_to @ 0;\nu8 target @ jump_to;"
        results = interp.execute_bytes(source, bytes(data))
        target = _field(results, "target")
        assert target["offset"] == 10
        assert target["display_value"] == "0xCC"

    def test_field_value_used_as_array_size(self, interp: HexPatInterpreter) -> None:
        """A u8 field value used as a dynamic array size determines element count.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytearray(64)
        data[0] = 5
        data[1:6] = bytes([10, 20, 30, 40, 50])
        source = "u8 count @ 0;\nu8 items[count] @ 1;"
        results = interp.execute_bytes(source, bytes(data))
        array_field = _field(results, "items")
        assert len(array_field["children"]) == 5


class TestConditionalFields:
    """Tests for if/else conditional field placement inside struct bodies."""

    def test_conditional_if_branch_taken(self, interp: HexPatInterpreter) -> None:
        """If branch fields are placed when the condition is truthy.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytearray(16)
        data[0] = 1
        source = "u8 flag @ 0;\nif (flag == 1) {\n    u8 type_a @ 1;\n} else {\n    u8 type_b @ 1;\n}"
        results = interp.execute_bytes(source, bytes(data))
        named = [r["name"] for r in results]
        assert "type_a" in named
        assert "type_b" not in named

    def test_conditional_else_branch_taken(self, interp: HexPatInterpreter) -> None:
        """Else branch fields are placed when the if condition is falsy.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytearray(16)
        data[0] = 0
        source = "u8 flag @ 0;\nif (flag == 1) {\n    u8 type_a @ 1;\n} else {\n    u8 type_b @ 1;\n}"
        results = interp.execute_bytes(source, bytes(data))
        named = [r["name"] for r in results]
        assert "type_b" in named
        assert "type_a" not in named

    def test_conditional_inside_struct_body(self, interp: HexPatInterpreter) -> None:
        """Conditional field placement works correctly inside a struct body.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytearray(16)
        data[0] = 1
        data[1] = 0x42
        source = "struct Conditional {\n    u8 has_extra;\n    if (has_extra != 0) {\n        u8 extra_data;\n    }\n};\nConditional c @ 0;"
        results = interp.execute_bytes(source, bytes(data))
        c = _field(results, "c")
        child_names = [ch["name"] for ch in c["children"]]
        assert "extra_data" in child_names


class TestNestedArrays:
    """Tests for arrays of structs and arrays with computed sizes."""

    def test_array_of_struct_elements(self, interp: HexPatInterpreter) -> None:
        """Array of a struct type produces one child per element.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(range(32))
        source = "struct Pair {\n    u8 lo;\n    u8 hi;\n};\nPair pairs[4] @ 0;"
        results = interp.execute_bytes(source, data)
        array_field = _field(results, "pairs")
        assert len(array_field["children"]) == 4

    def test_array_fixed_size_field_values(self, interp: HexPatInterpreter) -> None:
        """Array elements contain the correct raw bytes from the data buffer.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0])
        source = "u8 arr[4] @ 0;"
        results = interp.execute_bytes(source, data)
        array_field = _field(results, "arr")
        children = array_field["children"]
        assert len(children) == 4
        assert children[0]["raw_bytes"] == [0xAA]
        assert children[1]["raw_bytes"] == [0xBB]

    def test_array_size_from_variable(self, interp: HexPatInterpreter) -> None:
        """Array count derived from a variable produces the correct element count.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(range(16))
        source = "u8 n = 6;\nu8 items[n] @ 0;"
        results = interp.execute_bytes(source, data)
        array_field = _field(results, "items")
        assert len(array_field["children"]) == 6


class TestSizeofOperator:
    """Tests for the sizeof operator applied to primitive and named types."""

    def test_sizeof_u8(self, interp: HexPatInterpreter) -> None:
        """sizeof(u8) returns 1.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(8)
        source = "u8 result @ sizeof(u8);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 1

    def test_sizeof_u32(self, interp: HexPatInterpreter) -> None:
        """sizeof(u32) returns 4.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(8)
        source = "u8 result @ sizeof(u32);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 4

    def test_sizeof_u64(self, interp: HexPatInterpreter) -> None:
        """sizeof(u64) returns 8.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ sizeof(u64);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 8

    def test_sizeof_struct_type(self, interp: HexPatInterpreter) -> None:
        """Sizeof on a user-defined struct type returns its total byte size.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "struct TwoBytes {\n    u8 a;\n    u8 b;\n};\nu8 result @ sizeof(TwoBytes);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 2

    def test_sizeof_placed_variable(self, interp: HexPatInterpreter) -> None:
        """Sizeof applied to a placed variable returns the field size.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u32 my_val @ 0;\nu8 sz_result @ sizeof(my_val);"
        results = interp.execute_bytes(source, data)
        sz = _field(results, "sz_result")
        assert sz["offset"] == 4


class TestDollarOperator:
    """Tests for the $ (current offset) operator."""

    def test_dollar_reads_current_offset(self, interp: HexPatInterpreter) -> None:
        """$ returns the current parser offset after sequential field placements.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 a @ 0;\nu8 b @ 1;\nu8 cur_offset = $;\nu8 result @ cur_offset;"
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "result" for r in results)
        result_field = _field(results, "result")
        assert result_field["offset"] == 2

    def test_dollar_advances_with_field_reads(self, interp: HexPatInterpreter) -> None:
        """$ increments by the size of each sequentially placed field.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u32 first @ 0;\nu8 pos_after_u32 @ $;"
        results = interp.execute_bytes(source, data)
        pos_field = _field(results, "pos_after_u32")
        assert pos_field["offset"] == 4

    def test_dollar_assignable(self, interp: HexPatInterpreter) -> None:
        """Assigning to $ repositions the offset to the given value.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(32)
        source = "u8 a @ 0;\n$ = 10;\nu8 jumped @ $;"
        results = interp.execute_bytes(source, data)
        jumped = _field(results, "jumped")
        assert jumped["offset"] == 10


class TestTypeCasts:
    """Tests for explicit type cast expressions."""

    def test_cast_u32_to_u8_truncates(self, interp: HexPatInterpreter) -> None:
        """Casting a u32 value to u8 keeps only the low 8 bits.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (u8)(0x1FF);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 0xFF % 16

    def test_cast_float_to_u8(self, interp: HexPatInterpreter) -> None:
        """Casting a float to u8 truncates the fractional part.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (u8)(7.9);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 7

    def test_cast_negative_to_signed(self, interp: HexPatInterpreter) -> None:
        """Casting a negative integer to s8 preserves the sign bit.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = struct.pack("b", -1) + bytes(3)
        source = "s8 val @ 0;\n"
        interp.execute_bytes(source, data)

    def test_cast_int_to_bool_nonzero_is_true(self, interp: HexPatInterpreter) -> None:
        """Casting a non-zero integer to bool produces true.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(4)
        source = "if ((bool)(42)) { u8 yes @ 0; }"
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "yes" for r in results)

    def test_cast_zero_to_bool_is_false(self, interp: HexPatInterpreter) -> None:
        """Casting zero to bool produces false.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(4)
        source = "if ((bool)(0)) { u8 no @ 0; } else { u8 yes @ 0; }"
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "yes" for r in results)

    def test_cast_u8_to_u32_widens(self, interp: HexPatInterpreter) -> None:
        """Casting a small u8 value to u32 produces the same unsigned integer value.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (u32)(5);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 5

    def test_struct_sequential_fields_advance_offset(self, interp: HexPatInterpreter) -> None:
        """Sequential primitive fields in a struct advance the read offset correctly.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] + [0] * 8)
        source = "struct Header {\n    u16 sig;\n    u16 version;\n    u32 size;\n};\nHeader h @ 0;"
        results = interp.execute_bytes(source, data)
        h = _field(results, "h")
        assert h["size"] == 8
        child_names = [c["name"] for c in h["children"]]
        assert "sig" in child_names
        assert "version" in child_names
        assert "size" in child_names
