# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexPat control-flow constructs via execute_bytes."""

from __future__ import annotations

import pytest

from intellicrack.core.hexpat.interpreter import HexPatInterpreter


@pytest.fixture
def interp() -> HexPatInterpreter:
    """Provide a HexPatInterpreter with no custom include paths.

    Returns:
        HexPatInterpreter: A fresh interpreter instance.
    """
    return HexPatInterpreter()


class TestWhileLoops:
    """Tests for while loop constructs in pattern programs."""

    def test_while_counter_loop_produces_fields(self, interp: HexPatInterpreter) -> None:
        """While loop with a counter reads N fields, advancing offset.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(range(16))
        source = "u8 count = 4;\nu8 i = 0;\nwhile (i < count) {\n    u8 byte @ i;\n    i = i + 1;\n}"
        results = interp.execute_bytes(source, data)
        assert len(results) == 4

    def test_while_sentinel_stops_at_zero(self, interp: HexPatInterpreter) -> None:
        """While loop terminates when sentinel byte 0x00 is encountered.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = b"\x01\x02\x03\x00\x05\x06"
        source = "u8 idx = 0;\nwhile (read_unsigned(idx, 1) != 0) {\n    u8 byte @ idx;\n    idx = idx + 1;\n}"
        results = interp.execute_bytes(source, data)
        assert len(results) == 3

    def test_while_empty_body_terminates_immediately(self, interp: HexPatInterpreter) -> None:
        """While loop with a false initial condition executes zero iterations.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(8)
        source = "u8 run = 0;\nwhile (run != 0) {\n    u8 x @ 0;\n}"
        results = interp.execute_bytes(source, data)
        assert results == []


class TestForLoops:
    """Tests for for-loop constructs in pattern programs."""

    def test_for_loop_fixed_count(self, interp: HexPatInterpreter) -> None:
        """For loop with fixed count produces exactly N fields.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(range(8))
        source = "for (u8 i = 0; i < 5; i = i + 1) {\n    u8 elem @ i;\n}"
        results = interp.execute_bytes(source, data)
        assert len(results) == 5

    def test_for_loop_field_values_correct(self, interp: HexPatInterpreter) -> None:
        """For loop reads correct byte values from data.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([10, 20, 30, 40])
        source = "for (u8 i = 0; i < 4; i = i + 1) {\n    u8 val @ i;\n}"
        results = interp.execute_bytes(source, data)
        assert len(results) == 4
        values = [int(r["display_value"], 16) for r in results]
        assert values == [10, 20, 30, 40]

    def test_for_loop_zero_iterations(self, interp: HexPatInterpreter) -> None:
        """For loop with count 0 produces no fields.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(8)
        source = "for (u8 i = 0; i < 0; i = i + 1) {\n    u8 x @ i;\n}"
        results = interp.execute_bytes(source, data)
        assert results == []


class TestMatchStatement:
    """Tests for match/switch constructs in pattern programs."""

    def test_match_first_arm_selected(self, interp: HexPatInterpreter) -> None:
        """Match selects the arm whose value equals the subject.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = b"\x01" + bytes(15)
        source = "u8 tag @ 0;\nmatch (tag) {\n    1: { u8 field_a @ 1; }\n    2: { u8 field_b @ 1; }\n}"
        results = interp.execute_bytes(source, data)
        named = [r["name"] for r in results]
        assert "field_a" in named
        assert "field_b" not in named

    def test_match_second_arm_selected(self, interp: HexPatInterpreter) -> None:
        """Match selects the second arm when the value matches.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = b"\x02" + bytes(15)
        source = "u8 tag @ 0;\nmatch (tag) {\n    1: { u8 field_a @ 1; }\n    2: { u8 field_b @ 1; }\n}"
        results = interp.execute_bytes(source, data)
        named = [r["name"] for r in results]
        assert "field_b" in named
        assert "field_a" not in named

    def test_match_wildcard_arm_catches_unmatched(self, interp: HexPatInterpreter) -> None:
        """Match wildcard (_) arm executes when no other arm matches.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = b"\xff" + bytes(15)
        source = "u8 tag @ 0;\nmatch (tag) {\n    1: { u8 known @ 1; }\n    _: { u8 unknown @ 1; }\n}"
        results = interp.execute_bytes(source, data)
        named = [r["name"] for r in results]
        assert "unknown" in named
        assert "known" not in named

    def test_match_no_arm_matches_produces_no_extra_fields(self, interp: HexPatInterpreter) -> None:
        """Match with no matching arm and no wildcard produces only the subject field.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = b"\x09" + bytes(15)
        source = "u8 tag @ 0;\nmatch (tag) {\n    1: { u8 one @ 1; }\n    2: { u8 two @ 1; }\n}"
        results = interp.execute_bytes(source, data)
        assert len(results) == 1
        assert results[0]["name"] == "tag"


class TestTryCatch:
    """Tests for try/catch error handling constructs."""

    def test_try_catch_handles_out_of_bounds(self, interp: HexPatInterpreter) -> None:
        """try/catch catches out-of-bounds read and executes catch body.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(4)
        source = "u8 caught = 0;\ntry {\n    u32 oob @ 200;\n} catch {\n    u8 fallback @ 0;\n}"
        results = interp.execute_bytes(source, data)
        named = [r["name"] for r in results]
        assert "fallback" in named

    def test_try_body_succeeds_no_catch(self, interp: HexPatInterpreter) -> None:
        """Try body that succeeds runs without entering the catch block.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(8)
        source = "try {\n    u8 success @ 0;\n} catch {\n    u8 catch_field @ 1;\n}"
        results = interp.execute_bytes(source, data)
        named = [r["name"] for r in results]
        assert "success" in named
        assert "catch_field" not in named


class TestBreakContinue:
    """Tests for break and continue control flow in loops."""

    def test_break_exits_while_loop_early(self, interp: HexPatInterpreter) -> None:
        """Break in a while loop stops iteration before the limit.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(range(16))
        source = "u8 i = 0;\nwhile (i < 10) {\n    if (i == 3) {\n        break;\n    }\n    u8 val @ i;\n    i = i + 1;\n}"
        results = interp.execute_bytes(source, data)
        assert len(results) == 3

    def test_continue_skips_iteration_body(self, interp: HexPatInterpreter) -> None:
        """Continue in a for loop skips the field placement for that iteration.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(range(8))
        source = (
            "for (u8 i = 0; i < 6; i = i + 1) {\n"
            "    if (i == 2) {\n"
            "        continue;\n"
            "    }\n"
            "    if (i == 4) {\n"
            "        continue;\n"
            "    }\n"
            "    u8 val @ i;\n"
            "}"
        )
        results = interp.execute_bytes(source, data)
        assert len(results) == 4


class TestNestedControl:
    """Tests for nested control flow structures."""

    def test_nested_for_inside_while(self, interp: HexPatInterpreter) -> None:
        """Nested for inside while correctly iterates both levels.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(range(64))
        source = (
            "u8 outer = 0;\n"
            "while (outer < 2) {\n"
            "    for (u8 inner = 0; inner < 3; inner = inner + 1) {\n"
            "        u8 v @ (outer * 8 + inner);\n"
            "    }\n"
            "    outer = outer + 1;\n"
            "}"
        )
        results = interp.execute_bytes(source, data)
        assert len(results) == 6

    def test_conditional_inside_for_loop(self, interp: HexPatInterpreter) -> None:
        """if/else inside a for loop selects different field placements per iteration.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([1, 0, 1, 0, 1, 0, 0, 0])
        source = (
            "for (u8 i = 0; i < 6; i = i + 1) {\n"
            "    if (read_unsigned(i, 1) == 1) {\n"
            "        u8 one @ i;\n"
            "    } else {\n"
            "        u8 zero @ i;\n"
            "    }\n"
            "}"
        )
        results = interp.execute_bytes(source, data)
        assert len(results) == 6
        one_count = sum(bool(r["name"] == "one") for r in results)
        zero_count = sum(bool(r["name"] == "zero") for r in results)
        assert one_count == 3
        assert zero_count == 3

    def test_while_loop_accumulates_variable(self, interp: HexPatInterpreter) -> None:
        """While loop can accumulate a sum into a variable and place it.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([1, 2, 3, 4, 5, 0, 0, 0])
        source = "u32 total = 0;\nu8 i = 0;\nwhile (i < 5) {\n    total = total + read_unsigned(i, 1);\n    i = i + 1;\n}"
        interp.execute_bytes(source, data)

    def test_try_inside_for_loop_recovers_per_iteration(self, interp: HexPatInterpreter) -> None:
        """try/catch inside a for loop recovers from each failed iteration independently.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(4)
        source = "for (u8 i = 0; i < 4; i = i + 1) {\n    try {\n        u32 big @ i;\n    } catch {\n        u8 small @ i;\n    }\n}"
        results = interp.execute_bytes(source, data)
        assert len(results) >= 1

    def test_match_inside_while_selects_branch_each_iteration(self, interp: HexPatInterpreter) -> None:
        """Match inside while loop selects the correct branch per iteration.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([1, 2, 1, 2, 0, 0, 0, 0])
        source = (
            "u8 idx = 0;\n"
            "while (idx < 4) {\n"
            "    u8 cur = read_unsigned(idx, 1);\n"
            "    match (cur) {\n"
            "        1: { u8 type_a @ idx; }\n"
            "        2: { u8 type_b @ idx; }\n"
            "    }\n"
            "    idx = idx + 1;\n"
            "}"
        )
        results = interp.execute_bytes(source, data)
        type_a = sum(bool(r["name"] == "type_a") for r in results)
        type_b = sum(bool(r["name"] == "type_b") for r in results)
        assert type_a == 2
        assert type_b == 2
