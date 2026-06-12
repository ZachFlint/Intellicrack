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
        """While loop with a counter reads exactly N fields at the right offsets and values.

        The loop runs while ``i < count`` (count == 4), placing ``u8 byte @ i``
        each iteration. With ``data == bytes(range(16))`` the field at offset
        ``i`` must read raw byte value ``i``. The independently-known oracle is
        the identity mapping offset -> value of ``bytes(range(16))``: offsets
        0..3 carry values 0,1,2,3.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(range(16))
        source = "u8 count = 4;\nu8 i = 0;\nwhile (i < count) {\n    u8 byte @ i;\n    i = i + 1;\n}"
        results = interp.execute_bytes(source, data)
        assert len(results) == 4
        assert [r["name"] for r in results] == ["byte", "byte", "byte", "byte"]
        assert [r["offset"] for r in results] == [0, 1, 2, 3]
        assert [r["size"] for r in results] == [1, 1, 1, 1]
        assert [r["raw_bytes"] for r in results] == [[0], [1], [2], [3]]
        assert [r["display_value"] for r in results] == ["0x0", "0x1", "0x2", "0x3"]

    def test_while_sentinel_stops_at_zero(self, interp: HexPatInterpreter) -> None:
        """While loop terminates exactly at the 0x00 sentinel without parsing it or past it.

        The condition ``read_unsigned(idx, 1) != 0`` must consume bytes
        0x01, 0x02, 0x03 (offsets 0..2) and stop the moment it reaches the
        0x00 at offset 3, never placing a field there nor for the trailing
        0x05/0x06. The oracle is the input layout itself: three non-zero
        leading bytes followed by a sentinel.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = b"\x01\x02\x03\x00\x05\x06"
        source = "u8 idx = 0;\nwhile (read_unsigned(idx, 1) != 0) {\n    u8 byte @ idx;\n    idx = idx + 1;\n}"
        results = interp.execute_bytes(source, data)
        assert len(results) == 3
        assert [r["offset"] for r in results] == [0, 1, 2]
        assert [r["raw_bytes"] for r in results] == [[1], [2], [3]]
        assert [r["display_value"] for r in results] == ["0x1", "0x2", "0x3"]
        parsed_offsets = {r["offset"] for r in results}
        assert 3 not in parsed_offsets
        assert 4 not in parsed_offsets
        assert 5 not in parsed_offsets

    def test_while_false_condition_executes_zero_iterations(self, interp: HexPatInterpreter) -> None:
        """While loop with a false initial condition skips its body but lets execution continue.

        The guard ``run != 0`` is false from the start, so the in-loop field
        ``inside`` must never be placed. To prove the loop was truly skipped
        rather than execution aborting, a post-loop field ``after`` is placed
        and must read the distinctive sentinel byte 0x42 at offset 0. The
        oracle is the input layout: a single 0x42 byte means exactly one field
        named ``after`` with that value, and no ``inside`` field at all.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = b"\x42\x00\x00\x00\x00\x00\x00\x00"
        source = "u8 run = 0;\nwhile (run != 0) {\n    u8 inside @ 0;\n}\nu8 after @ 0;"
        results = interp.execute_bytes(source, data)
        assert len(results) == 1
        assert results[0]["name"] == "after"
        assert results[0]["offset"] == 0
        assert results[0]["size"] == 1
        assert results[0]["raw_bytes"] == [0x42]
        assert results[0]["display_value"] == "0x42"
        assert "inside" not in [r["name"] for r in results]

    def test_while_true_condition_executes_body(self, interp: HexPatInterpreter) -> None:
        """While loop with a true initial condition runs the body and places the field.

        This is the positive counterpart to the false-condition case: the loop
        enters with ``run == 1``, places ``u8 x @ 0`` (reading the known byte
        0xAB), then clears ``run`` so it iterates exactly once. Proves the
        guard is actually evaluated rather than always skipped.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = b"\xab\xcd\x00\x00"
        source = "u8 run = 1;\nwhile (run != 0) {\n    u8 x @ 0;\n    run = 0;\n}"
        results = interp.execute_bytes(source, data)
        assert len(results) == 1
        assert results[0]["name"] == "x"
        assert results[0]["offset"] == 0
        assert results[0]["raw_bytes"] == [0xAB]
        assert results[0]["display_value"] == "0xAB"


class TestForLoops:
    """Tests for for-loop constructs in pattern programs."""

    def test_for_loop_fixed_count(self, interp: HexPatInterpreter) -> None:
        """For loop with fixed count produces exactly N fields at correct offsets and values.

        With ``data == bytes(range(8))`` and the loop ``i < 5`` placing
        ``u8 elem @ i``, the oracle is the identity mapping of
        ``bytes(range(8))``: offsets 0..4 read values 0,1,2,3,4. The loop must
        stop at i == 5 and not read offsets 5..7.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(range(8))
        source = "for (u8 i = 0; i < 5; i = i + 1) {\n    u8 elem @ i;\n}"
        results = interp.execute_bytes(source, data)
        assert len(results) == 5
        assert [r["name"] for r in results] == ["elem"] * 5
        assert [r["offset"] for r in results] == [0, 1, 2, 3, 4]
        assert [r["raw_bytes"] for r in results] == [[0], [1], [2], [3], [4]]
        assert [r["display_value"] for r in results] == ["0x0", "0x1", "0x2", "0x3", "0x4"]

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
        """Break in a while loop stops iteration exactly at the break condition.

        Loop runs ``while i < 10`` placing ``u8 val @ i`` then incrementing i,
        but breaks when ``i == 3``. The break fires before the placement for
        i == 3, so exactly three fields at offsets 0, 1, 2 are produced.
        With ``data == bytes(range(16))`` each byte at offset k has value k.
        The oracle is the arithmetic: offsets 0..2 read values 0,1,2 and no
        field for offset 3 or beyond must appear.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(range(16))
        source = "u8 i = 0;\nwhile (i < 10) {\n    if (i == 3) {\n        break;\n    }\n    u8 val @ i;\n    i = i + 1;\n}"
        results = interp.execute_bytes(source, data)
        assert len(results) == 3
        assert [r["name"] for r in results] == ["val", "val", "val"]
        assert [r["offset"] for r in results] == [0, 1, 2]
        assert [r["size"] for r in results] == [1, 1, 1]
        assert [r["raw_bytes"] for r in results] == [[0], [1], [2]]
        assert [r["display_value"] for r in results] == ["0x0", "0x1", "0x2"]
        parsed_offsets = {r["offset"] for r in results}
        assert 3 not in parsed_offsets
        assert 4 not in parsed_offsets

    def test_continue_skips_iteration_body(self, interp: HexPatInterpreter) -> None:
        """Continue in a for loop skips field placement for the continued iterations.

        The loop runs i == 0..5. The ``continue`` fires for i == 2 and i == 4,
        so those iterations skip the ``u8 val @ i`` placement. Fields are
        placed only for i in {0, 1, 3, 5}. With ``data == bytes(range(8))``
        each byte at offset k is k, giving values 0, 1, 3, 5 at those offsets.
        The oracle is the set arithmetic: i in 0..5 minus {2, 4} == {0,1,3,5}.

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
        assert [r["name"] for r in results] == ["val", "val", "val", "val"]
        assert [r["offset"] for r in results] == [0, 1, 3, 5]
        assert [r["size"] for r in results] == [1, 1, 1, 1]
        assert [r["raw_bytes"] for r in results] == [[0], [1], [3], [5]]
        assert [r["display_value"] for r in results] == ["0x0", "0x1", "0x3", "0x5"]
        parsed_offsets = {r["offset"] for r in results}
        assert 2 not in parsed_offsets
        assert 4 not in parsed_offsets


class TestNestedControl:
    """Tests for nested control flow structures."""

    def test_nested_for_inside_while(self, interp: HexPatInterpreter) -> None:
        """Nested for inside while iterates both levels with correct offsets and values.

        The while runs outer == 0, 1 (two iterations). Inside each, the for
        runs inner == 0, 1, 2, placing ``u8 v @ (outer * 8 + inner)``. The
        six resulting offsets are 0,1,2 (outer=0) and 8,9,10 (outer=1).
        With ``data == bytes(range(64))`` byte at offset k is k, so the
        display values are "0x0","0x1","0x2","0x8","0x9","0xA". The oracle
        is the explicit formula outer*8+inner evaluated for outer in {0,1}
        and inner in {0,1,2}.

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
        assert [r["name"] for r in results] == ["v"] * 6
        assert [r["offset"] for r in results] == [0, 1, 2, 8, 9, 10]
        assert [r["size"] for r in results] == [1] * 6
        assert [r["raw_bytes"] for r in results] == [[0], [1], [2], [8], [9], [10]]
        assert [r["display_value"] for r in results] == ["0x0", "0x1", "0x2", "0x8", "0x9", "0xA"]

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
        """While loop accumulates a running sum and the value drives a field offset.

        The loop sums the first five bytes (1+2+3+4+5 == 15) into ``total``,
        then places ``u8 marker @ total``. The accumulated total is exposed
        through the placement offset: the marker field must land at offset 15
        and read the distinctive sentinel byte 0x7E planted there. The oracle
        is the arithmetic sum 15 computed by hand and a marker byte that exists
        at exactly that offset and nowhere else among the leading/zero bytes.
        A wrong accumulation (14 or 16) would place the marker on a 0x00 byte,
        flipping ``display_value`` to ``0x0``.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([1, 2, 3, 4, 5, *([0] * 10), 0x7E])
        assert len(data) == 16
        source = (
            "u32 total = 0;\nu8 i = 0;\nwhile (i < 5) {\n    total = total + read_unsigned(i, 1);\n    i = i + 1;\n}\nu8 marker @ total;"
        )
        results = interp.execute_bytes(source, data)
        assert len(results) == 1
        marker = results[0]
        assert marker["name"] == "marker"
        assert marker["offset"] == 15
        assert marker["size"] == 1
        assert marker["raw_bytes"] == [0x7E]
        assert marker["display_value"] == "0x7E"

    def test_try_inside_for_loop_recovers_per_iteration(self, interp: HexPatInterpreter) -> None:
        """try/catch inside a for loop recovers per iteration with exactly one field each.

        Over a 4-byte buffer the loop attempts ``u32 big @ i`` (needs 4 bytes)
        for i in 0..3. Only i == 0 has 4 bytes available, so that iteration
        succeeds and yields a 4-byte ``big`` field. For i == 1,2,3 the u32 read
        runs off the end, the catch fires, and a 1-byte ``small`` field is read
        instead. The oracle is the buffer geometry: success at offset 0,
        recovery at offsets 1,2,3, giving exactly four fields with known
        names, sizes, and bytes.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = b"\xaa\xbb\xcc\xdd"
        source = "for (u8 i = 0; i < 4; i = i + 1) {\n    try {\n        u32 big @ i;\n    } catch {\n        u8 small @ i;\n    }\n}"
        results = interp.execute_bytes(source, data)
        assert len(results) == 4
        assert [r["name"] for r in results] == ["big", "small", "small", "small"]
        assert [r["offset"] for r in results] == [0, 1, 2, 3]
        assert [r["size"] for r in results] == [4, 1, 1, 1]
        assert results[0]["raw_bytes"] == [0xAA, 0xBB, 0xCC, 0xDD]
        assert results[0]["display_value"] == "0xDDCCBBAA"
        assert [r["raw_bytes"] for r in results[1:]] == [[0xBB], [0xCC], [0xDD]]
        assert [r["display_value"] for r in results[1:]] == ["0xBB", "0xCC", "0xDD"]

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
