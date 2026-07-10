# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexPat expression evaluation via execute_bytes.

Every test here drives a real ``.hexpat`` source string through the full
interpreter pipeline (preprocessor, lexer, parser, evaluator) against real
binary data and validates the *computed value*, not merely that a field was
produced.

Two independent oracle strategies are used so that a regression in any single
operator surfaces as a red test:

* Value-oracle guard - an expression's result is compared against a
  known-correct constant inside the pattern, and the test asserts that the
  ``correct`` branch executed and the ``wrong`` branch did not. A broken
  operator yields a different value, takes the ``else`` branch, and the test
  fails. The expected constants are hand-computed (e.g. ``0xF0 | 0x0F == 0xFF``)
  and never lifted from the implementation.
* Offset-plus-byte oracle - placement patterns (``T name @ expr``) are run
  against ``bytes(range(256))`` so that the byte stored at offset ``N`` equals
  ``N``. The test then asserts both the resolved ``offset`` and the
  ``raw_bytes``/``display_value`` read back from that offset, giving two
  independent confirmations that the placement expression computed the right
  address.
"""

from __future__ import annotations

import struct

import pytest

from intellicrack.core.hexpat.errors import HexPatRuntimeError
from intellicrack.core.hexpat.interpreter import HexPatInterpreter


# Data whose byte at index N equals N (for offsets 0..255). Used so that a
# placement at a computed offset reads back a byte that independently confirms
# the computed address.
_INDEXED_DATA: bytes = bytes(range(256))


@pytest.fixture
def interp() -> HexPatInterpreter:
    """Provide a HexPatInterpreter with no custom include paths.

    Returns:
        HexPatInterpreter: A fresh interpreter instance.
    """
    return HexPatInterpreter()


def _names(results: list[dict[str, object]]) -> list[str]:
    """Extract the ordered ``name`` field of every parsed result.

    Args:
        results: Parsed-field dictionaries returned by ``execute_bytes``.

    Returns:
        list[str]: The ``name`` of each result, in order.
    """
    return [str(r["name"]) for r in results]


def _field(results: list[dict[str, object]], name: str) -> dict[str, object]:
    """Return the single parsed-field dictionary with the given name.

    Args:
        results: Parsed-field dictionaries returned by ``execute_bytes``.
        name: The field name to locate.

    Returns:
        dict[str, object]: The matching parsed-field dictionary.
    """
    matches = [r for r in results if r["name"] == name]
    assert len(matches) == 1, f"expected exactly one field named {name!r}, got {_names(results)}"
    return matches[0]


class TestArithmeticValueOracle:
    """Arithmetic operators validated against independently computed values.

    Each pattern computes ``expr`` then branches on equality with a constant
    that was worked out by hand. The test asserts the ``correct`` branch fired
    (placing a sentinel at a fixed offset) and that no ``wrong`` field exists.
    Swapping any operator for another (e.g. subtraction returning a sum) drives
    the wrong branch and fails the assertion.
    """

    def test_addition_value(self, interp: HexPatInterpreter) -> None:
        """3 + 4 evaluates to exactly 7.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 v = 3 + 4;\nif (v == 7) { u8 correct @ 11; } else { u8 wrong @ 22; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["correct"]
        correct = _field(results, "correct")
        assert correct["offset"] == 11
        assert correct["raw_bytes"] == [11]
        assert correct["display_value"] == "0xB"

    def test_subtraction_value_is_difference_not_sum(self, interp: HexPatInterpreter) -> None:
        """10 - 3 evaluates to 7, distinct from the sum 13.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 v = 10 - 3;\nif (v == 7) { u8 correct @ 70; }\nif (v == 13) { u8 sum_bug @ 130; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["correct"]
        correct = _field(results, "correct")
        assert correct["offset"] == 70
        assert correct["raw_bytes"] == [70]

    def test_subtraction_negative_result_is_signed(self, interp: HexPatInterpreter) -> None:
        """3 - 10 evaluates to the signed value -7, not 7 or a wrapped byte.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 v = 3 - 10;\nif (v == -7) { u8 neg @ 7; }\nif (v == 7) { u8 abs_bug @ 8; }\nif (v == 249) { u8 wrap_bug @ 9; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["neg"]
        neg = _field(results, "neg")
        assert neg["offset"] == 7
        assert neg["raw_bytes"] == [7]

    def test_multiplication_value(self, interp: HexPatInterpreter) -> None:
        """6 * 7 evaluates to exactly 42, distinct from the sum 13.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 v = 6 * 7;\nif (v == 42) { u8 correct @ 42; }\nif (v == 13) { u8 add_bug @ 130; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["correct"]
        correct = _field(results, "correct")
        assert correct["offset"] == 42
        assert correct["raw_bytes"] == [42]

    def test_integer_division_truncates(self, interp: HexPatInterpreter) -> None:
        """15 / 4 truncates toward zero to 3, not 3.75 or 4.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 v = 15 / 4;\nif (v == 3) { u8 trunc @ 30; }\nif (v == 4) { u8 round_bug @ 40; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["trunc"]
        trunc = _field(results, "trunc")
        assert trunc["offset"] == 30
        assert trunc["raw_bytes"] == [30]

    def test_modulo_value(self, interp: HexPatInterpreter) -> None:
        """17 % 5 evaluates to the remainder 2, distinct from the quotient 3.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 v = 17 % 5;\nif (v == 2) { u8 rem @ 2; }\nif (v == 3) { u8 quot_bug @ 3; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["rem"]
        rem = _field(results, "rem")
        assert rem["offset"] == 2
        assert rem["raw_bytes"] == [2]

    def test_addition_does_not_wrap_at_u8_boundary(self, interp: HexPatInterpreter) -> None:
        """200 + 100 evaluates to 300 (no implicit u8 truncation in arithmetic).

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 a = 200;\nu8 b = 100;\nu8 s = a + b;\nif (s == 300) { u8 big @ 1; }\nif (s == 44) { u8 wrapped @ 2; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["big"]
        assert _field(results, "big")["offset"] == 1

    def test_operator_precedence_multiply_before_add(self, interp: HexPatInterpreter) -> None:
        """2 + 3 * 4 binds multiplication first, yielding 14 not 20.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 v = 2 + 3 * 4;\nif (v == 14) { u8 correct @ 14; }\nif (v == 20) { u8 leftassoc_bug @ 20; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["correct"]
        correct = _field(results, "correct")
        assert correct["offset"] == 14
        assert correct["raw_bytes"] == [14]


class TestArithmeticPlacementOracle:
    """Placement expressions validated by reading back the indexed byte.

    The pattern places a field at a computed offset in ``bytes(range(256))``;
    the byte read there equals the offset, so ``raw_bytes`` is a second,
    independent witness of the computed address.
    """

    def test_addition_placement(self, interp: HexPatInterpreter) -> None:
        """u8 @ (3 + 4) lands at offset 7 and reads the byte 0x07.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        results = interp.execute_bytes("u8 r @ (3 + 4);", _INDEXED_DATA)
        assert len(results) == 1
        assert results[0]["offset"] == 7
        assert results[0]["size"] == 1
        assert results[0]["raw_bytes"] == [7]
        assert results[0]["display_value"] == "0x7"

    def test_left_shift_placement(self, interp: HexPatInterpreter) -> None:
        """u8 @ (1 << 3) lands at offset 8 and reads the byte 0x08.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        results = interp.execute_bytes("u8 r @ (1 << 3);", _INDEXED_DATA)
        assert results[0]["offset"] == 8
        assert results[0]["raw_bytes"] == [8]
        assert results[0]["display_value"] == "0x8"

    def test_right_shift_placement(self, interp: HexPatInterpreter) -> None:
        """u8 @ (16 >> 2) lands at offset 4 and reads the byte 0x04.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        results = interp.execute_bytes("u8 r @ (16 >> 2);", _INDEXED_DATA)
        assert results[0]["offset"] == 4
        assert results[0]["raw_bytes"] == [4]
        assert results[0]["display_value"] == "0x4"


class TestBitwiseValueOracle:
    """Bitwise operators validated against hand-computed bit patterns.

    Each constant (e.g. ``0xF0 | 0x0F == 0xFF``) is derived independently of the
    implementation; an operator returning a different bit pattern takes the
    ``else`` branch and fails the test.
    """

    def test_bitwise_and_masks_low_nibble(self, interp: HexPatInterpreter) -> None:
        """0xFF & 0x0F isolates the low nibble, yielding 0x0F.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 v = 0xFF & 0x0F;\nif (v == 0x0F) { u8 correct @ 15; } else { u8 wrong @ 200; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["correct"]
        correct = _field(results, "correct")
        assert correct["offset"] == 15
        assert correct["raw_bytes"] == [15]

    def test_bitwise_or_sets_all_bits(self, interp: HexPatInterpreter) -> None:
        """0xF0 | 0x0F sets every low byte bit, yielding 0xFF.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 v = 0xF0 | 0x0F;\nif (v == 0xFF) { u8 correct @ 255; } else { u8 wrong @ 100; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["correct"]
        correct = _field(results, "correct")
        assert correct["offset"] == 255
        assert correct["raw_bytes"] == [255]

    def test_bitwise_xor_flips_bits(self, interp: HexPatInterpreter) -> None:
        """0xFF ^ 0xF0 flips the high nibble, yielding 0x0F.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 v = 0xFF ^ 0xF0;\nif (v == 0x0F) { u8 correct @ 15; }\nif (v == 0xFF) { u8 or_bug @ 100; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["correct"]
        correct = _field(results, "correct")
        assert correct["offset"] == 15
        assert correct["raw_bytes"] == [15]

    def test_left_shift_value(self, interp: HexPatInterpreter) -> None:
        """0x01 << 4 produces 0x10, distinct from a right shift to 0.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 v = 1 << 4;\nif (v == 16) { u8 correct @ 16; }\nif (v == 0) { u8 rshift_bug @ 99; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["correct"]
        correct = _field(results, "correct")
        assert correct["offset"] == 16
        assert correct["raw_bytes"] == [16]

    def test_right_shift_value(self, interp: HexPatInterpreter) -> None:
        """0xF0 >> 4 produces 0x0F, distinct from a left shift overflow.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 v = 0xF0 >> 4;\nif (v == 0x0F) { u8 correct @ 15; }\nif (v == 0xF00) { u8 lshift_bug @ 1; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["correct"]
        correct = _field(results, "correct")
        assert correct["offset"] == 15
        assert correct["raw_bytes"] == [15]

    def test_bitwise_not_inverts_all_bits(self, interp: HexPatInterpreter) -> None:
        """~0 masked to 32 bits yields 0xFFFFFFFF; ~0xFF masked yields 0xFFFFFF00.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = (
            "u32 a = ~0 & 0xFFFFFFFF;\n"
            "u32 b = ~0xFF & 0xFFFFFFFF;\n"
            "if (a == 0xFFFFFFFF) { u8 all_ones @ 1; }\n"
            "if (b == 0xFFFFFF00) { u8 cleared_low @ 2; }"
        )
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["all_ones", "cleared_low"]
        assert _field(results, "all_ones")["offset"] == 1
        assert _field(results, "cleared_low")["offset"] == 2


class TestComparisonAndLogical:
    """Comparison and logical operators validated via branch selection.

    Each operator drives an ``if/else``; the test asserts the taken branch by
    name and that the untaken branch produced nothing.
    """

    def test_equal_true_takes_then_branch(self, interp: HexPatInterpreter) -> None:
        """5 == 5 is true, so the then-branch sentinel is produced.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "if (5 == 5) { u8 yes @ 50; } else { u8 no @ 60; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["yes"]
        assert _field(results, "yes")["offset"] == 50

    def test_equal_false_takes_else_branch(self, interp: HexPatInterpreter) -> None:
        """5 == 4 is false, so the else-branch sentinel is produced.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "if (5 == 4) { u8 yes @ 50; } else { u8 no @ 60; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["no"]
        assert _field(results, "no")["offset"] == 60

    def test_not_equal(self, interp: HexPatInterpreter) -> None:
        """5 != 4 is true and 5 != 5 is false.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        truthy = interp.execute_bytes("if (5 != 4) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        assert _names(truthy) == ["yes"]
        falsy = interp.execute_bytes("if (5 != 5) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        assert _names(falsy) == ["no"]

    def test_less_than_boundary(self, interp: HexPatInterpreter) -> None:
        """3 < 5 is true, 5 < 5 is false, 5 < 3 is false.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        lt = interp.execute_bytes("if (3 < 5) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        eq = interp.execute_bytes("if (5 < 5) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        gt = interp.execute_bytes("if (5 < 3) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        assert _names(lt) == ["yes"]
        assert _names(eq) == ["no"]
        assert _names(gt) == ["no"]

    def test_greater_than_boundary(self, interp: HexPatInterpreter) -> None:
        """5 > 3 is true, 5 > 5 is false, 3 > 5 is false.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        gt = interp.execute_bytes("if (5 > 3) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        eq = interp.execute_bytes("if (5 > 5) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        lt = interp.execute_bytes("if (3 > 5) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        assert _names(gt) == ["yes"]
        assert _names(eq) == ["no"]
        assert _names(lt) == ["no"]

    def test_greater_equal_and_less_equal(self, interp: HexPatInterpreter) -> None:
        """>= and <= include the boundary value.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        ge = interp.execute_bytes("if (5 >= 5) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        le = interp.execute_bytes("if (5 <= 5) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        ge_fail = interp.execute_bytes("if (4 >= 5) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        assert _names(ge) == ["yes"]
        assert _names(le) == ["yes"]
        assert _names(ge_fail) == ["no"]

    def test_logical_and_truth_table(self, interp: HexPatInterpreter) -> None:
        """Logical AND is true only when both operands are truthy.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        both = interp.execute_bytes("if (1 && 1) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        one = interp.execute_bytes("if (1 && 0) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        none = interp.execute_bytes("if (0 && 0) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        assert _names(both) == ["yes"]
        assert _names(one) == ["no"]
        assert _names(none) == ["no"]

    def test_logical_or_truth_table(self, interp: HexPatInterpreter) -> None:
        """Logical OR is true when at least one operand is truthy.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        one = interp.execute_bytes("if (0 || 1) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        both = interp.execute_bytes("if (1 || 1) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        none = interp.execute_bytes("if (0 || 0) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        assert _names(one) == ["yes"]
        assert _names(both) == ["yes"]
        assert _names(none) == ["no"]


class TestArithmeticErrorPaths:
    """Arithmetic runtime errors surface as HexPatRuntimeError, not swallowed."""

    def test_division_by_zero_raises_with_message(self, interp: HexPatInterpreter) -> None:
        """10 / 0 raises HexPatRuntimeError mentioning division by zero.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        with pytest.raises(HexPatRuntimeError) as exc_info:
            interp.execute_bytes("u8 x @ (10 / 0);", _INDEXED_DATA)
        assert "division by zero" in str(exc_info.value)

    def test_modulo_by_zero_raises_with_message(self, interp: HexPatInterpreter) -> None:
        """10 % 0 raises HexPatRuntimeError mentioning modulo by zero.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        with pytest.raises(HexPatRuntimeError) as exc_info:
            interp.execute_bytes("u8 x @ (10 % 0);", _INDEXED_DATA)
        assert "modulo by zero" in str(exc_info.value)


class TestUnaryExpressions:
    """Unary operators validated against independently computed results."""

    def test_negation_in_arithmetic(self, interp: HexPatInterpreter) -> None:
        """-5 + 10 evaluates to 5; the placement reads back the indexed byte.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        results = interp.execute_bytes("u8 placed @ (-5 + 10);", _INDEXED_DATA)
        assert len(results) == 1
        assert results[0]["offset"] == 5
        assert results[0]["raw_bytes"] == [5]
        assert results[0]["display_value"] == "0x5"

    def test_logical_not_of_falsy_is_true(self, interp: HexPatInterpreter) -> None:
        """!0 is truthy and !5 is falsy.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        not_zero = interp.execute_bytes("if (!0) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        not_five = interp.execute_bytes("if (!5) { u8 yes @ 1; } else { u8 no @ 2; }", _INDEXED_DATA)
        assert _names(not_zero) == ["yes"]
        assert _names(not_five) == ["no"]

    def test_bitwise_not_value(self, interp: HexPatInterpreter) -> None:
        """~0 masked to a byte equals 0xFF and differs from logical !0.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u32 v = ~0 & 0xFF;\nif (v == 0xFF) { u8 correct @ 255; }\nif (v == 1) { u8 logical_bug @ 1; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["correct"]
        assert _field(results, "correct")["offset"] == 255


class TestTernaryExpression:
    """Ternary conditional selects the correct sub-expression by value."""

    def test_ternary_true_branch_value(self, interp: HexPatInterpreter) -> None:
        """1 ? 5 : 10 selects 5; the placement reads back byte 0x05.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        results = interp.execute_bytes("u8 r @ (1 ? 5 : 10);", _INDEXED_DATA)
        assert results[0]["offset"] == 5
        assert results[0]["raw_bytes"] == [5]

    def test_ternary_false_branch_value(self, interp: HexPatInterpreter) -> None:
        """0 ? 5 : 10 selects 10; the placement reads back byte 0x0A.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        results = interp.execute_bytes("u8 r @ (0 ? 5 : 10);", _INDEXED_DATA)
        assert results[0]["offset"] == 10
        assert results[0]["raw_bytes"] == [10]
        assert results[0]["display_value"] == "0xA"

    def test_ternary_with_runtime_variable_condition(self, interp: HexPatInterpreter) -> None:
        """A condition read from data drives branch selection at runtime.

        With a non-zero byte at offset 0 the truthy arm (1) is chosen; with a
        zero byte the falsy arm (2) is chosen.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 flag = read_unsigned(0, 1);\nu8 result @ (flag ? 1 : 2);"
        truthy = interp.execute_bytes(source, bytes([0x09, 0xAA, 0xBB, 0xCC]))
        falsy = interp.execute_bytes(source, bytes([0x00, 0xAA, 0xBB, 0xCC]))
        assert truthy[0]["offset"] == 1
        assert truthy[0]["raw_bytes"] == [0xAA]
        assert falsy[0]["offset"] == 2
        assert falsy[0]["raw_bytes"] == [0xBB]


class TestVariableScoping:
    """Variable scoping and shadowing across nested blocks."""

    def test_outer_variable_visible_in_loop_body(self, interp: HexPatInterpreter) -> None:
        """An outer variable is readable inside a loop and combines with the index.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([0x00, 0x00, 0xA0, 0xA1, 0xA2, 0x00, 0x00, 0x00])
        source = "u8 base = 2;\nfor (u8 i = 0; i < 3; i = i + 1) {\n    u8 val @ (base + i);\n}"
        results = interp.execute_bytes(source, data)
        assert len(results) == 3
        assert [r["offset"] for r in results] == [2, 3, 4]
        assert [r["raw_bytes"] for r in results] == [[0xA0], [0xA1], [0xA2]]
        assert [r["display_value"] for r in results] == ["0xA0", "0xA1", "0xA2"]

    def test_loop_variable_does_not_leak_to_outer_scope(self, interp: HexPatInterpreter) -> None:
        """A for-init variable is scoped to the loop; an outer name reuses it freely.

        The loop iterates twice placing at offsets 0 and 1, then an outer field
        named ``loop_var`` is declared, proving the loop's ``loop_var`` did not
        leak as a still-live binding that would collide.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "for (u8 loop_var = 0; loop_var < 2; loop_var = loop_var + 1) {\n    u8 val @ loop_var;\n}\nu8 loop_var @ 5;"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        offsets = [(r["name"], r["offset"]) for r in results]
        assert offsets == [("val", 0), ("val", 1), ("loop_var", 5)]
        assert _field([results[2]], "loop_var")["raw_bytes"] == [5]


class TestFunctionDefinitions:
    """User-defined functions compute and return values correctly."""

    def test_user_function_returns_computed_value(self, interp: HexPatInterpreter) -> None:
        """doubler(21) returns 42, validated by branch and placement.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = (
            "fn doubler(u8 x) {\n    return x * 2;\n}\nu8 v = doubler(21);\nif (v == 42) { u8 ok @ 42; }\nif (v == 23) { u8 add_bug @ 1; }"
        )
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["ok"]
        ok = _field(results, "ok")
        assert ok["offset"] == 42
        assert ok["raw_bytes"] == [42]

    def test_user_function_with_two_parameters(self, interp: HexPatInterpreter) -> None:
        """add(20, 22) sums its parameters to 42.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "fn add(u8 a, u8 b) {\n    return a + b;\n}\nu8 v = add(20, 22);\nif (v == 42) { u8 ok @ 42; }\nif (v == 2) { u8 firstparam_bug @ 1; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["ok"]
        ok = _field(results, "ok")
        assert ok["offset"] == 42
        assert ok["raw_bytes"] == [42]

    def test_function_side_effect_placement(self, interp: HexPatInterpreter) -> None:
        """A void function places a field at its argument offset.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "fn side_effect(u8 x) {\n    u8 placed @ x;\n}\nside_effect(3);"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        placed = _field(results, "placed")
        assert placed["offset"] == 3
        assert placed["raw_bytes"] == [3]
        assert placed["display_value"] == "0x3"


class TestTypeCoercion:
    """Implicit promotion and explicit casts produce correct values."""

    def test_u32_reads_full_width_value(self, interp: HexPatInterpreter) -> None:
        """A u32 field reads four little-endian bytes as a single value.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytearray(16)
        struct.pack_into("<I", data, 0, 300)
        results = interp.execute_bytes("u32 wide @ 0;", bytes(data))
        wide = _field(results, "wide")
        assert wide["size"] == 4
        assert wide["raw_bytes"] == [0x2C, 0x01, 0x00, 0x00]
        assert int(str(wide["display_value"]), 16) == 300

    def test_u8_value_promotes_in_arithmetic_with_wider_literal(self, interp: HexPatInterpreter) -> None:
        """A u8 variable plus a large literal promotes past the u8 range.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 n = 100;\nu32 wide = n + 1000;\nif (wide == 1100) { u8 ok @ 200; }\nif (wide == 76) { u8 truncated_bug @ 1; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["ok"]
        assert _field(results, "ok")["offset"] == 200

    def test_cast_float_to_int_truncates_toward_zero(self, interp: HexPatInterpreter) -> None:
        """(u8)(3.9) truncates to 3, not rounds to 4.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 v = (u8)(3.9);\nif (v == 3) { u8 trunc @ 33; }\nif (v == 4) { u8 round_bug @ 44; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["trunc"]
        trunc = _field(results, "trunc")
        assert trunc["offset"] == 33
        assert trunc["raw_bytes"] == [33]

    def test_cast_int_to_float_preserves_value(self, interp: HexPatInterpreter) -> None:
        """(float)(5) equals 5.0 and compares equal to the integer 5.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "float f = (float)(5);\nif (f == 5.0) { u8 ok @ 9; } else { u8 wrong @ 99; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["ok"]
        assert _field(results, "ok")["offset"] == 9

    def test_cast_large_int_to_u8_masks_low_byte(self, interp: HexPatInterpreter) -> None:
        """(u8)(0x1FF) masks to the low byte 0xFF.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        source = "u8 v = (u8)(0x1FF);\nif (v == 0xFF) { u8 masked @ 255; }\nif (v == 0x1FF) { u8 unmasked_bug @ 1; }"
        results = interp.execute_bytes(source, _INDEXED_DATA)
        assert _names(results) == ["masked"]
        masked = _field(results, "masked")
        assert masked["offset"] == 255
        assert masked["raw_bytes"] == [255]
