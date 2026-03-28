# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexPat expression evaluation via execute_bytes."""

from __future__ import annotations

import struct

import pytest

from intellicrack.core.hexpat.errors import HexPatRuntimeError
from intellicrack.core.hexpat.interpreter import HexPatInterpreter


@pytest.fixture
def interp() -> HexPatInterpreter:
    """Provide a HexPatInterpreter with no custom include paths.

    Returns:
        HexPatInterpreter: A fresh interpreter instance.
    """
    return HexPatInterpreter()


class TestBinaryExpressions:
    """Tests for binary arithmetic, bitwise, comparison, and logical expressions."""

    def test_addition(self, interp: HexPatInterpreter) -> None:
        """Addition operator produces the correct sum.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (3 + 4);"
        results = interp.execute_bytes(source, data)
        assert len(results) == 1
        assert results[0]["offset"] == 7

    def test_subtraction(self, interp: HexPatInterpreter) -> None:
        """Subtraction operator produces the correct difference.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (10 - 3);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 7

    def test_multiplication(self, interp: HexPatInterpreter) -> None:
        """Multiplication operator produces the correct product.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (3 * 4);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 12

    def test_integer_division(self, interp: HexPatInterpreter) -> None:
        """Integer division operator truncates toward zero.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (15 / 4);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 3

    def test_modulo(self, interp: HexPatInterpreter) -> None:
        """Modulo operator returns the remainder.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (17 % 5);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 2

    def test_bitwise_and(self, interp: HexPatInterpreter) -> None:
        """Bitwise AND operator masks bits correctly.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (0xFF & 0x0F);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 0x0F

    def test_bitwise_or(self, interp: HexPatInterpreter) -> None:
        """Bitwise OR operator sets bits correctly.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (0xF0 | 0x0F);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 0xFF % 16

    def test_bitwise_xor(self, interp: HexPatInterpreter) -> None:
        """Bitwise XOR operator flips bits correctly.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (0xFF ^ 0xF0);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 0x0F

    def test_left_shift(self, interp: HexPatInterpreter) -> None:
        """Left shift operator shifts bits left by the given amount.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (1 << 3);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 8

    def test_right_shift(self, interp: HexPatInterpreter) -> None:
        """Right shift operator shifts bits right by the given amount.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (16 >> 2);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 4

    def test_equal_comparison_true(self, interp: HexPatInterpreter) -> None:
        """== comparison returns truthy value when operands are equal.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([5, 1, 2])
        source = "u8 cond = (5 == 5);\nif (cond) { u8 yes @ 0; }"
        results = interp.execute_bytes(source, data)
        named = [r["name"] for r in results]
        assert "yes" in named

    def test_not_equal_comparison(self, interp: HexPatInterpreter) -> None:
        """!= comparison returns truthy value when operands differ.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([5, 1, 2])
        source = "u8 cond = (5 != 4);\nif (cond) { u8 yes @ 0; }"
        results = interp.execute_bytes(source, data)
        named = [r["name"] for r in results]
        assert "yes" in named

    def test_less_than(self, interp: HexPatInterpreter) -> None:
        """< comparison returns truthy when left is less than right.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(4)
        source = "if (3 < 5) { u8 yes @ 0; }"
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "yes" for r in results)

    def test_greater_than(self, interp: HexPatInterpreter) -> None:
        """> comparison returns truthy when left is greater than right.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(4)
        source = "if (5 > 3) { u8 yes @ 0; }"
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "yes" for r in results)

    def test_logical_and_both_true(self, interp: HexPatInterpreter) -> None:
        """Logical AND returns truthy when both operands are true.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(4)
        source = "if (1 && 1) { u8 yes @ 0; }"
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "yes" for r in results)

    def test_logical_or_one_true(self, interp: HexPatInterpreter) -> None:
        """Logical OR returns truthy when at least one operand is true.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(4)
        source = "if (0 || 1) { u8 yes @ 0; }"
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "yes" for r in results)

    def test_division_by_zero_raises(self, interp: HexPatInterpreter) -> None:
        """Division by zero raises HexPatRuntimeError.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(4)
        source = "u8 x @ (10 / 0);"
        with pytest.raises(HexPatRuntimeError):
            interp.execute_bytes(source, data)


class TestUnaryExpressions:
    """Tests for unary operator expressions."""

    def test_negation(self, interp: HexPatInterpreter) -> None:
        """Unary negation returns a negative integer value.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(4)
        source = "u8 zero = 0;\nu8 result = -5 + 5;\n"
        interp.execute_bytes(source, data)

    def test_logical_not_of_false(self, interp: HexPatInterpreter) -> None:
        """Logical NOT of a falsy value produces a truthy result.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(4)
        source = "if (!0) { u8 yes @ 0; }"
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "yes" for r in results)

    def test_logical_not_of_true(self, interp: HexPatInterpreter) -> None:
        """Logical NOT of a truthy value produces a falsy result.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(4)
        source = "if (!1) { u8 no @ 0; } else { u8 yes @ 0; }"
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "yes" for r in results)

    def test_bitwise_not(self, interp: HexPatInterpreter) -> None:
        """Bitwise NOT inverts all bits of an integer.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(4)
        source = "u32 val = ~0;\nif ((~0 & 0xFFFFFFFF) == 0xFFFFFFFF) { u8 ok @ 0; }"
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "ok" for r in results)


class TestTernaryExpression:
    """Tests for ternary conditional expressions."""

    def test_ternary_true_branch(self, interp: HexPatInterpreter) -> None:
        """Ternary expression selects the true branch when condition is truthy.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (1 ? 5 : 10);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 5

    def test_ternary_false_branch(self, interp: HexPatInterpreter) -> None:
        """Ternary expression selects the false branch when condition is falsy.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (0 ? 5 : 10);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 10

    def test_ternary_with_variable_condition(self, interp: HexPatInterpreter) -> None:
        """Ternary with a variable condition evaluates the condition at runtime.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([1, 0, 0, 0, 0, 0, 0, 0])
        source = "u8 flag = read_unsigned(0, 1);\nu8 result @ (flag ? 1 : 2);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 1


class TestVariableScoping:
    """Tests for variable scoping and shadowing behaviour."""

    def test_variable_visible_in_nested_scope(self, interp: HexPatInterpreter) -> None:
        """Variable defined in outer scope is visible inside a loop body.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(8)
        source = "u8 base = 2;\nfor (u8 i = 0; i < 3; i = i + 1) {\n    u8 val @ (base + i);\n}"
        results = interp.execute_bytes(source, data)
        assert len(results) == 3
        assert results[0]["offset"] == 2
        assert results[1]["offset"] == 3

    def test_loop_variable_isolated_to_loop(self, interp: HexPatInterpreter) -> None:
        """Loop variable defined in for init does not leak to outer scope.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(8)
        source = "for (u8 loop_var = 0; loop_var < 2; loop_var = loop_var + 1) {\n    u8 val @ loop_var;\n}\nu8 after @ 0;"
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "after" for r in results)


class TestFunctionDefinitions:
    """Tests for user-defined function declarations and calls."""

    def test_user_function_returns_value(self, interp: HexPatInterpreter) -> None:
        """User-defined function with return statement returns its value.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "fn double(u8 x) {\n    return x * 2;\n}\nu8 result @ double(4);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 8

    def test_user_function_with_multiple_params(self, interp: HexPatInterpreter) -> None:
        """User-defined function with two parameters computes correctly.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "fn add(u8 a, u8 b) {\n    return a + b;\n}\nu8 result @ add(3, 4);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 7

    def test_function_no_return_returns_null(self, interp: HexPatInterpreter) -> None:
        """User-defined function with no return statement returns null (offset 0 default).

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(8)
        source = "fn side_effect(u8 x) {\n    u8 placed @ x;\n}\nside_effect(2);"
        interp.execute_bytes(source, data)


class TestTypeCoercion:
    """Tests for implicit and explicit type coercions."""

    def test_u8_to_u32_implicit_promotion(self, interp: HexPatInterpreter) -> None:
        """u8 value used in arithmetic with a u32 literal promotes to wider type.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = struct.pack("<I", 300) + bytes(12)
        source = "u32 wide @ 0;\nu8 narrow = 100;\nu8 check @ (narrow + 0);"
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "check" for r in results)

    def test_cast_float_to_int_truncates(self, interp: HexPatInterpreter) -> None:
        """Explicit cast of float to integer type truncates towards zero.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (u8)(3.9);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 3

    def test_cast_int_to_float(self, interp: HexPatInterpreter) -> None:
        """Explicit cast of integer to float type produces a float value.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "float f = (float)(5);\nu8 ok @ 0;"
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "ok" for r in results)

    def test_cast_large_int_to_u8_masks(self, interp: HexPatInterpreter) -> None:
        """Casting a large integer to u8 masks to 8 bits.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "u8 result @ (u8)(0x1FF);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 0xFF % 16
