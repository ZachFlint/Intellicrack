# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Second-pass critical-coverage tests for the HexPat evaluator and standard library.

Drives the real preprocessor, lexer, parser, evaluator and ``BuiltinFunctions``
with small pattern sources over a byte buffer built in the tests. Expected
offsets and display values are derived from that buffer and from integer
arithmetic done in Python. The tests cover the evaluator's tolerant fallbacks
(a non-integer placement offset, a non-integer assignment to ``$``, a struct
parent that is not a struct, a non-integer bitfield width inside ``sizeof``),
compound assignment on ``$``, a cast to the variable-width ``str`` type and the
standard library's tolerance of a stream that fails while it is being closed.
"""

from __future__ import annotations

import contextlib
import io
import os
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.evaluator import HexPatEvaluator
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatParser
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor
from intellicrack.core.hexpat.stdlib import BuiltinFunctions
from intellicrack.core.hexpat.type_system import TypeRegistry


if TYPE_CHECKING:
    from typing import BinaryIO

    from intellicrack.core.hexpat.ast_nodes import DeclNode, StmtNode
    from intellicrack.core.hexpat.interpreter import HexPatInterpreter


_DATA: bytes = bytes(range(0x20, 0x40))
_PROBE_DATA: bytes = bytes(64)


def _hex_of(index: int) -> str:
    """Format one byte of the shared buffer the way the evaluator displays an unsigned byte.

    Args:
        index: The offset of the byte inside the shared buffer.

    Returns:
        str: The byte as ``0x`` followed by upper-case hexadecimal digits.
    """
    return f"0x{_DATA[index]:X}"


def _field(results: list[dict[str, Any]], name: str) -> dict[str, Any]:
    """Find a parsed-field dict by name.

    Args:
        results: Parsed field dicts produced by the evaluator.
        name: The field name to locate.

    Returns:
        dict[str, Any]: The matching field dict.
    """
    found = next((r for r in results if r["name"] == name), None)
    assert found is not None, f"field '{name}' not in {[r['name'] for r in results]}"
    return found


def _holds(interp: HexPatInterpreter, prelude: str, condition: str) -> bool:
    """Evaluate a pattern-language condition by placing a probe byte at one of two offsets.

    Args:
        interp: The interpreter used to run the pattern.
        prelude: Pattern source executed before the probe placement.
        condition: A pattern-language expression whose truthiness is observed.

    Returns:
        bool: True when the condition was truthy (probe placed at offset 3),
        False when it was falsy (probe placed at offset 5).
    """
    results = interp.execute_bytes(f"{prelude}\nu8 probe @ {condition} ? 3 : 5;", _PROBE_DATA)
    probe = _field(results, "probe")
    assert probe["offset"] in {3, 5}
    return bool(probe["offset"] == 3)


def _wire(source: str, data: bytes) -> tuple[HexPatEvaluator, list[DeclNode | StmtNode], BuiltinFunctions]:
    """Build an evaluator wired to the standard library exactly as the interpreter wires it.

    Args:
        source: The pattern source to preprocess, lex and parse.
        data: The bytes the evaluator and the built-ins read from.

    Returns:
        tuple[HexPatEvaluator, list[DeclNode | StmtNode], BuiltinFunctions]: The
        evaluator, the parsed program it has not yet evaluated and the built-in
        library registered into the evaluator's scope.
    """
    processed, pragma = HexPatPreprocessor().process(source)
    program = HexPatParser(HexPatLexer(processed).tokenize()).parse()
    reader = DataReader.from_bytes(data)
    evaluator = HexPatEvaluator(reader, TypeRegistry(), pragma)
    stdlib = BuiltinFunctions(reader, pragma)
    stdlib.set_array_index_provider(evaluator.current_array_index)
    stdlib.set_endian_listener(evaluator.set_default_endian)
    stdlib.set_reflection_provider(evaluator.reflection_provider())
    stdlib.register_all(evaluator.scope)
    return evaluator, program, stdlib


class TestNonIntegerOffsets:
    """A placement offset that is not an integer leaves the cursor where it was."""

    def test_top_level_placement_with_text_offset_stays_at_the_cursor(self, interp: HexPatInterpreter) -> None:
        """A string after ``@`` is not an offset, so the placement lands at the cursor.

        Args:
            interp: A fresh interpreter.
        """
        results = interp.execute_bytes('u8 first @ 0;\nu8 second @ "far";', _DATA)
        layout = [(r["name"], r["offset"], r["display_value"]) for r in results]
        assert layout == [("first", 0, _hex_of(0)), ("second", 1, _hex_of(1))]

    def test_struct_field_with_text_offset_stays_at_the_cursor(self, interp: HexPatInterpreter) -> None:
        """A field whose ``@`` operand is a string is read at the cursor and does not advance it.

        Args:
            interp: A fresh interpreter.
        """
        source = 'struct Row {\n    u8 a;\n    u8 b @ "far";\n    u8 c;\n};\nRow row @ 0;'
        row = _field(interp.execute_bytes(source, _DATA), "row")
        layout = [(c["name"], c["offset"], c["size"], c["display_value"]) for c in row["children"]]
        assert layout == [("a", 0, 1, _hex_of(0)), ("b", 1, 1, _hex_of(1)), ("c", 1, 1, _hex_of(1))]
        assert row["size"] == 2


class TestStructParentThatIsNotAStruct:
    """Inheritance from a name that does not resolve to a struct contributes nothing."""

    @pytest.mark.parametrize(
        "prelude",
        ["union Base {\n    u8 x;\n    u8 y[3];\n};", ""],
        ids=["union-parent", "undeclared-parent"],
    )
    def test_layout_and_sizeof_ignore_the_parent(self, interp: HexPatInterpreter, prelude: str) -> None:
        """Only the derived struct's own fields are laid out and counted by ``sizeof``.

        Args:
            interp: A fresh interpreter.
            prelude: Pattern source declaring (or omitting) the named parent.
        """
        source = f"{prelude}\nstruct Derived : Base {{\n    u8 b;\n    u8 c;\n}};\nDerived d @ 0;\nu8 probe @ sizeof(Derived);"
        results = interp.execute_bytes(source, _DATA)
        derived = _field(results, "d")
        layout = [(c["name"], c["offset"], c["display_value"]) for c in derived["children"]]
        assert layout == [("b", 0, _hex_of(0)), ("c", 1, _hex_of(1))]
        assert derived["size"] == 2
        assert _field(results, "probe")["offset"] == 2


class TestDollarAssignment:
    """Assignments to the placement cursor ``$``."""

    def test_text_assigned_to_dollar_leaves_the_cursor_alone(self, interp: HexPatInterpreter) -> None:
        """Assigning a string to ``$`` does not move the cursor.

        Args:
            interp: A fresh interpreter.
        """
        results = interp.execute_bytes('u8 first @ 0;\n$ = "skip";\nu8 second;', _DATA)
        assert [(r["name"], r["offset"]) for r in results] == [("first", 0), ("second", 1)]

    @pytest.mark.parametrize(
        ("operator_text", "operand", "expected"),
        [("*=", 3, 4 * 3), ("<<=", 1, 4 << 1), ("|=", 3, 4 | 3), ("%=", 3, 4 % 3)],
        ids=["multiply", "shift-left", "bit-or", "modulo"],
    )
    def test_compound_assignment_applies_the_operator_to_the_cursor(
        self,
        interp: HexPatInterpreter,
        operator_text: str,
        operand: int,
        expected: int,
    ) -> None:
        """``$ op= n`` sets the cursor to the result of ``$ op n``, as it does for any variable.

        Args:
            interp: A fresh interpreter.
            operator_text: The compound assignment operator under test.
            operand: The right-hand operand.
            expected: The cursor value after the assignment, computed in Python from a cursor of 4.
        """
        source = f"u32 head @ 0;\n$ {operator_text} {operand};\nu8 tail;"
        results = interp.execute_bytes(source, _DATA)
        assert _field(results, "head")["size"] == 4
        assert _field(results, "tail")["offset"] == expected


class TestSizeofAndCastEdges:
    """``sizeof`` over a bitfield with a non-integer width and casts to ``str``."""

    def test_sizeof_bitfield_skips_entries_whose_width_is_not_an_integer(self, interp: HexPatInterpreter) -> None:
        """Only the integer widths are summed and rounded up to whole bytes.

        Args:
            interp: A fresh interpreter.
        """
        source = 'bitfield Odd {\n    low : 5;\n    label : "wide";\n    high : 6;\n};\nu8 probe @ sizeof(Odd);'
        results = interp.execute_bytes(source, _DATA)
        assert _field(results, "probe")["offset"] == (5 + 6 + 7) // 8

    @pytest.mark.parametrize(
        ("prelude", "condition"),
        [
            ("", "(str)(0x12345) == 0x12345"),
            ("using Text = str;", "(Text)(0x12345) == 0x12345"),
            ("", 'typenameof((str)(65)) == "str"'),
        ],
        ids=["wide-value-unmasked", "alias-value-unmasked", "type-stays-str"],
    )
    def test_cast_to_str_keeps_the_integer_and_the_type(self, interp: HexPatInterpreter, prelude: str, condition: str) -> None:
        """A variable-width target has no bit width to mask to, so the integer passes through typed as ``str``.

        Args:
            interp: A fresh interpreter.
            prelude: Pattern source executed before the probe.
            condition: The comparison that must hold.
        """
        assert _holds(interp, prelude, condition) is True


class TestFileCloseFailure:
    """``std::file::close`` over a stream whose own close raises."""

    def test_stream_that_fails_to_close_is_forgotten_without_an_error(self) -> None:
        """A failing flush during ``close`` is tolerated: the call returns null and the handle is gone."""
        evaluator, program, stdlib = _wire("auto closed = std::file::close(1);\nu8 after @ 0;", _DATA)
        handles: dict[int, BinaryIO] = getattr(stdlib, "_file_handles")
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        writer = io.BufferedWriter(io.FileIO(write_fd, "wb"))
        try:
            writer.write(b"x")
            handles[1] = writer
            results = evaluator.evaluate(program)
            still_registered = 1 in handles
        finally:
            handles.clear()
            with contextlib.suppress(OSError):
                writer.close()
        assert not still_registered
        closed = evaluator.scope.get("closed")
        assert closed is not None
        assert closed.value is None
        assert _field(results, "after")["offset"] == 0
