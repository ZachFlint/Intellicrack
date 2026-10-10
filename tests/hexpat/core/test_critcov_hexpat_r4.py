# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Fourth-pass critical-coverage tests for two private helpers of the HexPat evaluator.

``HexPatEvaluator._declared_user_type`` names the user-defined type a variable was declared with and is documented to return ``None``
when the declaration does not name one. ``HexPatEvaluator._dispatch_resolved_type`` is documented to hand a resolved struct, union,
enum, bitfield or primitive entry to the matching instantiation helper, and to read a primitive from the data. Both are driven here on a
real evaluator over a real data reader and a real type registry. Expected values come from the :mod:`struct` module and from the
documented display rules of the pattern language (unsigned integers as upper-case hexadecimal, signed integers as decimal).
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.hexpat.ast_nodes import NamedType
from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.evaluator import HexPatEvaluator
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatParser
from intellicrack.core.hexpat.pragma import PragmaInfo
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor
from intellicrack.core.hexpat.type_system import HexPatType, TypeRegistry


if TYPE_CHECKING:
    from collections.abc import Callable


_COLOR: str = "#102030"
_NOTE: str = "dispatch probe"


def _named(name: str, namespace: str | None) -> NamedType:
    """Build a named type node without template arguments.

    Args:
        name: The type name.
        namespace: The namespace qualifier, or ``None`` for an unqualified name.

    Returns:
        NamedType: The named type node.
    """
    return NamedType(name=name, namespace=namespace, line=1, column=1)


def _evaluator_with_header_struct() -> HexPatEvaluator:
    """Build an evaluator whose registry holds one struct named ``Hdr``.

    Returns:
        HexPatEvaluator: An evaluator that has evaluated the declaration of ``Hdr`` and placed nothing.
    """
    processed, pragma = HexPatPreprocessor().process("struct Hdr {\n    u16 magic;\n};")
    program = HexPatParser(HexPatLexer(processed).tokenize()).parse()
    registry = TypeRegistry()
    evaluator = HexPatEvaluator(DataReader.from_bytes(bytes(16)), registry, pragma)
    assert evaluator.evaluate(program) == []
    assert registry.resolve("Hdr") is not None
    return evaluator


@pytest.mark.parametrize("namespace", [None, "outer"])
def test_declared_user_type_of_an_unregistered_name_is_none(namespace: str | None) -> None:
    """A declaration that names no registered type yields no type descriptor, qualified or not.

    ``Ghost`` is neither a primitive, an alias nor a registered struct, union, enum or bitfield, so the declaration does not name a
    user-defined type and the documented result is ``None``. The registered ``Hdr`` right next to it does yield a descriptor carrying
    its name and the instance size, so the ``None`` is not simply what the helper returns for everything.

    Args:
        namespace: The qualifier of the unregistered type name, or ``None``.
    """
    evaluator = _evaluator_with_header_struct()
    declared: Callable[[NamedType, int], HexPatType | None] = getattr(evaluator, "_declared_user_type")
    assert declared(_named("Hdr", None), 2) == HexPatType("Hdr", 2, signed=False, endian=None)
    assert declared(_named("Ghost", namespace), 4) is None


@pytest.mark.parametrize(
    ("type_name", "endian", "format_code", "payload"),
    [
        ("u16", None, "<H", b"\x34\x12"),
        ("u16", "big", ">H", b"\x34\x12"),
        ("s16", None, "<h", b"\xfe\xff"),
        ("u32", None, "<I", b"\x78\x56\x34\x12"),
    ],
)
def test_dispatch_resolved_primitive_reads_the_value_at_the_offset(
    type_name: str,
    endian: str | None,
    format_code: str,
    payload: bytes,
) -> None:
    """A resolved primitive is read from the data at the requested offset and described as a parsed field.

    The expected value is unpacked from the payload with :mod:`struct`; an unsigned value is shown as upper-case hexadecimal and a
    signed one as decimal.

    Args:
        type_name: The primitive type name to resolve.
        endian: The endianness override of the resolved type, or ``None`` for the evaluator default (little endian).
        format_code: The :mod:`struct` format that decodes the payload the way the type does.
        payload: The bytes placed at offset 3.
    """
    data = bytes([0xEE] * 3) + payload + bytes([0xDD] * 8)
    evaluator = HexPatEvaluator(DataReader.from_bytes(data), TypeRegistry(), PragmaInfo())
    resolved = TypeRegistry().resolve_primitive(type_name, endian)
    assert resolved is not None
    dispatch: Callable[..., dict[str, Any]] = getattr(evaluator, "_dispatch_resolved_type")
    field = dispatch(resolved=resolved, var_name="probe", offset=3, color=_COLOR, description=_NOTE)
    (expected,) = struct.unpack(format_code, payload)
    expected_display = str(expected) if resolved.signed else f"0x{expected:X}"
    assert field["name"] == "probe"
    assert field["offset"] == 3
    assert field["size"] == len(payload)
    assert field["raw_bytes"] == list(payload)
    assert field["display_value"] == expected_display
    assert field["_value"] == expected
    assert field["children"] == []
    assert field["color"] == _COLOR
    assert field["description"] == _NOTE
