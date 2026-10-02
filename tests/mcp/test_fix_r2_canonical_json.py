# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2: the canonical JSON that sizes, fingerprints and consents to server schemas works at any depth, byte for byte as before.

``canonical_json`` used to be :func:`json.dumps`, which recurses in C. Python 3.13 stops C recursion at 3000 levels on Windows and
10000 elsewhere, so a server's schema nested past that made listing its tools raise ``RecursionError``. The encoder is now iterative;
these gates check it writes exactly what :func:`json.dumps` wrote for every value it could encode -- a stored launch-consent digest
depends on those bytes -- and that nesting past every platform's limit is encoded, measured and fingerprinted.
"""

from __future__ import annotations

import json
from enum import IntEnum
from typing import Final

import pytest
from hypothesis import (
    given,
    settings,
    strategies as st,
)
from mcp_types import Tool

from intellicrack.mcp.catalog import build_catalog, canonical_json


_BEYOND_C_RECURSION: Final[int] = 12_000
_EXAMPLES: Final[int] = 1500


class _Level(IntEnum):
    """An integer subclass whose ``repr`` is not its JSON text."""

    HIGH = 3


def _reference(value: object) -> str:
    """Encode a value the way ``canonical_json`` always has.

    Args:
        value: The value.

    Returns:
        str: What :func:`json.dumps` writes for it.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


_LEAVES = st.none() | st.booleans() | st.integers() | st.floats() | st.text()
_VALUES = st.recursive(
    _LEAVES,
    lambda children: (
        st.lists(children, max_size=4) | st.tuples(children, children) | st.dictionaries(st.text(max_size=5), children, max_size=4)
    ),
    max_leaves=40,
)


@settings(max_examples=_EXAMPLES, derandomize=True, deadline=None)
@given(_VALUES)
def test_every_json_value_is_written_as_json_dumps_wrote_it(value: object) -> None:
    """Generated values of every JSON shape, including NaN, infinities and unpaired surrogates, encode to the same text.

    Args:
        value: The value.
    """
    assert canonical_json(value) == _reference(value)


@pytest.mark.parametrize(
    "value",
    [
        {2: "b", 1: "a"},
        {1.5: 0, 0.5: 1},
        {True: 1, False: 0},
        {None: 2},
        _Level.HIGH,
        {"level": [_Level.HIGH]},
        {"tags": frozenset({"a"})},
        ValueError("boom"),
        -0.0,
        {"s": chr(0x2028) + chr(0xD800)},
    ],
    ids=[
        "int-keys",
        "float-keys",
        "bool-keys",
        "null-key",
        "int-subclass",
        "nested-int-subclass",
        "set-as-str",
        "exception-as-str",
        "negative-zero",
        "separators",
    ],
)
def test_values_outside_plain_json_are_written_as_json_dumps_wrote_them(value: object) -> None:
    """Non-string keys, integer subclasses and objects JSON cannot hold, which go through ``str``, encode to the same text.

    Args:
        value: The value.
    """
    assert canonical_json(value) == _reference(value)


def test_keys_json_cannot_write_are_refused_as_json_dumps_refused_them() -> None:
    """A tuple key raises the same ``TypeError`` it always did."""
    with pytest.raises(TypeError, match="keys must be str, int, float, bool or None, not tuple"):
        _reference({(1,): 0})
    with pytest.raises(TypeError, match="keys must be str, int, float, bool or None, not tuple"):
        canonical_json({(1,): 0})


def test_a_container_holding_itself_is_refused() -> None:
    """A list that contains itself raises ``ValueError`` instead of looping, as :func:`json.dumps` did."""
    looped: list[object] = []
    looped.append(looped)

    with pytest.raises(ValueError, match="Circular reference detected"):
        canonical_json(looped)


def test_a_value_deeper_than_c_recursion_allows_is_encoded() -> None:
    """Twelve thousand nested objects, past the C recursion limit of every platform, encode to the expected text."""
    value: object = "leaf"
    for _ in range(_BEYOND_C_RECURSION):
        value = {"n": value}

    assert canonical_json(value) == '{"n":' * _BEYOND_C_RECURSION + '"leaf"' + "}" * _BEYOND_C_RECURSION


def test_a_tool_whose_schema_is_that_deep_is_listed() -> None:
    """A server tool whose input schema nests twelve thousand objects, still inside the size bound, is measured, fingerprinted and listed."""
    nested: object = {}
    for _ in range(_BEYOND_C_RECURSION):
        nested = {"n": nested}
    schema: dict[str, object] = {"type": "object", "properties": {"n": nested}}

    catalog = build_catalog([Tool(name="deep", description="d", input_schema=schema)], "srv")

    assert catalog.tool_count == 1
    assert catalog.generation == build_catalog([Tool(name="deep", description="d", input_schema=schema)], "srv").generation
