# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates on output-schema validation: server-controlled regexes, ``nullable``, and JSON equality.

An MCP server writes both a tool's ``outputSchema`` and the result checked
against it, so a ``pattern`` or ``patternProperties`` regex and the text it is
matched against are both attacker-controlled. The checker must refuse the
shapes that backtrack catastrophically and bound the time of every pattern it
does run, or one tool result can hold the event loop indefinitely.

The time-bound gates run in a child interpreter under a hard timeout, so a
regression fails the test instead of hanging the run.

The same checker must also read OpenAPI-style ``nullable: true``, which
servers built on OpenAPI tooling emit, and must compare ``const`` and
``enum`` values as JSON does, where ``1`` and ``true`` are different values.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any, Final

import pytest

from intellicrack.mcp.validation import (
    PATTERN_MATCH_TIMEOUT_S,
    PATTERN_VALIDATION_BUDGET_S,
    compile_schema_pattern,
    search_pattern,
    validate_against_schema,
)


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_CHILD_TIMEOUT_S: Final[float] = 240.0
"""Hard bound on one child run, interpreter start-up included."""

_VALIDATION_BOUND_S: Final[float] = 2.0
"""Hard bound on one validation measured inside the child."""

_ADVERSARIAL: Final[tuple[tuple[str, str], ...]] = (
    ("(a+){2,40}", "a" * 40 + "!"),
    ("(a+){2,40}$", "a" * 40 + "!"),
    ("(.*a){12}", "a" * 40 + "b"),
    ("(.*a){12}$", "a" * 40 + "b"),
    ("a*a*a*a*a*b", "a" * 400),
    ("(a{1,1000})+", "a" * 40 + "!"),
    ("(a{1,1000})+$", "a" * 40 + "!"),
    ("(a+)+$", "a" * 40 + "!"),
    ("(a|aa)+$", "a" * 40 + "!"),
    ("^(\\w+\\s?)*$", "an ordinary sentence of words that ends badly!"),
)
"""Pattern and the input that makes a backtracking engine run away with it."""


def _run_child(code: str) -> dict[str, Any]:
    """Run a snippet in a fresh interpreter under a hard timeout.

    Args:
        code: Python source that prints one JSON object as its last line.

    Returns:
        dict[str, Any]: The decoded JSON object.
    """
    env = {"PYTHONPATH": f"{_REPO_ROOT / 'src'}{os.pathsep}{_REPO_ROOT}", "PYTHONIOENCODING": "utf-8"}
    for key in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "USERPROFILE"):
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    try:
        completed = subprocess.run(
            [sys.executable, "-c", textwrap.dedent(code)],
            capture_output=True,
            text=True,
            timeout=_CHILD_TIMEOUT_S,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"validation did not finish within {_CHILD_TIMEOUT_S:g}s")
    assert completed.returncode == 0, completed.stderr[-4000:]
    decoded: dict[str, Any] = json.loads(completed.stdout.strip().splitlines()[-1])
    return decoded


_VALIDATE_CHILD: Final[str] = """
    import json, time
    from intellicrack.mcp.validation import validate_against_schema
    pattern, text = json.loads({case!r})
    started = time.perf_counter()
    as_value = validate_against_schema(text, {{"type": "string", "pattern": pattern}})
    as_key = validate_against_schema(
        {{text: 1}},
        {{"type": "object", "patternProperties": {{pattern: {{"type": "string"}}}}, "additionalProperties": False}},
    )
    print(json.dumps({{"elapsed": time.perf_counter() - started, "violations": [str(v) for v in as_value + as_key]}}))
"""


@pytest.mark.parametrize(("pattern", "text"), _ADVERSARIAL, ids=[pattern for pattern, _ in _ADVERSARIAL])
def test_adversarial_pattern_cannot_hold_validation(pattern: str, text: str) -> None:
    """A catastrophic pattern in ``pattern`` or ``patternProperties`` costs next to nothing.

    Args:
        pattern: The server-supplied regular expression.
        text: The server-supplied string it is matched against.
    """
    result = _run_child(_VALIDATE_CHILD.format(case=json.dumps([pattern, text])))

    assert result["elapsed"] < _VALIDATION_BOUND_S
    assert result["violations"] == []


@pytest.mark.parametrize("pattern", [pattern for pattern, _ in _ADVERSARIAL])
def test_catastrophic_shapes_are_refused_before_they_run(pattern: str) -> None:
    """Every listed shape is refused by the structural analysis itself.

    Args:
        pattern: A pattern with nested or adjacent overlapping repetition.
    """
    assert compile_schema_pattern(pattern) is None


@pytest.mark.parametrize(
    ("pattern", "matching", "failing"),
    [
        (r"^(\d{1,3}\.){3}\d{1,3}$", "192.168.0.1", "192.168.0"),
        (r"^[A-Za-z0-9_]+$", "entry_point", "entry point"),
        (r"^\d{4}-\d{2}-\d{2}$", "2026-09-26", "26-09-2026"),
        (r"^\s*\w+\s*$", "  word  ", "two words"),
        (r".*foo.*", "a foo b", "a fo b"),
        (r"^[^@]+@[^@]+\.[a-z]{2,}$", "ops@example.org", "ops@example"),
        (r"^(?:abc)+$", "abcabc", "abcab"),
        (r"^\p{L}+$", "Straße", "abc1"),
        (r"^0x[0-9a-fA-F]{1,16}$", "0x401000", "0x"),
    ],
)
def test_ordinary_patterns_are_still_enforced(pattern: str, matching: str, failing: str) -> None:
    """Refusing hazards must not cost the assertions ordinary schemas make.

    Args:
        pattern: A pattern without a backtracking hazard.
        matching: A string it accepts.
        failing: A string it rejects.
    """
    schema: dict[str, Any] = {"type": "string", "pattern": pattern}

    assert compile_schema_pattern(pattern) is not None
    assert validate_against_schema(matching, schema) == []
    assert [str(item) for item in validate_against_schema(failing, schema)] == [f"$: must match {pattern!r}"]


def test_polynomial_pattern_the_analysis_allows_is_cut_off_by_the_time_limit() -> None:
    """Two adjacent overlapping repetitions pass the analysis, and the time limit still bounds them."""
    compiled = compile_schema_pattern(r"[a-z]*[a-z0-9]*$")
    assert compiled is not None

    started = time.perf_counter()
    decided = search_pattern(compiled, "a" * 20000 + "!")
    elapsed = time.perf_counter() - started

    assert decided is None
    assert elapsed < PATTERN_MATCH_TIMEOUT_S * 10


def test_one_validation_shares_one_pattern_budget() -> None:
    """Many slow strings in one result cost the shared budget, not one timeout each."""
    schema: dict[str, Any] = {"type": "array", "items": {"type": "string", "pattern": r"[a-z]*[a-z0-9]*$"}}
    value = ["a" * 20000 + "!" for _ in range(40)]

    started = time.perf_counter()
    violations = validate_against_schema(value, schema)
    elapsed = time.perf_counter() - started

    assert violations == []
    assert elapsed < PATTERN_VALIDATION_BUDGET_S * 4
    assert elapsed < PATTERN_MATCH_TIMEOUT_S * len(value)


def test_undecidable_pattern_property_is_not_reported_as_unexpected() -> None:
    """A property name whose pattern could not be decided is neither validated nor flagged."""
    schema: dict[str, Any] = {
        "type": "object",
        "patternProperties": {"(a+)+$": {"type": "integer"}, "^n_": {"type": "integer"}},
        "additionalProperties": False,
    }

    assert validate_against_schema({"aaaa": "text", "n_count": 3}, schema) == []
    assert [str(item) for item in validate_against_schema({"n_count": "three"}, schema)] == [
        "$.n_count: expected an integer, found a string",
    ]


@pytest.mark.parametrize(
    ("schema", "value"),
    [
        ({"type": "string", "nullable": True}, None),
        ({"type": "integer", "nullable": True, "minimum": 3}, None),
        ({"type": "string", "enum": ["low", "high"], "nullable": True}, None),
        ({"type": "object", "properties": {"note": {"type": "string", "nullable": True}}, "required": ["note"]}, {"note": None}),
        ({"type": "array", "items": {"type": "number", "nullable": True}}, [1.5, None, 2]),
    ],
)
def test_nullable_true_accepts_null(schema: dict[str, Any], value: object) -> None:
    """OpenAPI ``nullable: true`` admits ``null`` alongside the declared type.

    Args:
        schema: A schema using ``nullable``.
        value: A value using the ``null`` it allows.
    """
    assert validate_against_schema(value, schema) == []


def test_nullable_does_not_widen_anything_else() -> None:
    """``nullable`` admits ``null`` only; other values are still checked, and ``nullable: false`` admits nothing."""
    assert [str(item) for item in validate_against_schema(5, {"type": "string", "nullable": True})] == [
        "$: expected a string, found an integer",
    ]
    assert [str(item) for item in validate_against_schema("mid", {"type": "string", "enum": ["low"], "nullable": True})] == [
        "$: must be one of ['low']",
    ]
    assert [str(item) for item in validate_against_schema(None, {"type": "string", "nullable": False})] == [
        "$: expected a string, found null",
    ]


@pytest.mark.parametrize(
    ("schema", "value"),
    [
        ({"const": 1}, True),
        ({"const": True}, 1),
        ({"const": 0}, False),
        ({"const": False}, 0),
        ({"enum": [1, 2]}, True),
        ({"enum": [True]}, 1),
        ({"enum": [0]}, False),
        ({"enum": [False]}, 0),
        ({"const": [1, 0]}, [True, False]),
        ({"const": {"flag": 1}}, {"flag": True}),
        ({"enum": [{"k": [0]}]}, {"k": [False]}),
    ],
)
def test_const_and_enum_distinguish_booleans_from_numbers(schema: dict[str, Any], value: object) -> None:
    """``1`` is not ``true`` and ``0`` is not ``false``, at any depth.

    Args:
        schema: A ``const`` or ``enum`` schema.
        value: A value Python's ``==`` would wrongly accept.
    """
    assert len(validate_against_schema(value, schema)) == 1


@pytest.mark.parametrize(
    ("schema", "value"),
    [
        ({"const": 1}, 1.0),
        ({"enum": [2.0]}, 2),
        ({"const": True}, True),
        ({"const": {"a": [1, None]}}, {"a": [1.0, None]}),
        ({"enum": ["x", 1, False]}, False),
    ],
)
def test_const_and_enum_accept_equal_json_values(schema: dict[str, Any], value: object) -> None:
    """Numbers compare by value and equal structures are equal.

    Args:
        schema: A ``const`` or ``enum`` schema.
        value: A value JSON considers equal to an allowed one.
    """
    assert validate_against_schema(value, schema) == []


def test_unique_items_treats_one_and_true_as_different() -> None:
    """``uniqueItems`` uses the same JSON equality."""
    schema: dict[str, Any] = {"type": "array", "uniqueItems": True}

    assert validate_against_schema([1, True, 0, False], schema) == []
    assert [str(item) for item in validate_against_schema([1, 1.0], schema)] == ["$: items must be unique"]
