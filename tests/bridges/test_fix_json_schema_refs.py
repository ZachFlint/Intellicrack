# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates on ``$ref`` inlining: bounded work on recursive schemas, and property names left alone.

``inline_refs`` feeds output-schema validation and the Responses and Gemini
reductions. It used to expand every reference to a fixed depth, so a
definition that referred to itself twice doubled at every level and never
finished; and it dropped every key named ``definitions`` or ``$defs`` wherever
it appeared, including in a ``properties`` map, where those are the names of
real arguments.

The time-bound gates run each expansion in a child interpreter under a hard
timeout, so a regression fails the test rather than hanging the run.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any, Final

import pytest

from intellicrack.bridges.json_schema import MAX_REF_REENTRY, inline_refs, to_gemini_subset, to_strict_subset
from intellicrack.mcp.validation import validate_against_schema


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_CHILD_TIMEOUT_S: Final[float] = 240.0
"""Hard bound on one child run, interpreter start-up included."""

_WORK_BOUND_S: Final[float] = 5.0
"""Hard bound on the expansion work measured inside the child."""

_TREE_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "properties": {"root": {"$ref": "#/$defs/Node"}},
    "required": ["root"],
    "$defs": {
        "Node": {
            "type": "object",
            "properties": {
                "value": {"type": "integer"},
                "left": {"$ref": "#/$defs/Node"},
                "right": {"$ref": "#/$defs/Node"},
            },
            "required": ["value"],
        },
    },
}
"""A binary tree: one definition referring to itself twice."""

_MUTUAL_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "properties": {"a": {"$ref": "#/$defs/A"}},
    "$defs": {
        "A": {"type": "object", "properties": {"x": {"$ref": "#/$defs/B"}, "y": {"$ref": "#/$defs/C"}}},
        "B": {"type": "object", "properties": {"x": {"$ref": "#/$defs/C"}, "y": {"$ref": "#/$defs/A"}}},
        "C": {"type": "object", "properties": {"x": {"$ref": "#/$defs/A"}, "y": {"$ref": "#/$defs/B"}}},
    },
}
"""Three mutually recursive definitions with two references each."""

_FANOUT_DEPTH: Final[int] = 40

_FANOUT_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "properties": {"start": {"$ref": "#/$defs/D0"}},
    "$defs": {
        f"D{index}": {
            "type": "object",
            "properties": {"a": {"$ref": f"#/$defs/D{index + 1}"}, "b": {"$ref": f"#/$defs/D{index + 1}"}},
        }
        for index in range(_FANOUT_DEPTH)
    }
    | {f"D{_FANOUT_DEPTH}": {"type": "string"}},
}
"""A non-recursive chain of forty definitions, each referring to the next twice."""


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
        pytest.fail(f"schema expansion did not finish within {_CHILD_TIMEOUT_S:g}s")
    assert completed.returncode == 0, completed.stderr[-4000:]
    decoded: dict[str, Any] = json.loads(completed.stdout.strip().splitlines()[-1])
    return decoded


_EXPAND_CHILD: Final[str] = """
    import json, time
    from intellicrack.bridges.json_schema import inline_refs, to_gemini_subset, to_strict_subset
    from intellicrack.mcp.validation import validate_against_schema
    schema = json.loads({schema!r})
    started = time.perf_counter()
    inlined = inline_refs(schema)
    strict, faithful = to_strict_subset(schema)
    gemini = to_gemini_subset(schema)
    violations = validate_against_schema({value}, schema)
    elapsed = time.perf_counter() - started
    print(json.dumps({{
        "elapsed": elapsed,
        "inlined_chars": len(json.dumps(inlined)),
        "gemini_chars": len(json.dumps(gemini)),
        "has_ref": "$ref" in json.dumps(inlined) or "$ref" in json.dumps(gemini),
        "faithful": faithful,
        "violations": [str(item) for item in violations],
    }}))
"""


@pytest.mark.parametrize(
    ("schema", "value"),
    [
        pytest.param(_TREE_SCHEMA, {"root": {"value": 1, "left": {"value": 2}, "right": {"value": 3}}}, id="two-self-references"),
        pytest.param(_MUTUAL_SCHEMA, {"a": {"x": {"y": {}}}}, id="mutual-recursion"),
        pytest.param(_FANOUT_SCHEMA, {"start": {"a": {"b": {}}}}, id="non-recursive-fanout"),
    ],
)
def test_expansion_is_bounded_on_reference_graphs_that_explode(schema: dict[str, Any], value: dict[str, Any]) -> None:
    """Every consumer of ``inline_refs`` finishes quickly and produces bounded output.

    Args:
        schema: A reference graph whose naive expansion is exponential.
        value: A conforming value to validate against it.
    """
    result = _run_child(_EXPAND_CHILD.format(schema=json.dumps(schema), value=repr(value)))

    assert result["elapsed"] < _WORK_BOUND_S
    assert result["inlined_chars"] < 2_000_000
    assert result["gemini_chars"] < 2_000_000
    assert not result["has_ref"]
    assert result["violations"] == []
    assert result["faithful"] is False


def test_recursive_definition_unrolls_to_the_reentry_limit_then_goes_permissive() -> None:
    """A self-referencing tree keeps its shape for a few levels, then accepts anything."""
    inlined = inline_refs(_TREE_SCHEMA)

    node: dict[str, Any] = inlined["properties"]["root"]
    for _ in range(MAX_REF_REENTRY - 1):
        assert node["type"] == "object"
        assert node["properties"]["value"] == {"type": "integer"}
        node = node["properties"]["left"]
    assert node["type"] == "object"
    assert node["properties"]["left"] == {}
    assert node["properties"]["right"] == {}


def test_deep_conforming_tree_validates_and_a_shallow_violation_is_caught() -> None:
    """Validation of a recursive output schema still asserts what it can reach."""
    deep: dict[str, Any] = {"value": 0}
    for level in range(1, 50):
        deep = {"value": level, "left": deep, "right": {"value": -level}}

    assert validate_against_schema({"root": deep}, _TREE_SCHEMA) == []

    wrong = validate_against_schema({"root": {"value": 1, "left": {"value": "not-a-number"}}}, _TREE_SCHEMA)
    assert [str(item) for item in wrong] == ["$.root.left.value: expected an integer, found a string"]


_NAMED_LIKE_CONTAINERS: Final[dict[str, Any]] = {
    "type": "object",
    "properties": {
        "definitions": {"type": "string", "description": "symbol definitions to import"},
        "$defs": {"type": "integer"},
        "anchor": {"$ref": "#/$defs/Anchor"},
    },
    "required": ["definitions", "$defs", "anchor"],
    "$defs": {"Anchor": {"type": "string"}},
}


def test_properties_named_like_definition_containers_survive_inlining() -> None:
    """A property called ``definitions`` or ``$defs`` is an argument, not a container."""
    inlined = inline_refs(_NAMED_LIKE_CONTAINERS)

    assert set(inlined["properties"]) == {"definitions", "$defs", "anchor"}
    assert inlined["properties"]["definitions"]["description"] == "symbol definitions to import"
    assert inlined["properties"]["$defs"] == {"type": "integer"}
    assert inlined["properties"]["anchor"] == {"type": "string"}
    assert inlined["required"] == ["definitions", "$defs", "anchor"]
    assert "$defs" not in {key for key in inlined if key != "properties"}


def test_reductions_keep_arguments_named_like_definition_containers() -> None:
    """The Responses and Gemini reductions keep every required argument they are told about."""
    strict, faithful = to_strict_subset(_NAMED_LIKE_CONTAINERS)
    assert faithful
    assert set(strict["properties"]) == set(strict["required"]) == {"definitions", "$defs", "anchor"}

    gemini = to_gemini_subset(_NAMED_LIKE_CONTAINERS)
    assert set(gemini["properties"]) == {"definitions", "$defs", "anchor"}
    assert gemini["properties"]["$defs"]["type"] == "INTEGER"
    assert set(gemini["required"]) <= set(gemini["properties"])


def test_validation_checks_arguments_named_like_definition_containers() -> None:
    """An output value is checked against the schema of a ``definitions`` property."""
    conforming = {"definitions": "a b c", "$defs": 3, "anchor": "x"}
    assert validate_against_schema(conforming, _NAMED_LIKE_CONTAINERS) == []

    violations = validate_against_schema({"definitions": 5, "$defs": "three", "anchor": "x"}, _NAMED_LIKE_CONTAINERS)
    assert sorted(str(item) for item in violations) == [
        "$.$defs: expected an integer, found a string",
        "$.definitions: expected a string, found an integer",
    ]


def test_data_keywords_are_copied_verbatim() -> None:
    """``enum``, ``const`` and ``default`` values are data even when they look like schema."""
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "choice": {"enum": [{"$ref": "#/$defs/Anything"}, {"definitions": 1}]},
            "fixed": {"const": {"$defs": {"k": 1}}},
            "preset": {"type": "object", "default": {"$ref": "literal"}},
        },
        "$defs": {"Anything": {"type": "string"}},
    }

    inlined = inline_refs(schema)

    assert inlined["properties"]["choice"]["enum"] == [{"$ref": "#/$defs/Anything"}, {"definitions": 1}]
    assert inlined["properties"]["fixed"]["const"] == {"$defs": {"k": 1}}
    assert inlined["properties"]["preset"]["default"] == {"$ref": "literal"}
    assert validate_against_schema({"choice": {"definitions": 1}}, schema) == []
