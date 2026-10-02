# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 19: a tool's one-line signature describes ``allOf`` arguments and nested objects instead of calling them ``any``.

The gates map real MCP catalog entries to the functions the system prompt and the tool search list, and read the signature they get. An
``allOf`` argument shows every branch it must satisfy, a nested object shows its own properties, and a schema built to be wide and deep
at once still gives a signature of bounded length.
"""

from __future__ import annotations

from typing import Any, Final

from intellicrack.mcp.catalog import McpToolEntry
from intellicrack.mcp.tool_source import map_tool_to_function


_WIDTH: Final[int] = 40
_SIGNATURE_LIMIT: Final[int] = 20_000


def _signature(schema: dict[str, Any]) -> str:
    """Map a catalog entry with this input schema and read its signature.

    Args:
        schema: The tool's input schema.

    Returns:
        str: The signature the model is shown.
    """
    entry = McpToolEntry(
        name="scan",
        canonical_name="mcp-demo.scan",
        title=None,
        description="Scan a binary.",
        input_schema=schema,
        output_schema=None,
        annotations=None,
    )
    return map_tool_to_function(entry).signature


def test_all_of_argument_lists_each_branch() -> None:
    """An ``allOf`` argument is shown as the types it must satisfy, joined with ``&``."""
    signature = _signature(
        {
            "type": "object",
            "properties": {
                "path": {"allOf": [{"type": "string"}, {"minLength": 1}]},
                "mode": {"allOf": [{"$ref": "#/$defs/Mode"}, {"anyOf": [{"type": "string"}, {"type": "null"}]}]},
            },
            "required": ["path"],
        },
    )
    assert "(path: string, mode?: Mode&(string|null))" in signature


def test_nested_object_lists_its_properties() -> None:
    """An object argument shows its properties, marking the optional ones, instead of just ``object``."""
    signature = _signature(
        {
            "type": "object",
            "properties": {
                "options": {
                    "type": "object",
                    "properties": {
                        "depth": {"type": "integer"},
                        "follow": {"type": "boolean"},
                        "filter": {"properties": {"glob": {"type": "string"}}},
                    },
                    "required": ["depth"],
                },
                "extra": {"type": "object"},
            },
        },
    )
    assert "(options?: {depth: integer, follow?: boolean, filter?: {glob?: string}}, extra?: object)" in signature


def test_wide_and_deep_schema_gives_a_bounded_signature() -> None:
    """Objects nested three deep with forty properties at each level still give a signature of bounded length, eliding the rest."""
    leaf = {"type": "object", "properties": {f"leaf_{index}": {"type": "string"} for index in range(_WIDTH)}}
    middle = {"type": "object", "properties": {f"middle_{index}": leaf for index in range(_WIDTH)}}
    top = {"type": "object", "properties": {f"top_{index}": middle for index in range(_WIDTH)}}
    signature = _signature({"type": "object", "properties": {"config": top}})
    assert len(signature) < _SIGNATURE_LIMIT
    assert f"+{_WIDTH - 16} more" in signature
    assert "..." in signature
