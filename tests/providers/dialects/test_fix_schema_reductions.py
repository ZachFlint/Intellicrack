# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates on what the Responses and Gemini dialects claim about, and send for, a tool's argument schema.

OpenAI Structured Outputs strict mode accepts a documented JSON Schema subset:
the root is an object, every object lists all its properties in ``required``
and sets ``additionalProperties: false``, free-form objects and map-style
``additionalProperties`` are not expressible, only listed keywords and string
formats are allowed, and the schema is bounded at 10 levels of object nesting,
5000 properties and 1000 enum values. A tool definition that says
``strict: true`` over a schema outside that subset is rejected by the API.

Gemini's ``Schema`` rejects an ``OBJECT`` whose ``properties`` is empty or
missing ("should be non-empty for OBJECT type"), both for the parameter object
of a function with no arguments and for a nested free-form object.

Every gate renders through the real adapters, and the Gemini gates also drive
the real ``google-genai`` SDK against a loopback endpoint and inspect the JSON
it put on the wire.
"""

from __future__ import annotations

import importlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, Final

import pytest
from google.genai import Client as GenaiClient
from google.genai.types import HttpOptions

from intellicrack.bridges.json_schema import normalize_object_schema
from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.types import Message, ToolDefinition, ToolFunction, ToolParameter
from intellicrack.providers.capabilities import ApiDialect, ModelCapabilities, merge_capabilities
from intellicrack.providers.dialects.registry import adapter_for
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.presets import preset_for


if TYPE_CHECKING:
    from collections.abc import Iterator

    from intellicrack.bridges.base import ToolBridgeBase


_BRIDGE_CLASSES: Final[tuple[tuple[str, str], ...]] = (
    ("intellicrack.bridges.process", "ProcessBridge"),
    ("intellicrack.bridges.frida_bridge", "FridaBridge"),
    ("intellicrack.bridges.ghidra", "GhidraBridge"),
    ("intellicrack.bridges.cutter", "CutterBridge"),
    ("intellicrack.bridges.x64dbg", "X64DbgBridge"),
    ("intellicrack.bridges.sandbox_bridge", "SandboxBridge"),
    ("intellicrack.bridges.hex_editor", "HexEditorBridge"),
)

_STRICT_MAX_NESTING: Final[int] = 10
_STRICT_MAX_ENUM_VALUES: Final[int] = 1000


def _capabilities(preset_id: str, model: str) -> ModelCapabilities:
    """Resolve a model's capabilities through the shipped presets.

    Args:
        preset_id: The preset to resolve through.
        model: The model id.

    Returns:
        ModelCapabilities: The resolved record.
    """
    preset = preset_for(preset_id)
    assert preset is not None
    return merge_capabilities(ModelCapabilities(), preset.capabilities_for(model))


def _raw_tool(name: str, schema: dict[str, Any]) -> ToolDefinition:
    """Wrap one raw JSON Schema as a single-function tool.

    Args:
        name: The function name, dotted.
        schema: The function's argument schema.

    Returns:
        ToolDefinition: The tool.
    """
    return ToolDefinition(
        tool_name=name.partition(".")[0],
        description="external tool",
        functions=[ToolFunction(name=name, description="does a thing", parameters=[], returns="result", input_schema=schema)],
    )


def _responses_entry(schema: dict[str, Any]) -> dict[str, Any]:
    """Render one raw schema as a Responses function entry.

    Args:
        schema: The function's argument schema.

    Returns:
        dict[str, Any]: The rendered entry.
    """
    capabilities = _capabilities("openai", "gpt-5.4")
    assert capabilities.dialect is ApiDialect.RESPONSES
    entries = adapter_for(ApiDialect.RESPONSES).build_tool_schemas([_raw_tool("ext.run", schema)], capabilities)
    functions = [entry for entry in entries if entry.get("type") == "function"]
    assert len(functions) == 1
    return functions[0]


def _strict_violations(node: object, level: int, path: str) -> Iterator[str]:
    """Walk a schema sent with ``strict: true`` and name every rule it breaks.

    Args:
        node: The schema node.
        level: How many objects enclose ``node``.
        path: Location used in the messages.

    Yields:
        str: One message per broken rule.
    """
    if not is_json_object(node):
        yield f"{path}: not a schema object"
        return
    schema = node
    if "$ref" in schema or "allOf" in schema or "oneOf" in schema or "not" in schema or "patternProperties" in schema:
        yield f"{path}: unsupported composition keyword"
    declared = schema.get("type")
    names: list[str] = [declared] if isinstance(declared, str) else [str(entry) for entry in declared] if is_json_array(declared) else []
    if not names and "anyOf" not in schema and "enum" not in schema and "const" not in schema:
        yield f"{path}: accepts any value"
    if "object" in names:
        if level + 1 > _STRICT_MAX_NESTING:
            yield f"{path}: object nested {level + 1} levels deep"
        if schema.get("additionalProperties") is not False:
            yield f"{path}: additionalProperties is not false"
        declared_properties = schema.get("properties")
        properties: dict[str, Any] = declared_properties if is_json_object(declared_properties) else {}
        if not is_json_object(declared_properties):
            yield f"{path}: object without properties"
        declared_required = schema.get("required")
        required = [str(entry) for entry in declared_required] if is_json_array(declared_required) else []
        if sorted(required) != sorted(properties):
            yield f"{path}: required does not list every property"
        for name, member in properties.items():
            yield from _strict_violations(member, level + 1, f"{path}.{name}")
    items = schema.get("items")
    if "array" in names and not is_json_object(items):
        yield f"{path}: array without items"
    if is_json_object(items):
        yield from _strict_violations(items, level, f"{path}[]")
    for index, option in enumerate(schema.get("anyOf", [])):
        yield from _strict_violations(option, level, f"{path}|{index}")


def _strict_ok(entry: dict[str, Any]) -> list[str]:
    """Check a Responses entry claiming ``strict: true`` against the strict-mode rules.

    Args:
        entry: The rendered function entry.

    Returns:
        list[str]: Every broken rule; empty when the claim is honest.
    """
    parameters = entry["parameters"]
    problems = list(_strict_violations(parameters, 0, "$"))
    if "anyOf" in parameters or parameters.get("type") != "object":
        problems.append("$: root is not a plain object")
    return problems


def _nested_objects(depth: int) -> dict[str, Any]:
    """Build an object schema nested ``depth`` objects deep, root included.

    Args:
        depth: Total object levels.

    Returns:
        dict[str, Any]: The schema.
    """
    node: dict[str, Any] = {"type": "object", "properties": {"leaf": {"type": "string"}}, "required": ["leaf"]}
    for _ in range(depth - 1):
        node = {"type": "object", "properties": {"child": node}, "required": ["child"]}
    return node


@pytest.mark.parametrize(
    "schema",
    [
        pytest.param({"type": "object", "properties": {"options": {"type": "object"}}}, id="free-form-object"),
        pytest.param(
            {"type": "object", "properties": {"env": {"type": "object", "additionalProperties": {"type": "string"}}}},
            id="map-style-additional-properties",
        ),
        pytest.param(
            {"type": "object", "properties": {"rows": {"type": "array", "items": {"type": "object"}}}},
            id="free-form-object-in-array",
        ),
        pytest.param({"type": "object", "properties": {"blob": {}}}, id="unconstrained-property"),
        pytest.param({"type": "object", "properties": {"link": {"type": "string", "format": "uri"}}}, id="unsupported-format"),
        pytest.param({"type": "object", "properties": {"name": {"type": "string", "minLength": 3}}}, id="unsupported-keyword"),
        pytest.param({"type": "object", "properties": {"tags": {"type": "array"}}}, id="array-without-items"),
        pytest.param({"anyOf": [{"type": "object", "properties": {"a": {"type": "string"}}}]}, id="root-any-of"),
        pytest.param(_nested_objects(_STRICT_MAX_NESTING + 1), id="nesting-past-limit"),
        pytest.param(
            {"type": "object", "properties": {"pick": {"type": "integer", "enum": list(range(_STRICT_MAX_ENUM_VALUES + 1))}}},
            id="too-many-enum-values",
        ),
        pytest.param(
            {
                "type": "object",
                "properties": {"tree": {"$ref": "#/$defs/Node"}},
                "$defs": {"Node": {"type": "object", "properties": {"kids": {"type": "array", "items": {"$ref": "#/$defs/Node"}}}}},
            },
            id="recursive-reference",
        ),
    ],
)
def test_non_compliant_schemas_ship_with_strict_false_and_their_own_schema(schema: dict[str, Any]) -> None:
    """A schema outside the strict subset is sent as the tool wrote it, with ``strict: false``.

    Args:
        schema: A schema strict mode cannot express faithfully.
    """
    entry = _responses_entry(schema)

    assert entry["strict"] is False
    assert entry["parameters"] == normalize_object_schema(schema)


def test_compliant_schema_is_closed_and_claims_strict() -> None:
    """A schema inside the subset is closed the way strict mode requires and claims ``strict: true``."""
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "file to open", "pattern": "^[A-Z]:"},
            "when": {"type": "string", "format": "date-time"},
            "mode": {"enum": ["fast", "full"]},
            "count": {"type": "integer", "minimum": 1, "maximum": 10},
            "note": {"type": "string", "nullable": True},
            "range": {
                "type": "object",
                "properties": {"start": {"type": "integer"}, "end": {"type": "integer"}},
                "required": ["start"],
            },
            "ids": {"type": "array", "items": {"type": "integer"}, "maxItems": 4},
        },
        "required": ["path", "range", "note"],
        "additionalProperties": False,
        "default": {"path": "C:"},
    }

    entry = _responses_entry(schema)
    parameters = entry["parameters"]

    assert entry["strict"] is True
    assert _strict_ok(entry) == []
    assert parameters["properties"]["path"] == {"type": "string", "description": "file to open", "pattern": "^[A-Z]:"}
    assert parameters["properties"]["when"]["type"] == ["string", "null"]
    assert parameters["properties"]["mode"] == {"anyOf": [{"enum": ["fast", "full"]}, {"type": "null"}]}
    assert parameters["properties"]["count"]["type"] == ["integer", "null"]
    assert parameters["properties"]["note"]["type"] == ["string", "null"]
    assert parameters["properties"]["range"]["properties"]["end"]["type"] == ["integer", "null"]
    assert parameters["properties"]["range"]["properties"]["start"]["type"] == "integer"
    assert "default" not in parameters


def test_nesting_at_the_limit_still_claims_strict() -> None:
    """Exactly ten levels of objects is within the documented limit."""
    entry = _responses_entry(_nested_objects(_STRICT_MAX_NESTING))

    assert entry["strict"] is True
    assert _strict_ok(entry) == []


@pytest.fixture(scope="module")
def bridge_tools() -> list[ToolDefinition]:
    """Collect every shipped bridge's tool definition.

    Returns:
        list[ToolDefinition]: One definition per bridge.
    """
    definitions: list[ToolDefinition] = []
    for module_path, class_name in _BRIDGE_CLASSES:
        bridge_class: type[ToolBridgeBase] = getattr(importlib.import_module(module_path), class_name)
        definitions.append(bridge_class().tool_definition)
    return definitions


def test_every_bridge_function_claiming_strict_is_actually_compliant(bridge_tools: list[ToolDefinition]) -> None:
    """Across the whole shipped tool surface, ``strict: true`` is never a false claim.

    Args:
        bridge_tools: Every shipped bridge definition.
    """
    capabilities = _capabilities("openai", "gpt-5.4")
    entries = adapter_for(ApiDialect.RESPONSES).build_tool_schemas(bridge_tools, capabilities)
    functions = [entry for entry in entries if entry.get("type") == "function"]
    assert len(functions) > 700

    dishonest = {entry["name"]: problems for entry in functions if entry["strict"] and (problems := _strict_ok(entry))}
    assert dishonest == {}
    assert any(entry["strict"] for entry in functions)
    assert any(not entry["strict"] for entry in functions)


def _gemini_declarations(tools: list[ToolDefinition]) -> list[dict[str, Any]]:
    """Render tools as Gemini function declarations.

    Args:
        tools: The tools to render.

    Returns:
        list[dict[str, Any]]: The flat declaration list.
    """
    capabilities = _capabilities("google", "gemini-2.5-pro")
    rendered = adapter_for(ApiDialect.GEMINI).build_tool_schemas(tools, capabilities)
    assert len(rendered) == 1
    declarations: list[dict[str, Any]] = rendered[0]["functionDeclarations"]
    return declarations


def _empty_objects(node: object, path: str) -> Iterator[str]:
    """Find every Gemini ``OBJECT`` node with empty or missing ``properties``.

    Args:
        node: A Gemini ``Schema`` node.
        path: Location used in the messages.

    Yields:
        str: The location of each offending node.
    """
    if is_json_array(node):
        for index, entry in enumerate(node):
            yield from _empty_objects(entry, f"{path}[{index}]")
        return
    if not is_json_object(node):
        return
    schema = node
    if str(schema.get("type", "")).upper() == "OBJECT" and not schema.get("properties"):
        yield path
    for key in ("properties",):
        members = schema.get(key)
        if is_json_object(members):
            for name, member in members.items():
                yield from _empty_objects(member, f"{path}.{name}")
    for key in ("items", "anyOf", "any_of"):
        if key in schema:
            yield from _empty_objects(schema[key], f"{path}.{key}")


def test_function_without_arguments_declares_no_parameters() -> None:
    """Neither a raw no-argument schema nor an empty bridge parameter list yields an empty ``OBJECT``."""
    raw = _raw_tool("ext.ping", {"type": "object", "properties": {}})
    bridge = ToolDefinition(
        tool_name="local",
        description="local tool",
        functions=[ToolFunction(name="local.status", description="reports status", parameters=[], returns="status")],
    )

    declarations = _gemini_declarations([raw, bridge])

    assert [sorted(declaration) for declaration in declarations] == [["description", "name"], ["description", "name"]]


def test_nested_free_form_object_is_declared_as_json_schema() -> None:
    """An open-ended nested object goes in ``parametersJsonSchema``, which accepts it."""
    raw_schema: dict[str, Any] = {
        "type": "object",
        "properties": {"target": {"type": "string"}, "env": {"type": "object", "additionalProperties": {"type": "string"}}},
        "required": ["target"],
    }
    bridge = ToolDefinition(
        tool_name="local",
        description="local tool",
        functions=[
            ToolFunction(
                name="local.spawn",
                description="spawns",
                parameters=[
                    ToolParameter(name="path", type="string", description="binary"),
                    ToolParameter(name="env", type="dict", description="environment", required=False),
                ],
                returns="pid",
            ),
        ],
    )

    raw_declaration, bridge_declaration = _gemini_declarations([_raw_tool("ext.spawn", raw_schema), bridge])

    assert "parameters" not in raw_declaration
    assert raw_declaration["parametersJsonSchema"] == raw_schema
    assert "parameters" not in bridge_declaration
    assert bridge_declaration["parametersJsonSchema"]["properties"]["env"]["type"] == "object"
    assert bridge_declaration["parametersJsonSchema"]["required"] == ["path"]


def test_root_accepting_arbitrary_keys_is_declared_as_json_schema() -> None:
    """A root with no named properties but open keys still declares its arguments."""
    schema: dict[str, Any] = {"type": "object", "additionalProperties": {"type": "integer"}}

    (declaration,) = _gemini_declarations([_raw_tool("ext.counts", schema)])

    assert "parameters" not in declaration
    assert declaration["parametersJsonSchema"]["additionalProperties"] == {"type": "integer"}


def test_expressible_schema_stays_in_parameters_without_empty_objects() -> None:
    """A schema the ``Schema`` subset can carry is sent in ``parameters``, as before."""
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {"point": {"type": "object", "properties": {"x": {"type": "number"}}, "required": ["x"]}},
        "required": ["point"],
    }

    (declaration,) = _gemini_declarations([_raw_tool("ext.move", schema)])

    assert "parametersJsonSchema" not in declaration
    assert declaration["parameters"]["properties"]["point"]["properties"]["x"]["type"] == "NUMBER"
    assert list(_empty_objects(declaration["parameters"], "$")) == []


def test_no_bridge_declaration_carries_an_empty_object(bridge_tools: list[ToolDefinition]) -> None:
    """Across every shipped bridge function, ``parameters`` never holds an ``OBJECT`` Gemini rejects.

    Args:
        bridge_tools: Every shipped bridge definition.
    """
    declarations = _gemini_declarations(bridge_tools)

    offending = {
        declaration["name"]: found for declaration in declarations if (found := list(_empty_objects(declaration.get("parameters"), "$")))
    }
    assert offending == {}
    assert sum("parametersJsonSchema" in declaration for declaration in declarations) > 0


_JSON_SCHEMA_FIELDS: Final[tuple[str, ...]] = ("parametersJsonSchema", "parameters_json_schema")
"""How the field reaches the wire: the SDK serialises declarations with snake_case keys, which the API accepts as proto field names."""


class _GeminiEndpoint:
    """A loopback ``generateContent`` endpoint that records every request body."""

    def __init__(self) -> None:
        """Start serving."""
        self.bodies: list[dict[str, Any]] = []
        owner = self

        class _Handler(BaseHTTPRequestHandler):
            """Answers every ``POST`` with a one-part text candidate."""

            def do_POST(self) -> None:
                """Record the request and answer it."""
                length = int(self.headers.get("Content-Length", "0"))
                owner.bodies.append(json.loads(self.rfile.read(length)))
                reply = json.dumps({
                    "candidates": [{"content": {"role": "model", "parts": [{"text": "ok"}]}, "finishReason": "STOP"}],
                    "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 1, "totalTokenCount": 4},
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                _ = self.wfile.write(reply)

            def log_message(self, *args: object, **kwargs: object) -> None:
                """Silence per-request logging.

                Args:
                    *args: Ignored.
                    **kwargs: Ignored.
                """

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        """The endpoint origin.

        Returns:
            str: ``http://127.0.0.1:<port>``.
        """
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def close(self) -> None:
        """Stop serving."""
        self._server.shutdown()
        self._server.server_close()


@pytest.mark.asyncio
async def test_sdk_request_carries_no_empty_object_schemas() -> None:
    """The ``google-genai`` SDK path puts the chosen declaration fields on the wire unchanged."""
    endpoint = _GeminiEndpoint()
    try:
        provider = GoogleProvider()
        provider.connected = True
        provider.client = GenaiClient(api_key="loopback-key", http_options=HttpOptions(base_url=endpoint.url))
        tools = [
            _raw_tool("ext.ping", {"type": "object", "properties": {}}),
            _raw_tool("ext.spawn", {"type": "object", "properties": {"env": {"type": "object"}, "target": {"type": "string"}}}),
            _raw_tool("ext.move", {"type": "object", "properties": {"x": {"type": "number"}}, "required": ["x"]}),
        ]

        reply, _ = await provider.chat([Message(role="user", content="go")], "gemini-2.5-pro", tools=tools)
    finally:
        endpoint.close()

    assert reply.content == "ok"
    assert len(endpoint.bodies) == 1
    sent = {declaration["name"]: declaration for declaration in endpoint.bodies[0]["tools"][0]["functionDeclarations"]}
    ping, spawn, move = (next(value for key, value in sent.items() if key.endswith(suffix)) for suffix in ("ping", "spawn", "move"))
    assert "parameters" not in ping
    assert not set(ping) & set(_JSON_SCHEMA_FIELDS)
    assert "parameters" not in spawn
    (json_schema,) = (spawn[key] for key in _JSON_SCHEMA_FIELDS if key in spawn)
    assert json_schema["properties"]["env"] == {"type": "object"}
    assert move["parameters"]["properties"]["x"]["type"] == "NUMBER"
    assert all(not list(_empty_objects(declaration.get("parameters"), "$")) for declaration in sent.values())
