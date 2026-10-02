# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 35: the model reaches a server's resources and prompts, and hears when they change.

The gates run a real ``MCPServer`` on 2026-07-28 over stdio and 2025-11-25 over SSE. Through the real agent loop and a loopback model
endpoint, the model is offered each server's ``context.*`` functions, reads a text resource that comes back fenced and cleaned, and a
binary one that comes back as an image part. Called directly, the functions page through listings with the server's cursor, list
templates and prompts, fetch a prompt, and complete arguments of both. Subscriptions reach the server on both generations, the server's
announcements reach the connection's listener, a 2025-11-25 subscription survives a reconnect, and a server's changes are named to the
model until it reads the resource again. What the operator must confirm follows the server's trust, and ``tools.search`` finds them.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import AsyncExitStack
from dataclasses import replace
from typing import TYPE_CHECKING, Any, Final

import pytest
from mcp_types import TextContent

from intellicrack.core.types import ImageResultPart, TextResultPart
from intellicrack.core.untrusted_text import UNTRUSTED_BLOCK_START
from intellicrack.mcp.config import to_canonical_name
from intellicrack.mcp.consent import TrustState, server_identity
from intellicrack.mcp.context_events import McpContextChange, McpContextEvent
from intellicrack.mcp.context_tools import ContextTool, run_context_tool
from intellicrack.mcp.errors import McpProtocolError
from intellicrack.mcp.uri_template import expand_uri_template, template_variables
from intellicrack.providers.capabilities import ApiDialect
from intellicrack.providers.tool_names import to_wire_name
from tests._helpers.mcp_agent_harness import DIALECT_SCRIPTS, TURN_TIMEOUT_S, agent_stack
from tests._helpers.mcp_features_server import (
    FORGET_SUBSCRIPTIONS_TOOL,
    GREET_PROMPT,
    HIDDEN_MARK,
    NOTES_RESOURCE,
    PIXEL_RESOURCE,
    REPORT_TEMPLATE,
    SUBSCRIBED_TOOL,
    TOUCH_TOOL,
)
from tests._helpers.mcp_features_support import FEATURES_SERVER_SCRIPT, Era, features_config, features_connection
from tests._helpers.mcp_http_process import running_server


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from intellicrack.core.types import ToolResult
    from intellicrack.mcp.connection import McpConnection
    from tests._helpers.mcp_agent_harness import AgentStack
    from tests._helpers.scripted_http_server import RecordedRequest, ScriptedResponse


_ERAS: Final[list[Era]] = [Era.MODERN, Era.LEGACY]
_ERA_IDS: Final[list[str]] = [era.name.lower() for era in _ERAS]
_DIALECT: Final[ApiDialect] = ApiDialect.CHAT_COMPLETIONS
_TIMEOUT_S: Final[float] = 90.0


def _name(tool: ContextTool) -> str:
    """Name one context function in the fixture server's namespace.

    Args:
        tool: The function.

    Returns:
        str: Its canonical name.
    """
    return to_canonical_name("features", tool.value)


async def _text(connection: McpConnection, tool: str) -> str:
    """Call a fixture tool and read its text.

    Args:
        connection: The connection.
        tool: The tool.

    Returns:
        str: Its text result.
    """
    result = await connection.call_tool(tool, {"uri": NOTES_RESOURCE} if tool == TOUCH_TOOL else {})
    [block] = result.content
    assert isinstance(block, TextContent)
    return block.text


async def _run_turn(
    tmp_path: Path,
    era: Era,
    responses: list[dict[str, Any] | Callable[[RecordedRequest], ScriptedResponse]],
    *,
    dynamic_loading: bool = False,
) -> tuple[list[ToolResult], list[dict[str, Any]]]:
    """Run one agent turn against the fixture server.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
        responses: The model's scripted answers.
        dynamic_loading: Whether tools are loaded on demand.

    Returns:
        tuple[list[ToolResult], list[dict[str, Any]]]: The tool results and the model requests.
    """
    async with AsyncExitStack() as stack:
        port = stack.enter_context(running_server(FEATURES_SERVER_SCRIPT, "--transport", "sse")) if era is Era.LEGACY else None
        servers = (features_config(era, port=port),)
        agents: AgentStack = await stack.enter_async_context(
            agent_stack(tmp_path, _DIALECT, servers, responses, dynamic_loading=dynamic_loading),
        )
        await asyncio.wait_for(agents.orchestrator.process_user_input("look at the server's context"), TURN_TIMEOUT_S)
        return list(agents.results), agents.model_requests()


@pytest.mark.parametrize("era", _ERAS, ids=_ERA_IDS)
def test_model_is_offered_every_context_function(tmp_path: Path, era: Era) -> None:
    """The model's first request lists every context function the server's capabilities call for.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    _, requests = asyncio.run(_run_turn(tmp_path, era, [DIALECT_SCRIPTS[_DIALECT].final()]))
    offered = {tool["function"]["name"] for tool in requests[0]["tools"]}
    assert {to_wire_name(_name(tool)) for tool in ContextTool} <= offered


@pytest.mark.parametrize("era", _ERAS, ids=_ERA_IDS)
def test_model_reads_text_fenced_and_binary_as_an_image(tmp_path: Path, era: Era) -> None:
    """A text resource reaches the model fenced and cleaned; a PNG resource reaches it as an image part.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    script = DIALECT_SCRIPTS[_DIALECT]
    responses: list[dict[str, Any] | Callable[[RecordedRequest], ScriptedResponse]] = [
        script.tool_call(_name(ContextTool.READ_RESOURCE), {"uri": NOTES_RESOURCE}),
        script.tool_call(_name(ContextTool.READ_RESOURCE), {"uri": PIXEL_RESOURCE}),
        script.final(),
    ]
    results, requests = asyncio.run(_run_turn(tmp_path, era, responses))
    text_result, image_result = results
    assert text_result.success
    assert isinstance(text_result.content, list)
    [text_part] = text_result.content
    assert isinstance(text_part, TextResultPart)
    assert UNTRUSTED_BLOCK_START in text_part.text
    assert "remember the target" in text_part.text
    assert HIDDEN_MARK not in text_part.text
    assert UNTRUSTED_BLOCK_START in json.dumps(requests[1])
    assert image_result.success
    assert isinstance(image_result.content, list)
    assert [(type(part), getattr(part, "mime_type", None)) for part in image_result.content] == [(ImageResultPart, "image/png")]


@pytest.mark.parametrize("era", _ERAS, ids=_ERA_IDS)
def test_listings_page_and_prompts_and_completions_work(tmp_path: Path, era: Era) -> None:
    """Resources page with the server's cursor; templates, prompts, a prompt fetch and completions answer as the server does.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """

    async def run() -> dict[str, str]:
        """Call each reading function once.

        Returns:
            dict[str, str]: Each call's text.
        """
        async with features_connection(tmp_path, era) as connection:

            async def text(tool: ContextTool, arguments: dict[str, object]) -> str:
                """Run one function and join its text.

                Args:
                    tool: The function.
                    arguments: Its arguments.

                Returns:
                    str: The text parts, joined.
                """
                output = await run_context_tool(connection, tool, arguments)
                return "\n".join(part.text for part in output.parts if isinstance(part, TextResultPart))

            outputs = {
                "first": await text(ContextTool.LIST_RESOURCES, {}),
                "second": await text(ContextTool.LIST_RESOURCES, {"cursor": "1"}),
                "templates": await text(ContextTool.LIST_RESOURCE_TEMPLATES, {}),
                "prompts": await text(ContextTool.LIST_PROMPTS, {}),
                "greeting": await text(ContextTool.GET_PROMPT, {"name": GREET_PROMPT, "arguments": {"person": "ada"}}),
                "report": await text(
                    ContextTool.COMPLETE,
                    {"kind": "resource_template", "name": REPORT_TEMPLATE, "argument": "name", "value": "al"},
                ),
                "person": await text(ContextTool.COMPLETE, {"kind": "prompt", "name": GREET_PROMPT, "argument": "person", "value": "a"}),
            }
            with pytest.raises(McpProtocolError):
                _ = await run_context_tool(connection, ContextTool.COMPLETE, {"kind": "tool", "name": "x", "argument": "y", "value": ""})
            return outputs

    outputs = asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S))
    assert NOTES_RESOURCE in outputs["first"]
    assert "call again with cursor '1'" in outputs["first"]
    assert PIXEL_RESOURCE in outputs["second"]
    assert "This is the last page." in outputs["second"]
    assert REPORT_TEMPLATE in outputs["templates"]
    assert "greet(person*, style)" in outputs["prompts"]
    assert "Greet ada in a plain way." in outputs["greeting"]
    assert "- alpha\n" in outputs["report"]
    assert "- alpine" in outputs["report"]
    assert "beta" not in outputs["report"]
    assert "- ada\n" in outputs["person"]
    assert "- alan" in outputs["person"]


@pytest.mark.parametrize("era", _ERAS, ids=_ERA_IDS)
def test_subscriptions_reach_the_server_and_its_announcements_come_back(tmp_path: Path, era: Era) -> None:
    """A subscribed resource's update and the list changes reach the listener; after unsubscribing, updates stop.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    events: list[McpContextEvent] = []

    async def run() -> tuple[list[McpContextEvent], list[McpContextEvent], frozenset[str]]:
        """Subscribe, have the server announce, unsubscribe, announce again.

        Returns:
            tuple[list[McpContextEvent], list[McpContextEvent], frozenset[str]]: The events while subscribed, the events after, and
            the subscriptions after.
        """
        async with features_connection(tmp_path, era) as connection:
            connection.set_context_listener(events.append)
            connection.start_listening(lambda _server_id: None)
            _ = await run_context_tool(connection, ContextTool.SUBSCRIBE_RESOURCE, {"uri": NOTES_RESOURCE})
            await asyncio.sleep(0.5)
            _ = await _text(connection, TOUCH_TOOL)
            await asyncio.sleep(0.5)
            first = list(events)
            events.clear()
            _ = await run_context_tool(connection, ContextTool.UNSUBSCRIBE_RESOURCE, {"uri": NOTES_RESOURCE})
            await asyncio.sleep(0.5)
            _ = await _text(connection, TOUCH_TOOL)
            await asyncio.sleep(0.5)
            return first, list(events), connection.subscriptions

    subscribed, after, remaining = asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S))
    changes = {(event.change, event.uri) for event in subscribed}
    assert (McpContextChange.RESOURCE_UPDATED, NOTES_RESOURCE) in changes
    assert (McpContextChange.RESOURCES_LISTED, None) in changes
    assert (McpContextChange.PROMPTS_LISTED, None) in changes
    assert {event.server_id for event in subscribed} == {"features"}
    assert McpContextChange.RESOURCE_UPDATED not in {event.change for event in after}
    assert remaining == frozenset()


def test_a_legacy_subscription_survives_a_reconnect(tmp_path: Path) -> None:
    """A 2025-11-25 server that lost its subscriptions is subscribed again when the connection is re-established.

    Args:
        tmp_path: Per-test directory.
    """

    async def run() -> tuple[str, str]:
        """Subscribe, make the server forget, reconnect, and ask it.

        Returns:
            tuple[str, str]: What the server held after forgetting, and after the reconnect.
        """
        async with features_connection(tmp_path, Era.LEGACY) as connection:
            _ = await run_context_tool(connection, ContextTool.SUBSCRIBE_RESOURCE, {"uri": NOTES_RESOURCE})
            _ = await _text(connection, FORGET_SUBSCRIPTIONS_TOOL)
            forgotten = await _text(connection, SUBSCRIBED_TOOL)
            await connection.disconnect()
            await connection.connect()
            return forgotten, await _text(connection, SUBSCRIBED_TOOL)

    assert asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S)) == ("[]", json.dumps([NOTES_RESOURCE]))


@pytest.mark.parametrize("era", _ERAS, ids=_ERA_IDS)
def test_updated_resources_are_named_to_the_model_until_read(tmp_path: Path, era: Era) -> None:
    """A subscribed resource the server updates is named in the prompt's MCP section until the model reads it again.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    script = DIALECT_SCRIPTS[_DIALECT]

    async def run() -> tuple[bool, bool, bool]:
        """Subscribe through the model, update, then read through the model.

        Returns:
            tuple[bool, bool, bool]: Whether the resource was named before the update, after it, and after the read.
        """
        async with AsyncExitStack() as stack:
            port = stack.enter_context(running_server(FEATURES_SERVER_SCRIPT, "--transport", "sse")) if era is Era.LEGACY else None
            responses: list[dict[str, Any] | Callable[[RecordedRequest], ScriptedResponse]] = [
                script.tool_call(_name(ContextTool.SUBSCRIBE_RESOURCE), {"uri": NOTES_RESOURCE}),
                script.final(),
                script.tool_call(_name(ContextTool.READ_RESOURCE), {"uri": NOTES_RESOURCE}),
                script.final(),
            ]
            agents = await stack.enter_async_context(agent_stack(tmp_path, _DIALECT, (features_config(era, port=port),), responses))
            agents.manager.set_context_listener(agents.source.note_context_event)
            await asyncio.wait_for(agents.orchestrator.process_user_input("subscribe"), TURN_TIMEOUT_S)
            before = "Subscribed resources that changed" in "\n".join(agents.source.catalog_lines())
            connection = agents.manager.connection("features")
            assert connection is not None
            await asyncio.sleep(0.5)
            _ = await _text(connection, TOUCH_TOOL)
            await asyncio.sleep(0.5)
            lines = "\n".join(agents.source.catalog_lines())
            named = "Subscribed resources that changed" in lines and NOTES_RESOURCE in lines
            await asyncio.wait_for(agents.orchestrator.process_user_input("read it"), TURN_TIMEOUT_S)
            still = "Subscribed resources that changed" in "\n".join(agents.source.catalog_lines())
            return before, named, still

    assert asyncio.run(run()) == (False, True, False)


@pytest.mark.parametrize("trusted", [False, True], ids=["untrusted", "trusted"])
def test_confirmation_follows_trust_and_subscribing_always_asks(tmp_path: Path, *, trusted: bool) -> None:
    """Reading functions skip confirmation only for a trusted server; subscribing is always confirmed.

    Args:
        tmp_path: Per-test directory.
        trusted: Whether the operator trusts the server.
    """

    async def run() -> tuple[dict[ContextTool, bool], bool]:
        """Ask the tool source how each function is classified.

        Returns:
            tuple[dict[ContextTool, bool], bool]: Each function's read-only verdict, and whether a disabled one is still offered.
        """
        async with agent_stack(tmp_path, _DIALECT, (features_config(Era.MODERN),), [DIALECT_SCRIPTS[_DIALECT].final()]) as agents:
            config = agents.manager.document.server("features")
            assert config is not None
            if trusted:
                agents.manager.consent.trust.set_state("features", TrustState.TRUSTED, identity=server_identity(config))
            verdicts = {tool: agents.source.is_read_only(_name(tool)) for tool in ContextTool}
            agents.manager.store.save(
                agents.manager.document.with_server(replace(config, disabled_tools=frozenset({ContextTool.SUBSCRIBE_RESOURCE.value}))),
            )
            _ = agents.manager.reload()
            await asyncio.wait_for(agents.orchestrator.process_user_input("anything"), TURN_TIMEOUT_S)
            offered = {tool["function"]["name"] for tool in agents.model_requests()[0]["tools"]}
            return verdicts, to_wire_name(_name(ContextTool.SUBSCRIBE_RESOURCE)) in offered

    verdicts, disabled_offered = asyncio.run(run())
    assert verdicts[ContextTool.SUBSCRIBE_RESOURCE] is False
    assert verdicts[ContextTool.UNSUBSCRIBE_RESOURCE] is False
    reading = {
        tool: verdict for tool, verdict in verdicts.items() if tool.value.startswith(("context.list", "context.read", "context.get"))
    }
    assert set(reading.values()) == {trusted}
    assert disabled_offered is False


def test_tools_search_finds_the_context_functions(tmp_path: Path) -> None:
    """With tools loaded on demand, ``tools.search`` finds a server's resource functions.

    Args:
        tmp_path: Per-test directory.
    """
    script = DIALECT_SCRIPTS[_DIALECT]
    responses: list[dict[str, Any] | Callable[[RecordedRequest], ScriptedResponse]] = [
        script.tool_call("tools.search", {"query": "read_resource"}),
        script.final(),
    ]
    results, _ = asyncio.run(_run_turn(tmp_path, Era.MODERN, responses, dynamic_loading=True))
    [result] = results
    assert result.success
    assert _name(ContextTool.READ_RESOURCE) in json.dumps(result.result)


@pytest.mark.parametrize(
    ("template", "expanded"),
    [
        ("{var}", "value"),
        ("{hello}", "Hello%20World%21"),
        ("{+hello}", "Hello%20World!"),
        ("{+path}/here", "/foo/bar/here"),
        ("{#hello}", "#Hello%20World!"),
        ("X{.var}", "X.value"),
        ("{/var}", "/value"),
        ("{;x,y,empty}", ";x=1024;y=768;empty"),
        ("{?x,y,empty}", "?x=1024&y=768&empty="),
        ("?fixed=yes{&x}", "?fixed=yes&x=1024"),
        ("{var:3}", "val"),
        ("{/undefined}", ""),
    ],
)
def test_resource_templates_expand_as_rfc_6570_says(template: str, expanded: str) -> None:
    """Every RFC 6570 operator expands as the RFC's own examples do, and an undefined variable is left out.

    Args:
        template: The template.
        expanded: What it must expand to.
    """
    values = {"var": "value", "hello": "Hello World!", "path": "/foo/bar", "x": "1024", "y": "768", "empty": ""}
    assert expand_uri_template(template, values) == expanded


def test_template_variables_are_listed_once_in_order() -> None:
    """A template's variables are listed in order, each once, and a malformed expression is refused."""
    assert template_variables("db://t/{table}{?limit,offset}{/table}") == ["table", "limit", "offset"]
    with pytest.raises(ValueError, match="is not valid"):
        _ = template_variables("db://{bad name}")
