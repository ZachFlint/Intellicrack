# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The real agent loop, a real MCP server and a loopback LLM endpoint, wired together.

A gate that asks "what did the model actually receive?" needs every layer to be real: an MCP server spoken to over a real transport, the
real tool source and tool registry, the real orchestrator, and the real provider writing a real request body to a real socket. This module
wires those together once, for every dialect, so a gate only says which server to launch, which tool the model calls, and what to assert
about the request bodies the endpoint recorded.

The endpoint is :class:`~tests._helpers.scripted_http_server.ScriptedHttpServer`. Each dialect answers the first model request with a
call to one tool and the second with a plain answer, in that dialect's own response shape.
"""

from __future__ import annotations

import asyncio
import json
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from intellicrack.core.orchestrator import Orchestrator, OrchestratorConfig
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ConfirmationLevel, ProviderCredentials, ToolResult
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.config import McpConfigDocument, McpConfigStore, McpServerConfig, McpTransportKind, StdioServerSpec
from intellicrack.mcp.connection import McpConnectionManager
from intellicrack.mcp.consent import McpConsentGate, TrustStore
from intellicrack.mcp.secrets import McpSecretResolver
from intellicrack.mcp.tool_source import McpToolSource
from intellicrack.providers.capabilities import ApiDialect, CapabilityOverride
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.instances import ProviderInstance
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.providers.tool_names import to_wire_name
from tests._helpers.scripted_http_server import ScriptedHttpServer, json_response


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable
    from pathlib import Path

    from intellicrack.mcp.consent import LaunchPrompt
    from tests._helpers.scripted_http_server import RecordedRequest, ScriptedResponse


MODEL: Final[str] = "loopback-model"
"""The model id every scripted endpoint serves."""

CONNECT_TIMEOUT_S: Final[float] = 60.0
"""How long the MCP servers may take to come up."""

TURN_TIMEOUT_S: Final[float] = 90.0
"""How long one agent turn may take."""

_MODEL_LISTINGS: Final[int] = 64
"""Model listings queued per endpoint; every listing is answered identically."""

_CALL_ID: Final[str] = "call_1"


def _chat_tool_call(function_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Build a Chat Completions response asking for one tool call.

    Args:
        function_name: Canonical dotted function name.
        arguments: Call arguments.

    Returns:
        dict[str, Any]: The response body.
    """
    call = {"id": _CALL_ID, "type": "function", "function": {"name": to_wire_name(function_name), "arguments": json.dumps(arguments)}}
    return {
        "id": "c1",
        "object": "chat.completion",
        "model": MODEL,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": None, "tool_calls": [call]}, "finish_reason": "tool_calls"}],
    }


def _chat_final() -> dict[str, Any]:
    """Build a Chat Completions response ending the turn.

    Returns:
        dict[str, Any]: The response body.
    """
    return {
        "id": "c2",
        "object": "chat.completion",
        "model": MODEL,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "done"}, "finish_reason": "stop"}],
    }


def _messages_tool_call(function_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Build an Anthropic Messages response asking for one tool call.

    Args:
        function_name: Canonical dotted function name.
        arguments: Call arguments.

    Returns:
        dict[str, Any]: The response body.
    """
    block = {"type": "tool_use", "id": "toolu_1", "name": to_wire_name(function_name), "input": arguments}
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": MODEL,
        "content": [block],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }


def _messages_final() -> dict[str, Any]:
    """Build an Anthropic Messages response ending the turn.

    Returns:
        dict[str, Any]: The response body.
    """
    return {
        "id": "msg_2",
        "type": "message",
        "role": "assistant",
        "model": MODEL,
        "content": [{"type": "text", "text": "done"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }


def _responses_tool_call(function_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Build an OpenAI Responses response asking for one tool call.

    Args:
        function_name: Canonical dotted function name.
        arguments: Call arguments.

    Returns:
        dict[str, Any]: The response body.
    """
    item = {
        "type": "function_call",
        "id": "fc_1",
        "call_id": _CALL_ID,
        "name": to_wire_name(function_name),
        "arguments": json.dumps(arguments),
        "status": "completed",
    }
    return {
        "id": "resp_1",
        "object": "response",
        "status": "completed",
        "model": MODEL,
        "output": [item],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
    }


def _responses_final() -> dict[str, Any]:
    """Build an OpenAI Responses response ending the turn.

    Returns:
        dict[str, Any]: The response body.
    """
    message: dict[str, Any] = {
        "type": "message",
        "id": "msg_1",
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": "done", "annotations": []}],
    }
    return {
        "id": "resp_2",
        "object": "response",
        "status": "completed",
        "model": MODEL,
        "output": [message],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
    }


def _gemini_tool_call(function_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Build a Gemini ``generateContent`` response asking for one tool call.

    Args:
        function_name: Canonical dotted function name.
        arguments: Call arguments.

    Returns:
        dict[str, Any]: The response body.
    """
    part = {"functionCall": {"id": _CALL_ID, "name": to_wire_name(function_name), "args": arguments}}
    return {
        "candidates": [{"content": {"role": "model", "parts": [part]}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2},
    }


def _gemini_final() -> dict[str, Any]:
    """Build a Gemini ``generateContent`` response ending the turn.

    Returns:
        dict[str, Any]: The response body.
    """
    return {
        "candidates": [{"content": {"role": "model", "parts": [{"text": "done"}]}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2},
    }


@dataclass(frozen=True, slots=True)
class DialectScript:
    """How one dialect's loopback endpoint is addressed and answers.

    Attributes:
        base_path: Path appended to the origin to form the instance's base URL.
        generate_path: Path the model request is POSTed to.
        models_path: Path the model listing is read from.
        tool_call: Builds the response asking for one tool call.
        final: Builds the response ending the turn.
    """

    base_path: str
    generate_path: str
    models_path: str
    tool_call: Callable[[str, dict[str, Any]], dict[str, Any]]
    final: Callable[[], dict[str, Any]]


DIALECT_SCRIPTS: Final[dict[ApiDialect, DialectScript]] = {
    ApiDialect.CHAT_COMPLETIONS: DialectScript("/v1", "/v1/chat/completions", "/v1/models", _chat_tool_call, _chat_final),
    ApiDialect.RESPONSES: DialectScript("/v1", "/v1/responses", "/v1/models", _responses_tool_call, _responses_final),
    ApiDialect.MESSAGES: DialectScript("", "/v1/messages", "/v1/models", _messages_tool_call, _messages_final),
    ApiDialect.GEMINI: DialectScript(
        "",
        f"/v1beta/models/{MODEL}:generateContent",
        "/v1beta/models",
        _gemini_tool_call,
        _gemini_final,
    ),
}
"""Every dialect the configurable provider speaks."""


def _models_listing() -> dict[str, Any]:
    """Build one model listing every dialect's parser accepts.

    Returns:
        dict[str, Any]: A body carrying the model under both ``data`` and ``models``.
    """
    entry = {"id": MODEL, "object": "model", "type": "model", "display_name": MODEL, "created_at": "2026-01-01T00:00:00Z"}
    gemini = {"name": f"models/{MODEL}", "displayName": MODEL, "supportedGenerationMethods": ["generateContent"]}
    return {"object": "list", "data": [entry], "models": [gemini], "has_more": False, "first_id": MODEL, "last_id": MODEL}


def approve_every_launch(_config: object, _rendered: str, _findings: object) -> bool:
    """Approve every launch, for a gate whose subject is not consent.

    Args:
        _config: The server being launched.
        _rendered: The rendered launch description.
        _findings: Dangerous patterns found in the command.

    Returns:
        bool: Always ``True``.
    """
    return True


def stdio_server(server_id: str, script: Path, *args: str, request_timeout_s: float = 30.0) -> McpServerConfig:
    """Configure a Python MCP server script launched over stdio.

    Args:
        server_id: The id to configure it under.
        script: The server script.
        *args: Extra command-line arguments for the script.
        request_timeout_s: Per-request timeout.

    Returns:
        McpServerConfig: An enabled stdio configuration.
    """
    return McpServerConfig(
        server_id=server_id,
        kind=McpTransportKind.STDIO,
        stdio=StdioServerSpec(command=sys.executable, args=(str(script), *args)),
        enabled=True,
        request_timeout_s=request_timeout_s,
    )


@dataclass
class AgentStack:
    """Everything a gate drives.

    Attributes:
        orchestrator: The real orchestrator.
        manager: The real MCP connection manager.
        source: The real MCP tool source.
        endpoint: The loopback LLM endpoint.
        results: Every tool result the orchestrator reported.
        generate_path: Path the model requests are POSTed to.
    """

    orchestrator: Orchestrator
    manager: McpConnectionManager
    source: McpToolSource
    endpoint: ScriptedHttpServer
    results: list[ToolResult]
    generate_path: str

    def model_requests(self) -> list[dict[str, Any]]:
        """Decode every model request the endpoint received.

        Returns:
            list[dict[str, Any]]: The request bodies, in order.
        """
        return [request.json_object() for request in self.endpoint.requests(self.generate_path)]


@asynccontextmanager
async def agent_stack(
    tmp_path: Path,
    dialect: ApiDialect,
    servers: tuple[McpServerConfig, ...],
    responses: list[dict[str, Any] | Callable[[RecordedRequest], ScriptedResponse]],
    *,
    prompt: LaunchPrompt = approve_every_launch,
    overrides: CapabilityOverride | None = None,
    dynamic_loading: bool = False,
) -> AsyncGenerator[AgentStack]:
    """Bring the whole stack up, yield it, and tear it all down.

    Args:
        tmp_path: Directory backing every store.
        dialect: Wire format the loopback endpoint speaks.
        servers: The MCP servers to configure and start.
        responses: Model responses in answer order: a body, or a callable
            computing the scripted response from the request.
        prompt: Launch-consent prompt the gate is built with.
        overrides: Capability override for the model, defaulting to one with
            vision and a large context window.
        dynamic_loading: Whether the orchestrator loads tools on demand.

    Yields:
        AgentStack: The running stack.
    """
    script = DIALECT_SCRIPTS[dialect]
    store = McpConfigStore(tmp_path / "mcp.json")
    store.save(McpConfigDocument(servers=servers))
    credentials = CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env"))
    manager = McpConnectionManager(store, McpSecretResolver(credentials), McpConsentGate(TrustStore(tmp_path / "trust.json"), prompt))
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(exist_ok=True)
    registry = ToolRegistry(tools_dir=tools_dir)
    source = McpToolSource(manager, registry)
    with ScriptedHttpServer() as endpoint:
        endpoint.script("GET", script.models_path, *(json_response(200, _models_listing()) for _ in range(_MODEL_LISTINGS)))
        endpoint.script(
            "POST",
            script.generate_path,
            *(entry if callable(entry) else json_response(200, entry) for entry in responses),
        )
        instance = ProviderInstance(
            instance_id="loopback",
            dialect=dialect,
            api_base=f"{endpoint.origin}{script.base_path}",
            requires_api_key=False,
            model_overrides={MODEL: overrides or CapabilityOverride(supports_vision=True, context_window=200_000)},
        )
        provider = ConfigurableProvider(instance)
        await provider.connect(ProviderCredentials())
        providers = ProviderRegistry()
        providers.register(provider)
        orchestrator = Orchestrator(
            provider_registry=providers,
            tool_registry=registry,
            session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db"), auto_save=False),
            config=OrchestratorConfig(
                stream_responses=False,
                confirmation_level=ConfirmationLevel.NONE,
                enable_dynamic_loading=dynamic_loading,
            ),
        )
        orchestrator.set_mcp_tool_source(source)
        results: list[ToolResult] = []
        orchestrator.set_tool_result_callback(results.append)
        try:
            await asyncio.wait_for(manager.start(), timeout=CONNECT_TIMEOUT_S)
            source.register_all()
            _ = await orchestrator.start_session("loopback", MODEL)
            yield AgentStack(orchestrator, manager, source, endpoint, results, script.generate_path)
        finally:
            orchestrator.set_mcp_tool_source(None)
            await manager.stop()
            await provider.disconnect()


def run_tool_turn(
    tmp_path: Path,
    dialect: ApiDialect,
    server: McpServerConfig,
    function_name: str,
    arguments: dict[str, Any],
    *,
    overrides: CapabilityOverride | None = None,
) -> tuple[list[ToolResult], list[dict[str, Any]]]:
    """Run one agent turn in which the model calls one MCP tool.

    Args:
        tmp_path: Directory backing every store.
        dialect: Wire format the loopback endpoint speaks.
        server: The MCP server to launch.
        function_name: Canonical name the model calls.
        arguments: Arguments the model passes.
        overrides: Capability override for the model.

    Returns:
        tuple[list[ToolResult], list[dict[str, Any]]]: The tool results the
        orchestrator produced and every model request body the endpoint saw.
    """
    script = DIALECT_SCRIPTS[dialect]

    async def _turn() -> tuple[list[ToolResult], list[dict[str, Any]]]:
        """Drive the turn inside a running stack.

        Returns:
            tuple[list[ToolResult], list[dict[str, Any]]]: Results and request bodies.
        """
        responses: list[dict[str, Any] | Callable[[RecordedRequest], ScriptedResponse]] = [
            script.tool_call(function_name, arguments),
            script.final(),
        ]
        async with agent_stack(tmp_path, dialect, (server,), responses, overrides=overrides) as stack:
            await asyncio.wait_for(stack.orchestrator.process_user_input("call the tool"), timeout=TURN_TIMEOUT_S)
            return list(stack.results), stack.model_requests()

    return asyncio.run(_turn())


def tool_result_payload(dialect: ApiDialect, body: dict[str, Any]) -> list[Any]:
    """Pull out everything a request body carries for the replayed tool result.

    Args:
        dialect: The dialect the body is written in.
        body: The second model request, which replays the tool result.

    Returns:
        list[Any]: The dialect-native items carrying the result and any
        images that ride with it, in order.
    """
    if dialect is ApiDialect.CHAT_COMPLETIONS:
        messages: list[dict[str, Any]] = body["messages"]
        first = next(index for index, message in enumerate(messages) if message.get("role") == "tool")
        return messages[first:]
    if dialect is ApiDialect.RESPONSES:
        items: list[dict[str, Any]] = body["input"]
        first = next(index for index, item in enumerate(items) if item.get("type") == "function_call_output")
        return items[first:]
    if dialect is ApiDialect.MESSAGES:
        turns: list[dict[str, Any]] = body["messages"]
        return [
            block
            for turn in turns
            if isinstance(turn.get("content"), list)
            for block in turn["content"]
            if block.get("type") == "tool_result"
        ]
    contents: list[dict[str, Any]] = body["contents"]
    return [part for content in contents for part in content.get("parts", []) if "function_response" in part or "inline_data" in part]


__all__ = [
    "CONNECT_TIMEOUT_S",
    "DIALECT_SCRIPTS",
    "MODEL",
    "TURN_TIMEOUT_S",
    "AgentStack",
    "DialectScript",
    "agent_stack",
    "approve_every_launch",
    "run_tool_turn",
    "stdio_server",
    "tool_result_payload",
]
