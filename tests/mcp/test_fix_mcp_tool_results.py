# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""MCP tool calls work end to end, through the real agent loop.

Every gate here launches a real MCP server over stdio, registers it into a
real :class:`ToolRegistry`, and drives the real :class:`Orchestrator` agent
loop against a real :class:`ConfigurableProvider` talking to a scripted
loopback endpoint. What the tests assert on is the JSON that actually reached
that endpoint, so a result the dialects cannot serialize, an error that
aborts the turn, or an error reduced to a truncated string all show up
exactly as the model would have seen them.
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Final, Self, cast

import pytest

from intellicrack.core.orchestrator import Orchestrator, OrchestratorConfig, classify_tool_call
from intellicrack.core.session import Session, SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import (
    ConfirmationLevel,
    ImageResultPart,
    ProviderCredentials,
    StructuredResultPart,
    TextResultPart,
    ToolError,
    ToolResult,
)
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.config import McpConfigDocument, McpConfigStore, McpServerConfig, McpTransportKind, StdioServerSpec
from intellicrack.mcp.connection import McpConnectionManager
from intellicrack.mcp.consent import McpConsentGate, TrustStore
from intellicrack.mcp.secrets import McpSecretResolver
from intellicrack.mcp.tool_source import UNTRUSTED_BLOCK_END, UNTRUSTED_BLOCK_START, McpToolSource
from intellicrack.providers.capabilities import ApiDialect, CapabilityOverride
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.dialects.base import parse_tool_call
from intellicrack.providers.instances import ProviderInstance
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.providers.tool_names import to_wire_name
from tests._helpers.mcp_multipart_server import BIG_TEXT_CHARS, CONTROL_TEXT, ERROR_DETAIL, STRUCTURED_REPORT


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from types import TracebackType


_SERVER_SCRIPT: Final[Path] = Path(__file__).resolve().parents[1] / "_helpers" / "mcp_multipart_server.py"
_SERVER_ID: Final[str] = "mp"
_NAMESPACE: Final[str] = f"mcp-{_SERVER_ID}"
_MODEL: Final[str] = "loopback-model"
_CONNECT_TIMEOUT_S: Final[float] = 60.0
_TURN_TIMEOUT_S: Final[float] = 90.0
_LEGACY_ERROR_CAP: Final[int] = 512


@dataclass
class _ScriptedEndpoint:
    """A loopback LLM endpoint that answers from a script and records requests.

    Attributes:
        responses: JSON bodies to answer successive ``POST`` requests with.
        bodies: Every request body received, decoded.
    """

    responses: list[dict[str, object]]
    bodies: list[dict[str, object]] = field(default_factory=list)
    _server: ThreadingHTTPServer | None = None
    _thread: threading.Thread | None = None

    def __enter__(self) -> Self:
        """Start serving on an ephemeral loopback port.

        Returns:
            Self: The running endpoint.
        """
        endpoint = self

        class _Handler(BaseHTTPRequestHandler):
            """Answer each POST with the next scripted body."""

            def do_POST(self) -> None:
                """Record the request and send the next scripted response."""
                length = int(self.headers.get("Content-Length", "0"))
                endpoint.bodies.append(cast("dict[str, object]", json.loads(self.rfile.read(length))))
                body = json.dumps(endpoint.responses.pop(0)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                """Answer a model listing in a shape both dialects accept."""
                model = {"id": _MODEL, "object": "model", "type": "model", "display_name": _MODEL, "created_at": "2026-01-01T00:00:00Z"}
                body = json.dumps({"object": "list", "data": [model], "has_more": False, "first_id": _MODEL, "last_id": _MODEL}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object, **kwargs: object) -> None:
                """Silence per-request logging.

                Args:
                    *args: Ignored.
                    **kwargs: Ignored.
                """

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        """Stop serving.

        Args:
            exc_type: Exception type, if the block raised.
            exc: Exception instance, if the block raised.
            tb: Traceback, if the block raised.
        """
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    @property
    def origin(self) -> str:
        """The endpoint's base URL.

        Returns:
            str: ``http://127.0.0.1:<port>``.
        """
        assert self._server is not None
        return f"http://127.0.0.1:{self._server.server_address[1]}"


def _chat_tool_call(function_name: str, arguments: dict[str, object]) -> dict[str, object]:
    """Build a Chat Completions response asking for one tool call.

    Args:
        function_name: Canonical dotted function name.
        arguments: Call arguments.

    Returns:
        dict[str, object]: The response body.
    """
    call = {"id": "call_1", "type": "function", "function": {"name": to_wire_name(function_name), "arguments": json.dumps(arguments)}}
    message = {"role": "assistant", "content": None, "tool_calls": [call]}
    return {
        "id": "c1",
        "object": "chat.completion",
        "model": _MODEL,
        "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls"}],
    }


def _chat_final() -> dict[str, object]:
    """Build a Chat Completions response ending the turn.

    Returns:
        dict[str, object]: The response body.
    """
    message = {"role": "assistant", "content": "done"}
    return {
        "id": "c2",
        "object": "chat.completion",
        "model": _MODEL,
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
    }


def _messages_tool_call(function_name: str, arguments: dict[str, object]) -> dict[str, object]:
    """Build an Anthropic Messages response asking for one tool call.

    Args:
        function_name: Canonical dotted function name.
        arguments: Call arguments.

    Returns:
        dict[str, object]: The response body.
    """
    block = {"type": "tool_use", "id": "toolu_1", "name": to_wire_name(function_name), "input": arguments}
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": _MODEL,
        "content": [block],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }


def _messages_final() -> dict[str, object]:
    """Build an Anthropic Messages response ending the turn.

    Returns:
        dict[str, object]: The response body.
    """
    return {
        "id": "msg_2",
        "type": "message",
        "role": "assistant",
        "model": _MODEL,
        "content": [{"type": "text", "text": "done"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }


def _server_config(*, disabled: frozenset[str] = frozenset(), request_timeout_s: float = 30.0) -> McpServerConfig:
    """Configure the multi-part fixture server.

    Args:
        disabled: Tool names the operator switched off.
        request_timeout_s: Per-call timeout.

    Returns:
        McpServerConfig: An enabled stdio configuration.
    """
    spec = StdioServerSpec(command=sys.executable, args=(str(_SERVER_SCRIPT),))
    return McpServerConfig(
        server_id=_SERVER_ID,
        kind=McpTransportKind.STDIO,
        stdio=spec,
        enabled=True,
        disabled_tools=disabled,
        request_timeout_s=request_timeout_s,
    )


def _approve(_config: object, _rendered: str, _findings: object) -> bool:
    """Approve every launch.

    Args:
        _config: The server being launched.
        _rendered: The rendered launch description.
        _findings: Dangerous patterns found in the command.

    Returns:
        bool: Always ``True``.
    """
    return True


@dataclass
class _Harness:
    """Everything one gate drives.

    Attributes:
        orchestrator: The real orchestrator.
        manager: The real MCP connection manager.
        source: The real MCP tool source.
        endpoint: The scripted LLM endpoint.
        results: Every tool result the orchestrator reported.
    """

    orchestrator: Orchestrator
    manager: McpConnectionManager
    source: McpToolSource
    endpoint: _ScriptedEndpoint
    results: list[ToolResult]


async def _run_harness[T](
    tmp_path: Path,
    dialect: ApiDialect,
    responses: list[dict[str, object]],
    body: Callable[[_Harness], Awaitable[T]],
    *,
    server: McpServerConfig | None = None,
    dynamic_loading: bool = False,
) -> T:
    """Wire the real stack together, run a body, and tear it all down.

    Args:
        tmp_path: Directory backing the stores.
        dialect: Wire format the loopback endpoint speaks.
        responses: Scripted endpoint responses.
        body: Coroutine factory run while everything is up.
        server: The server configuration, defaulting to the fixture server.
        dynamic_loading: Whether the orchestrator loads tools on demand.

    Returns:
        T: Whatever ``body`` produced.
    """
    store = McpConfigStore(tmp_path / "mcp.json")
    store.save(McpConfigDocument(servers=(server or _server_config(),)))
    resolver = McpSecretResolver(CredentialStore())
    manager = McpConnectionManager(store, resolver, McpConsentGate(TrustStore(tmp_path / "trust.json"), _approve))
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(exist_ok=True)
    tool_registry = ToolRegistry(tools_dir=tools_dir)
    source = McpToolSource(manager, tool_registry)

    with _ScriptedEndpoint(responses=list(responses)) as endpoint:
        base = f"{endpoint.origin}/v1" if dialect is ApiDialect.CHAT_COMPLETIONS else endpoint.origin
        instance = ProviderInstance(
            instance_id="loopback",
            dialect=dialect,
            api_base=base,
            requires_api_key=False,
            model_overrides={_MODEL: CapabilityOverride(supports_vision=True, context_window=200_000)},
        )
        provider = ConfigurableProvider(instance)
        await provider.connect(ProviderCredentials())
        providers = ProviderRegistry()
        providers.register(provider)
        orchestrator = Orchestrator(
            provider_registry=providers,
            tool_registry=tool_registry,
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
        await asyncio.wait_for(manager.start(), timeout=_CONNECT_TIMEOUT_S)
        source.register_all()
        _ = await orchestrator.start_session("loopback", _MODEL)
        try:
            return await body(_Harness(orchestrator, manager, source, endpoint, results))
        finally:
            orchestrator.set_mcp_tool_source(None)
            await manager.stop()
            await provider.disconnect()


def _run_turn(
    tmp_path: Path,
    dialect: ApiDialect,
    function_name: str,
    arguments: dict[str, object],
    *,
    server: McpServerConfig | None = None,
) -> tuple[list[ToolResult], list[dict[str, object]]]:
    """Run one agent turn in which the model calls one MCP tool.

    Args:
        tmp_path: Directory backing the stores.
        dialect: Wire format the loopback endpoint speaks.
        function_name: Canonical name the model calls.
        arguments: Arguments the model passes.
        server: The server configuration, defaulting to the fixture server.

    Returns:
        tuple[list[ToolResult], list[dict[str, object]]]: The tool results
        the orchestrator produced and every request body the endpoint saw.
    """
    if dialect is ApiDialect.MESSAGES:
        responses = [_messages_tool_call(function_name, arguments), _messages_final()]
    else:
        responses = [_chat_tool_call(function_name, arguments), _chat_final()]

    async def body(harness: _Harness) -> tuple[list[ToolResult], list[dict[str, object]]]:
        """Drive one turn.

        Args:
            harness: The wired stack.

        Returns:
            tuple[list[ToolResult], list[dict[str, object]]]: Results and bodies.
        """
        await asyncio.wait_for(harness.orchestrator.process_user_input("call the tool"), timeout=_TURN_TIMEOUT_S)
        return list(harness.results), list(harness.endpoint.bodies)

    return asyncio.run(_run_harness(tmp_path, dialect, responses, body, server=server))


def _messages_tool_result_block(bodies: list[dict[str, object]]) -> dict[str, object]:
    """Find the ``tool_result`` block the second Messages request replayed.

    Args:
        bodies: Request bodies the endpoint saw.

    Returns:
        dict[str, object]: The tool-result block.
    """
    assert len(bodies) == 2, "the tool result must have been sent back to the model"
    messages = cast("list[dict[str, object]]", bodies[1]["messages"])
    for message in messages:
        content = message.get("content")
        if isinstance(content, list):
            for block in cast("list[dict[str, object]]", content):
                if block.get("type") == "tool_result":
                    return block
    pytest.fail("no tool_result block was sent")


def _chat_tool_messages(bodies: list[dict[str, object]]) -> list[dict[str, object]]:
    """Find the ``tool`` messages the second Chat Completions request replayed.

    Args:
        bodies: Request bodies the endpoint saw.

    Returns:
        list[dict[str, object]]: The tool messages.
    """
    assert len(bodies) == 2, "the tool result must have been sent back to the model"
    messages = cast("list[dict[str, object]]", bodies[1]["messages"])
    return [message for message in messages if message.get("role") == "tool"]


class TestMultiPartResultsReachTheModel:
    """Blocker 1: a multi-part result serializes through every dialect."""

    def test_chat_completions_turn_carries_every_part(self, tmp_path: Path) -> None:
        """Text, image and structured parts reach a Chat Completions endpoint.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        results, bodies = _run_turn(tmp_path, ApiDialect.CHAT_COMPLETIONS, f"{_NAMESPACE}.snapshot", {})

        assert len(results) == 1
        result = results[0]
        assert result.success is True
        assert result.is_error is False
        assert result.content is not None
        assert any(isinstance(part, ImageResultPart) and part.mime_type == "image/png" for part in result.content)
        assert StructuredResultPart(content={"frame": 1}) in result.content
        assert isinstance(result.result, str)
        tool_messages = _chat_tool_messages(bodies)
        assert len(tool_messages) == 1
        assert "caption: grey frame" in str(tool_messages[0]["content"])
        encoded = json.dumps(bodies[1])
        assert "image/png" in encoded

    def test_messages_turn_sends_the_image_natively(self, tmp_path: Path) -> None:
        """Anthropic Messages receives the image as a native image block.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        results, bodies = _run_turn(tmp_path, ApiDialect.MESSAGES, f"{_NAMESPACE}.snapshot", {})

        assert results[0].success is True
        block = _messages_tool_result_block(bodies)
        assert block.get("is_error") is False
        content = cast("list[dict[str, object]]", block["content"])
        assert any(item.get("type") == "image" for item in content)
        assert any("caption: grey frame" in str(item.get("text", "")) for item in content)

    def test_structured_output_matching_its_schema_is_kept(self, tmp_path: Path) -> None:
        """Structured output that honours its schema arrives as a structured part.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        results, _ = _run_turn(tmp_path, ApiDialect.CHAT_COMPLETIONS, f"{_NAMESPACE}.report", {})

        result = results[0]
        assert result.success is True
        assert result.content is not None
        assert StructuredResultPart(content=dict(STRUCTURED_REPORT)) in result.content


class TestToolErrorsReachTheModel:
    """Blocker 3: an ``isError`` result is an error result, not an aborted turn."""

    def test_error_result_is_flagged_and_complete(self, tmp_path: Path) -> None:
        """The model sees ``is_error`` and every character the tool reported.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        results, bodies = _run_turn(tmp_path, ApiDialect.MESSAGES, f"{_NAMESPACE}.fail", {})

        result = results[0]
        assert result.success is True
        assert result.is_error is True
        assert result.content is not None
        texts = [part.text for part in result.content if isinstance(part, TextResultPart)]
        assert any(ERROR_DETAIL in text for text in texts)
        assert len(ERROR_DETAIL) > _LEGACY_ERROR_CAP
        block = _messages_tool_result_block(bodies)
        assert block.get("is_error") is True
        assert ERROR_DETAIL in json.dumps(block["content"])

    def test_error_without_content_still_explains_itself(self, tmp_path: Path) -> None:
        """An ``isError`` result with no content still tells the model it failed.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        results, bodies = _run_turn(tmp_path, ApiDialect.CHAT_COMPLETIONS, f"{_NAMESPACE}.fail_silently", {})

        result = results[0]
        assert result.is_error is True
        assert result.content
        tool_messages = _chat_tool_messages(bodies)
        assert "reported an error" in str(tool_messages[0]["content"])

    @pytest.mark.parametrize(
        ("function_name", "arguments", "expected"),
        [
            (f"{_NAMESPACE}.strict", {"n": "not a number"}, "must be an integer"),
            (f"{_NAMESPACE}.lie", {}, "Invalid structured content"),
            (f"{_NAMESPACE}.missing_tool", {}, "missing_tool"),
        ],
    )
    def test_call_failures_become_failed_results(
        self,
        tmp_path: Path,
        function_name: str,
        arguments: dict[str, object],
        expected: str,
    ) -> None:
        """Invalid params, a broken output schema and unknown tools fail the call only.

        Args:
            tmp_path: Pytest-provided temporary directory.
            function_name: The tool the model calls.
            arguments: The arguments it passes.
            expected: Text the failure must carry.
        """
        results, bodies = _run_turn(tmp_path, ApiDialect.CHAT_COMPLETIONS, function_name, arguments)

        assert len(results) == 1
        assert results[0].success is False
        assert results[0].error is not None
        assert expected in results[0].error
        assert len(bodies) == 2, "the turn must continue after a failed call"

    def test_disabled_tool_becomes_a_failed_result(self, tmp_path: Path) -> None:
        """Calling a tool the operator switched off fails the call, not the turn.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        server = _server_config(disabled=frozenset({"fail"}))
        results, bodies = _run_turn(tmp_path, ApiDialect.CHAT_COMPLETIONS, f"{_NAMESPACE}.fail", {}, server=server)

        assert results[0].success is False
        assert results[0].error is not None
        assert "switched off" in results[0].error
        assert len(bodies) == 2

    def test_malformed_wire_name_becomes_a_failed_result(self, tmp_path: Path) -> None:
        """A wire name with no tool component fails the call without crashing.

        This is item 29: ``mcp-mp__`` reverses to ``mcp-mp.``, which
        :func:`from_canonical_name` rejects with ``McpConfigError``.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        results, bodies = _run_turn(tmp_path, ApiDialect.CHAT_COMPLETIONS, f"{_NAMESPACE}.", {})

        assert results[0].success is False
        assert results[0].error is not None
        assert "not a canonical MCP tool name" in results[0].error
        assert len(bodies) == 2

    def test_stopped_server_becomes_a_failed_result(self, tmp_path: Path) -> None:
        """A call to a server that went down fails the call, not the turn.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """

        async def body(harness: _Harness) -> list[ToolResult]:
            """Stop the server, then run a turn that calls it.

            Args:
                harness: The wired stack.

            Returns:
                list[ToolResult]: The tool results.
            """
            await harness.manager.stop_server(_SERVER_ID)
            await asyncio.wait_for(harness.orchestrator.process_user_input("call it"), timeout=_TURN_TIMEOUT_S)
            return list(harness.results)

        responses = [_chat_tool_call(f"{_NAMESPACE}.snapshot", {}), _chat_final()]
        results = asyncio.run(_run_harness(tmp_path, ApiDialect.CHAT_COMPLETIONS, responses, body))

        assert results[0].success is False
        assert results[0].error is not None
        assert "not running" in results[0].error

    def test_timed_out_call_becomes_a_failed_result(self, tmp_path: Path) -> None:
        """A call that exceeds the per-call timeout fails the call, not the turn.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        server = _server_config(request_timeout_s=1.0)
        results, bodies = _run_turn(tmp_path, ApiDialect.CHAT_COMPLETIONS, f"{_NAMESPACE}.stall", {}, server=server)

        assert results[0].success is False
        assert results[0].error is not None
        assert "exceeded" in results[0].error
        assert len(bodies) == 2

    def test_routed_server_mismatch_is_refused(self, tmp_path: Path) -> None:
        """A call routed through one namespace cannot run another server's tool.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """

        async def body(harness: _Harness) -> str:
            """Dispatch a call whose name disagrees with its route.

            Args:
                harness: The wired stack.

            Returns:
                str: The refusal message.
            """
            with pytest.raises(ToolError) as caught:
                _ = await harness.source.execute("mcp-other.snapshot", {}, routed_server_id=_SERVER_ID)
            return str(caught.value)

        message = asyncio.run(_run_harness(tmp_path, ApiDialect.CHAT_COMPLETIONS, [], body))
        assert "was routed to MCP server 'mp'" in message


class TestUntrustedTextIsFenced:
    """Item 28: server text reaches the model fenced and stripped of controls."""

    def test_result_text_is_fenced_and_stripped(self, tmp_path: Path) -> None:
        """A result carrying escapes arrives fenced with the controls removed.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        results, bodies = _run_turn(tmp_path, ApiDialect.CHAT_COMPLETIONS, f"{_NAMESPACE}.controls", {})

        assert results[0].content is not None
        text = next(part.text for part in results[0].content if isinstance(part, TextResultPart))
        assert text.startswith(UNTRUSTED_BLOCK_START)
        assert text.endswith(UNTRUSTED_BLOCK_END)
        for control in ("\x1b", "\x07", "\u202e"):
            assert control not in text
        assert "cleanredbellevil" in text.replace("[31m", "")
        sent = str(_chat_tool_messages(bodies)[0]["content"])
        assert UNTRUSTED_BLOCK_START in sent
        assert "\x1b" not in sent

    def test_descriptions_are_fenced_everywhere_the_model_reads_them(self, tmp_path: Path) -> None:
        """Server descriptions are fenced in provider tool definitions and the prompt.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        _, bodies = _run_turn(tmp_path, ApiDialect.CHAT_COMPLETIONS, f"{_NAMESPACE}.snapshot", {})

        tools = cast("list[dict[str, object]]", bodies[0]["tools"])
        descriptions = {
            cast("dict[str, object]", tool["function"])["name"]: str(cast("dict[str, object]", tool["function"])["description"])
            for tool in tools
        }
        controls = descriptions[to_wire_name(f"{_NAMESPACE}.controls")]
        assert UNTRUSTED_BLOCK_START in controls
        assert UNTRUSTED_BLOCK_END in controls
        assert "\x1b" not in controls
        assert "\u202e" not in controls
        system = json.dumps(bodies[0]["messages"])
        assert CONTROL_TEXT not in system
        assert "Description with" not in system or UNTRUSTED_BLOCK_START in system

    def test_tools_search_returns_fenced_descriptions(self, tmp_path: Path) -> None:
        """``tools.search`` hands the model fenced server descriptions.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """

        async def body(harness: _Harness) -> list[ToolResult]:
            """Run a turn whose only call is a search.

            Args:
                harness: The wired stack.

            Returns:
                list[ToolResult]: The tool results.
            """
            await asyncio.wait_for(harness.orchestrator.process_user_input("find it"), timeout=_TURN_TIMEOUT_S)
            return list(harness.results)

        responses = [_chat_tool_call("tools.search", {"query": "Description with"}), _chat_final()]
        results = asyncio.run(_run_harness(tmp_path, ApiDialect.CHAT_COMPLETIONS, responses, body, dynamic_loading=True))

        payload = cast("dict[str, list[dict[str, str]]]", results[0].result)
        matched = [match for match in payload["matches"] if match["name"] == f"{_NAMESPACE}.controls"]
        assert matched
        assert matched[0]["description"].count(UNTRUSTED_BLOCK_START) == 1
        assert "\x1b" not in matched[0]["description"]


class TestMalformedNamesDoNotCrashClassification:
    """Item 29: a malformed MCP name is classified, never raised."""

    def test_classification_and_lookups_survive_a_bare_namespace(self, tmp_path: Path) -> None:
        """Classifying ``mcp-mp.`` answers destructive; lookups answer nothing.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """

        async def body(harness: _Harness) -> tuple[str, str | None, bool]:
            """Classify and look up a malformed name.

            Args:
                harness: The wired stack.

            Returns:
                tuple[str, str | None, bool]: The classification, the
                generation lookup and the read-only lookup.
            """
            await asyncio.sleep(0)
            call = parse_tool_call(call_id="c", function_name=f"{_NAMESPACE}__", raw_arguments="{}")
            return (
                classify_tool_call(call),
                harness.source.generation_for(call.function_name),
                harness.source.is_read_only(call.function_name),
            )

        classification, generation, read_only = asyncio.run(_run_harness(tmp_path, ApiDialect.CHAT_COMPLETIONS, [], body))
        assert classification == "destructive"
        assert generation is None
        assert read_only is False


class TestSchemaArgumentsAreAdvertised:
    """Item 33: an MCP tool's arguments appear in its signature and the prompt."""

    def test_signature_and_prompt_render_schema_arguments(self, tmp_path: Path) -> None:
        """``strict`` is advertised as taking ``n: integer``, not nothing.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        _, bodies = _run_turn(tmp_path, ApiDialect.CHAT_COMPLETIONS, f"{_NAMESPACE}.snapshot", {})

        system = str(cast("list[dict[str, object]]", bodies[0]["messages"])[0]["content"])
        assert f"`{_NAMESPACE}.strict(n: integer) ->" in system


class TestMcpHistoryPersists:
    """Blocker 2: a session holding real MCP results saves and reloads."""

    def test_session_with_mcp_results_round_trips(self, tmp_path: Path) -> None:
        """The image, structured and error parts survive a save and a load.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """

        async def body(harness: _Harness) -> Session:
            """Run two MCP turns and return the live session.

            Args:
                harness: The wired stack.

            Returns:
                Session: The session holding both turns.
            """
            await asyncio.wait_for(harness.orchestrator.process_user_input("snap"), timeout=_TURN_TIMEOUT_S)
            await asyncio.wait_for(harness.orchestrator.process_user_input("fail"), timeout=_TURN_TIMEOUT_S)
            session = harness.orchestrator.current_session
            assert session is not None
            return session

        responses = [
            _chat_tool_call(f"{_NAMESPACE}.snapshot", {}),
            _chat_final(),
            _chat_tool_call(f"{_NAMESPACE}.fail", {}),
            _chat_final(),
        ]
        session = asyncio.run(_run_harness(tmp_path, ApiDialect.CHAT_COMPLETIONS, responses, body))
        store = SessionStore(db_path=tmp_path / "persisted.db")
        store.save(session)
        loaded = store.load(session.id)

        assert loaded is not None
        original = [result for message in session.messages for result in message.tool_results or ()]
        restored = [result for message in loaded.messages for result in message.tool_results or ()]
        assert len(original) == 2
        assert [result.content for result in restored] == [result.content for result in original]
        assert [result.is_error for result in restored] == [False, True]


class TestLargeResultsAreBounded:
    """Item 35: multi-part content is bounded before it reaches the model."""

    def test_long_text_part_is_cut_in_the_request(self, tmp_path: Path) -> None:
        """A 50,000-character result reaches the endpoint cut to the bound.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        results, bodies = _run_turn(tmp_path, ApiDialect.CHAT_COMPLETIONS, f"{_NAMESPACE}.big", {})

        assert results[0].content is not None
        stored = "".join(part.text for part in results[0].content if isinstance(part, TextResultPart))
        assert stored.count("z") == BIG_TEXT_CHARS
        sent = str(_chat_tool_messages(bodies)[0]["content"])
        assert sent.count("z") < 9000
        assert "truncated" in sent


class TestBareLeafNamesResolve:
    """Item 46: a model answering with a loaded tool's bare leaf name is served."""

    def test_bare_leaf_dispatches_to_the_loaded_tool(self, tmp_path: Path) -> None:
        """``snapshot`` resolves to the loaded ``mcp-mp.snapshot``.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """

        async def body(harness: _Harness) -> list[ToolResult]:
            """Load the tool, then run a turn that calls it by its leaf.

            Args:
                harness: The wired stack.

            Returns:
                list[ToolResult]: The tool results.
            """
            session = harness.orchestrator.current_session
            assert session is not None
            assert session.add_loaded_tool(f"{_NAMESPACE}.snapshot")
            await asyncio.wait_for(harness.orchestrator.process_user_input("snap"), timeout=_TURN_TIMEOUT_S)
            return list(harness.results)

        responses = [_chat_tool_call("snapshot", {}), _chat_final()]
        results = asyncio.run(_run_harness(tmp_path, ApiDialect.CHAT_COMPLETIONS, responses, body, dynamic_loading=True))

        assert results[0].success is True
        assert results[0].content is not None
        assert any(isinstance(part, ImageResultPart) for part in results[0].content)
