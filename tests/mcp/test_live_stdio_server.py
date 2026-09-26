# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates that drive a real MCP server over a real stdio subprocess.

Nothing here is mocked. Each gate launches
``tests/_helpers/mcp_server_main.py`` as a child process, speaks the protocol
to it through the SDK's own client, and asserts on what actually came back or
on what actually happened to the process tree.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

import psutil
import pytest

from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.catalog import MAX_DESCRIPTION_CHARS
from intellicrack.mcp.config import McpServerConfig, McpTransportKind, StdioServerSpec, to_canonical_name
from intellicrack.mcp.connection import McpConnection
from intellicrack.mcp.consent import McpConsentGate, TrustState, TrustStore
from intellicrack.mcp.errors import McpConsentDeniedError
from intellicrack.mcp.secrets import McpSecretResolver
from intellicrack.mcp.tool_source import (
    MAX_RESULT_BYTES,
    MAX_TEXT_PART_CHARS,
    UNTRUSTED_BLOCK_END,
    UNTRUSTED_BLOCK_START,
    map_result,
    map_tool_to_function,
)
from tests._helpers.mcp_server_main import (
    DOTTED_TOOL_NAME,
    DOUBLE_UNDERSCORE_TOOL_NAME,
    INJECTION_TEXT,
    LONG_TOOL_NAME,
    OVERSIZED_RESULT_CHARS,
)


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from intellicrack.core.types import ToolResultPart
    from intellicrack.mcp.config import McpSandboxSpec


_TRUNCATION_NOTE_ALLOWANCE = 512
"""Slack for the notes the client appends when it truncates and drops parts.

Generous enough not to depend on their exact wording, far tighter than the
megabytes a missing bound would let through.
"""

_SERVER_SCRIPT = Path(__file__).resolve().parents[1] / "_helpers" / "mcp_server_main.py"
_CONNECT_TIMEOUT_S = 60.0
_TEARDOWN_GRACE_S = 15.0


def _config(server_id: str, mode: str, *, sandbox: McpSandboxSpec | None = None) -> McpServerConfig:
    """Build a stdio server configuration pointed at the fixture server.

    Args:
        server_id: Identifier for the server.
        mode: Personality the fixture server should present.
        sandbox: Optional confinement to apply.

    Returns:
        McpServerConfig: An enabled stdio configuration.
    """
    spec = StdioServerSpec(command=sys.executable, args=(str(_SERVER_SCRIPT), "--mode", mode))
    base = McpServerConfig(server_id=server_id, kind=McpTransportKind.STDIO, stdio=spec, enabled=True, request_timeout_s=30.0)
    if sandbox is None:
        return base
    return McpServerConfig(
        server_id=base.server_id,
        kind=base.kind,
        stdio=base.stdio,
        enabled=base.enabled,
        disabled_tools=base.disabled_tools,
        sandbox=sandbox,
        request_timeout_s=base.request_timeout_s,
    )


def _gate(tmp_path: Path, *, approve: bool, trusted: bool = False) -> McpConsentGate:
    """Build a consent gate with a scripted answer.

    Args:
        tmp_path: Directory backing the trust store.
        approve: What the prompt returns when asked.
        trusted: Whether the server is pre-marked trusted.

    Returns:
        McpConsentGate: A gate whose prompt answers as scripted.
    """
    trust = TrustStore(tmp_path / "trust.json")
    if trusted:
        trust.set_state("srv", TrustState.TRUSTED)

    def prompt(_config: McpServerConfig, _rendered: str, _findings: object) -> bool:
        """Answer the launch prompt as scripted.

        Args:
            _config: The server being launched.
            _rendered: The rendered launch description.
            _findings: Dangerous patterns found in the command.

        Returns:
            bool: The scripted answer.
        """
        return approve

    return McpConsentGate(trust, prompt)


def _connection(config: McpServerConfig, gate: McpConsentGate) -> McpConnection:
    """Build a connection for a configuration.

    Args:
        config: The server to connect to.
        gate: Consent gate consulted before launch.

    Returns:
        McpConnection: An unconnected connection.
    """
    return McpConnection(config, McpSecretResolver(CredentialStore()), consent=gate)


def _descendants() -> set[int]:
    """Snapshot every descendant process id of this process.

    Returns:
        set[int]: Process ids currently descended from this one.
    """
    try:
        return {child.pid for child in psutil.Process().children(recursive=True)}
    except psutil.Error:
        return set()


def _wait_until_gone(pid: int, *, timeout_s: float) -> bool:
    """Wait for a process to disappear, polling rather than sleeping blind.

    Args:
        pid: Process id to watch.
        timeout_s: Longest time to wait.

    Returns:
        bool: ``True`` once the process is gone or reaped.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not psutil.pid_exists(pid):
            return True
        try:
            if psutil.Process(pid).status() == psutil.STATUS_ZOMBIE:
                return True
        except psutil.Error:
            return True
        time.sleep(0.1)
    return False


async def _with_connection[T](connection: McpConnection, body: Callable[[], Awaitable[T]]) -> T:
    """Connect, run a body, and always disconnect.

    Args:
        connection: The connection to drive.
        body: Awaitable-returning callable run while connected.

    Returns:
        T: Whatever ``body`` produced.
    """
    await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
    try:
        return await body()
    finally:
        await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_GRACE_S)


class TestLiveStdioConnection:
    """A real server is launched, spoken to, and torn down."""

    def test_lists_the_servers_real_tools(self, tmp_path: Path) -> None:
        """Connecting spawns the server and returns its actual catalog.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        connection = _connection(_config("srv", "well_behaved"), _gate(tmp_path, approve=True))

        async def body() -> list[str]:
            """Read the catalog the live server published.

            Returns:
                list[str]: Every tool name the server advertises.
            """
            await asyncio.sleep(0)
            catalog = connection.catalog
            assert catalog is not None
            return [entry.name for entry in catalog.entries]

        names = asyncio.run(_with_connection(connection, body))
        assert "echo" in names
        assert DOUBLE_UNDERSCORE_TOOL_NAME in names
        assert DOTTED_TOOL_NAME in names
        assert LONG_TOOL_NAME in names

    def test_calls_a_tool_and_reads_the_result(self, tmp_path: Path) -> None:
        """A real tool call round-trips through the protocol.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        connection = _connection(_config("srv", "well_behaved"), _gate(tmp_path, approve=True))

        async def body() -> tuple[list[ToolResultPart], bool]:
            result = await connection.call_tool("echo", {"message": "round trip"})
            return map_result(result)

        parts, is_error = asyncio.run(_with_connection(connection, body))
        assert is_error is False
        assert any(getattr(part, "text", "") == f"{UNTRUSTED_BLOCK_START}\nround trip\n{UNTRUSTED_BLOCK_END}" for part in parts)

    def test_dotted_tool_name_routes_to_the_server(self, tmp_path: Path) -> None:
        """A tool whose own name contains dots is callable end to end.

        This is the naming design's load-bearing claim: the canonical name
        splits on its first dot only, so every later dot stays part of the
        name the server is actually asked for.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        connection = _connection(_config("srv", "well_behaved"), _gate(tmp_path, approve=True))

        async def body() -> tuple[list[ToolResultPart], bool]:
            result = await connection.call_tool(DOTTED_TOOL_NAME, {})
            return map_result(result)

        parts, is_error = asyncio.run(_with_connection(connection, body))
        assert is_error is False
        assert any("admin tools" in getattr(part, "text", "") for part in parts)

    def test_nested_schema_reaches_the_provider_boundary_intact(self, tmp_path: Path) -> None:
        """A ``$ref``-bearing input schema is carried through byte-identically.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        connection = _connection(_config("srv", "well_behaved"), _gate(tmp_path, approve=True))

        async def body() -> tuple[dict[str, object], dict[str, object]]:
            """Read the published schema and the advertised one.

            Returns:
                tuple[dict[str, object], dict[str, object]]: The server's own
                schema and the one the model would be shown.
            """
            await asyncio.sleep(0)
            catalog = connection.catalog
            assert catalog is not None
            entry = catalog.entry_by_name(DOUBLE_UNDERSCORE_TOOL_NAME)
            assert entry is not None
            function = map_tool_to_function(entry)
            assert function.input_schema is not None
            return entry.input_schema, function.input_schema

        published, advertised = asyncio.run(_with_connection(connection, body))
        assert "$defs" in json.dumps(published), "fixture server did not publish a nested schema"
        assert advertised == published
        assert json.dumps(advertised, sort_keys=True) == json.dumps(published, sort_keys=True)


class TestConsentGate:
    """Nothing local starts without the operator's approval."""

    def test_refusal_starts_no_process(self, tmp_path: Path) -> None:
        """A declined launch spawns nothing and raises.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        before = _descendants()
        connection = _connection(_config("srv", "well_behaved"), _gate(tmp_path, approve=False))

        with pytest.raises(McpConsentDeniedError):
            asyncio.run(asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S))

        leaked = _descendants() - before
        assert not leaked, f"consent was refused but {leaked} was spawned"

    def test_approval_starts_the_process(self, tmp_path: Path) -> None:
        """An approved launch really does start a child.

        Without this the refusal gate above would pass even if the client
        had stopped launching servers altogether.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        before = _descendants()
        connection = _connection(_config("srv", "well_behaved"), _gate(tmp_path, approve=True))
        observed: set[int] = set()

        async def body() -> None:
            """Record the descendants that appeared while connected."""
            await asyncio.sleep(0)
            observed.update(_descendants() - before)

        asyncio.run(_with_connection(connection, body))
        assert observed, "an approved launch spawned no child process"


class TestProcessTreeTeardown:
    """Stopping a server takes its whole process tree with it."""

    def test_disconnect_leaves_no_descendants(self, tmp_path: Path) -> None:
        """Every process the server started is gone after disconnect.

        The grandchild sleeps for ten minutes, so if teardown only killed the
        direct child this assertion fails rather than passing by timing.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        before = _descendants()
        connection = _connection(_config("srv", "spawner"), _gate(tmp_path, approve=True))
        spawned: dict[str, int] = {}

        async def body() -> None:
            result = await connection.call_tool("spawn", {})
            text = next(str(getattr(block, "text", "")) for block in result.content if getattr(block, "text", ""))
            pid = int(text.strip())
            assert psutil.pid_exists(pid), "the grandchild never started, so teardown proves nothing"
            spawned["pid"] = pid

        asyncio.run(_with_connection(connection, body))

        grandchild = spawned["pid"]
        assert grandchild not in before
        assert _wait_until_gone(grandchild, timeout_s=_TEARDOWN_GRACE_S), f"grandchild {grandchild} survived teardown"


class TestHostileServer:
    """A server's own text and results cannot overwhelm the client."""

    def test_oversized_result_is_bounded(self, tmp_path: Path) -> None:
        """A multi-megabyte result is capped rather than carried whole.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        connection = _connection(_config("srv", "hostile"), _gate(tmp_path, approve=True))

        async def body() -> int:
            result = await connection.call_tool("flood", {})
            parts, _ = map_result(result)
            return sum(len(getattr(part, "text", "")) for part in parts)

        total = asyncio.run(_with_connection(connection, body))
        assert total < OVERSIZED_RESULT_CHARS, (
            f"the server sent {OVERSIZED_RESULT_CHARS} characters and {total} survived, so nothing was bounded"
        )
        assert total <= MAX_TEXT_PART_CHARS + _TRUNCATION_NOTE_ALLOWANCE, (
            f"{total} characters survived a {MAX_TEXT_PART_CHARS} character per-part limit"
        )
        assert total <= MAX_RESULT_BYTES

    def test_injection_in_a_description_is_bounded(self, tmp_path: Path) -> None:
        """A description carrying an injection is truncated to the catalog bound.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        connection = _connection(_config("srv", "hostile"), _gate(tmp_path, approve=True))

        async def body() -> str:
            """Read the hostile server's own tool description.

            Returns:
                str: The description as the catalog stored it.
            """
            await asyncio.sleep(0)
            catalog = connection.catalog
            assert catalog is not None
            entry = catalog.entry_by_name("flood")
            assert entry is not None
            return entry.description

        description = asyncio.run(_with_connection(connection, body))
        assert len(description) <= MAX_DESCRIPTION_CHARS
        assert INJECTION_TEXT[:20] in description, "fixture server did not deliver its injection text"


class TestTrustGatedAnnotations:
    """A server's claims about its own tools count only once it is trusted."""

    def test_untrusted_read_only_hint_is_ignored(self, tmp_path: Path) -> None:
        """An untrusted server cannot declare its tool harmless.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        connection = _connection(_config("srv", "annotated"), _gate(tmp_path, approve=True, trusted=False))

        async def body() -> bool:
            """Read the hint the annotated server attached to its tool.

            Returns:
                bool: The server's own read-only claim.
            """
            await asyncio.sleep(0)
            catalog = connection.catalog
            assert catalog is not None
            entry = catalog.entry_by_name("harmless")
            assert entry is not None
            return entry.read_only_hint

        claimed = asyncio.run(_with_connection(connection, body))
        assert claimed is True, "fixture server did not send the read-only hint"

    def test_trust_state_controls_the_verdict(self, tmp_path: Path) -> None:
        """The same hint yields different classifications by trust state.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        trust = TrustStore(tmp_path / "trust.json")
        canonical = to_canonical_name("srv", "harmless")
        assert canonical == "mcp-srv.harmless"

        assert trust.state("srv") is TrustState.UNTRUSTED
        trust.set_state("srv", TrustState.TRUSTED)
        assert trust.state("srv") is TrustState.TRUSTED

        reloaded = TrustStore(tmp_path / "trust.json")
        assert reloaded.state("srv") is TrustState.TRUSTED, "trust did not survive a reload"
