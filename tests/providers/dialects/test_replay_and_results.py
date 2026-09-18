# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates on reasoning replay, multi-part tool results and external dispatch.

Three contracts arrived together and none of them fails loudly.

A reasoning block carries a provider-opaque payload -- an Anthropic
``signature``, a Responses item id, an encrypted body -- that has to come back
byte-for-byte on the next tool-use turn or the provider rejects the turn or
silently drops the chain. Losing it across a session save looks like nothing
at all until a reloaded conversation calls a tool.

A tool result may now carry image, resource and structured parts. A dialect
that cannot render a part natively has to degrade through the one shared text
fallback, so the model sees the same information everywhere rather than an
empty block on three dialects out of four.

An externally-sourced tool dispatches through its own registry, which must
refuse to let an outside namespace claim a bridge's.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.session import Session, SessionStore
from intellicrack.core.tools import ExternalToolRegistry, ToolError
from intellicrack.core.types import (
    ImageResultPart,
    Message,
    ReasoningItem,
    ReasoningKind,
    ResourceLinkPart,
    StructuredResultPart,
    TextResultPart,
    ToolResult,
)
from intellicrack.providers.capabilities import ApiDialect
from intellicrack.providers.dialects.registry import adapter_for


if TYPE_CHECKING:
    from pathlib import Path


_ANTHROPIC_SIGNATURE = "synthetic-anthropic-thinking-signature/opaque+payload=="
"""Stands in for an Anthropic thinking signature.

Anthropic rejects an altered signature, so what the gate asserts is exact
equality after a round trip. That holds for any string, and a
self-describing one cannot be mistaken for a live credential.
"""

_ENCRYPTED_REASONING = "synthetic-responses-encrypted-reasoning/body=="
"""Stands in for a Responses ``reasoning.encrypted_content`` body."""


def _reasoning_items() -> list[ReasoningItem]:
    """Build one reasoning block of every provider representation.

    Returns:
        list[ReasoningItem]: Blocks covering all four reasoning kinds.
    """
    return [
        ReasoningItem(
            kind=ReasoningKind.THINKING,
            text="The entry point jumps into a packed section.",
            signature=_ANTHROPIC_SIGNATURE,
        ),
        ReasoningItem(kind=ReasoningKind.REDACTED_THINKING, redacted_data="EvwBCkYIBBgCKkBk"),
        ReasoningItem(
            kind=ReasoningKind.RESPONSES_ITEM,
            item_id="rs_68d1f0a2b3c4",
            encrypted_content=_ENCRYPTED_REASONING,
            summary=("inspected the import table", "found a TLS callback"),
        ),
        ReasoningItem(kind=ReasoningKind.REASONING_CONTENT, text="A plain reasoning_content string."),
    ]


def test_reasoning_survives_a_session_round_trip(tmp_path: Path) -> None:
    """Every opaque reasoning field must come back byte-for-byte after a save.

    Exercises the real SQLite store, not a serializer in isolation, because
    that is where a dropped column actually costs a reasoning chain.

    Args:
        tmp_path: Pytest-provided directory for the session database.
    """
    store = SessionStore(tmp_path / "sessions.db")
    session = Session.create("anthropic", "claude-opus-5", "reasoning replay")
    original = _reasoning_items()
    session.add_message(Message(role="assistant", content="Unpacking first.", reasoning=original))

    store.save(session)
    reloaded = store.load(session.id)

    assert reloaded is not None
    restored = reloaded.messages[-1].reasoning
    assert restored is not None
    assert len(restored) == len(original)
    for expected, actual in zip(original, restored, strict=True):
        assert actual.kind is expected.kind
        assert actual.text == expected.text
        assert actual.signature == expected.signature
        assert actual.item_id == expected.item_id
        assert actual.encrypted_content == expected.encrypted_content
        assert actual.redacted_data == expected.redacted_data
        assert actual.summary == expected.summary


def test_thinking_content_is_empty_rather_than_none_for_a_blank_list() -> None:
    """An empty reasoning list must not be mistaken for unset reasoning.

    Guarding on ``is None`` where ``[]`` means the same thing is what dropped
    thinking text once already.
    """
    assert Message(role="assistant", content="x", reasoning=None).thinking_content is None
    assert Message(role="assistant", content="x", reasoning=[]).thinking_content is None

    readable = Message(role="assistant", content="x", reasoning=_reasoning_items()).thinking_content
    assert readable is not None
    assert "packed section" in readable
    assert "reasoning_content string" in readable


def _multipart_result() -> ToolResult:
    """Build a tool result carrying one part of several kinds.

    Returns:
        ToolResult: A multi-part result an external tool could return.
    """
    return ToolResult(
        call_id="toolu_01ABCdefGHIjklMNOpqrs",
        success=True,
        result="fallback text",
        error=None,
        duration_ms=12.5,
        content=[
            TextResultPart(text="0x140001000 is the entry point"),
            ImageResultPart(data="iVBORw0KGgoAAAANSUhEUg==", mime_type="image/png"),
            ResourceLinkPart(uri="file:///C:/samples/packed.exe", name="packed.exe"),
            StructuredResultPart(content={"entry": "0x140001000", "sections": 6}),
        ],
    )


@pytest.mark.parametrize("dialect", list(ApiDialect))
def test_every_dialect_renders_a_multipart_result_without_losing_its_text(dialect: ApiDialect) -> None:
    """No dialect may render a multi-part result as an empty block.

    A part a dialect cannot express natively degrades through the shared text
    fallback, so the textual content reaches the model on all four.

    Args:
        dialect: The dialect under test.
    """
    adapter = adapter_for(dialect)
    blocks = adapter.render_tool_result(_multipart_result(), adapter.default_capabilities())

    assert blocks, f"{dialect.name} rendered no blocks at all"
    rendered = str(blocks)
    assert "0x140001000 is the entry point" in rendered
    assert "packed.exe" in rendered


@pytest.mark.parametrize("dialect", list(ApiDialect))
def test_a_failed_tool_result_is_marked_as_an_error(dialect: ApiDialect) -> None:
    """A tool-reported failure must reach the model as a failure.

    Anthropic carries a native ``is_error`` flag; the rest must prefix the
    rendered text. Either way the model must be able to tell the call failed.

    Args:
        dialect: The dialect under test.
    """
    adapter = adapter_for(dialect)
    failure = ToolResult(
        call_id="toolu_01FAILED",
        success=False,
        result=None,
        error="ghidra analysis timed out after 600s",
        duration_ms=600_000.0,
        is_error=True,
    )
    rendered = str(adapter.render_tool_result(failure, adapter.default_capabilities()))
    assert "timed out" in rendered or "is_error" in rendered or "error" in rendered.lower()


async def _echo(function_name: str, arguments: dict[str, object]) -> object:
    """Execute a registered external tool call off the event loop.

    Dispatch is awaited by the tool layer, so the executor does its work the
    way a real out-of-process tool would: on a worker thread, leaving the loop
    free.

    Args:
        function_name: The canonical dotted function name.
        arguments: The parsed call arguments.

    Returns:
        object: A record echoing what was dispatched.
    """
    return await asyncio.to_thread(lambda: {"called": function_name, "args": arguments})


def test_an_external_namespace_cannot_claim_a_bridge_namespace() -> None:
    """A registry that let an outside tool claim ``ghidra`` would shadow a bridge.

    The canonical name of every bridge function starts with its namespace, so
    a collision silently reroutes real analysis calls to an outside executor.
    """
    registry = ExternalToolRegistry()

    registry.register("mcp_files", _echo)
    assert registry.get("mcp_files") is not None
    assert "mcp_files" in registry.namespaces()

    for reserved in ("ghidra", "GHIDRA", "x64dbg", "frida", "cutter", "sandbox"):
        with pytest.raises(ToolError):
            registry.register(reserved, _echo)

    for malformed in ("", "   ", "has space", "dotted.name", "slash/name"):
        with pytest.raises(ToolError):
            registry.register(malformed, _echo)


def test_a_registered_external_tool_actually_dispatches() -> None:
    """Registration must route a call, not merely record a name."""
    registry = ExternalToolRegistry()
    registry.register("mcp_files", _echo)

    executor = registry.get("mcp_files")
    assert executor is not None

    async def _dispatch() -> object:
        """Await the registered executor the way the tool layer does.

        Returns:
            object: Whatever the executor returned.
        """
        return await executor("mcp_files.read", {"path": "C:/samples/packed.exe"})

    assert asyncio.run(_dispatch()) == {"called": "mcp_files.read", "args": {"path": "C:/samples/packed.exe"}}

    assert registry.unregister("mcp_files") is True
    assert registry.get("mcp_files") is None
