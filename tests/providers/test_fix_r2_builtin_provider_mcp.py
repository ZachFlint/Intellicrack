# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 15: every provider sends a tool's images natively and says when the tool reported an error.

Each gate runs a whole agent turn: a real MCP server over stdio, the real tool source, the real orchestrator, and a real provider writing
a real request body to a loopback endpoint that asks for one tool call and then ends the turn. The built-in OpenAI chat, Grok, OpenRouter
and Ollama providers are driven as themselves, and the Responses and Gemini dialects through the configurable provider. The
second request, which replays the tool's result, must carry the images a vision model can take as native image parts -- never as a text
placeholder -- and must mark a result the tool reported as an error.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.providers.capabilities import ApiDialect
from intellicrack.providers.grok import GrokProvider
from intellicrack.providers.ollama import OllamaProvider
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.openrouter import OpenRouterProvider
from tests._helpers.mcp_agent_harness import (
    DIALECT_SCRIPTS,
    OLLAMA_SCRIPT,
    BuiltinProvider,
    run_tool_turn,
    stdio_server,
    tool_result_payload,
)
from tests._helpers.mcp_hostile_server import SOFT_ERROR_TEXT


if TYPE_CHECKING:
    from intellicrack.mcp.config import McpServerConfig


_HOSTILE: Final[Path] = Path(__file__).resolve().parents[1] / "_helpers" / "mcp_hostile_server.py"
_NAMESPACE: Final[str] = "mcp-hostile"
_ACCEPTED_IMAGES: Final[int] = 2
"""The ``images`` tool returns a PNG and a JPEG labelled as a PNG that every endpoint here takes; its BMP, its text file and its broken
image are described instead."""

_CHAT: Final = DIALECT_SCRIPTS[ApiDialect.CHAT_COMPLETIONS]

_BUILTINS: Final[dict[str, BuiltinProvider]] = {
    "openai": BuiltinProvider(OpenAIProvider, _CHAT),
    "grok": BuiltinProvider(GrokProvider, _CHAT),
    "openrouter": BuiltinProvider(OpenRouterProvider, _CHAT),
    "ollama": BuiltinProvider(OllamaProvider, OLLAMA_SCRIPT),
}


def _server() -> McpServerConfig:
    """Configure the hostile server.

    Returns:
        McpServerConfig: The configuration.
    """
    return stdio_server("hostile", _HOSTILE)


def _replayed_messages(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Take the messages from the tool message on, in a chat-shaped request.

    Args:
        body: The second request body.

    Returns:
        list[dict[str, Any]]: The tool message and everything after it.
    """
    messages: list[dict[str, Any]] = body["messages"]
    first = next(index for index, message in enumerate(messages) if message.get("role") == "tool")
    return messages[first:]


@pytest.mark.parametrize("name", list(_BUILTINS))
def test_builtin_provider_sends_images_natively(tmp_path: Path, name: str) -> None:
    """A vision model receives the images the tool returned as native image parts, and those it cannot take described with the reason.

    Args:
        tmp_path: Per-test directory.
        name: The built-in provider.
    """
    builtin = _BUILTINS[name]
    _, bodies = run_tool_turn(tmp_path, ApiDialect.CHAT_COMPLETIONS, _server(), f"{_NAMESPACE}.images", {}, builtin=builtin)

    tool, carrier = _replayed_messages(bodies[1])[:2]
    assert tool["role"] == "tool"
    assert "image/bmp" in tool["content"]
    assert carrier["role"] == "user"
    if builtin.script is OLLAMA_SCRIPT:
        assert len(carrier["images"]) == _ACCEPTED_IMAGES
        assert all(isinstance(image, str) and image for image in carrier["images"])
    else:
        urls = [part["image_url"]["url"] for part in carrier["content"] if part.get("type") == "image_url"]
        assert [url.split(";", 1)[0] for url in urls] == ["data:image/png", "data:image/jpeg"]


@pytest.mark.parametrize("name", list(_BUILTINS))
def test_builtin_provider_marks_a_reported_error(tmp_path: Path, name: str) -> None:
    """A result the tool marked as an error reaches the model marked as one.

    Args:
        tmp_path: Per-test directory.
        name: The built-in provider.
    """
    _, bodies = run_tool_turn(tmp_path, ApiDialect.CHAT_COMPLETIONS, _server(), f"{_NAMESPACE}.soft_error", {}, builtin=_BUILTINS[name])

    [tool] = [message for message in _replayed_messages(bodies[1]) if message["role"] == "tool"]
    assert tool["content"].startswith("[tool reported an error]\n")
    assert SOFT_ERROR_TEXT in tool["content"]


@pytest.mark.parametrize("dialect", [ApiDialect.RESPONSES, ApiDialect.GEMINI], ids=["responses", "gemini"])
def test_dialect_sends_images_natively_and_marks_errors(tmp_path: Path, dialect: ApiDialect) -> None:
    """The Responses and Gemini dialects carry the tool's images natively and mark a reported error.

    Args:
        tmp_path: Per-test directory.
        dialect: The dialect.
    """
    _, image_bodies = run_tool_turn(tmp_path / "images", dialect, _server(), f"{_NAMESPACE}.images", {})
    _, error_bodies = run_tool_turn(tmp_path / "error", dialect, _server(), f"{_NAMESPACE}.soft_error", {})

    images = json.dumps(tool_result_payload(dialect, image_bodies[1]))
    error = tool_result_payload(dialect, error_bodies[1])
    if dialect is ApiDialect.RESPONSES:
        assert images.count('"type": "input_image"') == _ACCEPTED_IMAGES
        assert error[0]["output"].startswith("[tool reported an error]\n")
    else:
        assert images.count('"inline_data"') == _ACCEPTED_IMAGES
        assert "error" in error[0]["function_response"]["response"]
