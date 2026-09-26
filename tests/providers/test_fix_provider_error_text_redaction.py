# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Provider error text is redacted before it is logged or shown.

Providers echo request material back in their error bodies: the key that was
rejected, an ``Authorization`` header, a request body. The built-in
providers put the SDK's error text into the typed exception the user sees and
into the structured log, so both must be free of credentials. Each test
drives a real provider SDK against a loopback server whose error body echoes
the key, then inspects the raised exception and the captured log events.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest
from structlog.testing import capture_logs

from intellicrack.core.types import AuthenticationError, Message, ProviderCredentials, ProviderError
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.openai import OpenAIProvider
from tests._helpers.scripted_sdk_server import ScriptedHTTPServer, json_response


if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence


_PREFIXED_KEY: Final[str] = "sk-" + "proj-" + "EchoedKeyMaterial0123456789"
_PLAIN_KEY: Final[str] = "gatewaykey" + "7f3a9c2e5b1d4a6f"
_OPENAI_MODELS: Final[dict[str, object]] = {
    "object": "list",
    "data": [{"id": "gpt-4o", "object": "model", "created": 0, "owned_by": "openai"}],
}


@pytest.fixture
def servers() -> Iterator[list[ScriptedHTTPServer]]:
    """Collect started servers and stop them after the test.

    Yields:
        list[ScriptedHTTPServer]: The list a test appends its servers to.
    """
    started: list[ScriptedHTTPServer] = []
    yield started
    for server in started:
        server.close()


def _echo_error(key: str, *, status: int) -> dict[str, object]:
    """Build an OpenAI-style error body that echoes the key back.

    Args:
        key: The key to echo.
        status: The HTTP status the body accompanies.

    Returns:
        dict[str, object]: The error body.
    """
    return {
        "error": {"message": f"status {status}: key {key} rejected; header Authorization: Bearer {key}", "type": "invalid_request_error"},
    }


def _logged_text(logs: Sequence[Mapping[str, object]]) -> str:
    """Join every captured log event into one searchable string.

    Args:
        logs: Events captured by :func:`structlog.testing.capture_logs`.

    Returns:
        str: The concatenated ``repr`` of every event.
    """
    return "\n".join(repr(entry) for entry in logs)


def _assert_clean(text: str, key: str) -> None:
    """Assert that a key is absent from text that still reports the failure.

    Args:
        text: The exception message or log text.
        key: The key that must not appear.
    """
    assert key not in text
    assert key[-12:] not in text
    assert "[REDACTED]" in text


@pytest.mark.asyncio
async def test_openai_chat_error_text_redacts_prefixed_key(servers: list[ScriptedHTTPServer]) -> None:
    """A Chat Completions error echoing an ``sk-`` key is redacted in the exception and the log."""
    server = ScriptedHTTPServer({
        ("GET", "/v1/models"): json_response(_OPENAI_MODELS),
        ("POST", "/v1/chat/completions"): json_response(_echo_error(_PREFIXED_KEY, status=400), status=400),
    })
    servers.append(server)
    provider = OpenAIProvider()
    await provider.connect(ProviderCredentials(api_key=_PREFIXED_KEY, api_base=f"{server.origin}/v1"))
    assert provider.client is not None
    provider.client = provider.client.with_options(max_retries=0)

    with capture_logs() as logs, pytest.raises(ProviderError) as excinfo:
        await provider.chat([Message(role="user", content="hi")], "gpt-4o")

    assert "rejected" in str(excinfo.value)
    _assert_clean(str(excinfo.value), _PREFIXED_KEY)
    _assert_clean(_logged_text(logs), _PREFIXED_KEY)


@pytest.mark.asyncio
async def test_openai_connect_error_text_redacts_unprefixed_key(servers: list[ScriptedHTTPServer]) -> None:
    """A key with no recognisable prefix is still blanked out, by its literal value."""
    server = ScriptedHTTPServer({("GET", "/v1/models"): json_response(_echo_error(_PLAIN_KEY, status=401), status=401)})
    servers.append(server)
    provider = OpenAIProvider()

    with capture_logs() as logs, pytest.raises(AuthenticationError) as excinfo:
        await provider.connect(ProviderCredentials(api_key=_PLAIN_KEY, api_base=f"{server.origin}/v1"))

    assert "rejected" in str(excinfo.value)
    _assert_clean(str(excinfo.value), _PLAIN_KEY)
    _assert_clean(_logged_text(logs), _PLAIN_KEY)


@pytest.mark.asyncio
async def test_anthropic_connect_error_text_redacts_unprefixed_key(servers: list[ScriptedHTTPServer]) -> None:
    """The Anthropic provider's connect failure carries no echoed key."""
    body = {"type": "error", "error": {"type": "authentication_error", "message": f"invalid x-api-key {_PLAIN_KEY}"}}
    server = ScriptedHTTPServer({("GET", "/v1/models"): json_response(body, status=401)})
    servers.append(server)
    provider = AnthropicProvider()

    with capture_logs() as logs, pytest.raises(AuthenticationError) as excinfo:
        await provider.connect(ProviderCredentials(api_key=_PLAIN_KEY, api_base=server.origin))

    _assert_clean(_logged_text(logs), _PLAIN_KEY)
    assert "invalid x-api-key" in str(excinfo.value)
    _assert_clean(str(excinfo.value), _PLAIN_KEY)
