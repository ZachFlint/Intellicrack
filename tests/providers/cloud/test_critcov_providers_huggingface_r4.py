# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Drive the real HuggingFace provider against an inference endpoint that accepts a request and never answers.

The inference client follows the provider's own ``api_base``, so it is pointed at a loopback listener that accepts the TCP connection,
reads the request and stays silent. The client's request timeout then fires inside ``httpx`` as a read timeout, which the Hugging Face
client does not translate into its own timeout error. The identity probe of ``connect`` goes through the synchronous Hub client, which is
pointed at a loopback server through ``huggingface_hub``'s public ``set_client_factory`` hook. Nothing leaves the machine and no real
token is used.
"""

from __future__ import annotations

import contextlib
import importlib
from typing import TYPE_CHECKING, Final, cast
from urllib.parse import urlsplit

import httpx
import pytest
from huggingface_hub import set_client_factory

from intellicrack.core.types import Message, ProviderCredentials, ProviderError
from intellicrack.providers.huggingface import HuggingFaceProvider
from tests._helpers.scripted_sdk_server import ScriptedHTTPServer, json_response
from tests._helpers.stalling_http import StallingServer


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable, Generator


_TOKEN: Final[str] = "hf" + "_" + "loopback" + "Token" + "01" * 5
_MODEL: Final[str] = "org/served-model"
_WHOAMI_PATH: Final[str] = "/api/whoami-v2"
_REQUEST_TIMEOUT_S: Final[float] = 1.0
_TIMEOUT_PREFIX: Final[str] = "HuggingFace inference timeout:"


@contextlib.contextmanager
def _hub_pointed_at(origin: str) -> Generator[None]:
    """Route the Hub's synchronous client to a loopback origin.

    Installs an HTTP client factory through ``huggingface_hub``'s public setter and restores the factory that was installed before,
    closing the shared Hub session each time.

    Args:
        origin: The loopback origin that Hub requests are rewritten to.

    Yields:
        None: Control while the Hub client targets the loopback origin.
    """
    http_module = importlib.import_module("huggingface_hub.utils._http")
    previous = cast("Callable[[], httpx.Client]", getattr(http_module, "_GLOBAL_CLIENT_FACTORY"))
    port = urlsplit(origin).port
    assert port is not None

    def _redirect(request: httpx.Request) -> None:
        """Rewrite a Hub request to the loopback port.

        Args:
            request: The outgoing Hub request.
        """
        request.url = request.url.copy_with(scheme="http", host="127.0.0.1", port=port)

    def _client() -> httpx.Client:
        """Build the synchronous Hub client.

        Returns:
            httpx.Client: A client that rewrites requests to the loopback server.
        """
        return httpx.Client(event_hooks={"request": [_redirect]}, follow_redirects=True, timeout=10.0)

    set_client_factory(_client)
    try:
        yield
    finally:
        set_client_factory(previous)


@contextlib.asynccontextmanager
async def _connected_to_silent_endpoint() -> AsyncGenerator[tuple[HuggingFaceProvider, StallingServer]]:
    """Connect a provider whose inference endpoint accepts connections and never replies.

    Yields:
        tuple[HuggingFaceProvider, StallingServer]: The connected provider and the silent listener it targets.
    """
    routes = {("GET", _WHOAMI_PATH): json_response({"type": "user", "name": "loopback-user"})}
    with ScriptedHTTPServer(routes) as hub, StallingServer() as silent, _hub_pointed_at(hub.origin):
        provider = HuggingFaceProvider()
        try:
            await provider.connect(ProviderCredentials(api_key=_TOKEN, api_base=silent.url, timeout=_REQUEST_TIMEOUT_S))
            yield provider, silent
        finally:
            await provider.disconnect()


def _user() -> list[Message]:
    """Build a one-message conversation.

    Returns:
        list[Message]: A conversation holding a single user message.
    """
    return [Message(role="user", content="hello")]


@pytest.mark.asyncio
async def test_chat_reports_an_httpx_read_timeout_as_a_provider_timeout() -> None:
    """A chat request the endpoint never answers fails with a timeout provider error, not an API error."""
    async with _connected_to_silent_endpoint() as (provider, silent):
        with pytest.raises(ProviderError) as info:
            _ = await provider.chat(_user(), _MODEL)
        accepted = silent.connections

    assert type(info.value) is ProviderError
    assert str(info.value).startswith(_TIMEOUT_PREFIX)
    assert isinstance(info.value.__cause__, httpx.TimeoutException)
    assert accepted >= 1


@pytest.mark.asyncio
async def test_stream_reports_an_httpx_read_timeout_as_a_provider_timeout() -> None:
    """A streaming request the endpoint never answers fails with a timeout provider error, not a stream failure."""
    async with _connected_to_silent_endpoint() as (provider, silent):
        with pytest.raises(ProviderError) as info:
            _ = [piece async for piece in provider.chat_stream(_user(), _MODEL)]
        accepted = silent.connections

    assert type(info.value) is ProviderError
    assert str(info.value).startswith(_TIMEOUT_PREFIX)
    assert isinstance(info.value.__cause__, httpx.TimeoutException)
    assert accepted >= 1
