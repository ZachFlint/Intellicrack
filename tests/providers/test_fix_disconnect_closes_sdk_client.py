# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate: a provider closes the SDK client it built, on disconnect, on a failed connect and on a reconnect.

The Anthropic, OpenAI, Grok and Google providers dropped their SDK client by
setting the attribute to ``None``. Each SDK client owns an HTTP connection pool,
and each SDK's finalizer closes a pool nobody closed by scheduling a task on
whichever event loop is running when the garbage collector reaches it. That
task then fails against connections belonging to a loop that closed long ago,
and asyncio reports the failure in the middle of whatever unrelated work the
running loop is doing: one such report landed in another test's log on CI and
failed it.

Every gate drives the real SDK client against a loopback server speaking the
provider's own model-listing dialect, so the client under test holds a real
connection when the provider lets go of it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, cast

import anthropic
import openai
import pytest

from intellicrack.core.types import AuthenticationError, ProviderCredentials
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.grok import GrokProvider
from intellicrack.providers.openai import OpenAIProvider
from tests._helpers.provider_endpoint_server import ProviderEndpointServer
from tests._helpers.provider_state import isolate_provider_environment


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from intellicrack.providers.base import LLMProviderBase


_ACCEPTED_KEY: Final[str] = "loopback-accepted-" + ("k" * 24)
_REJECTED_KEY: Final[str] = "loopback-rejected-" + ("r" * 24)


@pytest.fixture
def endpoint_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[ProviderEndpointServer]:
    """Provide a loopback provider endpoint server in a provider-free environment.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        ProviderEndpointServer: The running server.
    """
    isolate_provider_environment(monkeypatch)
    with ProviderEndpointServer(accepted_key=_ACCEPTED_KEY, model_ids=["loopback-model"]) as server:
        yield server


def _credentials(server: ProviderEndpointServer, provider: LLMProviderBase, key: str) -> ProviderCredentials:
    """Build credentials that point one provider's SDK client at the loopback server.

    Args:
        server: The loopback server.
        provider: The provider the credentials are for.
        key: The API key to present.

    Returns:
        ProviderCredentials: Credentials naming the endpoint that speaks the provider's dialect.
    """
    if isinstance(provider, AnthropicProvider):
        return ProviderCredentials(api_key=key, api_base=server.anthropic_base_url)
    if isinstance(provider, GoogleProvider):
        return ProviderCredentials(api_key=key, api_base=server.gemini_base_url)
    return ProviderCredentials(api_key=key, api_base=server.openai_compatible_base_url)


def _sdk_client(provider: LLMProviderBase) -> object | None:
    """Read the SDK client a provider currently holds.

    Args:
        provider: An Anthropic, OpenAI, Grok or Google provider.

    Returns:
        object | None: Its SDK client, or ``None`` when it holds none.
    """
    attribute = "_client" if isinstance(provider, AnthropicProvider) else "client"
    return cast("object | None", getattr(provider, attribute))


def _is_closed(client: object) -> bool:
    """Report whether an SDK client has closed every connection pool it owns.

    A Gemini client owns a synchronous and an asynchronous HTTP client, and is
    closed only when both are.

    Args:
        client: An Anthropic, OpenAI or Gemini SDK client.

    Returns:
        bool: ``True`` when its pools are closed.
    """
    if isinstance(client, (anthropic.AsyncAnthropic, openai.AsyncOpenAI)):
        return client.is_closed()
    api_client = cast("object", getattr(client, "_api_client"))
    pools = [cast("object", getattr(api_client, name)) for name in ("_httpx_client", "_async_httpx_client")]
    return all(cast("bool", getattr(pool, "is_closed")) for pool in pools)


def _keeping[**P, T](build: Callable[P, T], built: list[T]) -> Callable[P, T]:
    """Wrap an SDK client's constructor so every client it builds is kept for inspection.

    A provider forgets the client of a failed connect, so the only way to see
    what became of that client is to have held on to it when it was built.

    Args:
        build: The real constructor.
        built: Where each constructed client is appended.

    Returns:
        Callable[P, T]: A callable taking the constructor's own arguments and returning the real client.
    """

    def _build(*args: P.args, **kwargs: P.kwargs) -> T:
        """Build the real client and keep it.

        Args:
            *args: The constructor's positional arguments.
            **kwargs: The constructor's keyword arguments.

        Returns:
            T: The real client.
        """
        client = build(*args, **kwargs)
        built.append(client)
        return client

    return _build


_PROVIDERS: Final[tuple[Callable[[], LLMProviderBase], ...]] = (AnthropicProvider, OpenAIProvider, GrokProvider, GoogleProvider)
_PROVIDER_IDS: Final[tuple[str, ...]] = ("anthropic", "openai", "grok", "google")


@pytest.mark.asyncio
@pytest.mark.parametrize("factory", _PROVIDERS, ids=_PROVIDER_IDS)
async def test_disconnect_closes_the_sdk_client(endpoint_server: ProviderEndpointServer, factory: Callable[[], LLMProviderBase]) -> None:
    """Disconnecting closes the client the provider connected with, rather than only forgetting it.

    Falsifiable: a provider that sets its client attribute to ``None`` leaves
    the client's connection pool open.

    Args:
        endpoint_server: Loopback server fixture.
        factory: Builds the provider under test.
    """
    provider = factory()
    await provider.connect(_credentials(endpoint_server, provider, _ACCEPTED_KEY))
    client = _sdk_client(provider)
    assert client is not None
    assert not _is_closed(client), "the client was already closed while the provider was connected"

    await provider.disconnect()

    assert _sdk_client(provider) is None
    assert _is_closed(client), "disconnect dropped the SDK client without closing its connection pool"


@pytest.mark.asyncio
@pytest.mark.parametrize("factory", _PROVIDERS, ids=_PROVIDER_IDS)
async def test_connecting_again_closes_the_client_it_replaces(
    endpoint_server: ProviderEndpointServer,
    factory: Callable[[], LLMProviderBase],
) -> None:
    """A second connect closes the first connect's client before building its own.

    Args:
        endpoint_server: Loopback server fixture.
        factory: Builds the provider under test.
    """
    provider = factory()
    credentials = _credentials(endpoint_server, provider, _ACCEPTED_KEY)
    await provider.connect(credentials)
    first = _sdk_client(provider)
    assert first is not None

    await provider.connect(credentials)
    try:
        second = _sdk_client(provider)
        assert second is not None
        assert second is not first
        assert _is_closed(first), "reconnecting replaced the SDK client without closing the one it replaced"
        assert not _is_closed(second)
    finally:
        await provider.disconnect()


@pytest.mark.asyncio
@pytest.mark.parametrize("factory", [OpenAIProvider, GrokProvider], ids=["openai", "grok"])
async def test_a_rejected_key_closes_the_openai_client_that_was_built(
    endpoint_server: ProviderEndpointServer,
    monkeypatch: pytest.MonkeyPatch,
    factory: Callable[[], LLMProviderBase],
) -> None:
    """A connect the endpoint rejects closes the client it built for the attempt.

    Falsifiable: a failed connect that sets the client attribute to ``None``
    leaves the client it built with its connection pool open.

    Args:
        endpoint_server: Loopback server fixture.
        monkeypatch: Pytest monkeypatch fixture.
        factory: Builds the provider under test.
    """
    built: list[openai.AsyncOpenAI] = []
    monkeypatch.setattr(openai, "AsyncOpenAI", _keeping(openai.AsyncOpenAI, built))
    provider = factory()
    rejected = _credentials(endpoint_server, provider, _REJECTED_KEY)

    with pytest.raises(AuthenticationError):
        await provider.connect(rejected)

    assert len(built) == 1
    assert _sdk_client(provider) is None
    assert built[0].is_closed(), "a rejected connect dropped the SDK client without closing its connection pool"


@pytest.mark.asyncio
async def test_a_rejected_key_closes_the_anthropic_client_that_was_built(
    endpoint_server: ProviderEndpointServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A connect Anthropic's endpoint rejects closes the client it built for the attempt.

    Falsifiable: a failed connect that keeps or forgets the client without
    closing it leaves its connection pool open.

    Args:
        endpoint_server: Loopback server fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    built: list[anthropic.AsyncAnthropic] = []
    monkeypatch.setattr(anthropic, "AsyncAnthropic", _keeping(anthropic.AsyncAnthropic, built))
    provider = AnthropicProvider()
    rejected = _credentials(endpoint_server, provider, _REJECTED_KEY)

    with pytest.raises(AuthenticationError):
        await provider.connect(rejected)

    assert len(built) == 1
    assert _sdk_client(provider) is None
    assert built[0].is_closed(), "a rejected connect dropped the SDK client without closing its connection pool"
