# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Provider-specific pytest fixtures.

This module provides async fixtures for creating connected provider instances
that can be used in integration tests. Each fixture handles connection setup,
skip conditions, and cleanup automatically.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import httpx
import pytest
import pytest_asyncio

from intellicrack.core.types import ProviderCredentials, ProviderError, ProviderName
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.grok import GrokProvider
from intellicrack.providers.huggingface import HuggingFaceProvider
from intellicrack.providers.ollama import OllamaProvider
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.openrouter import OpenRouterProvider


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator

    from intellicrack.credentials.env_loader import CredentialLoader


_ACCOUNT_LIMIT_SIGNALS: tuple[str, ...] = (
    "credit balance is too low",
    "insufficient_quota",
    "exceeded your current quota",
    "quota or spending cap exhausted",
    "insufficient credits",
    "payment required",
    "model not supported by provider",
    "organization has been disabled",
    "organization has been deactivated",
    "account has been disabled",
)


_NETWORK_UNAVAILABLE_SIGNALS: tuple[str, ...] = (
    "getaddrinfo failed",
    "name or service not known",
    "temporary failure in name resolution",
    "nodename nor servname provided",
    "no address associated with hostname",
    "failed to establish a new connection",
    "network is unreachable",
    "connection refused",
    "[errno 11001]",
    "[errno -2]",
    "[errno -3]",
)


_PROVIDER_KEY_ENV_VARS: tuple[str, ...] = (
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "HUGGINGFACE_API_TOKEN",
    "OLLAMA_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "XAI_API_KEY",
)


@pytest.fixture(autouse=True)
def restore_provider_key_env() -> Generator[None]:
    """Snapshot and restore provider API-key env vars around every test.

    ``CredentialLoader`` copies the values of any loaded ``.env`` file into
    ``os.environ``. Tests that load synthetic env files with deliberately wrong
    keys (for format-validation coverage) would otherwise leak those keys into
    the process environment, where a later live-provider test reads them and
    fails with a 401. Restoring the snapshot confines each test's environment
    mutations to that test.

    Yields:
        None: Yields control to the test.
    """
    saved: dict[str, str | None] = {name: os.environ.get(name) for name in _PROVIDER_KEY_ENV_VARS}
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _account_limit_reason(exc: BaseException) -> str | None:
    """Return the account-limit signal found in an exception chain, if any.

    Walks the ``__cause__``/``__context__`` chain of a provider failure and
    looks for a billing, quota, credit, or payment signal indicating the live
    cloud account cannot fulfil the request - an unmet environment
    precondition rather than a defect in the provider code.

    Args:
        exc: The exception raised by a provider call.

    Returns:
        str | None: The matched account-limit signal substring, or ``None``
        when the failure is not attributable to account state.
    """
    seen: set[int] = set()
    parts: list[str] = []
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        parts.append(str(current))
        current = current.__cause__ or current.__context__
    haystack = " ".join(parts).lower()
    return next(
        (signal for signal in _ACCOUNT_LIMIT_SIGNALS if signal in haystack),
        None,
    )


def _network_unavailable_reason(exc: BaseException) -> str | None:
    """Return the network-unreachable signal found in an exception chain, if any.

    Walks the ``__cause__``/``__context__`` chain of a provider failure looking
    for a DNS-resolution or connection-establishment failure signal indicating
    the live cloud endpoint could not be reached at all (for example an offline
    sandbox run with ``--network none``). That is an unmet environment
    precondition for a live, billable API test rather than a defect in the
    provider code, so it is treated exactly like an exhausted-account signal.

    Args:
        exc: The exception raised by a provider call.

    Returns:
        str | None: The matched network-unavailable signal substring, or
        ``None`` when the failure is not attributable to a missing network.
    """
    seen: set[int] = set()
    parts: list[str] = []
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        parts.append(str(current))
        current = current.__cause__ or current.__context__
    haystack = " ".join(parts).lower()
    return next(
        (signal for signal in _NETWORK_UNAVAILABLE_SIGNALS if signal in haystack),
        None,
    )


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call() -> Generator[None]:
    """Skip live provider tests on an unmet environment precondition.

    The opt-in live provider tests issue real, billable API calls. Two failure
    modes reflect the environment rather than an Intellicrack defect and are
    turned into skips instead of false negatives:

    * the configured account is out of credit / has an exhausted quota or
      spending cap - the provider raises
      :class:`~intellicrack.core.types.ProviderError` carrying a billing signal;
    * the live endpoint is unreachable because the run has no outbound network
      (for example ``--network none``) - the transport raises an
      :class:`httpx.HTTPError` / :class:`OSError` whose chain carries a
      DNS-resolution or connection-establishment failure.

    Every other failure - including a genuine provider bug that surfaces as a
    connection or protocol error against a reachable host - propagates unchanged.

    Yields:
        None: Control passed to the wrapped test-call implementation.

    Raises:
        ProviderError: Re-raised when a provider failure is attributable to
            neither a live-account limit nor a missing network.
        httpx.HTTPError: Re-raised when a transport failure against a reachable
            host is not a missing-network condition.
        OSError: Re-raised when a socket-level failure is not a missing-network
            condition.
    """
    try:
        yield
    except (ProviderError, httpx.HTTPError, OSError) as exc:
        if isinstance(exc, ProviderError):
            account_reason = _account_limit_reason(exc)
            if account_reason is not None:
                pytest.skip(f"live provider account limit reached ({account_reason})")
        network_reason = _network_unavailable_reason(exc)
        if network_reason is None:
            raise
        pytest.skip(f"live provider endpoint unreachable ({network_reason})")


@pytest_asyncio.fixture
async def anthropic_provider(
    credential_loader: CredentialLoader,
    *,
    has_anthropic_key: bool,
) -> AsyncGenerator[AnthropicProvider]:
    """Get a connected Anthropic provider instance.

    Skips the test if ANTHROPIC_API_KEY is not configured.
    Automatically disconnects after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_anthropic_key: Whether Anthropic key is configured.

    Yields:
        AsyncGenerator[AnthropicProvider]: A connected AnthropicProvider instance.
    """
    if not has_anthropic_key:
        pytest.skip("ANTHROPIC_API_KEY not configured in .env")

    provider = AnthropicProvider()
    credentials = credential_loader.get_credentials(ProviderName.ANTHROPIC)
    assert credentials is not None, "Expected credentials after validation"

    await provider.connect(credentials)
    yield provider
    await provider.disconnect()


@pytest_asyncio.fixture
async def openai_provider(
    credential_loader: CredentialLoader,
    *,
    has_openai_key: bool,
) -> AsyncGenerator[OpenAIProvider]:
    """Get a connected OpenAI provider instance.

    Skips the test if OPENAI_API_KEY is not configured.
    Automatically disconnects after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_openai_key: Whether OpenAI key is configured.

    Yields:
        AsyncGenerator[OpenAIProvider]: A connected OpenAIProvider instance.
    """
    if not has_openai_key:
        pytest.skip("OPENAI_API_KEY not configured in .env")

    provider = OpenAIProvider()
    credentials = credential_loader.get_credentials(ProviderName.OPENAI)
    assert credentials is not None, "Expected credentials after validation"

    await provider.connect(credentials)
    yield provider
    await provider.disconnect()


@pytest_asyncio.fixture
async def google_provider(
    credential_loader: CredentialLoader,
    *,
    has_google_key: bool,
) -> AsyncGenerator[GoogleProvider]:
    """Get a connected Google provider instance.

    Skips the test if GOOGLE_API_KEY is not configured.
    Automatically disconnects after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_google_key: Whether Google key is configured.

    Yields:
        AsyncGenerator[GoogleProvider]: A connected GoogleProvider instance.
    """
    if not has_google_key:
        pytest.skip("GOOGLE_API_KEY not configured in .env")

    provider = GoogleProvider()
    credentials = credential_loader.get_credentials(ProviderName.GOOGLE)
    assert credentials is not None, "Expected credentials after validation"

    await provider.connect(credentials)
    yield provider
    await provider.disconnect()


@pytest_asyncio.fixture
async def openrouter_provider(
    credential_loader: CredentialLoader,
    *,
    has_openrouter_key: bool,
) -> AsyncGenerator[OpenRouterProvider]:
    """Get a connected OpenRouter provider instance.

    Skips the test if OPENROUTER_API_KEY is not configured.
    Automatically disconnects after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_openrouter_key: Whether OpenRouter key is configured.

    Yields:
        AsyncGenerator[OpenRouterProvider]: A connected OpenRouterProvider instance.
    """
    if not has_openrouter_key:
        pytest.skip("OPENROUTER_API_KEY not configured in .env")

    provider = OpenRouterProvider()
    credentials = credential_loader.get_credentials(ProviderName.OPENROUTER)
    assert credentials is not None, "Expected credentials after validation"

    await provider.connect(credentials)
    yield provider
    await provider.disconnect()


@pytest_asyncio.fixture
async def ollama_provider(
    credential_loader: CredentialLoader,
    *,
    has_ollama_available: bool,
) -> AsyncGenerator[OllamaProvider]:
    """Get a connected Ollama provider instance.

    Skips the test if Ollama is not running locally.
    Automatically disconnects after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_ollama_available: Whether Ollama is running.

    Yields:
        AsyncGenerator[OllamaProvider]: A connected OllamaProvider instance.
    """
    if not has_ollama_available:
        pytest.skip("Ollama not running locally at http://localhost:11434")

    provider = OllamaProvider()
    credentials = credential_loader.get_credentials(ProviderName.OLLAMA)

    if credentials is None:
        credentials = ProviderCredentials(
            api_key=None,
            api_base="http://localhost:11434",
        )

    await provider.connect(credentials)
    yield provider
    await provider.disconnect()


@pytest_asyncio.fixture
async def huggingface_provider(
    credential_loader: CredentialLoader,
    *,
    has_huggingface_key: bool,
) -> AsyncGenerator[HuggingFaceProvider]:
    """Get a connected HuggingFace provider instance.

    Skips the test if HUGGINGFACE_API_TOKEN is not configured.
    Automatically disconnects after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_huggingface_key: Whether HuggingFace token is configured.

    Yields:
        AsyncGenerator[HuggingFaceProvider]: A connected HuggingFaceProvider instance.
    """
    if not has_huggingface_key:
        pytest.skip("HUGGINGFACE_API_TOKEN not configured in .env")

    provider = HuggingFaceProvider()
    credentials = credential_loader.get_credentials(ProviderName.HUGGINGFACE)
    assert credentials is not None, "Expected credentials after validation"

    await provider.connect(credentials)
    yield provider
    await provider.disconnect()


@pytest_asyncio.fixture
async def grok_provider(
    credential_loader: CredentialLoader,
    *,
    has_grok_key: bool,
) -> AsyncGenerator[GrokProvider]:
    """Get a connected Grok (X.AI) provider instance.

    Skips the test if XAI_API_KEY is not configured.
    Automatically disconnects after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_grok_key: Whether Grok key is configured.

    Yields:
        AsyncGenerator[GrokProvider]: A connected GrokProvider instance.
    """
    if not has_grok_key:
        pytest.skip("XAI_API_KEY not configured in .env")

    provider = GrokProvider()
    credentials = credential_loader.get_credentials(ProviderName.GROK)
    assert credentials is not None, "Expected credentials after validation"

    await provider.connect(credentials)
    yield provider
    await provider.disconnect()
