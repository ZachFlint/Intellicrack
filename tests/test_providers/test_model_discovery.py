# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Integration tests for cross-provider model discovery.

These tests verify that each connected provider returns real, parseable
model records and that the per-provider listing integrates correctly when
multiple providers are queried together.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from intellicrack.credentials.env_loader import CredentialLoader
    from intellicrack.providers.base import LLMProviderBase

from intellicrack.core.types import ModelInfo, ProviderCredentials, ProviderError, ProviderName
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.ollama import OllamaProvider
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.openrouter import OpenRouterProvider


_logger = logging.getLogger(__name__)

_OFFLINE_SIGNALS: tuple[str, ...] = (
    "offline",
    "connection error",
    "connection refused",
    "connection reset",
    "network unreachable",
    "failed to connect",
    "winError",
    "winerror",
    "no route to host",
    "name or service not known",
    "temporary failure in name resolution",
    "getaddrinfo failed",
    "socket.gaierror",
    "cannot connect",
    "timed out",
    "nodename nor servname provided",
)


def _is_offline_error(exc: BaseException) -> bool:
    """Return True when the exception chain contains a network-offline signal.

    Walks the ``__cause__``/``__context__`` chain of a provider failure and
    looks for a connectivity signal (offline, refused, unreachable, etc.)
    indicating the live cloud endpoint cannot be reached due to an absent
    network capability rather than a code defect.

    Args:
        exc: The exception raised by a provider call.

    Returns:
        bool: True when a connectivity signal is found, False otherwise.
    """
    seen: set[int] = set()
    parts: list[str] = []
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        parts.append(str(current))
        current = current.__cause__ or current.__context__
    haystack = " ".join(parts).lower()
    return any(signal.lower() in haystack for signal in _OFFLINE_SIGNALS)


async def _query_provider_count(
    provider: LLMProviderBase,
    credential_loader: CredentialLoader,
    provider_name: ProviderName,
    label: str,
) -> int:
    """Connect a provider, list its models, assert non-empty, then disconnect.

    Skips (rather than fails) when the provider endpoint cannot be reached due
    to an absent network capability (e.g. sandbox with ``network='none'``).
    When the network is live the assertion is a real gate: an empty model list
    from a connected provider is a genuine bridge defect.

    Args:
        provider: Fresh unconnected provider instance.
        credential_loader: Credential loader used to retrieve live credentials.
        provider_name: Enum key for retrieving credentials from the loader.
        label: Human-readable provider name used in assertion messages.

    Returns:
        int: Number of models returned by the provider.

    Raises:
        ProviderError: Re-raised when the failure is not attributable to
            network unavailability.
    """
    creds: ProviderCredentials | None = credential_loader.get_credentials(provider_name)
    assert creds is not None, f"{label}: configured flag is True but credentials are missing"
    try:
        await provider.connect(creds)
    except ProviderError as exc:
        if _is_offline_error(exc):
            pytest.skip(f"{label}: network unreachable in this environment ({exc})")
        raise
    models: list[ModelInfo] = await provider.list_models()
    assert len(models) > 0, (
        f"{label} is configured and connected but list_models() returned an empty list"
    )
    await provider.disconnect()
    return len(models)


@pytest.mark.integration
class TestOllamaLocalModelListing:
    """Gate that Ollama returns parseable, provider-tagged records when models are installed."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_display_ollama_models(
        ollama_provider: OllamaProvider,
    ) -> None:
        """Each locally installed Ollama model is provider-tagged and has a non-empty id.

        The fixture skips when Ollama is not reachable, making this test run
        only when the daemon is live.  When the daemon is live but no models
        are pulled, the test also skips because there is nothing to assert
        (an empty list cannot reveal a parsing regression).  When at least one
        model is present, the bridge must tag it as OLLAMA and populate a
        non-empty id string; either failure indicates a real defect.

        Args:
            ollama_provider: Connected Ollama provider fixture.
        """
        models: list[ModelInfo] = await ollama_provider.list_models()

        if len(models) == 0:
            pytest.skip("No Ollama models installed; cannot assert model-record correctness")

        for model in models:
            assert model.id, f"Ollama model must have a non-empty id; got {model.id!r}"
            assert model.provider == ProviderName.OLLAMA, (
                f"Ollama model {model.id!r} must carry ProviderName.OLLAMA, got {model.provider!r}"
            )
            assert model.context_window > 0, (
                f"Ollama model {model.id!r} must have a positive context_window, got {model.context_window}"
            )


@pytest.mark.integration
class TestAllProvidersModelCount:
    """Summary gate: every configured provider returns at least one model record."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_summary_all_providers(
        credential_loader: CredentialLoader,
        *,
        has_openai_key: bool,
        has_google_key: bool,
        has_openrouter_key: bool,
        has_anthropic_key: bool,
        has_ollama_available: bool,
    ) -> None:
        """Every configured provider returns a non-empty model list.

        Each provider block connects, calls ``list_models()``, and
        asserts independently that the count is greater than zero.  A
        provider that returns an empty list despite being connected and
        configured fails this gate, exposing a silent bridge regression
        that an aggregate-count assertion would miss.  Providers that are
        not configured are recorded as ``NOT CONFIGURED`` and excluded
        from the non-empty requirement; the test skips entirely when no
        providers are configured.

        For Ollama, the daemon must be running with at least one model pulled.
        When the daemon is reachable ``has_ollama_available`` is True and this
        gate asserts that ``list_models()`` returns a non-empty list; a bridge
        regression that silently empties the model list will fail the assertion
        and turn the test red.

        Args:
            credential_loader: Credential loader fixture.
            has_openai_key: Whether an OpenAI API key is configured.
            has_google_key: Whether a Google API key is configured.
            has_openrouter_key: Whether an OpenRouter API key is configured.
            has_anthropic_key: Whether an Anthropic API key is configured.
            has_ollama_available: Whether a local Ollama server is running.
        """
        results: dict[str, int | str] = {}

        if has_openai_key:
            results["OpenAI"] = await _query_provider_count(
                OpenAIProvider(), credential_loader, ProviderName.OPENAI, "OpenAI",
            )
        else:
            results["OpenAI"] = "NOT CONFIGURED"

        if has_google_key:
            results["Google"] = await _query_provider_count(
                GoogleProvider(), credential_loader, ProviderName.GOOGLE, "Google",
            )
        else:
            results["Google"] = "NOT CONFIGURED"

        if has_openrouter_key:
            results["OpenRouter"] = await _query_provider_count(
                OpenRouterProvider(), credential_loader, ProviderName.OPENROUTER, "OpenRouter",
            )
        else:
            results["OpenRouter"] = "NOT CONFIGURED"

        if has_anthropic_key:
            results["Anthropic"] = await _query_provider_count(
                AnthropicProvider(), credential_loader, ProviderName.ANTHROPIC, "Anthropic",
            )
        else:
            results["Anthropic"] = "NOT CONFIGURED"

        if has_ollama_available:
            ollama_prov = OllamaProvider()
            ol_creds: ProviderCredentials | None = credential_loader.get_credentials(ProviderName.OLLAMA)
            if ol_creds is None:
                ol_creds = ProviderCredentials(api_base="http://localhost:11434")
            await ollama_prov.connect(ol_creds)
            ol_models: list[ModelInfo] = await ollama_prov.list_models()
            await ollama_prov.disconnect()
            assert len(ol_models) > 0, (
                "Ollama is running and connected but list_models() returned an empty list; "
                "pull at least one model (e.g. ollama pull llama3) to satisfy this gate"
            )
            results["Ollama"] = len(ol_models)
        else:
            results["Ollama"] = "NOT RUNNING"

        for provider_name, count in results.items():
            if isinstance(count, int):
                _logger.info("%s: %d models", provider_name, count)
            else:
                _logger.info("%s: %s", provider_name, count)

        configured_count: int = sum(isinstance(v, int) for v in results.values())
        if configured_count == 0:
            pytest.skip("No providers are configured; skipping cross-provider summary gate")

        assert configured_count > 0, (
            "At least one provider must be configured and return models"
        )
