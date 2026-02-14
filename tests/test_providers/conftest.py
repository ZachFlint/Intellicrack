"""Provider-specific pytest fixtures.

This module provides async fixtures for creating connected provider instances
that can be used in integration tests. Each fixture handles connection setup,
skip conditions, and cleanup automatically.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

from intellicrack.core.types import ProviderCredentials, ProviderName
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.grok import GrokProvider
from intellicrack.providers.huggingface import HuggingFaceProvider
from intellicrack.providers.ollama import OllamaProvider
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.openrouter import OpenRouterProvider


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from intellicrack.credentials.env_loader import CredentialLoader


@pytest_asyncio.fixture
async def anthropic_provider(
    credential_loader: CredentialLoader,
    has_anthropic_key: bool,
) -> AsyncGenerator[AnthropicProvider]:
    """Get a connected Anthropic provider instance.

    Skips the test if ANTHROPIC_API_KEY is not configured.
    Automatically disconnects after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_anthropic_key: Whether Anthropic key is configured.

    Yields:
        A connected AnthropicProvider instance.
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
    has_openai_key: bool,
) -> AsyncGenerator[OpenAIProvider]:
    """Get a connected OpenAI provider instance.

    Skips the test if OPENAI_API_KEY is not configured.
    Automatically disconnects after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_openai_key: Whether OpenAI key is configured.

    Yields:
        A connected OpenAIProvider instance.
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
    has_google_key: bool,
) -> AsyncGenerator[GoogleProvider]:
    """Get a connected Google provider instance.

    Skips the test if GOOGLE_API_KEY is not configured.
    Automatically disconnects after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_google_key: Whether Google key is configured.

    Yields:
        A connected GoogleProvider instance.
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
    has_openrouter_key: bool,
) -> AsyncGenerator[OpenRouterProvider]:
    """Get a connected OpenRouter provider instance.

    Skips the test if OPENROUTER_API_KEY is not configured.
    Automatically disconnects after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_openrouter_key: Whether OpenRouter key is configured.

    Yields:
        A connected OpenRouterProvider instance.
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
    has_ollama_available: bool,
) -> AsyncGenerator[OllamaProvider]:
    """Get a connected Ollama provider instance.

    Skips the test if Ollama is not running locally.
    Automatically disconnects after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_ollama_available: Whether Ollama is running.

    Yields:
        A connected OllamaProvider instance.
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
    has_huggingface_key: bool,
) -> AsyncGenerator[HuggingFaceProvider]:
    """Get a connected HuggingFace provider instance.

    Skips the test if HUGGINGFACE_API_TOKEN is not configured.
    Automatically disconnects after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_huggingface_key: Whether HuggingFace token is configured.

    Yields:
        A connected HuggingFaceProvider instance.
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
    has_grok_key: bool,
) -> AsyncGenerator[GrokProvider]:
    """Get a connected Grok (X.AI) provider instance.

    Skips the test if XAI_API_KEY is not configured.
    Automatically disconnects after test completion.

    Args:
        credential_loader: The credential loader instance.
        has_grok_key: Whether Grok key is configured.

    Yields:
        A connected GrokProvider instance.
    """
    if not has_grok_key:
        pytest.skip("XAI_API_KEY not configured in .env")

    provider = GrokProvider()
    credentials = credential_loader.get_credentials(ProviderName.GROK)
    assert credentials is not None, "Expected credentials after validation"

    await provider.connect(credentials)
    yield provider
    await provider.disconnect()
