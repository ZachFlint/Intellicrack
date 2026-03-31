# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for providers.registry module - provider registration and management."""

from __future__ import annotations

from typing import TYPE_CHECKING, override

import pytest

from intellicrack.core.types import (
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
    ToolCall,
)
from intellicrack.providers.base import LLMProviderBase
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from intellicrack.core.types import ToolDefinition


class ConcreteTestProvider(LLMProviderBase):
    """Minimal concrete provider for registry testing.

    Args:
        provider_name: The provider name to use.
    """

    def __init__(self, provider_name: ProviderName = ProviderName.ANTHROPIC) -> None:
        super().__init__()
        self._name = provider_name

    @property
    @override
    def name(self) -> ProviderName:
        """Return the provider name.

        Returns:
            ProviderName: Configured ProviderName.
        """
        return self._name

    def mark_connected(self) -> None:
        """Set provider to connected state for testing."""
        self._connected = True

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Mark provider as connected.

        Args:
            credentials: Provider credentials.
        """
        self._credentials = credentials
        self._connected = True

    @override
    async def list_models(self) -> list[ModelInfo]:
        """Return empty model list.

        Returns:
            list[ModelInfo]: Empty list.
        """
        return []

    @override
    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Return empty response.

        Args:
            messages: Conversation history.
            model: Model ID.
            tools: Available tools.
            temperature: Sampling temperature.
            max_tokens: Max response tokens.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of empty message and None.
        """
        return Message(role="assistant", content="test"), None

    @override
    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[str]:
        """Yield empty stream.

        Args:
            messages: Conversation history.
            model: Model ID.
            tools: Available tools.
            temperature: Sampling temperature.
            max_tokens: Max response tokens.

        Yields:
            str: Empty string.
        """
        yield ""

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Return empty tool list.

        Args:
            tools: Tool definitions.

        Returns:
            list[dict[str, object]]: Empty list.
        """
        return []

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Return empty message list.

        Args:
            messages: Messages to convert.

        Returns:
            list[dict[str, object]]: Empty list.
        """
        return []


def _make_provider(
    name: ProviderName = ProviderName.ANTHROPIC,
) -> ConcreteTestProvider:
    """Create a test provider instance.

    Args:
        name: Provider name.

    Returns:
        ConcreteTestProvider: ConcreteTestProvider instance.
    """
    return ConcreteTestProvider(provider_name=name)


def _make_connected(
    name: ProviderName = ProviderName.ANTHROPIC,
) -> ConcreteTestProvider:
    """Create a connected test provider.

    Args:
        name: Provider name.

    Returns:
        ConcreteTestProvider: Connected ConcreteTestProvider.
    """
    p = ConcreteTestProvider(provider_name=name)
    p.mark_connected()
    return p


def test_registry_empty() -> None:
    """Verify empty registry has no providers."""
    reg = ProviderRegistry()
    assert reg.list_registered() == []
    assert reg.list_connected() == []
    assert reg.active is None
    assert reg.active_name is None


def test_register_provider() -> None:
    """Verify provider registration."""
    reg = ProviderRegistry()
    reg.register(_make_provider())
    assert ProviderName.ANTHROPIC in reg.list_registered()


def test_register_replaces_existing() -> None:
    """Verify re-registering replaces the provider."""
    reg = ProviderRegistry()
    p1 = _make_provider()
    p2 = _make_provider()
    reg.register(p1)
    reg.register(p2)
    assert reg.get(ProviderName.ANTHROPIC) is p2


def test_unregister_provider() -> None:
    """Verify provider unregistration."""
    reg = ProviderRegistry()
    reg.register(_make_provider())
    assert reg.unregister(ProviderName.ANTHROPIC) is True
    assert reg.list_registered() == []


def test_unregister_nonexistent() -> None:
    """Verify unregistering non-existent provider returns False."""
    reg = ProviderRegistry()
    assert reg.unregister(ProviderName.ANTHROPIC) is False


def test_unregister_clears_active() -> None:
    """Verify unregistering active provider clears active."""
    reg = ProviderRegistry()
    reg.register(_make_connected())
    reg.set_active(ProviderName.ANTHROPIC)
    reg.unregister(ProviderName.ANTHROPIC)
    assert reg.active_name is None


def test_get_registered() -> None:
    """Verify get returns registered provider."""
    reg = ProviderRegistry()
    provider = _make_provider()
    reg.register(provider)
    assert reg.get(ProviderName.ANTHROPIC) is provider


def test_get_not_registered() -> None:
    """Verify get returns None for unregistered provider."""
    reg = ProviderRegistry()
    assert reg.get(ProviderName.ANTHROPIC) is None


def test_get_or_raise_success() -> None:
    """Verify get_or_raise returns registered provider."""
    reg = ProviderRegistry()
    provider = _make_provider()
    reg.register(provider)
    assert reg.get_or_raise(ProviderName.ANTHROPIC) is provider


def test_get_or_raise_not_registered() -> None:
    """Verify get_or_raise raises ProviderError for unregistered."""
    reg = ProviderRegistry()
    with pytest.raises(ProviderError):
        reg.get_or_raise(ProviderName.ANTHROPIC)


def test_list_connected_empty() -> None:
    """Verify list_connected returns empty for disconnected providers."""
    reg = ProviderRegistry()
    reg.register(_make_provider())
    assert reg.list_connected() == []


def test_list_connected_with_connected() -> None:
    """Verify list_connected includes connected providers."""
    reg = ProviderRegistry()
    reg.register(_make_connected())
    assert ProviderName.ANTHROPIC in reg.list_connected()


def test_set_active_success() -> None:
    """Verify set_active works for connected provider."""
    reg = ProviderRegistry()
    provider = _make_connected()
    reg.register(provider)
    reg.set_active(ProviderName.ANTHROPIC)
    assert reg.active_name == ProviderName.ANTHROPIC
    assert reg.active is provider


def test_set_active_not_registered() -> None:
    """Verify set_active raises for unregistered provider."""
    reg = ProviderRegistry()
    with pytest.raises(ProviderError):
        reg.set_active(ProviderName.ANTHROPIC)


def test_set_active_not_connected() -> None:
    """Verify set_active raises for disconnected provider."""
    reg = ProviderRegistry()
    reg.register(_make_provider())
    with pytest.raises(ProviderError):
        reg.set_active(ProviderName.ANTHROPIC)


def test_has_connected_provider_false() -> None:
    """Verify has_connected_provider returns False when none connected."""
    reg = ProviderRegistry()
    reg.register(_make_provider())
    assert reg.has_connected_provider() is False


def test_has_connected_provider_true() -> None:
    """Verify has_connected_provider returns True when one connected."""
    reg = ProviderRegistry()
    reg.register(_make_connected())
    assert reg.has_connected_provider() is True


def test_multiple_providers() -> None:
    """Verify registry handles multiple providers."""
    reg = ProviderRegistry()
    reg.register(_make_provider(ProviderName.ANTHROPIC))
    reg.register(_make_provider(ProviderName.OPENAI))
    registered = reg.list_registered()
    assert ProviderName.ANTHROPIC in registered
    assert ProviderName.OPENAI in registered
