# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Provider registry for managing LLM providers.

This module provides a centralized registry for registering, connecting,
and managing all LLM provider instances.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..core.logging import get_logger
from ..core.types import ProviderCredentials, ProviderError, ProviderName


if TYPE_CHECKING:
    from ..credentials.env_loader import CredentialLoader
    from .base import LLMProviderBase


_MSG_NOT_REGISTERED = "Not registered"
_MSG_NO_CREDENTIALS = "No credentials"
_MSG_NOT_CONNECTED = "Not connected"
_MSG_NO_ACTIVE_PROVIDER = "No active provider"


class ProviderRegistry:
    """Registry for all LLM providers.

    Manages provider instances, connections, and provides a unified interface
    for accessing any configured LLM provider.

    Args:
        credential_loader: Optional credential loader for auto-connecting providers.
    """

    def __init__(
        self,
        credential_loader: CredentialLoader | None = None,
    ) -> None:
        self._providers: dict[ProviderName, LLMProviderBase] = {}
        self._active_provider: ProviderName | None = None
        self._credential_loader = credential_loader
        self._logger = get_logger("providers.registry")

    def register(self, provider: LLMProviderBase) -> None:
        """Register a provider instance.

        Args:
            provider: The provider instance to register.

        Note:
            If a provider with the same name is already registered, it will be
            replaced with a warning logged.
        """
        name = provider.name
        if name in self._providers:
            self._logger.warning("provider_already_registered", provider=name.value)
        self._providers[name] = provider
        self._logger.info("provider_registered", provider=name.value)

    def unregister(self, name: ProviderName) -> bool:
        """Unregister a provider.

        Args:
            name: The provider name to unregister.

        Returns:
            bool: True if provider was removed, False if not found.
        """
        if name in self._providers:
            del self._providers[name]
            if self._active_provider == name:
                self._active_provider = None
            self._logger.info("provider_unregistered", provider=name.value)
            return True
        return False

    def get(self, name: ProviderName) -> LLMProviderBase | None:
        """Get a registered provider by name.

        Args:
            name: The provider name.

        Returns:
            LLMProviderBase | None: The provider instance or None if not registered.
        """
        return self._providers.get(name)

    def get_or_raise(self, name: ProviderName) -> LLMProviderBase:
        """Get a registered provider by name, raising if not found.

        Args:
            name: The provider name.

        Returns:
            LLMProviderBase: The provider instance.

        Raises:
            ProviderError: If provider is not registered.
        """
        provider = self._providers.get(name)
        if provider is None:
            raise ProviderError(_MSG_NOT_REGISTERED)
        return provider

    def list_registered(self) -> list[ProviderName]:
        """List all registered providers.

        Returns:
            list[ProviderName]: List of registered provider names.
        """
        return list(self._providers.keys())

    def list_connected(self) -> list[ProviderName]:
        """List all connected providers.

        Returns:
            list[ProviderName]: List of connected provider names.
        """
        connected: list[ProviderName] = [name for name, provider in self._providers.items() if provider.is_connected]
        return connected

    async def connect_provider(
        self,
        name: ProviderName,
        credentials: ProviderCredentials | None = None,
    ) -> bool:
        """Connect a specific provider.

        Args:
            name: The provider to connect.
            credentials: Credentials to use. If None, attempts to load from
                        credential loader.

        Returns:
            bool: True if connection succeeded.

        Raises:
            ProviderError: If provider not registered or no credentials.
            Exception: If connection fails (re-raised from provider).
        """
        provider = self.get_or_raise(name)

        if credentials is None and self._credential_loader is not None:
            credentials = self._credential_loader.get_credentials(name)

        if credentials is None:
            raise ProviderError(_MSG_NO_CREDENTIALS)

        try:
            await provider.connect(credentials)
            self._logger.info("provider_connected", provider=name.value)
        except Exception:
            self._logger.exception("provider_connection_failed", provider=name.value)
            raise
        else:
            return True

    async def disconnect_provider(self, name: ProviderName) -> None:
        """Disconnect a specific provider.

        Args:
            name: The provider to disconnect.
        """
        provider = self.get(name)
        if provider is not None and provider.is_connected:
            await provider.disconnect()
            self._logger.info("provider_disconnected", provider=name.value)

    async def disconnect_all(self) -> None:
        """Disconnect from all providers."""
        for name in list(self._providers.keys()):
            await self.disconnect_provider(name)

    def set_active(self, name: ProviderName) -> None:
        """Set the active provider.

        Args:
            name: The provider to make active.

        Raises:
            ProviderError: If provider not registered or not connected.
        """
        provider = self.get_or_raise(name)
        if not provider.is_connected:
            raise ProviderError(_MSG_NOT_CONNECTED)
        self._active_provider = name
        self._logger.info("active_provider_set", provider=name.value)

    @property
    def active(self) -> LLMProviderBase | None:
        """Get the currently active provider.

        Returns:
            LLMProviderBase | None: The active provider instance or None if none set.
        """
        if self._active_provider is None:
            return None
        return self._providers.get(self._active_provider)

    @property
    def active_name(self) -> ProviderName | None:
        """Get the name of the currently active provider.

        Returns:
            ProviderName | None: The active provider name or None if none set.
        """
        return self._active_provider

    def has_connected_provider(self) -> bool:
        """Check if any provider is connected.

        Returns:
            bool: True if at least one provider is connected.
        """
        return len(self.list_connected()) > 0


class _RegistryHolder:
    """Holder for the singleton registry instance."""

    instance: ProviderRegistry | None = None


def get_provider_registry() -> ProviderRegistry:
    """Get the global provider registry instance.

    Returns:
        ProviderRegistry: The singleton ProviderRegistry instance.
    """
    if _RegistryHolder.instance is None:
        _RegistryHolder.instance = ProviderRegistry()
    return _RegistryHolder.instance
