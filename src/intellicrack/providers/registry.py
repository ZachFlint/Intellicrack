"""Provider registry for managing LLM providers.

This module provides a centralized registry for registering, connecting,
and managing all LLM provider instances.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from ..core.logging import get_logger
from ..core.types import ModelInfo, ProviderCredentials, ProviderError, ProviderName


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

    Attributes:
        _providers: Dictionary mapping provider names to provider instances.
        _active_provider: The currently active provider name.
        _credential_loader: Optional credential loader for auto-connection.
    """

    def __init__(
        self,
        credential_loader: CredentialLoader | None = None,
    ) -> None:
        """Initialize the provider registry.

        Args:
            credential_loader: Optional credential loader for auto-connecting providers.
        """
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
            self._logger.warning("provider_already_registered", extra={"provider": name.value})
        self._providers[name] = provider
        self._logger.info("provider_registered", extra={"provider": name.value})

    def unregister(self, name: ProviderName) -> bool:
        """Unregister a provider.

        Args:
            name: The provider name to unregister.

        Returns:
            True if provider was removed, False if not found.
        """
        if name in self._providers:
            del self._providers[name]
            if self._active_provider == name:
                self._active_provider = None
            self._logger.info("provider_unregistered", extra={"provider": name.value})
            return True
        return False

    def get(self, name: ProviderName) -> LLMProviderBase | None:
        """Get a registered provider by name.

        Args:
            name: The provider name.

        Returns:
            The provider instance or None if not registered.
        """
        return self._providers.get(name)

    def get_or_raise(self, name: ProviderName) -> LLMProviderBase:
        """Get a registered provider by name, raising if not found.

        Args:
            name: The provider name.

        Returns:
            The provider instance.

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
            List of registered provider names.
        """
        return list(self._providers.keys())

    def list_connected(self) -> list[ProviderName]:
        """List all connected providers.

        Returns:
            List of connected provider names.
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
            True if connection succeeded.

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
            self._logger.info("provider_connected", extra={"provider": name.value})
        except Exception:
            self._logger.exception("provider_connection_failed", extra={"provider": name.value})
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
            self._logger.info("provider_disconnected", extra={"provider": name.value})

    async def connect_all(
        self,
        credentials_map: dict[ProviderName, ProviderCredentials] | None = None,
    ) -> dict[ProviderName, bool]:
        """Connect to all registered providers.

        Args:
            credentials_map: Optional mapping of providers to credentials.
                           Falls back to credential loader if not provided.

        Returns:
            Dictionary mapping provider names to connection success status.
        """
        results: dict[ProviderName, bool] = {}

        async def connect_one(name: ProviderName) -> tuple[ProviderName, bool]:
            try:
                creds = None
                if credentials_map and name in credentials_map:
                    creds = credentials_map[name]
                elif self._credential_loader:
                    creds = self._credential_loader.get_credentials(name)

                if creds is None:
                    return name, False

                await self.connect_provider(name, creds)
            except Exception as e:
                self._logger.warning("provider_connection_failed", extra={"provider": name.value, "error": str(e)})
                return name, False
            else:
                return name, True

        tasks = [connect_one(name) for name in self._providers]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for result in completed:
            if isinstance(result, tuple):
                name, success = result
                results[name] = success
            else:
                self._logger.error("connection_task_failed", extra={"error": str(result)})

        return results

    async def disconnect_all(self) -> None:
        """Disconnect from all providers."""
        for name in list(self._providers.keys()):
            await self.disconnect_provider(name)

    async def get_all_models(self) -> dict[ProviderName, list[ModelInfo]]:
        """Get models from all connected providers.

        Returns:
            Dict mapping provider names to their available models.
        """
        models: dict[ProviderName, list[ModelInfo]] = {}

        for name, provider in self._providers.items():
            if provider.is_connected:
                try:
                    provider_models = await provider.list_models()
                    models[name] = provider_models
                except Exception as e:
                    self._logger.warning("models_fetch_failed", extra={"provider": name.value, "error": str(e)})
                    models[name] = []
            else:
                models[name] = []

        return models

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
        self._logger.info("active_provider_set", extra={"provider": name.value})

    @property
    def active(self) -> LLMProviderBase | None:
        """Get the currently active provider.

        Returns:
            The active provider instance or None if none set.
        """
        if self._active_provider is None:
            return None
        return self._providers.get(self._active_provider)

    @property
    def active_name(self) -> ProviderName | None:
        """Get the name of the currently active provider.

        Returns:
            The active provider name or None if none set.
        """
        return self._active_provider

    def has_connected_provider(self) -> bool:
        """Check if any provider is connected.

        Returns:
            True if at least one provider is connected.
        """
        return len(self.list_connected()) > 0

    def set_credential_loader(self, loader: CredentialLoader) -> None:
        """Set the credential loader for auto-connection.

        Args:
            loader: The credential loader to use.
        """
        self._credential_loader = loader


class _RegistryHolder:
    """Holder for the singleton registry instance."""

    instance: ProviderRegistry | None = None


def get_provider_registry() -> ProviderRegistry:
    """Get the global provider registry instance.

    Returns:
        The singleton ProviderRegistry instance.
    """
    if _RegistryHolder.instance is None:
        _RegistryHolder.instance = ProviderRegistry()
    return _RegistryHolder.instance


def register_provider(provider: LLMProviderBase) -> None:
    """Register a provider with the global registry.

    Args:
        provider: The provider to register.
    """
    registry = get_provider_registry()
    registry.register(provider)


def get_active_provider() -> LLMProviderBase:
    """Get the currently active provider.

    Returns:
        The active provider.

    Raises:
        ProviderError: If no provider is active.
    """
    registry = get_provider_registry()
    provider = registry.active
    if provider is None:
        raise ProviderError(_MSG_NO_ACTIVE_PROVIDER)
    return provider
