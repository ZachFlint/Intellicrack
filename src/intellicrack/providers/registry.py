# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Provider registry for managing LLM providers.

This module provides a centralized registry for registering, connecting, and managing all LLM provider instances.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Protocol

from intellicrack.core.logging import get_logger
from intellicrack.core.types import (
    AuthenticationError,
    ConfigurationError,
    ProviderCredentials,
    ProviderError,
    ProviderName,
)


if TYPE_CHECKING:
    from intellicrack.providers.base import LLMProviderBase


_MSG_NOT_REGISTERED = "Not registered"
_MSG_NO_CREDENTIALS = "No credentials"
_MSG_NOT_CONNECTED = "Not connected"
_MSG_NO_ACTIVE_PROVIDER = "No active provider"
_MSG_DISCONNECT_FAILURES = "One or more providers failed to disconnect"
_MSG_NO_CLASS_REGISTERED = "No class registered for provider"

_logger = get_logger(__name__)


class CredentialLoaderProtocol(Protocol):
    """Protocol for objects that can load provider credentials.

    Any object exposing
    ``get_credentials(ProviderName) -> ProviderCredentials | None`` is acceptable.
    """

    def get_credentials(self, provider: ProviderName) -> ProviderCredentials | None:
        """Return credentials for the given provider, or None when unavailable.

        Args:
            provider: The provider to load credentials for.

        Returns:
            ProviderCredentials | None: Loaded credentials or None when unavailable.
        """


class ProviderRegistry:
    """Registry for all LLM providers.

    Manages provider instances, connections, and provides a unified interface for accessing any configured LLM provider.
    """

    def __init__(
        self,
        credential_loader: CredentialLoaderProtocol | None = None,
    ) -> None:
        """Initialize the ProviderRegistry with an optional credential loader.

        Args:
            credential_loader: Optional credential loader for auto-connecting providers.
        """
        self._providers: dict[ProviderName, LLMProviderBase] = {}
        self._provider_classes: dict[ProviderName, type[LLMProviderBase]] = {}
        self._active_provider: ProviderName | None = None
        self._credential_loader = credential_loader
        self._lock = threading.RLock()
        _logger.info(
            "provider_registry_initialized",
            has_credential_loader=credential_loader is not None,
        )

    def register(self, provider: LLMProviderBase) -> None:
        """Register a provider instance.

        The provider's concrete class is also recorded so the registry can
        act as a name-to-class factory through :meth:`connect_provider`.

        Args:
            provider: The provider instance to register.

        Note:
            If a provider with the same name is already registered, it will be
            replaced with a warning logged.
        """
        name = provider.name
        with self._lock:
            if name in self._providers:
                _logger.warning("provider_already_registered", provider=name.value)
            self._providers[name] = provider
            self._provider_classes[name] = type(provider)
            _logger.info("provider_registered", provider=name.value)

    def register_class(
        self,
        name: ProviderName,
        provider_class: type[LLMProviderBase],
    ) -> None:
        """Register a provider class without instantiating it.

        Useful when callers want :meth:`connect_provider` to construct the
        provider on demand from credentials provided by the configured
        :class:`CredentialLoaderProtocol`.

        Args:
            name: The provider name to associate with the class.
            provider_class: Concrete provider class to register.
        """
        with self._lock:
            self._provider_classes[name] = provider_class
            _logger.info("provider_class_registered", provider=name.value)

    def unregister(self, name: ProviderName) -> bool:
        """Unregister a provider.

        Args:
            name: The provider name to unregister.

        Returns:
            bool: True if provider was removed, False if not found.
        """
        with self._lock:
            if name in self._providers:
                del self._providers[name]
                if name in self._provider_classes:
                    del self._provider_classes[name]
                if self._active_provider == name:
                    self._active_provider = None
                _logger.info("provider_unregistered", provider=name.value)
                return True
            return False

    def get(self, name: ProviderName) -> LLMProviderBase | None:
        """Get a registered provider by name.

        Args:
            name: The provider name.

        Returns:
            LLMProviderBase | None: The provider instance or None if not registered.
        """
        with self._lock:
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
        with self._lock:
            provider = self._providers.get(name)
        if provider is None:
            _logger.error("provider_not_registered", provider=name.value)
            raise ProviderError(_MSG_NOT_REGISTERED, provider_name=name.value)
        return provider

    def list_registered(self) -> list[ProviderName]:
        """List all registered providers.

        Returns:
            list[ProviderName]: List of registered provider names.
        """
        with self._lock:
            return list(self._providers.keys())

    def list_connected(self) -> list[ProviderName]:
        """List all connected providers.

        Returns:
            list[ProviderName]: List of connected provider names.
        """
        with self._lock:
            connected: list[ProviderName] = [name for name, provider in self._providers.items() if provider.is_connected]
        return connected

    async def connect_provider(
        self,
        name: ProviderName,
        credentials: ProviderCredentials | None = None,
    ) -> bool:
        """Connect a specific provider.

        When ``credentials`` is None and a credential loader was supplied at
        construction time, this method calls
        ``loader.get_credentials(name)`` to fetch credentials before
        connecting the provider. If no instance exists yet but a class was
        registered via :meth:`register_class`, the class is instantiated and
        registered before connecting.

        Args:
            name: The provider to connect.
            credentials: Credentials to use. If None, attempts to load from
                        credential loader.

        Returns:
            bool: True on successful connection. The current implementation
            re-raises every failure for the caller, so callers can rely on
            True meaning "connected".

        Raises:
            ProviderError: If provider not registered or no credentials are
                available, or the provider raises ProviderError during connect.
            AuthenticationError: If provider authentication fails.
            ConfigurationError: If a configuration problem prevents connection.
            ConnectionError: If network connection fails.
            TimeoutError: If connection times out.
            OSError: If an OS-level I/O error occurs.
            RuntimeError: If the provider encounters a runtime failure.
            ValueError: If an invalid value is encountered during connection.
        """
        provider = self._get_or_construct(name)

        if credentials is None and self._credential_loader is not None:
            credentials = self._credential_loader.get_credentials(name)

        if credentials is None:
            _logger.error("provider_connect_no_credentials", provider=name.value)
            raise ProviderError(_MSG_NO_CREDENTIALS, provider_name=name.value)

        try:
            await provider.connect(credentials)
        except (AuthenticationError, ProviderError, ConfigurationError) as exc:
            _logger.warning(
                "provider_connection_failed",
                provider=name.value,
                error=str(exc),
            )
            raise
        except (ConnectionError, TimeoutError, OSError, RuntimeError, ValueError) as exc:
            _logger.warning(
                "provider_connection_failed",
                provider=name.value,
                error=str(exc),
            )
            raise

        _logger.info("provider_connected", provider=name.value)
        return True

    def _get_or_construct(self, name: ProviderName) -> LLMProviderBase:
        """Return the registered instance, constructing one from a class if needed.

        Args:
            name: The provider name.

        Returns:
            LLMProviderBase: The registered or freshly constructed provider.

        Raises:
            ProviderError: If neither an instance nor a class is registered
                for the requested provider, or class construction fails.
        """
        with self._lock:
            provider = self._providers.get(name)
            if provider is not None:
                return provider

            provider_class = self._provider_classes.get(name)
            if provider_class is None:
                _logger.error("provider_not_registered", provider=name.value)
                raise ProviderError(_MSG_NOT_REGISTERED, provider_name=name.value)

            try:
                instance = provider_class()
            except (TypeError, ValueError, RuntimeError) as exc:
                _logger.warning(
                    "provider_construction_failed",
                    provider=name.value,
                    error=str(exc),
                )
                msg = f"{_MSG_NO_CLASS_REGISTERED}: construction failed: {exc}"
                raise ProviderError(msg, provider_name=name.value) from exc

            self._providers[name] = instance
            _logger.info("provider_constructed_from_class", provider=name.value)
            return instance

    async def disconnect_provider(self, name: ProviderName) -> None:
        """Disconnect a specific provider.

        Clears ``_active_provider`` if it pointed at the disconnected provider.

        Args:
            name: The provider to disconnect.
        """
        with self._lock:
            provider = self._providers.get(name)
        if provider is not None and provider.is_connected:
            await provider.disconnect()
            _logger.info("provider_disconnected", provider=name.value)
        with self._lock:
            if self._active_provider == name:
                self._active_provider = None
                _logger.info("active_provider_cleared", provider=name.value)

    async def disconnect_all(self) -> None:
        """Disconnect from all providers, aggregating any failures.

        Each provider's ``disconnect()`` is wrapped in an isolated
        try/except. After every provider has been processed, any collected
        errors are re-raised as a single :class:`ProviderError` whose
        ``details["errors"]`` field carries a list of per-provider failures.

        Raises:
            ProviderError: If one or more providers failed to disconnect.
        """
        with self._lock:
            names = list(self._providers.keys())

        errors: list[dict[str, str]] = []
        for name in names:
            try:
                await self.disconnect_provider(name)
            except (ProviderError, ConnectionError, OSError, RuntimeError, ValueError) as exc:
                _logger.warning(
                    "provider_disconnect_failed",
                    provider=name.value,
                    error=str(exc),
                )
                errors.append({"provider": name.value, "error": str(exc)})

        if errors:
            raise ProviderError(
                _MSG_DISCONNECT_FAILURES,
                details={"errors": errors},
            )

    def set_active(self, name: ProviderName) -> None:
        """Set the active provider.

        Args:
            name: The provider to make active.

        Raises:
            ProviderError: If provider not registered or not connected.
        """
        provider = self.get_or_raise(name)
        if not provider.is_connected:
            _logger.error("set_active_provider_not_connected", provider=name.value)
            raise ProviderError(_MSG_NOT_CONNECTED, provider_name=name.value)
        with self._lock:
            self._active_provider = name
        _logger.info("active_provider_set", provider=name.value)

    @property
    def active(self) -> LLMProviderBase | None:
        """The currently active provider.

        Returns:
            LLMProviderBase | None: The active provider instance or None if none set.
        """
        with self._lock:
            if self._active_provider is None:
                return None
            return self._providers.get(self._active_provider)

    @property
    def active_name(self) -> ProviderName | None:
        """The name of the currently active provider.

        Returns:
            ProviderName | None: The active provider name or None if none set.
        """
        with self._lock:
            return self._active_provider

    def get_active_provider(self) -> LLMProviderBase | None:
        """Return the currently active provider, if any.

        Returns:
            LLMProviderBase | None: The active provider instance or None if none set.
        """
        return self.active

    def has_connected_provider(self) -> bool:
        """Check if any provider is connected.

        Returns:
            bool: True if at least one provider is connected.
        """
        return len(self.list_connected()) > 0


class _RegistryHolder:
    """Holder for the singleton registry instance."""

    instance: ProviderRegistry | None = None


_registry_lock = threading.Lock()


def get_provider_registry(
    credential_loader: CredentialLoaderProtocol | None = None,
) -> ProviderRegistry:
    """Get the global provider registry instance.

    Uses double-checked locking to ensure thread-safe lazy initialization of the
    singleton instance. The first check avoids lock acquisition overhead on the
    common path after initialization, while the inner check under the lock
    guarantees that only one instance is ever created even under concurrent access.

    The optional ``credential_loader`` is used only on first construction; once
    the singleton exists, subsequent calls return the existing instance and the
    argument is ignored. Use :func:`reset_provider_registry` from tests to
    rebuild the singleton with a different loader.

    Args:
        credential_loader: Optional credential loader to inject on first construction.

    Returns:
        ProviderRegistry: The singleton ProviderRegistry instance.
    """
    if _RegistryHolder.instance is None:
        with _registry_lock:
            if _RegistryHolder.instance is None:
                _RegistryHolder.instance = ProviderRegistry(credential_loader=credential_loader)
    return _RegistryHolder.instance


def reset_provider_registry() -> None:
    """Reset the global provider registry singleton.

    Intended for use by tests that need to rebuild the registry between cases. Production code should not call this.
    """
    with _registry_lock:
        _RegistryHolder.instance = None
