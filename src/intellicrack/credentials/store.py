# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Secure credential storage using OS keyring.

This module provides secure credential storage using the operating system's native credential manager (Windows Credential Manager, macOS
Keychain, or Linux Secret Service via the keyring library).
"""

from __future__ import annotations

import asyncio
import json
import threading
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum
from functools import cached_property
from typing import TYPE_CHECKING, ClassVar, Final

from intellicrack.core.logging import get_logger
from intellicrack.core.types import IntellicrackError, ProviderCredentials, ProviderName
from intellicrack.credentials.env_loader import CredentialLoader, get_credential_loader


if TYPE_CHECKING:
    from types import ModuleType

_logger = get_logger("credentials.store")

try:
    import keyring as _keyring_module
    import keyring.errors as _keyring_errors_module
except ImportError:
    _logger.debug("keyring_import_failed", exc_info=True)
    _keyring_module = None
    _keyring_errors_module = None


class _KeyringFallbackError(Exception):
    """Sentinel exception used when keyring.errors is unavailable.

    This class is never raised. It exists only to provide a concrete
    exception type for the ``except`` tuples when the optional ``keyring``
    dependency is missing, keeping the code paths type-consistent.
    """


if _keyring_errors_module is not None:
    _KeyringError: type[BaseException] = _keyring_errors_module.KeyringError
else:
    _KeyringError = _KeyringFallbackError


class CredentialStoreError(IntellicrackError):
    """Base error for credential store operations."""


class KeyringUnavailableError(CredentialStoreError):
    """Keyring backend is not available."""


class CredentialNotFoundError(CredentialStoreError):
    """Requested credential was not found."""


class CredentialSource(Enum):
    """Source of stored credentials."""

    KEYRING = "keyring"
    ENV_FILE = "env_file"
    ENV_VAR = "env_var"
    OAUTH = "oauth"


@dataclass(frozen=True)
class StoredCredential:
    """Metadata for a stored credential.

    Attributes:
        provider: Provider this credential belongs to.
        key_name: Human-readable name or label for the credential.
        created_at: When the credential was first stored.
        updated_at: When the credential was last updated.
        source: Where the credential originated from.
    """

    provider: ProviderName
    key_name: str
    created_at: datetime
    updated_at: datetime
    source: CredentialSource


class CredentialStore:
    """Secure credential storage using OS keyring with env fallback.

    This class provides thread-safe, async-compatible access to credentials
    stored in the operating system's secure credential storage (Windows
    Credential Manager on Windows, Keychain on macOS, Secret Service on Linux).

    If keyring is unavailable, falls back to CredentialLoader for .env files.

    Args:
        fallback_loader: CredentialLoader instance for fallback.
                       If None, creates a new one.

    Attributes:
        SERVICE_NAME: The keyring service name for Intellicrack credentials.
        METADATA_KEY: Key suffix for storing credential metadata.
    """

    SERVICE_NAME: Final[str] = "intellicrack"
    METADATA_KEY: Final[str] = "_metadata"

    def __init__(self, fallback_loader: CredentialLoader | None = None) -> None:
        """Initialize the CredentialStore with an optional fallback loader.

        Args:
            fallback_loader: CredentialLoader instance for env-file fallback. If None, creates a new one.
        """
        self._fallback_loader = fallback_loader or get_credential_loader()
        self._lock = asyncio.Lock()
        self._keyring: ModuleType | None = None
        self._keyring_checked: bool = False
        self._keyring_available: bool = False

    _UNUSABLE_BACKEND_NAMES: ClassVar[frozenset[str]] = frozenset({
        "fail.Keyring",
        "null.Keyring",
    })

    def _check_keyring(self) -> bool:
        """Check if keyring backend is available and functional.

        Performs passive inspection of the active keyring backend instead of
        writing and deleting a probe key.  The previous approach mutated the
        user's keyring on every initialization, which could collide with
        legitimate keys named ``intellicrack_test`` and pollute audit logs.

        Returns:
            bool: True if keyring is available and the active backend is a
            real credential store (not a fail/null backend).
        """
        if self._keyring_checked:
            return self._keyring_available

        self._keyring_checked = True

        if _keyring_module is None:
            _logger.warning("keyring_unavailable", reason="library_not_installed")
            return False

        try:
            backend = _keyring_module.get_keyring()
        except (OSError, RuntimeError, KeyError, ValueError, _KeyringError) as e:
            _logger.warning("keyring_unavailable", error=str(e), exc_info=True)
            return False

        backend_module = getattr(type(backend), "__module__", "")
        backend_name = type(backend).__name__
        qualified_name = f"{backend_module.rsplit('.', 1)[-1]}.{backend_name}" if backend_module else backend_name

        if qualified_name in self._UNUSABLE_BACKEND_NAMES or backend_name in {"Keyring", "FailKeyring", "NullKeyring"}:
            _logger.warning(
                "keyring_unavailable",
                reason="backend_is_fail_or_null",
                backend=qualified_name,
            )
            return False

        priority = getattr(backend, "priority", None)
        if isinstance(priority, (int, float)) and priority <= 0:
            _logger.warning(
                "keyring_unavailable",
                reason="backend_priority_non_positive",
                backend=qualified_name,
                priority=priority,
            )
            return False

        self._keyring = _keyring_module
        self._keyring_available = True
        _logger.info("keyring_backend_available", backend=qualified_name)
        return True

    @cached_property
    def keyring_available(self) -> bool:
        """Check if keyring backend is available and functional.

        Returns:
            bool: True if keyring can be used for credential storage.
        """
        return self._check_keyring()

    def _get_keyring_key(self, provider: ProviderName) -> str:
        """Get the keyring key name for a provider.

        Args:
            provider: The provider.

        Returns:
            str: The key name for keyring storage.
        """
        return f"{self.SERVICE_NAME}_{provider.value}"

    @staticmethod
    def _serialize_credentials(creds: ProviderCredentials) -> str:
        """Serialize credentials to JSON for storage.

        Args:
            creds: Credentials to serialize.

        Returns:
            str: JSON string representation.
        """
        data = asdict(creds)
        return json.dumps(data, ensure_ascii=False)

    @staticmethod
    def _deserialize_credentials(data: str) -> ProviderCredentials:
        """Deserialize credentials from JSON.

        Args:
            data: JSON string to deserialize.

        Returns:
            ProviderCredentials: ProviderCredentials instance.

        Raises:
            CredentialStoreError: If deserialization fails.
        """
        try:
            parsed = json.loads(data)
            return ProviderCredentials(
                api_key=parsed.get("api_key"),
                api_base=parsed.get("api_base"),
                organization_id=parsed.get("organization_id"),
                project_id=parsed.get("project_id"),
            )
        except (json.JSONDecodeError, TypeError, KeyError) as e:
            _logger.warning("credential_deserialize_failed", error=str(e), exc_info=True)
            msg = f"Failed to deserialize credentials: {e}"
            raise CredentialStoreError(msg) from e

    @staticmethod
    def _serialize_metadata(metadata: StoredCredential) -> str:
        """Serialize credential metadata to JSON.

        Args:
            metadata: Metadata to serialize.

        Returns:
            str: JSON string representation.
        """
        data = {
            "provider": metadata.provider.value,
            "key_name": metadata.key_name,
            "created_at": metadata.created_at.isoformat(),
            "updated_at": metadata.updated_at.isoformat(),
            "source": metadata.source.value,
        }
        return json.dumps(data, ensure_ascii=False)

    @staticmethod
    def _deserialize_metadata(data: str, provider: ProviderName) -> StoredCredential:
        """Deserialize credential metadata from JSON.

        Args:
            data: JSON string to deserialize.
            provider: Provider for the metadata.

        Returns:
            StoredCredential: StoredCredential instance.
        """
        try:
            parsed = json.loads(data)
            return StoredCredential(
                provider=ProviderName(parsed["provider"]),
                key_name=parsed.get("key_name", provider.value),
                created_at=datetime.fromisoformat(parsed["created_at"]),
                updated_at=datetime.fromisoformat(parsed["updated_at"]),
                source=CredentialSource(parsed["source"]),
            )
        except (json.JSONDecodeError, TypeError, KeyError, ValueError):
            _logger.debug("metadata_deserialize_fallback", provider=provider.value, exc_info=True)
            now = datetime.now(UTC)
            return StoredCredential(
                provider=provider,
                key_name=provider.value,
                created_at=now,
                updated_at=now,
                source=CredentialSource.KEYRING,
            )

    async def _get_from_keyring(self, provider: ProviderName) -> ProviderCredentials | None:
        """Get credentials directly from keyring.

        Args:
            provider: Provider to get credentials for.

        Returns:
            ProviderCredentials | None: ProviderCredentials or None if not found.
        """
        if self._keyring is None:
            return None

        key = self._get_keyring_key(provider)
        keyring = self._keyring

        def _fetch() -> str | None:
            result = keyring.get_password(self.SERVICE_NAME, key)
            return str(result) if result is not None else None

        try:
            data = await asyncio.to_thread(_fetch)
            return self._deserialize_credentials(data) if data else None
        except (OSError, KeyError, ValueError, _KeyringError, CredentialStoreError) as e:
            _logger.warning("keyring_get_failed", provider=provider.value, error=str(e), exc_info=True)
            return None

    async def _set_to_keyring(
        self,
        provider: ProviderName,
        credentials: ProviderCredentials,
        key_name: str | None = None,
        source: CredentialSource = CredentialSource.KEYRING,
    ) -> None:
        """Store credentials directly to keyring.

        Args:
            provider: Provider to store credentials for.
            credentials: Credentials to store.
            key_name: Optional human-readable name.
            source: Origin of the credentials being stored.

        Raises:
            KeyringUnavailableError: If keyring is not available.
            CredentialStoreError: If storage fails.
        """
        if self._keyring is None:
            msg = "Keyring is not available"
            raise KeyringUnavailableError(msg)

        key = self._get_keyring_key(provider)
        metadata_key = f"{key}{self.METADATA_KEY}"
        data = self._serialize_credentials(credentials)

        now = datetime.now(UTC)
        existing_metadata = await self._get_metadata(provider)

        metadata = StoredCredential(
            provider=provider,
            key_name=key_name or provider.value,
            created_at=existing_metadata.created_at if existing_metadata else now,
            updated_at=now,
            source=source,
        )
        metadata_data = self._serialize_metadata(metadata)
        keyring = self._keyring

        def _store() -> None:
            keyring.set_password(self.SERVICE_NAME, key, data)
            keyring.set_password(self.SERVICE_NAME, metadata_key, metadata_data)

        try:
            await asyncio.to_thread(_store)
            _logger.info("credentials_stored", provider=provider.value, store="keyring")
        except (OSError, KeyError, ValueError, _KeyringError) as e:
            _logger.warning("credential_store_failed", provider=provider.value, error=str(e), exc_info=True)
            msg = f"Failed to store credentials: {e}"
            raise CredentialStoreError(msg) from e

    async def _get_metadata(self, provider: ProviderName) -> StoredCredential | None:
        """Get credential metadata from keyring.

        Args:
            provider: Provider to get metadata for.

        Returns:
            StoredCredential | None: StoredCredential metadata or None.
        """
        if self._keyring is None:
            return None

        key = f"{self._get_keyring_key(provider)}{self.METADATA_KEY}"
        keyring = self._keyring

        def _fetch() -> str | None:
            result = keyring.get_password(self.SERVICE_NAME, key)
            return str(result) if result is not None else None

        try:
            data = await asyncio.to_thread(_fetch)
            return self._deserialize_metadata(data, provider) if data else None
        except (OSError, KeyError, ValueError, _KeyringError):
            _logger.debug("metadata_get_failed", provider=provider.value, exc_info=True)
            return None

    async def _get_unlocked(self, provider: ProviderName) -> ProviderCredentials | None:
        """Get credentials without acquiring ``self._lock``.

        This private helper performs the actual keyring read and env
        fallback. It is used internally by methods that already hold
        ``self._lock`` (such as :meth:`list_providers`) to avoid re-entrant
        lock acquisition which would deadlock ``asyncio.Lock``.

        Args:
            provider: The provider to get credentials for.

        Returns:
            ProviderCredentials | None: ProviderCredentials if found, None otherwise.
        """
        if self.keyring_available:
            creds = await self._get_from_keyring(provider)
            if creds is not None and creds.api_key:
                return creds

        _logger.debug("credential_fallback_to_env", provider=provider.value)
        return await asyncio.to_thread(self._fallback_loader.get_credentials, provider)

    async def get(self, provider: ProviderName) -> ProviderCredentials | None:
        """Get credentials for a provider.

        Checks keyring first, then falls back to env loader.

        Args:
            provider: The provider to get credentials for.

        Returns:
            ProviderCredentials | None: ProviderCredentials if found, None otherwise.
        """
        async with self._lock:
            return await self._get_unlocked(provider)

    async def get_or_raise(self, provider: ProviderName) -> ProviderCredentials:
        """Get credentials for a provider, raising if not found.

        Args:
            provider: The provider to get credentials for.

        Returns:
            ProviderCredentials: ProviderCredentials for the provider.

        Raises:
            CredentialNotFoundError: If no credentials are found.
        """
        creds = await self.get(provider)
        if creds is None:
            msg = f"No credentials found for {provider.value}"
            raise CredentialNotFoundError(msg)
        return creds

    async def set(
        self,
        provider: ProviderName,
        credentials: ProviderCredentials,
        key_name: str | None = None,
        source: CredentialSource = CredentialSource.KEYRING,
    ) -> None:
        """Store credentials for a provider in keyring.

        Args:
            provider: The provider to store credentials for.
            credentials: The credentials to store.
            key_name: Optional human-readable name for the credential.
            source: Origin of the credentials being stored.

        Raises:
            KeyringUnavailableError: If keyring is not available.
        """
        if not self.keyring_available:
            msg = (
                "Keyring is not available. Install keyring package and ensure "
                "a backend is available (Windows Credential Manager, macOS Keychain, etc.)"
            )
            raise KeyringUnavailableError(msg)

        async with self._lock:
            await self._set_to_keyring(provider, credentials, key_name, source)

    async def delete(self, provider: ProviderName) -> bool:
        """Delete credentials for a provider from keyring.

        Args:
            provider: The provider to delete credentials for.

        Returns:
            bool: True if credentials were deleted, False if not found.

        Raises:
            KeyringUnavailableError: If keyring is not available.
        """
        if not self.keyring_available or self._keyring is None:
            msg = "Keyring is not available"
            raise KeyringUnavailableError(msg)

        key = self._get_keyring_key(provider)
        metadata_key = f"{key}{self.METADATA_KEY}"
        keyring = self._keyring

        def _delete() -> bool:
            try:
                keyring.delete_password(self.SERVICE_NAME, key)
            except (OSError, KeyError, ValueError, _KeyringError):
                _logger.debug("keyring_delete_credential_failed", provider=provider.value, exc_info=True)
                return False
            try:
                keyring.delete_password(self.SERVICE_NAME, metadata_key)
            except (OSError, KeyError, ValueError, _KeyringError):
                _logger.debug("keyring_delete_metadata_failed", provider=provider.value, exc_info=True)
            return True

        async with self._lock:
            result = await asyncio.to_thread(_delete)
            if result:
                _logger.info("credentials_deleted", provider=provider.value, store="keyring")
            return result

    async def list_providers(self) -> list[StoredCredential]:
        """List all stored credential metadata.

        Returns:
            list[StoredCredential]: List of StoredCredential with metadata for each provider.
        """
        results: list[StoredCredential] = []

        async with self._lock:
            for provider in ProviderName:
                creds = await self._get_unlocked(provider)
                if creds is not None and creds.api_key:
                    metadata = await self._get_metadata(provider)
                    if metadata:
                        results.append(metadata)
                    else:
                        now = datetime.now(UTC)
                        results.append(
                            StoredCredential(
                                provider=provider,
                                key_name=provider.value,
                                created_at=now,
                                updated_at=now,
                                source=CredentialSource.ENV_FILE,
                            ),
                        )

        return results

    async def migrate_from_env(
        self,
        providers: list[ProviderName] | None = None,
        *,
        overwrite: bool = False,
    ) -> dict[ProviderName, bool]:
        """Migrate credentials from .env file to keyring.

        Args:
            providers: Specific providers to migrate. If None, migrates all.
            overwrite: Whether to overwrite existing keyring credentials.

        Returns:
            dict[ProviderName, bool]: Dict mapping provider to success status.

        Raises:
            KeyringUnavailableError: If keyring is not available.
        """
        if not self.keyring_available:
            msg = "Keyring is not available for migration"
            raise KeyringUnavailableError(msg)

        target_providers = providers or list(ProviderName)
        results: dict[ProviderName, bool] = {}

        async with self._lock:
            for provider in target_providers:
                env_creds = await asyncio.to_thread(self._fallback_loader.get_credentials, provider)
                if env_creds is None or not env_creds.api_key:
                    results[provider] = False
                    continue

                if not overwrite:
                    existing = await self._get_from_keyring(provider)
                    if existing is not None and existing.api_key:
                        _logger.info("credential_migration_skipped", provider=provider.value, reason="exists")
                        results[provider] = True
                        continue

                try:
                    await self._set_to_keyring(
                        provider,
                        env_creds,
                        source=CredentialSource.ENV_FILE,
                    )
                    results[provider] = True
                    _logger.info("credentials_migrated", provider=provider.value, source="env", destination="keyring")
                except (OSError, KeyError, ValueError, _KeyringError, CredentialStoreError) as exc:
                    _logger.warning("credential_migration_failed", provider=provider.value, error=str(exc), exc_info=True)
                    results[provider] = False

        return results

    async def validate(self, provider: ProviderName) -> tuple[bool, str | None]:
        """Validate credentials exist and are properly formatted.

        Args:
            provider: The provider to validate.

        Returns:
            tuple[bool, str | None]: Tuple of (is_valid, error_message).
        """
        creds = await self.get(provider)
        if creds is None or not creds.api_key:
            return False, f"No credentials found for {provider.value}"

        if provider == ProviderName.ANTHROPIC:
            if not creds.api_key.startswith("sk-ant-"):
                return False, "Anthropic API key should start with 'sk-ant-'"

        elif provider == ProviderName.OPENAI:
            if not creds.api_key.startswith("sk-"):
                return False, "OpenAI API key should start with 'sk-'"

        elif provider == ProviderName.OPENROUTER and not creds.api_key.startswith("sk-or-"):
            return False, "OpenRouter API key should start with 'sk-or-'"

        elif provider == ProviderName.GOOGLE and not creds.api_key.startswith("AIza"):
            return False, "Google API key should start with 'AIza'"

        elif provider == ProviderName.GROK and not creds.api_key.startswith("xai-"):
            return False, "Grok API key should start with 'xai-'"

        elif provider == ProviderName.HUGGINGFACE and not creds.api_key.startswith("hf_"):
            return False, "HuggingFace API token should start with 'hf_'"

        return True, None

    async def get_source(self, provider: ProviderName) -> CredentialSource | None:
        """Get the source of credentials for a provider.

        Args:
            provider: The provider to check.

        Returns:
            CredentialSource | None: CredentialSource or None if no credentials found.
        """
        if self.keyring_available:
            keyring_creds = await self._get_from_keyring(provider)
            if keyring_creds is not None and keyring_creds.api_key:
                metadata = await self._get_metadata(provider)
                return metadata.source if metadata is not None else CredentialSource.KEYRING
        env_creds = await asyncio.to_thread(self._fallback_loader.get_credentials, provider)
        if env_creds is not None and env_creds.api_key:
            is_valid, source_desc = await asyncio.to_thread(self._fallback_loader.validate_credentials, provider)
            if is_valid and source_desc and "environment" in source_desc.lower():
                return CredentialSource.ENV_VAR
            return CredentialSource.ENV_FILE

        return None


_store_lock = threading.Lock()


class _CredentialStoreHolder:
    """Holder for the module-level singleton credential store instance.

    Attributes:
        instance: The shared CredentialStore instance or ``None`` before init.
    """

    instance: CredentialStore | None = None


_store_holder = _CredentialStoreHolder()


def get_credential_store() -> CredentialStore:
    """Get the global credential store instance.

    Uses double-checked locking with a module-level :class:`threading.Lock`
    so concurrent callers from multiple threads cannot observe a partially
    constructed instance or race to create duplicates.

    Returns:
        CredentialStore: The singleton CredentialStore instance.
    """
    if _store_holder.instance is None:
        with _store_lock:
            if _store_holder.instance is None:
                _store_holder.instance = CredentialStore()
    return _store_holder.instance


async def get_credentials(provider: ProviderName) -> ProviderCredentials | None:
    """Get credentials for a provider using the global store.

    Args:
        provider: The provider to get credentials for.

    Returns:
        ProviderCredentials | None: ProviderCredentials or None if not configured.
    """
    store = get_credential_store()
    return await store.get(provider)
